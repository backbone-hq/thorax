//! Shared record-building helpers for in-crate tests (`validate`, `merge`) and — via the
//! `test-support` feature — for downstream crates' tests (e.g. `thorax-ops`). Records are
//! signed with [`DeterministicCrypto`]; the trailing `counter` on builders is the LWW
//! Lamport counter.

use crate::crypto::{
    derive_seeded_hash, derive_user_id, key_hash, signed_record_message, CryptoProvider,
    DeterministicCrypto, RecordSigner,
};
use crate::format::*;
use crate::ids::derive_group_member_id;
use crate::ratchet::Ratchet;
use crate::validate::{validate_vault, ValidationReport};

#[derive(Clone, Debug)]
pub struct TestUser {
    pub id: UserId,
    pub signing_public_key: Bytes,
    pub hpke_public_key: Bytes,
}

/// Lets a [`TestUser`] act wherever ops expects a signing identity; signatures come from
/// [`DeterministicCrypto`], matching how every builder in this module signs records.
impl RecordSigner for TestUser {
    fn user_id(&self) -> &UserId {
        &self.id
    }

    fn signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    fn hpke_public_key(&self) -> &[u8] {
        &self.hpke_public_key
    }

    fn sign(&self, domain: &str, message: &[u8]) -> Bytes {
        DeterministicCrypto.sign(domain, &self.signing_public_key, message)
    }
}

/// A [`DeterministicCrypto`]-delegating provider that counts signature verifications —
/// for tests asserting how many times validation actually re-verified records.
#[derive(Debug, Default)]
pub struct CountingCrypto {
    pub verifications: std::cell::Cell<usize>,
}

impl CryptoProvider for CountingCrypto {
    fn hash(&self, domain: &str, canonical_bytes: &[u8]) -> HashValue {
        DeterministicCrypto.hash(domain, canonical_bytes)
    }

    fn verify_signature(
        &self,
        domain: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        self.verifications.set(self.verifications.get() + 1);
        DeterministicCrypto.verify_signature(domain, public_key, message, signature)
    }
}

pub struct Fixture {
    pub crypto: DeterministicCrypto,
    pub root: TestUser,
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Fixture {
    pub fn new() -> Self {
        let crypto = DeterministicCrypto;
        let root = test_user(&crypto, "root");
        Self { crypto, root }
    }

    pub fn validate(&self, records: Vec<VaultRecordV1>) -> ValidationReport {
        let ratchet = Ratchet::new(key_hash(&self.crypto, &self.root.signing_public_key).unwrap());
        self.validate_with_ratchet(records, &ratchet)
    }

    pub fn validate_with_ratchet(
        &self,
        records: Vec<VaultRecordV1>,
        ratchet: &Ratchet,
    ) -> ValidationReport {
        validate_vault(&vault_from_records(records), ratchet, &self.crypto).unwrap()
    }

    pub fn root_signing_public_key_hash(&self) -> HashValue {
        key_hash(&self.crypto, &self.root.signing_public_key).unwrap()
    }
}

pub fn vault_from_records(records: Vec<VaultRecordV1>) -> VaultStore {
    VaultStore::V1(VaultStoreV1 {
        records: records.into(),
    })
}

/// A signed record as a newer thorax would write it: a record *kind* at an enum index this
/// build's `RecordBodyV1` does not define. The body decodes as `Evolving::Unknown` with
/// the exact payload bytes, so it exercises the inert-but-preserved advisory path end to
/// end (decode, validate-as-warning, merge union, byte-identical re-encode).
pub fn future_record_kind(seed: u8) -> VaultRecordV1 {
    #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
    enum RecordBodyFuture {
        #[cord(index = 60)]
        Annotation { note: String, counter: u64 },
    }
    #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
    struct SignedFuture {
        #[cord(evolving = 32)]
        body: cord::Evolving<RecordBodyFuture>,
        signing_public_key: Bytes,
        signature: Bytes,
    }

    let future = SignedFuture {
        body: cord::Evolving::new(RecordBodyFuture::Annotation {
            note: format!("from-the-future-{seed}"),
            counter: u64::from(seed),
        }),
        signing_public_key: vec![seed; 32],
        signature: vec![seed; 8],
    };
    let bytes = cord::serialize(&future).expect("future record must serialize");
    let decoded: VaultRecordV1 =
        cord::deserialize(&bytes).expect("future record must decode as a signed envelope");
    assert!(
        decoded.body.is_unknown(),
        "future record kind must not be readable"
    );
    decoded
}

pub fn test_user(crypto: &DeterministicCrypto, name: &str) -> TestUser {
    let signing_public_key = format!("{name}:signing").into_bytes();
    let hpke_public_key = format!("{name}:hpke").into_bytes();
    let id = derive_user_id(crypto, &signing_public_key, &hpke_public_key).unwrap();
    TestUser {
        id,
        signing_public_key,
        hpke_public_key,
    }
}

pub fn vault_root_record(fixture: &Fixture) -> VaultRecordV1 {
    vault_root_record_for(&fixture.crypto, &fixture.root)
}

/// A self-signed `VaultRoot` for an arbitrary user — lets merge tests build a *different*
/// ratchet domain than the fixture's.
pub fn vault_root_record_for(crypto: &DeterministicCrypto, root: &TestUser) -> VaultRecordV1 {
    let body = RecordBodyV1::VaultRoot(VaultRootRecordV1 {
        id: root.id.clone(),
        hpke_public_key: root.hpke_public_key.clone(),
    });
    signed_record(crypto, root, body)
}

// User records are admin-signed; the fixture's root acts as the introducing admin.
pub fn user_record(fixture: &Fixture, user: &TestUser, counter: u64) -> VaultRecordV1 {
    user_record_signed_by(fixture, &fixture.root, user, counter)
}

pub fn user_record_signed_by(
    fixture: &Fixture,
    signer: &TestUser,
    user: &TestUser,
    counter: u64,
) -> VaultRecordV1 {
    let body = RecordBodyV1::User(UserRecordV1 {
        id: user.id.clone(),
        signing_public_key: user.signing_public_key.clone(),
        hpke_public_key: user.hpke_public_key.clone(),
        counter,
    });
    signed_record(&fixture.crypto, signer, body)
}

pub fn trust_root(
    crypto: &DeterministicCrypto,
    user: &TestUser,
    fixture: &Fixture,
    counter: u64,
) -> VaultRecordV1 {
    let body = RecordBodyV1::EntryPoint(EntryPointRecordV1 {
        trusted_root_user_id: fixture.root.id.clone(),
        hpke_public_key: user.hpke_public_key.clone(),
        counter,
    });
    signed_record(crypto, user, body)
}

pub fn grant_record(
    crypto: &DeterministicCrypto,
    seed: &str,
    issuer: &TestUser,
    subject: PrincipalRefV1,
    permission: GrantPermissionV1,
    counter: u64,
) -> VaultRecordV1 {
    grant_record_with_id(crypto, seed, issuer, subject, permission, counter)
}

pub fn grant_record_with_id(
    crypto: &DeterministicCrypto,
    seed: &str,
    issuer: &TestUser,
    subject: PrincipalRefV1,
    permission: GrantPermissionV1,
    counter: u64,
) -> VaultRecordV1 {
    let seed = seed_from(seed);
    let grant_id = GrantId(derive_seeded_hash(crypto, "thorax.grant.v1", &seed).unwrap());
    let body = RecordBodyV1::Grant(GrantRecordV1 {
        id: grant_id.clone(),
        seed,
        subject_id: subject,
        permission,
        counter,
    });
    signed_record(crypto, issuer, body)
}

pub fn grant_deleted_record(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    grant_id: GrantId,
    permission: GrantPermissionV1,
    counter: u64,
) -> VaultRecordV1 {
    let body = RecordBodyV1::GrantDeleted(GrantDeletedRecordV1 {
        id: grant_id.clone(),
        permission,
        counter,
    });
    signed_record(crypto, signer, body)
}

pub fn group_record(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    seed: &str,
    handle: &str,
    counter: u64,
) -> VaultRecordV1 {
    let seed = seed_from(seed);
    let group_id = GroupId(derive_seeded_hash(crypto, "thorax.group.v1", &seed).unwrap());
    let body = RecordBodyV1::Group(GroupRecordV1 {
        id: group_id.clone(),
        seed,
        handle: handle.to_string(),
        counter,
    });
    signed_record(crypto, signer, body)
}

pub fn group_member_record(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    group_id: GroupId,
    member: PrincipalRefV1,
    counter: u64,
) -> VaultRecordV1 {
    let id = derive_group_member_id(crypto, &group_id, &member).unwrap();
    let body = RecordBodyV1::GroupMember(GroupMemberRecordV1 {
        id,
        group_id,
        member_id: member,
        counter,
    });
    signed_record(crypto, signer, body)
}

pub fn user_deleted_record(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    user_id: UserId,
    counter: u64,
) -> VaultRecordV1 {
    let body = RecordBodyV1::UserDeleted(UserDeletedRecordV1 {
        id: user_id,
        reason: None,
        counter,
    });
    signed_record(crypto, signer, body)
}

pub fn secret_record(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    selector: &SecretSelectorV1,
    slot_readers: &[&TestUser],
    counter: u64,
) -> VaultRecordV1 {
    secret_record_with_payload(
        crypto,
        signer,
        selector,
        slot_readers,
        b"ciphertext",
        counter,
    )
}

/// Like [`secret_record`], with caller-chosen ciphertext bytes — merge tests use diverging
/// payloads to build genuinely conflicting same-counter writes at one selector.
pub fn secret_record_with_payload(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    selector: &SecretSelectorV1,
    slot_readers: &[&TestUser],
    ciphertext: &[u8],
    counter: u64,
) -> VaultRecordV1 {
    let secret_id = crate::ids::derive_secret_id(crypto, selector).unwrap();
    let body = RecordBodyV1::Secret(SecretRecordV1 {
        id: secret_id,
        selector: selector.clone(),
        sealed: SealedPayloadV1 {
            nonce: b"nonce".to_vec(),
            ciphertext: ciphertext.to_vec(),
            recipient_slots: slot_readers
                .iter()
                .map(|user| RecipientSlotV1 {
                    recipient_id: user.id.clone(),
                    hpke_encapsulated_key: b"enc".to_vec(),
                    wrapped_content_key: b"wrapped".to_vec(),
                })
                .collect(),
        },
        counter,
    });
    signed_record(crypto, signer, body)
}

pub fn signed_record(
    crypto: &DeterministicCrypto,
    signer: &TestUser,
    body: RecordBodyV1,
) -> VaultRecordV1 {
    let mut signed = VaultRecordV1 {
        body: cord::Evolving::new(body),
        signing_public_key: signer.signing_public_key.clone(),
        signature: Vec::new(),
    };
    let message = signed_record_message(&signed).unwrap();
    signed.signature = crypto.sign("thorax.signed.v1", &signer.signing_public_key, &message);
    signed
}

pub fn seed_from(seed: &str) -> IdSeed {
    IdSeed(seed.as_bytes().to_vec())
}

pub fn grant_id(crypto: &DeterministicCrypto, seed: &str) -> GrantId {
    GrantId(derive_seeded_hash(crypto, "thorax.grant.v1", &seed_from(seed)).unwrap())
}

pub fn group_id(crypto: &DeterministicCrypto, seed: &str) -> GroupId {
    GroupId(derive_seeded_hash(crypto, "thorax.group.v1", &seed_from(seed)).unwrap())
}

pub fn keyspace_prefix(parts: &[&str]) -> KeyspaceSelectorV1 {
    KeyspaceSelectorV1 {
        tuple: TupleMatcherV1::Prefix(parts.iter().map(|part| (*part).to_string()).collect()),
        labels: Vec::new(),
    }
}

pub fn secret_selector(parts: &[&str]) -> SecretSelectorV1 {
    SecretSelectorV1 {
        tuple: parts.iter().map(|part| (*part).to_string()).collect(),
        labels: Vec::new(),
    }
}
