use crate::authz::AuthoritySet;
use crate::crypto::{derive_hash, CryptoProvider};
use crate::format::*;
use crate::merge::{ConflictKind, ConflictReport};
use crate::ratchet::{Ratchet, RatchetUpdate};
use crate::Result;
use std::collections::{BTreeMap, BTreeSet};

mod effective;
mod pipeline;
mod state;
mod structure;
#[cfg(test)]
mod tests;

use pipeline::validate_v1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationIssue {
    InvalidStructure(String),
    InvalidSignature(RecordKey),
    /// A record's envelope names a signing key (by hash here) that no introduced identity
    /// holds — there is no one the signature could attest to. Like a bad signature, this
    /// is tamper-suspect and blocking.
    UnknownSignerKey(HashValue),
    RootNotTrusted,
    AmbiguousRoot,
    AuthorityDidNotConverge,
    /// The vault's format version is below the highest this machine has verified under
    /// this root — the downgrade analogue of a rollback (a newer vault's records
    /// re-wrapped in an older envelope, shedding the newer semantics). Fails closed.
    FormatVersionRegression {
        remembered: u64,
        current: u64,
    },
}

/// Non-blocking observations: surfaced by status/validate views, never a reason to refuse
/// reads, writes, or merges. Contrast [`ValidationIssue`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationWarning {
    /// Records written by a newer thorax whose kind this build cannot read. Advisory
    /// records never change what this build should compute: they are inert here, preserved
    /// byte-for-byte through merges and rewrites, and excluded from the Lamport maximum. A
    /// counter collision with one degrades to a visible conflict once upgraded, never silent
    /// corruption. Consider upgrading.
    UnknownRecords { count: usize },
    /// A signing public key (named by its hash) is claimed by more than one *attested*
    /// identity — i.e. more than one self-signed entry point under that key declares a
    /// distinct `(signing, hpke)` pairing. Only the key's own holder can produce such an
    /// entry point, so this is the holder self-colliding (corruption), never an attacker
    /// targeting someone else's key. The blast radius is contained: records signed under
    /// the contested key are inert (dropped), but the rest of the vault stays valid — so a
    /// self-collision can only deny the colliding party their own records, not brick the
    /// vault for everyone. Surfaced loudly here rather than silently dropped.
    AmbiguousSigningKey(HashValue),
}

#[derive(Clone, Debug)]
pub struct ValidationReport {
    pub effective: EffectiveState,
    pub ratchet_update: RatchetUpdate,
    pub issues: Vec<ValidationIssue>,
    pub warnings: Vec<ValidationWarning>,
}

#[derive(Clone, Debug, Default)]
pub struct EffectiveState {
    pub root_user_id: Option<UserId>,
    pub root_signing_public_key_hash: Option<HashValue>,
    pub users: BTreeMap<UserId, UserRecordV1>,
    pub handles: BTreeMap<UserHandleId, UserHandleRecordV1>,
    pub vault_handles: BTreeMap<VaultHandleId, VaultHandleRecordV1>,
    pub groups: BTreeMap<GroupId, GroupRecordV1>,
    pub memberships: BTreeMap<GroupMemberId, GroupMemberRecordV1>,
    pub grants: BTreeMap<GrantId, GrantRecordV1>,
    /// For each effective user, their self-signed statement of which root they trust. This
    /// is the in-vault half of the trust chain `private key -> UserId -> EntryPointRecord
    /// -> root`, letting a client confirm the root from its key plus the vault alone.
    pub entry_points: BTreeMap<UserId, EntryPointRecordV1>,
    /// Objects whose LWW winner is a deletion tombstone — explicitly deleted, as opposed to
    /// never having existed. Purely an observability view (diagnostics, "already deleted"
    /// guards); effectiveness is fully captured by the maps above.
    pub deleted_users: BTreeSet<UserId>,
    pub deleted_groups: BTreeSet<GroupId>,
    pub deleted_grants: BTreeSet<GrantId>,
    pub authorities: BTreeMap<PrincipalRefV1, AuthoritySet>,
    /// The authority fixpoint did not converge (or a format-version regression voided the
    /// state): the principal graph is unresolved, so everything authority-dependent fails
    /// closed — secrets classify `Invalid`, mutations are refused. Unknown *records* do
    /// NOT set this: they are advisory by contract and merely warn (see
    /// [`ValidationWarning::UnknownRecords`]).
    pub authority_unresolved: bool,
    /// Keys with no effective winner because their winning counter is disputed: a
    /// same-counter tie of diverging bodies, or a suspected rollback (the verified counter
    /// fell below this machine's remembered watermark). A conflicted key contributes
    /// nothing to the maps above — fail closed — reads of it error, listings flag it, and
    /// it stays that way until an authorized resolver re-signs a winner above the disputed
    /// counter (see `thorax-ops`' conflict resolution).
    pub conflicted: BTreeMap<RecordKey, ConflictReport>,
    /// Highest authority-admitted counter observed during validation. Unauthorized signed
    /// records are deliberately excluded so read-only members cannot poison the Lamport clock.
    admitted_counter_max: Option<u64>,
    verified_records: Vec<VerifiedRecord>,
    /// Per-secret LWW winner positions over `verified_records`, built once by
    /// [`EffectiveState::attach_verified_records`] — the O(log N) lookup behind
    /// `secret_record` / `secret_records`, replacing per-query rescans of the record set.
    secret_index: BTreeMap<SecretId, SecretSlot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretState {
    ActiveDecryptable,
    NotEncryptedForReader,
    Unauthorized,
    Missing,
    /// The secret's key is conflicted (a same-counter tie or a suspected rollback): no
    /// candidate is the value, so reads fail until an authorized resolver picks a winner.
    Conflicted,
    Invalid,
}

/// A live secret: the LWW-winning value record for a secret, with its signer. Deletions are not
/// representable here — a secret whose latest record is a deletion is simply absent from the live
/// view (see [`EffectiveState::secret_record`] / [`EffectiveState::secret_records`]).
/// Deletion remains a signed fact in the log, but it is never *returned* as a secret; the only
/// thing that observes it is [`EffectiveState::secret_record_is_current`], which ops uses to
/// verify a just-committed mutation took effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveSecretV1 {
    pub signed: VaultRecordV1,
    pub value: SecretRecordV1,
}

#[derive(Clone, Debug)]
struct VerifiedRecord {
    signed: VaultRecordV1,
    body: RecordBodyV1,
    /// The record's logical key, derived from its body (records no longer carry a redundant
    /// key in their signed header — see `record_key_for`).
    key: RecordKey,
    record_hash: HashValue,
    /// The identity the envelope's signing key resolved to under the key-uniqueness
    /// invariant — the record's *verified* author. The envelope itself never names a
    /// user; this is derived during validation and is what authority checks consume.
    signer: UserId,
}

/// One secret key's slot in the winner index: where its LWW-winning *authorized* record
/// sits in `verified_records`, and where the key first appeared there (which is the
/// listing order `secret_records` preserves). Conflict gating is not baked in — conflicted
/// keys are indexed but excluded at the query layer, exactly like the scans this replaced.
#[derive(Clone, Debug)]
struct SecretSlot {
    winner: usize,
    first_seen: usize,
}

/// The logical key (LWW grouping) a record body resolves to. The key is fully determined by
/// the body, so it is derived rather than stored alongside it — there is no separately-signed
/// key that could disagree with the body. Handle keys hash the normalized handle string; every
/// other kind already carries its identifying id in the body. Deletion tombstones share the
/// key of the object they remove, which is what makes them LWW competitors at that key.
///
/// `signer` is the *resolved* author (the identity the envelope's signing key maps to) —
/// only entry-point records, whose body carries no id, key on it.
pub fn record_key_for(body: &RecordBodyV1, signer: &UserId) -> Result<RecordKey> {
    Ok(match body {
        RecordBodyV1::VaultRoot(_) => RecordKey::VaultRoot,
        // EntryPoint has no in-body id; its owner is the record's (resolved) signer.
        RecordBodyV1::EntryPoint(_) => RecordKey::EntryPoint {
            user_id: signer.clone(),
        },
        RecordBodyV1::User(r) => RecordKey::User {
            user_id: r.id.clone(),
        },
        RecordBodyV1::UserDeleted(r) => RecordKey::User {
            user_id: r.id.clone(),
        },
        RecordBodyV1::UserHandle(r) => RecordKey::UserHandle {
            handle_id: r.id.clone(),
        },
        RecordBodyV1::VaultHandle(r) => RecordKey::VaultHandle {
            handle_id: r.id.clone(),
        },
        RecordBodyV1::Group(r) => RecordKey::Group {
            group_id: r.id.clone(),
        },
        RecordBodyV1::GroupDeleted(r) => RecordKey::Group {
            group_id: r.id.clone(),
        },
        RecordBodyV1::GroupMember(r) => RecordKey::GroupMember {
            group_member_id: r.id.clone(),
        },
        RecordBodyV1::GroupMemberDeleted(r) => RecordKey::GroupMember {
            group_member_id: r.id.clone(),
        },
        RecordBodyV1::Grant(r) => RecordKey::Grant {
            grant_id: r.id.clone(),
        },
        RecordBodyV1::GrantDeleted(r) => RecordKey::Grant {
            grant_id: r.id.clone(),
        },
        RecordBodyV1::Secret(r) => RecordKey::Secret {
            secret_id: r.id.clone(),
        },
        RecordBodyV1::SecretDeleted(r) => RecordKey::Secret {
            secret_id: r.id.clone(),
        },
    })
}

/// The vault file's leading magic, so the file identifies itself to humans and tools
/// (`file(1)`, corruption triage, future container re-parsing) before any cord parsing.
/// Not a version field — the format version is the `VaultStore` enum variant behind it.
pub const VAULT_MAGIC: &[u8] = b"thorax-vault\0";

pub fn encode_vault(vault: &VaultStore) -> Result<Vec<u8>> {
    let VaultStore::V1(v1) = vault;
    if v1.records.len() > MAX_VAULT_RECORDS {
        return Err(crate::CoreError::Validation(format!(
            "vault carries {} records, above the supported maximum of {MAX_VAULT_RECORDS}",
            v1.records.len()
        )));
    }
    let payload = cord::serialize(vault)?;
    let encoded_len = VAULT_MAGIC.len().saturating_add(payload.len());
    if encoded_len > MAX_VAULT_BYTES {
        return Err(crate::CoreError::Validation(format!(
            "vault is {encoded_len} bytes, above the supported maximum of {MAX_VAULT_BYTES}"
        )));
    }
    let mut bytes = Vec::with_capacity(VAULT_MAGIC.len() + payload.len());
    bytes.extend_from_slice(VAULT_MAGIC);
    bytes.extend(payload);
    Ok(bytes)
}

/// The largest vault file decode accepts, and the most records one may carry. The vault
/// is attacker-writable input (the threat model grants git write), and validation cost
/// scales with record count, so decode fails closed on anything past these ceilings
/// instead of letting a crafted file exhaust memory or wedge every load and `git merge`.
/// Both sit far above honest v0.1 usage; raising them is a compatible change (old
/// readers of a bigger vault fail closed, exactly like today), and the eventual
/// compaction design supersedes them.
pub const MAX_VAULT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_VAULT_RECORDS: usize = 1 << 18;

pub fn decode_vault(bytes: &[u8]) -> Result<VaultStore> {
    decode_vault_with_limits(bytes, MAX_VAULT_BYTES, MAX_VAULT_RECORDS)
}

fn decode_vault_with_limits(
    bytes: &[u8],
    max_bytes: usize,
    max_records: usize,
) -> Result<VaultStore> {
    let Some(payload) = bytes.strip_prefix(VAULT_MAGIC) else {
        return Err(crate::CoreError::Validation(
            "not a thorax vault file (missing magic prefix)".to_string(),
        ));
    };
    if bytes.len() > max_bytes {
        return Err(crate::CoreError::Validation(format!(
            "vault is {} bytes, above the supported maximum of {max_bytes}",
            bytes.len()
        )));
    }
    let vault: VaultStore = cord::deserialize(payload)?;
    let VaultStore::V1(v1) = &vault;
    if v1.records.len() > max_records {
        return Err(crate::CoreError::Validation(format!(
            "vault carries {} records, above the supported maximum of {max_records}",
            v1.records.len()
        )));
    }
    Ok(vault)
}

pub fn validate_vault(
    vault: &VaultStore,
    ratchet: &Ratchet,
    crypto: &impl CryptoProvider,
) -> Result<ValidationReport> {
    validate_vault_with_verified(vault, ratchet, crypto, &BTreeSet::new())
}

/// [`validate_vault`] with a set of pre-verified record hashes: records whose
/// content-addressed hash (`thorax.record-hash.v1`, over the **whole** signed envelope —
/// body, signing key, and signature) appears in `verified` skip *only* the envelope
/// signature check. Everything else — structure, signer resolution, key uniqueness,
/// authority, LWW, rollback — runs unchanged, so passing the empty set is byte-identical
/// to [`validate_vault`].
///
/// TRUST CONTRACT: the caller asserts every hash in `verified` names an envelope whose
/// signature it has already seen verify. Because the hash commits to the complete
/// verification triple, a hit can only ever skip re-verifying a byte-identical envelope;
/// the soundness of the *assertion itself* is the caller's responsibility (thorax-ops
/// accepts only self-signed, possession-checked caches on unlock-gated paths).
pub fn validate_vault_with_verified(
    vault: &VaultStore,
    ratchet: &Ratchet,
    crypto: &impl CryptoProvider,
    verified: &BTreeSet<HashValue>,
) -> Result<ValidationReport> {
    let version = vault.format_version();
    // The envelope's own ratchet, checked before anything inside the envelope is trusted:
    // a version below the remembered one means a newer vault's records were re-wrapped in
    // an older envelope (shedding semantics this machine already verified). Everything
    // fails closed, exactly like an unresolved authority graph.
    if version < ratchet.format_version {
        return Ok(ValidationReport {
            effective: EffectiveState {
                authority_unresolved: true,
                ..Default::default()
            },
            ratchet_update: RatchetUpdate::default(),
            issues: vec![ValidationIssue::FormatVersionRegression {
                remembered: ratchet.format_version,
                current: version,
            }],
            warnings: Vec::new(),
        });
    }

    let VaultStore::V1(v1) = vault;
    let mut report = validate_v1(v1, ratchet, crypto, verified)?;
    if version > ratchet.format_version && report.issues.is_empty() {
        report.ratchet_update.raised_format_version = Some(version);
    }
    Ok(report)
}

/// The highest Lamport counter a record may carry. A well-behaved client increments by one
/// per write from zero, so honest vaults never approach this; a counter above it is
/// corruption (or a hostile member trying to wedge the clock — a record at `u64::MAX`
/// would tie with every later write forever). Validation rejects records above the ceiling
/// as `InvalidStructure`, and writers refuse to mint a counter beyond it.
pub const MAX_LWW_COUNTER: u64 = 1 << 62;

/// The Lamport counter to stamp on the next LWW-resolved record written to `vault`: one
/// greater than the highest counter already observed across the vault's records. This is the
/// "send" step of the Lamport clock — ordering derives from observed records, never a wall
/// clock, so it is immune to clock skew or NTP manipulation.
///
/// Counters inside *unknown* future record bodies are not readable and so are excluded from
/// the maximum; a future counter collision becomes a visible conflict after upgrade.
pub fn next_counter(effective: &EffectiveState) -> u64 {
    effective
        .admitted_counter_max
        .map_or(0, |max| max.saturating_add(1))
}

impl EffectiveState {
    /// The content-addressed hashes of every record whose envelope signature this
    /// validation accepted (verified directly, or attested by the pre-verified set the
    /// caller passed — the two are indistinguishable here by design). This is exactly the
    /// set a verification cache persists.
    pub fn verified_record_hashes(&self) -> BTreeSet<HashValue> {
        self.verified_records
            .iter()
            .map(|record| record.record_hash.clone())
            .collect()
    }

    /// The minimum Lamport counter a new record must carry to clear every suspected
    /// rollback in this state: one above the highest remembered watermark among rollback
    /// conflicts (`0` when there are none). Writers take
    /// `max(next_counter(effective), rollback_counter_floor())` so a write at a rolled-back key
    /// re-passes the local watermark ratchet instead of landing below it.
    pub fn rollback_counter_floor(&self) -> u64 {
        self.conflicted
            .values()
            .filter_map(|conflict| match conflict.kind {
                ConflictKind::Rollback { remembered_counter } => {
                    Some(remembered_counter.saturating_add(1))
                }
                ConflictKind::Tie => None,
            })
            .max()
            .unwrap_or(0)
    }
}

/// The content-addressed hash of a signed record, identical to the `record_hash` that validation
/// assigns it. Lets a caller that just built a record (before it is validated) recover the hash
/// validation will key it under — used by ops to verify a committed mutation via
/// [`EffectiveState::secret_record_is_current`].
pub fn record_hash(crypto: &impl CryptoProvider, signed: &VaultRecordV1) -> Result<HashValue> {
    derive_hash(crypto, "thorax.record-hash.v1", signed)
}
