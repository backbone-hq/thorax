//! Low-level Thorax protocol construction APIs.
//!
//! This module is intentionally sharp: it builds raw record payloads and
//! signed records, but it does not load workspaces, check authorization, or
//! commit vault changes. Most consumers should use `thorax-ops`.

use crate::crypto::{derive_user_id, signed_record_message, CryptoProvider, RecordSigner};
use crate::format::*;
use crate::ids::{
    derive_grant_id, derive_group_id, derive_group_member_id, derive_secret_id,
    derive_user_handle_id, derive_vault_handle_id,
};

pub type Result<T> = std::result::Result<T, HazmatError>;

#[derive(Debug, thiserror::Error)]
pub enum HazmatError {
    #[error("core error: {0}")]
    Core(#[from] crate::CoreError),
    #[error("signer identity does not match signing public key")]
    InvalidSignerIdentity { claimed: UserId, derived: UserId },
}

pub fn append_record(vault: &mut VaultStore, signed: VaultRecordV1) {
    let VaultStore::V1(v1) = vault;
    v1.records.insert(signed);
}

/// The signable payload of a record: its body, evolving-wrapped. (Records carry no header
/// beyond the body — the logical key is derived from the body and ordering lives inside it.)
pub fn record_payload(body: RecordBodyV1) -> cord::Evolving<RecordBodyV1> {
    cord::Evolving::new(body)
}

pub fn vault_root_record_payload(
    crypto: &impl CryptoProvider,
    signing_public_key: Bytes,
    hpke_public_key: Bytes,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_user_id(crypto, &signing_public_key, &hpke_public_key)?;
    Ok(record_payload(RecordBodyV1::VaultRoot(VaultRootRecordV1 {
        id,
        hpke_public_key,
    })))
}

pub fn entry_point_record_payload(
    trusted_root_user_id: UserId,
    hpke_public_key: Bytes,
    counter: u64,
) -> cord::Evolving<RecordBodyV1> {
    record_payload(RecordBodyV1::EntryPoint(EntryPointRecordV1 {
        trusted_root_user_id,
        hpke_public_key,
        counter,
    }))
}

pub fn user_record_payload(
    crypto: &impl CryptoProvider,
    signing_public_key: Bytes,
    hpke_public_key: Bytes,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_user_id(crypto, &signing_public_key, &hpke_public_key)?;
    Ok(record_payload(RecordBodyV1::User(UserRecordV1 {
        id,
        signing_public_key,
        hpke_public_key,
        counter,
    })))
}

pub fn user_handle_record_payload(
    crypto: &impl CryptoProvider,
    handle: impl Into<String>,
    user_id: UserId,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let handle = handle.into();
    let id = derive_user_handle_id(crypto, &handle)?;
    Ok(record_payload(RecordBodyV1::UserHandle(
        UserHandleRecordV1 {
            id,
            handle,
            user_id,
            counter,
        },
    )))
}

pub fn vault_handle_record_payload(
    crypto: &impl CryptoProvider,
    handle: impl Into<String>,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let handle = handle.into();
    let id = derive_vault_handle_id(crypto, &handle)?;
    Ok(record_payload(RecordBodyV1::VaultHandle(
        VaultHandleRecordV1 {
            id,
            handle,
            counter,
        },
    )))
}

pub fn grant_record_payload(
    crypto: &impl CryptoProvider,
    subject: PrincipalRefV1,
    permission: GrantPermissionV1,
    seed: IdSeed,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_grant_id(crypto, &seed)?;
    Ok(record_payload(RecordBodyV1::Grant(GrantRecordV1 {
        id,
        seed,
        subject_id: subject,
        permission,
        counter,
    })))
}

pub fn grant_deleted_record_payload(
    grant_id: GrantId,
    permission: GrantPermissionV1,
    counter: u64,
) -> cord::Evolving<RecordBodyV1> {
    record_payload(RecordBodyV1::GrantDeleted(GrantDeletedRecordV1 {
        id: grant_id,
        permission,
        counter,
    }))
}

pub fn group_record_payload(
    crypto: &impl CryptoProvider,
    seed: IdSeed,
    handle: impl Into<String>,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_group_id(crypto, &seed)?;
    Ok(record_payload(RecordBodyV1::Group(GroupRecordV1 {
        id,
        seed,
        handle: handle.into(),
        counter,
    })))
}

pub fn group_deleted_record_payload(
    group_id: GroupId,
    counter: u64,
) -> cord::Evolving<RecordBodyV1> {
    record_payload(RecordBodyV1::GroupDeleted(GroupDeletedRecordV1 {
        id: group_id,
        counter,
    }))
}

pub fn group_member_record_payload(
    crypto: &impl CryptoProvider,
    group_id: GroupId,
    member: PrincipalRefV1,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_group_member_id(crypto, &group_id, &member)?;
    Ok(record_payload(RecordBodyV1::GroupMember(
        GroupMemberRecordV1 {
            id,
            group_id,
            member_id: member,
            counter,
        },
    )))
}

pub fn group_member_deleted_record_payload(
    crypto: &impl CryptoProvider,
    group_id: GroupId,
    member: PrincipalRefV1,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_group_member_id(crypto, &group_id, &member)?;
    Ok(record_payload(RecordBodyV1::GroupMemberDeleted(
        GroupMemberDeletedRecordV1 {
            id,
            group_id,
            member_id: member,
            counter,
        },
    )))
}

pub fn user_deleted_record_payload(
    user_id: UserId,
    reason: Option<String>,
    counter: u64,
) -> cord::Evolving<RecordBodyV1> {
    record_payload(RecordBodyV1::UserDeleted(UserDeletedRecordV1 {
        id: user_id,
        reason,
        counter,
    }))
}

pub fn secret_record_payload(
    crypto: &impl CryptoProvider,
    selector: SecretSelectorV1,
    sealed: SealedPayloadV1,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_secret_id(crypto, &selector)?;
    Ok(record_payload(RecordBodyV1::Secret(SecretRecordV1 {
        id,
        selector,
        sealed,
        counter,
    })))
}

pub fn secret_deleted_record_payload(
    crypto: &impl CryptoProvider,
    selector: SecretSelectorV1,
    counter: u64,
) -> Result<cord::Evolving<RecordBodyV1>> {
    let id = derive_secret_id(crypto, &selector)?;
    Ok(record_payload(RecordBodyV1::SecretDeleted(
        SecretDeletedRecordV1 {
            id,
            selector,
            counter,
        },
    )))
}

pub fn vault_root_record(
    crypto: &impl CryptoProvider,
    root: &impl RecordSigner,
) -> Result<VaultRecordV1> {
    let payload = vault_root_record_payload(
        crypto,
        root.signing_public_key().to_vec(),
        root.hpke_public_key().to_vec(),
    )?;
    signed_payload(crypto, root, payload)
}

pub fn entry_point_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    trusted_root_user_id: UserId,
    counter: u64,
) -> Result<VaultRecordV1> {
    // The entry point declares the signer's own HPKE key; `signed_payload` signs it under the
    // signer's signing key, which the envelope carries — so the pairing is `(envelope.signing,
    // body.hpke)` by construction, no duplicated signing key in the body.
    let payload = entry_point_record_payload(
        trusted_root_user_id,
        signer.hpke_public_key().to_vec(),
        counter,
    );
    signed_payload(crypto, signer, payload)
}

/// Build a user (membership) record: the introduced user's *public* keys, signed by the
/// introducing admin. Restoration is the same record at a higher counter.
pub fn user_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    signing_public_key: Bytes,
    hpke_public_key: Bytes,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = user_record_payload(crypto, signing_public_key, hpke_public_key, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn user_handle_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    handle: impl Into<String>,
    user_id: UserId,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = user_handle_record_payload(crypto, handle, user_id, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn vault_handle_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    handle: impl Into<String>,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = vault_handle_record_payload(crypto, handle, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn grant_record(
    crypto: &impl CryptoProvider,
    issuer: &impl RecordSigner,
    subject: PrincipalRefV1,
    permission: GrantPermissionV1,
    seed: IdSeed,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = grant_record_payload(crypto, subject, permission, seed, counter)?;
    signed_payload(crypto, issuer, payload)
}

pub fn grant_deleted_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    grant_id: GrantId,
    permission: GrantPermissionV1,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = grant_deleted_record_payload(grant_id, permission, counter);
    signed_payload(crypto, signer, payload)
}

pub fn group_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    seed: IdSeed,
    handle: impl Into<String>,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = group_record_payload(crypto, seed, handle, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn group_deleted_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    group_id: GroupId,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = group_deleted_record_payload(group_id, counter);
    signed_payload(crypto, signer, payload)
}

pub fn group_member_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    group_id: GroupId,
    member: PrincipalRefV1,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = group_member_record_payload(crypto, group_id, member, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn group_member_deleted_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    group_id: GroupId,
    member: PrincipalRefV1,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = group_member_deleted_record_payload(crypto, group_id, member, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn user_deleted_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    user_id: UserId,
    reason: Option<String>,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = user_deleted_record_payload(user_id, reason, counter);
    signed_payload(crypto, signer, payload)
}

pub fn secret_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    selector: SecretSelectorV1,
    sealed: SealedPayloadV1,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = secret_record_payload(crypto, selector, sealed, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn secret_deleted_record(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    selector: SecretSelectorV1,
    counter: u64,
) -> Result<VaultRecordV1> {
    let payload = secret_deleted_record_payload(crypto, selector, counter)?;
    signed_payload(crypto, signer, payload)
}

pub fn signed_payload(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    body: cord::Evolving<RecordBodyV1>,
) -> Result<VaultRecordV1> {
    // The envelope carries the verification key, not an identity claim; this check only
    // keeps a well-behaved signer from producing a record its own keypair disowns.
    ensure_identity_consistent(crypto, signer)?;
    let mut signed = VaultRecordV1 {
        body,
        signing_public_key: signer.signing_public_key().to_vec(),
        signature: Vec::new(),
    };
    let message = signed_record_message(&signed)?;
    signed.signature = signer.sign("thorax.signed.v1", &message);
    Ok(signed)
}

pub fn ensure_identity_consistent(
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
) -> Result<UserId> {
    let derived = derive_user_id(
        crypto,
        signer.signing_public_key(),
        signer.hpke_public_key(),
    )?;
    if &derived == signer.user_id() {
        Ok(derived)
    } else {
        Err(HazmatError::InvalidSignerIdentity {
            claimed: signer.user_id().clone(),
            derived,
        })
    }
}
