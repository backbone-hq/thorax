use super::ValidationIssue;
use crate::crypto::{derive_seeded_hash, derive_user_id, CryptoProvider};
use crate::format::*;
use crate::ids::{
    derive_group_member_id, derive_secret_id, derive_user_handle_id, derive_vault_handle_id,
    is_valid_handle,
};
use std::collections::BTreeSet;

pub(super) fn structurally_validate_record(
    signed: &VaultRecordV1,
    body: &RecordBodyV1,
    root: &VaultRootRecordV1,
    crypto: &impl CryptoProvider,
) -> std::result::Result<(), ValidationIssue> {
    // No honest writer approaches the counter ceiling (one increment per write from zero);
    // a counter above it is a wedge attempt — a near-`u64::MAX` record would tie with
    // every later write forever — and fails the record as corrupt.
    if body
        .lww_counter()
        .is_some_and(|counter| counter > super::MAX_LWW_COUNTER)
    {
        return Err(invalid("counter exceeds the supported ceiling"));
    }
    match body {
        RecordBodyV1::VaultRoot(record) => {
            // Self-signed: the root's signing key is the envelope's. The id commits to that
            // key paired with the body's HPKE key.
            if record.id
                != derive_user_id(crypto, &signed.signing_public_key, &record.hpke_public_key)
                    .map_err(to_issue)?
            {
                return Err(invalid("invalid root record"));
            }
        }
        RecordBodyV1::EntryPoint(record) => {
            // The entry point is a self-signed proof of possession of the *full* identity: it
            // is signed under the pinning user's signing key (the envelope), and its body
            // declares the HPKE key paired with it — so only that signing key's holder can
            // produce it (the attestation gate in `pipeline` relies on this to refuse a `User`
            // record pairing a real signing key with a forged HPKE key). `trusted_root_user_id`
            // pins the root, and a `UserId` commits to both root keys, so it is the full
            // substitution-defense pin.
            if record.trusted_root_user_id != root.id {
                return Err(invalid("invalid entry point record"));
            }
        }
        RecordBodyV1::User(record) => {
            structurally_valid_user(record, crypto)?;
        }
        RecordBodyV1::UserHandle(record) => {
            if !is_valid_handle(&record.handle)
                || record.id != derive_user_handle_id(crypto, &record.handle).map_err(to_issue)?
            {
                return Err(invalid("invalid user handle"));
            }
        }
        RecordBodyV1::VaultHandle(record) => {
            if !is_valid_handle(&record.handle)
                || record.id != derive_vault_handle_id(crypto, &record.handle).map_err(to_issue)?
            {
                return Err(invalid("invalid vault handle record"));
            }
        }
        RecordBodyV1::Group(record) => {
            let group = GroupId(
                derive_seeded_hash(crypto, "thorax.group.v1", &record.seed).map_err(to_issue)?,
            );
            if record.id != group || !is_valid_handle(&record.handle) {
                return Err(invalid("invalid group record"));
            }
        }
        // Deletion tombstones carry the id of the object they remove; that id is their key.
        RecordBodyV1::GroupDeleted(_) => {}
        RecordBodyV1::GroupMember(record) => {
            let membership = derive_group_member_id(crypto, &record.group_id, &record.member_id)
                .map_err(to_issue)?;
            if record.id != membership {
                return Err(invalid("invalid group membership"));
            }
        }
        RecordBodyV1::GroupMemberDeleted(record) => {
            let membership = derive_group_member_id(crypto, &record.group_id, &record.member_id)
                .map_err(to_issue)?;
            if record.id != membership {
                return Err(invalid("invalid group membership deletion"));
            }
        }
        RecordBodyV1::Grant(record) => {
            let grant = GrantId(
                derive_seeded_hash(crypto, "thorax.grant.v1", &record.seed).map_err(to_issue)?,
            );
            validate_permission(&record.permission)?;
            if record.id != grant {
                return Err(invalid("invalid grant"));
            }
        }
        RecordBodyV1::GrantDeleted(record) => {
            validate_permission(&record.permission)?;
        }
        RecordBodyV1::UserDeleted(record) => {
            // The root is the trust anchor; deleting it is not representable in v1.
            if record.id == root.id {
                return Err(invalid("invalid user deletion"));
            }
        }
        RecordBodyV1::Secret(record) => {
            validate_secret_selector(&record.selector)?;
            // The id commits to the whole selector (tuple + labels). Pinning id to the
            // selector here is what stops a writer claiming labels their grant covers while
            // landing at a key it does not — distinct labels are distinct keys.
            let secret = derive_secret_id(crypto, &record.selector).map_err(to_issue)?;
            if record.id != secret {
                return Err(invalid("invalid secret value"));
            }
            let mut slots = BTreeSet::new();
            for slot in &record.sealed.recipient_slots {
                if !slots.insert(slot.recipient_id.clone()) {
                    return Err(invalid("duplicate recipient slot"));
                }
            }
        }
        RecordBodyV1::SecretDeleted(record) => {
            validate_secret_selector(&record.selector)?;
            let secret = derive_secret_id(crypto, &record.selector).map_err(to_issue)?;
            if record.id != secret {
                return Err(invalid("invalid secret deletion"));
            }
        }
    }
    Ok(())
}

pub(super) fn structurally_valid_user(
    record: &UserRecordV1,
    crypto: &impl CryptoProvider,
) -> std::result::Result<(), ValidationIssue> {
    // Admin-signed: the signer is the introducing admin, not the user, so the only
    // structural fact is that the id commits to both public keys. Proof that the keys are
    // real comes from the user's own self-signed entry point.
    let user = derive_user_id(crypto, &record.signing_public_key, &record.hpke_public_key)
        .map_err(to_issue)?;
    if record.id != user {
        return Err(invalid("invalid user record"));
    }
    Ok(())
}

fn validate_permission(permission: &GrantPermissionV1) -> std::result::Result<(), ValidationIssue> {
    match permission {
        GrantPermissionV1::ReadKeyspace(selector) | GrantPermissionV1::WriteKeyspace(selector) => {
            validate_keyspace_selector(selector)
        }
        GrantPermissionV1::ManageKeyspace(manage) => {
            validate_keyspace_selector(&manage.selector)?;
            validate_sorted_unique_grantable(&manage.grantable)?;
            Ok(())
        }
        GrantPermissionV1::Administer => Ok(()),
    }
}

fn validate_secret_selector(
    selector: &SecretSelectorV1,
) -> std::result::Result<(), ValidationIssue> {
    validate_sorted_unique_secret_labels(&selector.labels)?;
    Ok(())
}

fn validate_keyspace_selector(
    selector: &KeyspaceSelectorV1,
) -> std::result::Result<(), ValidationIssue> {
    if matches!(&selector.tuple, TupleMatcherV1::Prefix(prefix) if prefix.is_empty()) {
        return Err(invalid("empty tuple prefix must be encoded as any"));
    }
    validate_sorted_unique_keyspace_labels(&selector.labels)?;
    for label in &selector.labels {
        if let LabelMatcherV1::In(values) = &label.matcher {
            validate_sorted_unique_strings(values, "label in matcher")?;
        }
    }
    Ok(())
}

fn validate_sorted_unique_secret_labels(
    labels: &[SecretLabelV1],
) -> std::result::Result<(), ValidationIssue> {
    let mut previous: Option<&str> = None;
    for label in labels {
        if let Some(previous) = previous {
            if previous >= label.key.as_str() {
                return Err(invalid("secret selector labels must be sorted and unique"));
            }
        }
        previous = Some(&label.key);
    }
    Ok(())
}

fn validate_sorted_unique_keyspace_labels(
    labels: &[KeyspaceLabelMatcherV1],
) -> std::result::Result<(), ValidationIssue> {
    let mut previous: Option<&str> = None;
    for label in labels {
        if let Some(previous) = previous {
            if previous >= label.key.as_str() {
                return Err(invalid(
                    "keyspace selector labels must be sorted and unique",
                ));
            }
        }
        previous = Some(&label.key);
    }
    Ok(())
}

fn validate_sorted_unique_strings(
    values: &[String],
    description: &str,
) -> std::result::Result<(), ValidationIssue> {
    if values.is_empty() {
        return Err(invalid(format!("{description} must not be empty")));
    }
    let mut previous: Option<&str> = None;
    for value in values {
        if let Some(previous) = previous {
            if previous >= value.as_str() {
                return Err(invalid(format!("{description} must be sorted and unique")));
            }
        }
        previous = Some(value);
    }
    Ok(())
}

fn validate_sorted_unique_grantable(
    values: &[KeyspaceGrantClassV1],
) -> std::result::Result<(), ValidationIssue> {
    if values.is_empty() {
        return Err(invalid("manage grant must grant at least one class"));
    }
    let mut previous: Option<&KeyspaceGrantClassV1> = None;
    for value in values {
        if let Some(previous) = previous {
            if previous >= value {
                return Err(invalid("manage grant classes must be sorted and unique"));
            }
        }
        previous = Some(value);
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ValidationIssue {
    ValidationIssue::InvalidStructure(message.into())
}

fn to_issue(error: crate::CoreError) -> ValidationIssue {
    ValidationIssue::InvalidStructure(error.to_string())
}
