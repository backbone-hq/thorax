//! Shared presentation for conflicts: how a conflict's key, kind, and candidates read in
//! the CLI's `thorax conflicts`, the merge driver's conflict summary, and the TUI's Conflicts
//! tab. Report-free (signers and subjects render as short ids) so the driver can print
//! outside any workspace; frontends with a report substitute handles where they have them.

use thorax_ops::{
    ConflictKind, ConflictReport, KeyOrigin, PrincipalRefV1, RecordBodyV1, RecordKey,
};

use crate::render::{short_hash, short_user_hex};
use crate::selector::selector_string;

pub fn record_key_kind(key: &RecordKey) -> &'static str {
    match key {
        RecordKey::VaultRoot => "trust root",
        RecordKey::EntryPoint { .. } => "entry point",
        RecordKey::User { .. } => "user",
        RecordKey::UserHandle { .. } => "user handle",
        RecordKey::VaultHandle { .. } => "vault name",
        RecordKey::Group { .. } => "group",
        RecordKey::GroupMember { .. } => "group membership",
        RecordKey::Grant { .. } => "grant",
        RecordKey::Secret { .. } => "secret",
    }
}

/// Short noun for a conflict's kind, for status lines and lists.
pub fn conflict_kind_name(kind: &ConflictKind) -> &'static str {
    match kind {
        ConflictKind::Tie => "tie",
        ConflictKind::Rollback { .. } => "rollback",
    }
}

/// One-line explanation of what a conflict means and how it resolves.
pub fn conflict_kind_summary(conflict: &ConflictReport) -> String {
    match &conflict.kind {
        ConflictKind::Tie => format!(
            "concurrent writes tied at counter {} — pick the winner",
            conflict.counter
        ),
        ConflictKind::Rollback { remembered_counter } => {
            if conflict.candidates.is_empty() {
                format!(
                    "this machine verified counter {remembered_counter} here, but the vault no longer carries the record — set a fresh value, or accept the rollback"
                )
            } else {
                format!(
                    "this machine verified counter {remembered_counter} here, but the vault now shows {} — newer content was dropped; ratify a survivor, set a fresh value, or accept the rollback",
                    conflict.counter
                )
            }
        }
    }
}

/// A human label for the object a conflict is about, derived from the key plus the first
/// candidate body (all candidates at one key share the object's identity). A rollback
/// conflict whose records were dropped entirely is named from the key's remembered origin
/// (the id preimage the ratchet kept: the secret's selector, a handle's string, a
/// membership's pair); only origin-less keys fall back to the short id.
pub fn conflict_label(conflict: &ConflictReport) -> String {
    let body = conflict
        .candidates
        .first()
        .and_then(|signed| signed.body.known());
    if body.is_none() {
        if let Some(origin) = &conflict.origin {
            return match origin {
                KeyOrigin::Secret(selector) => crate::selector::selector_string(selector),
                KeyOrigin::UserHandle(handle) => format!("@{handle}"),
                KeyOrigin::VaultHandle(handle) => handle.clone(),
                KeyOrigin::GroupMember {
                    group_id,
                    member_id,
                } => format!(
                    "{} in group {}",
                    principal_short(member_id),
                    short_hash(&group_id.0)
                ),
            };
        }
    }
    match (&conflict.key, body) {
        (_, Some(RecordBodyV1::Secret(record))) => selector_string(&record.selector),
        (_, Some(RecordBodyV1::SecretDeleted(record))) => selector_string(&record.selector),
        (_, Some(RecordBodyV1::UserHandle(record))) => format!("@{}", record.handle),
        (_, Some(RecordBodyV1::VaultHandle(record))) => record.handle.clone(),
        (_, Some(RecordBodyV1::Group(record))) => format!("%{}", record.handle),
        (RecordKey::User { user_id }, _) => short_user_hex(user_id),
        (RecordKey::EntryPoint { user_id }, _) => short_user_hex(user_id),
        (RecordKey::UserHandle { handle_id }, _) => short_hash(&handle_id.0),
        (RecordKey::VaultHandle { handle_id }, _) => short_hash(&handle_id.0),
        (RecordKey::Group { group_id }, _) => short_hash(&group_id.0),
        (RecordKey::GroupMember { group_member_id }, _) => short_hash(&group_member_id.0),
        (RecordKey::Grant { grant_id }, _) => short_hash(&grant_id.0),
        (RecordKey::Secret { secret_id }, _) => short_hash(&secret_id.0),
        (RecordKey::VaultRoot, _) => "root".to_string(),
    }
}

/// What choosing this candidate means, in Thorax terms.
pub fn candidate_summary(body: &RecordBodyV1) -> String {
    match body {
        RecordBodyV1::Secret(record) => format!(
            "set {} ({} bytes)",
            selector_string(&record.selector),
            record.sealed.ciphertext.len()
        ),
        RecordBodyV1::SecretDeleted(record) => {
            format!("delete {}", selector_string(&record.selector))
        }
        RecordBodyV1::User(record) => format!("add/restore user {}", short_user_hex(&record.id)),
        RecordBodyV1::UserDeleted(record) => format!("delete user {}", short_user_hex(&record.id)),
        RecordBodyV1::UserHandle(record) => format!(
            "assign @{} to {}",
            record.handle,
            short_user_hex(&record.user_id)
        ),
        RecordBodyV1::VaultHandle(record) => format!("name the vault {}", record.handle),
        RecordBodyV1::Group(record) => format!("create/rename group %{}", record.handle),
        RecordBodyV1::GroupDeleted(record) => format!("delete group {}", short_hash(&record.id.0)),
        RecordBodyV1::GroupMember(record) => format!(
            "add {} to group {}",
            principal_short(&record.member_id),
            short_hash(&record.group_id.0)
        ),
        RecordBodyV1::GroupMemberDeleted(record) => format!(
            "remove {} from group {}",
            principal_short(&record.member_id),
            short_hash(&record.group_id.0)
        ),
        RecordBodyV1::Grant(record) => format!(
            "grant {} to {}",
            permission_short(&record.permission),
            principal_short(&record.subject_id)
        ),
        RecordBodyV1::GrantDeleted(record) => {
            format!("delete grant ({})", permission_short(&record.permission))
        }
        RecordBodyV1::EntryPoint(_) => "pin the trusted root".to_string(),
        RecordBodyV1::VaultRoot(_) => "trust root".to_string(),
    }
}

fn principal_short(principal: &PrincipalRefV1) -> String {
    match principal {
        PrincipalRefV1::User(user) => short_user_hex(user),
        PrincipalRefV1::Group(group) => format!("%{}", short_hash(&group.0)),
    }
}

fn permission_short(permission: &thorax_ops::GrantPermissionV1) -> String {
    use thorax_ops::{GrantPermissionV1, TupleMatcherV1};
    let keyspace = |selector: &thorax_ops::KeyspaceSelectorV1| match &selector.tuple {
        TupleMatcherV1::Any => "*".to_string(),
        TupleMatcherV1::Exact(parts) => crate::selector::escape_tuple(parts),
        TupleMatcherV1::Prefix(parts) => format!("{}/*", crate::selector::escape_tuple(parts)),
    };
    match permission {
        GrantPermissionV1::ReadKeyspace(selector) => format!("read {}", keyspace(selector)),
        GrantPermissionV1::WriteKeyspace(selector) => format!("write {}", keyspace(selector)),
        GrantPermissionV1::ManageKeyspace(grant) => format!("manage {}", keyspace(&grant.selector)),
        GrantPermissionV1::Administer => "administer".to_string(),
    }
}
