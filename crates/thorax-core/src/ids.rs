use crate::crypto::{derive_hash, derive_seeded_hash, CryptoProvider};
use crate::format::*;
use crate::Result;

pub fn normalize_handle(handle: &str) -> String {
    handle.trim().to_ascii_lowercase()
}

/// Maximum handle length, in bytes.
pub const MAX_HANDLE_LEN: usize = 64;

/// True if `handle` is a valid normalized handle: a slug of lowercase ASCII
/// alphanumerics, `-`, and `_`, 1..=`MAX_HANDLE_LEN` bytes, that starts and ends
/// with an alphanumeric (`^[a-z0-9]([a-z0-9_-]*[a-z0-9])?$`). The slug charset
/// excludes uppercase and whitespace, so a valid handle is already its own
/// `normalize_handle` form. Applies to user, vault, and group handles.
pub fn is_valid_handle(handle: &str) -> bool {
    let bytes = handle.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_HANDLE_LEN {
        return false;
    }
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let is_inner = |b: u8| is_alnum(b) || b == b'-' || b == b'_';
    is_alnum(bytes[0]) && is_alnum(bytes[bytes.len() - 1]) && bytes.iter().all(|&b| is_inner(b))
}

pub fn derive_user_handle_id(crypto: &impl CryptoProvider, handle: &str) -> Result<UserHandleId> {
    Ok(UserHandleId(derive_hash(
        crypto,
        "thorax.handle.v1",
        &normalize_handle(handle),
    )?))
}

pub fn derive_vault_handle_id(crypto: &impl CryptoProvider, handle: &str) -> Result<VaultHandleId> {
    Ok(VaultHandleId(derive_hash(
        crypto,
        "thorax.vault-handle.v1",
        &normalize_handle(handle),
    )?))
}

pub fn derive_grant_id(crypto: &impl CryptoProvider, seed: &IdSeed) -> Result<GrantId> {
    Ok(GrantId(derive_seeded_hash(
        crypto,
        "thorax.grant.v1",
        seed,
    )?))
}

pub fn derive_group_id(crypto: &impl CryptoProvider, seed: &IdSeed) -> Result<GroupId> {
    Ok(GroupId(derive_seeded_hash(
        crypto,
        "thorax.group.v1",
        seed,
    )?))
}

pub fn derive_group_member_id(
    crypto: &impl CryptoProvider,
    group_id: &GroupId,
    member_id: &PrincipalRefV1,
) -> Result<GroupMemberId> {
    Ok(GroupMemberId(derive_hash(
        crypto,
        "thorax.group-member.v1",
        &GroupMemberIdInputV1 {
            group_id: group_id.clone(),
            member_id: member_id.clone(),
        },
    )?))
}

/// A secret's identity is its **whole selector** — tuple *and* labels. Labels are scope
/// axes folded into the key, not metadata: `app/db{env=dev}` and `app/db{env=prod}` are
/// distinct secrets that compete at distinct `RecordKey::Secret` keys. Because the id
/// commits to the full selector and structural validation rejects any record whose id is
/// not `derive_secret_id(its own selector)`, a writer cannot claim grant-friendly labels
/// while landing at a key those labels don't cover — which is what makes a label-scoped
/// `WriteKeyspace` grant an actual write boundary. Changing any label is therefore a
/// re-key (a move), not a same-key update.
///
/// Labels are validated sorted-unique by key (`validate_secret_selector`), so the selector
/// has one canonical cord encoding and the id is deterministic.
pub fn derive_secret_id(
    crypto: &impl CryptoProvider,
    selector: &SecretSelectorV1,
) -> Result<SecretId> {
    Ok(SecretId(derive_hash(crypto, "thorax.secret.v1", selector)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_charset_accepts_slugs_and_rejects_the_rest() {
        for ok in ["a", "alice", "deploy-bot", "app_prod", "a1", "x-y_z9"] {
            assert!(is_valid_handle(ok), "{ok:?} should be valid");
        }
        for bad in [
            "",         // empty
            "Alice",    // uppercase
            "a b",      // space
            "app.prod", // dot
            "-x",       // leading hyphen
            "x_",       // trailing underscore
            "café",     // non-ascii
            " alice",   // not normalized (leading space)
        ] {
            assert!(!is_valid_handle(bad), "{bad:?} should be invalid");
        }
        assert!(is_valid_handle(&"a".repeat(MAX_HANDLE_LEN)));
        assert!(!is_valid_handle(&"a".repeat(MAX_HANDLE_LEN + 1)));
    }
}
