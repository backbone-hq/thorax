//! Shared acting-user resolution for Thorax frontends.

use thorax_ops::{
    default_keychain_dir, is_valid_handle, normalize_handle, read_current_user, resolve_user_ref,
    write_current_user, Crypto, CurrentUserV1, HashValue, OpsError, ResolvedUserRef, UserId,
    UserRef, ValidationReport, WorkspacePaths,
};

use crate::runtime::ci_identity_user;
use crate::{user_hex, FrontendError};

/// The resolved acting user for one frontend invocation: who they are, whether they were named
/// explicitly (and so should become the stored default), and which vault root the resolution was
/// performed against.
pub struct CliUser {
    pub resolved: ResolvedUserRef,
    pub explicit: bool,
    pub root_signing_public_key_hash: HashValue,
}

pub fn resolve_cli_user_ref_with_report(
    paths: &WorkspacePaths,
    report: &ValidationReport,
    crypto: &Crypto,
    value: Option<&str>,
) -> Result<CliUser, FrontendError> {
    let (value, explicit) = match value {
        Some(value) => (value.to_string(), true),
        None => {
            let stored =
                stored_default_user(paths, &report_root_key_hash(report)?)?.map(|s| s.user_ref);
            let resolved = match stored {
                Some(value) => value,
                // CI identity mode: no stored default, but the injected identity is the actor.
                None => user_hex(&ci_identity_user()?.ok_or(FrontendError::MissingDefaultUser)?),
            };
            (resolved, false)
        }
    };
    Ok(CliUser {
        resolved: resolve_cli_user_ref_in_report(report, crypto, &value)?,
        explicit,
        root_signing_public_key_hash: report_root_key_hash(report)?,
    })
}

pub fn resolve_optional_cli_user_ref_with_report(
    paths: &WorkspacePaths,
    report: &ValidationReport,
    crypto: &Crypto,
    value: Option<&str>,
) -> Result<Option<CliUser>, FrontendError> {
    if value.is_some() {
        return resolve_cli_user_ref_with_report(paths, report, crypto, value).map(Some);
    }
    let root_signing_public_key_hash = report_root_key_hash(report)?;
    let value = match stored_default_user(paths, &root_signing_public_key_hash)?.map(|s| s.user_ref)
    {
        Some(value) => value,
        // CI identity mode: fall back to the injected identity as the acting user.
        None => match ci_identity_user()? {
            Some(user) => user_hex(&user),
            None => return Ok(None),
        },
    };
    Ok(Some(CliUser {
        resolved: resolve_cli_user_ref_in_report(report, crypto, &value)?,
        explicit: false,
        root_signing_public_key_hash,
    }))
}

pub fn resolve_cli_user_ref_in_report(
    report: &ValidationReport,
    crypto: &Crypto,
    value: &str,
) -> Result<ResolvedUserRef, FrontendError> {
    let user_ref = match resolve_user_hex_prefix(report, value)? {
        Some(user) => UserRef::Id(user),
        None => parse_user_ref(value)?,
    };
    Ok(resolve_user_ref(report, crypto, user_ref)?)
}

/// Treat an unprefixed, hex-like value as a short user-id prefix (git-style), so the
/// short hashes the CLI prints are usable as references. Returns `None` when the value
/// is a handle (`@name`), a full 64-char id (handled by the exact path), or not hex,
/// leaving those to the handle/exact resolvers.
fn resolve_user_hex_prefix(
    report: &ValidationReport,
    value: &str,
) -> Result<Option<UserId>, FrontendError> {
    if value.starts_with('@') {
        return Ok(None);
    }
    let Some(needle) = normalize_hex_prefix(value) else {
        return Ok(None);
    };
    if needle.len() >= 64 {
        return Ok(None);
    }
    let mut matches = report
        .effective
        .users
        .keys()
        .filter(|user| user_hex(user).starts_with(&needle))
        .cloned();
    let Some(first) = matches.next() else {
        // A clearly hex value (>= 8 nibbles) that matches no user is a missing id, not a
        // handle. Report it as such rather than falling through to a misleading
        // "no user with handle @..." error.
        return Err(FrontendError::UserNotFound(value.to_string()));
    };
    if matches.next().is_some() {
        return Err(FrontendError::AmbiguousUser(value.to_string()));
    }
    Ok(Some(first))
}

/// Normalize a candidate id prefix: strip `0x`, lowercase, and require it to be all-hex
/// and long enough (>= 8 nibbles) to be an intentional id prefix rather than a name.
pub fn normalize_hex_prefix(value: &str) -> Option<String> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.len() < 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

pub fn parse_user_ref(value: &str) -> Result<UserRef, FrontendError> {
    if let Some(handle) = value.strip_prefix('@') {
        return Ok(UserRef::Handle(parse_handle_name(handle)?));
    }
    match parse_user_id(value) {
        Ok(user) => Ok(UserRef::Id(user)),
        Err(_) => Ok(UserRef::Handle(parse_handle_name(value)?)),
    }
}

pub fn parse_user_id(value: &str) -> Result<UserId, FrontendError> {
    Ok(UserId(HashValue(decode_hex_exact(value, "user ID", 32)?)))
}

pub fn parse_handle_name(value: &str) -> Result<String, FrontendError> {
    let raw = value.strip_prefix('@').unwrap_or(value);
    let normalized = normalize_handle(raw);
    if !is_valid_handle(&normalized) {
        return Err(FrontendError::InvalidHandle {
            handle: value.to_string(),
            reason: "handle must be 1–64 chars of a–z, 0–9, '-', '_', starting and ending with a letter or digit",
        });
    }
    Ok(normalized)
}

pub fn decode_hex_exact(
    value: &str,
    name: &'static str,
    expected: usize,
) -> Result<Vec<u8>, FrontendError> {
    let bytes = decode_hex(value, name)?;
    if bytes.len() != expected {
        return Err(FrontendError::InvalidHexLength {
            name,
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

pub fn decode_hex(value: &str, name: &'static str) -> Result<Vec<u8>, FrontendError> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if !value.len().is_multiple_of(2) {
        return Err(FrontendError::InvalidHex {
            name,
            reason: "odd length".to_string(),
        });
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        bytes.push((hex_nibble(pair[0], name)? << 4) | hex_nibble(pair[1], name)?);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8, name: &'static str) -> Result<u8, FrontendError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(FrontendError::InvalidHex {
            name,
            reason: "non-hex character".to_string(),
        }),
    }
}

pub fn report_root_key_hash(report: &ValidationReport) -> Result<HashValue, FrontendError> {
    report
        .effective
        .root_signing_public_key_hash
        .clone()
        .ok_or_else(|| OpsError::MissingEffectiveRoot.into())
}

/// The stored default identity for this vault, from the keychain's `CurrentUser` selection.
pub struct StoredDefaultUser {
    /// Reference for resolution: the exact id hex (handles can move between users; the id
    /// cannot).
    pub user_ref: String,
    /// Human label: the handle captured at selection time, else `user_ref`.
    pub display: String,
}

pub fn stored_default_user(
    _paths: &WorkspacePaths,
    root_signing_public_key_hash: &HashValue,
) -> Result<Option<StoredDefaultUser>, FrontendError> {
    Ok(
        read_current_user(&default_keychain_dir()?, root_signing_public_key_hash)?.map(|current| {
            let user_ref = user_hex(&current.user_id);
            StoredDefaultUser {
                display: current.handle.unwrap_or_else(|| user_ref.clone()),
                user_ref,
            }
        }),
    )
}

/// When the user was named explicitly, remember them as this vault's default actor so the next
/// invocation can omit `--user`.
pub fn remember_user_if_explicit(
    _paths: &WorkspacePaths,
    user: &CliUser,
) -> Result<(), FrontendError> {
    if user.explicit {
        write_current_user_for_root(
            &user.root_signing_public_key_hash,
            &user.resolved.user_id,
            user.resolved.handle.clone(),
        )?;
    }
    Ok(())
}

/// Record `user` as this vault's `CurrentUser` selection in the per-root keychain — the
/// stored default actor *and* the identity unlock flows pre-select. The handle is a
/// display label captured now (prompts name the identity); resolution always uses the id.
pub fn write_current_user_for_root(
    root_signing_public_key_hash: &HashValue,
    user_id: &UserId,
    handle: Option<String>,
) -> Result<(), FrontendError> {
    write_current_user(
        &default_keychain_dir()?,
        root_signing_public_key_hash,
        Some(CurrentUserV1 {
            user_id: user_id.clone(),
            handle,
        }),
    )?;
    Ok(())
}

pub fn user_config_ref(user: &ResolvedUserRef) -> String {
    user.handle
        .clone()
        .unwrap_or_else(|| user_hex(&user.user_id))
}
