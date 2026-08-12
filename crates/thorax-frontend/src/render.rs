//! Identity and hash rendering shared by all frontends.
//!
//! Per the CLI UX plan, principals render as handle → short-hash → full hex, and only `--json`
//! emits full hex. These are the low-level hex/short-hash primitives that rendering builds on;
//! keeping them here lets the diagnostics layer and every frontend format identities identically.

use thorax_ops::{HashValue, UserId};

/// Lowercase hex encoding of arbitrary bytes.
pub fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Full lowercase hex of a hash value.
pub fn hash_hex(hash: &HashValue) -> String {
    hex_bytes(&hash.0)
}

/// Full lowercase hex of a user id.
pub fn user_hex(user: &UserId) -> String {
    hash_hex(&user.0)
}

/// First 8 hex chars of a hash — the eyeball-friendly short form.
pub fn short_hash(hash: &HashValue) -> String {
    let hex = hash_hex(hash);
    hex.get(..8).unwrap_or(&hex).to_string()
}

/// First 8 hex chars of a user id.
pub fn short_user_hex(user: &UserId) -> String {
    short_hash(&user.0)
}
