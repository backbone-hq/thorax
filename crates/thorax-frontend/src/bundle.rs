//! Text rendering for transferable Thorax invitations (`thrx1…`).
//!
//! On disk (`--invite-file`) an invitation is magic-prefixed Cord bytes. When it must be
//! pasted or shown for scanning, those bytes are rendered as a **bech32m** string with a
//! human-readable prefix: lowercase, paste-robust, self-identifying, and carrying a checksum
//! so a truncated or mistyped paste fails fast instead of producing a confusing downstream
//! This codec applies only to the transfer blobs; human-reference identifiers (user, grant,
//! group ids, hashes) stay hex, where short prefixes are easier to eyeball and match.

use bech32::{Bech32m, Hrp};
use qrcode::render::unicode::Dense1x2;
use qrcode::QrCode;

const INVITE_HRP: &str = "thrx";

#[derive(Debug)]
pub enum BundleStringError {
    /// Not valid bech32, or the checksum did not verify (likely a truncated/mistyped paste).
    Malformed,
    /// Valid bech32, but not the expected Thorax artifact (wrong human-readable prefix).
    WrongPrefix(String),
    /// The string is too large to render as a QR code.
    TooLargeForQr,
}

fn encode_with(hrp: &str, bytes: &[u8]) -> String {
    let hrp = Hrp::parse_unchecked(hrp);
    // Encoding only fails for lengths far beyond any real artifact; treat as unreachable.
    bech32::encode::<Bech32m>(hrp, bytes).expect("bech32m encoding of a Thorax artifact")
}

fn decode_with(expected_hrp: &str, text: &str) -> Result<Vec<u8>, BundleStringError> {
    let (hrp, data) = bech32::decode(text.trim()).map_err(|_| BundleStringError::Malformed)?;
    if hrp.as_str() != expected_hrp {
        return Err(BundleStringError::WrongPrefix(hrp.as_str().to_string()));
    }
    Ok(data)
}

/// Encode raw invite bytes as a `thrx1…` bech32m string.
pub fn encode(bytes: &[u8]) -> String {
    encode_with(INVITE_HRP, bytes)
}

/// Decode a `thrx1…` invite string back to raw bytes, verifying the checksum and prefix.
pub fn decode(text: &str) -> Result<Vec<u8>, BundleStringError> {
    decode_with(INVITE_HRP, text)
}

/// Render an artifact string as a QR code of unicode half-blocks for terminal display.
pub fn qr(text: &str) -> Result<String, BundleStringError> {
    let code = QrCode::new(text.as_bytes()).map_err(|_| BundleStringError::TooLargeForQr)?;
    Ok(code.render::<Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_is_prefixed() {
        let bytes = [1_u8, 2, 3, 4, 250, 0, 9];
        let text = encode(&bytes);
        assert!(text.starts_with("thrx1"), "got {text}");
        assert_eq!(decode(&text).unwrap(), bytes);
    }

    #[test]
    fn a_corrupted_paste_is_rejected() {
        let mut text = encode(&[7_u8; 48]);
        let idx = text.len() - 3;
        let bad = if text.as_bytes()[idx] == b'q' {
            'p'
        } else {
            'q'
        };
        text.replace_range(idx..idx + 1, &bad.to_string());
        assert!(matches!(decode(&text), Err(BundleStringError::Malformed)));
    }

    #[test]
    fn a_foreign_prefix_is_rejected() {
        let other = bech32::encode::<Bech32m>(Hrp::parse_unchecked("xyz"), &[1, 2, 3]).unwrap();
        assert!(matches!(
            decode(&other),
            Err(BundleStringError::WrongPrefix(_))
        ));
    }
}
