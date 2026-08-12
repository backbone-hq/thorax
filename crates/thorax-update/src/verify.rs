//! Ed25519 signature and artifact verification for release manifests.
//!
//! The target release scheme:
//!  1. Build a `ReleaseManifest` body containing all artifact hashes.
//!  2. Sign the canonical cord bytes of that body under `thorax.release-manifest.v1`.
//!  3. Publish a `SignedReleaseManifest` as `MANIFEST.cord`.
//!  4. Clients verify the manifest first, then verify downloaded artifacts against it.

use ed25519_dalek::{Signature, Signer, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::manifest::{ReleaseArtifactV1, ReleaseManifest, SignedReleaseManifest};

const SIGNATURE_DOMAIN: &str = "thorax.signature.v1";
pub const RELEASE_MANIFEST_DOMAIN: &str = "thorax.release-manifest.v1";

/// The compiled-in Ed25519 public key for update verification.
pub static UPDATE_PUBKEY: &[u8; 32] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/pubkey.bin"));

/// Encode the manifest body into the exact bytes covered by the release signature.
pub fn manifest_body_bytes(body: &ReleaseManifest) -> Result<Vec<u8>, VerifyError> {
    cord::serialize(body).map_err(|e| VerifyError::Cord(e.to_string()))
}

/// Build the domain-separated Ed25519 message for a release manifest.
pub fn manifest_signature_message(body_bytes: &[u8]) -> Vec<u8> {
    signature_transcript(RELEASE_MANIFEST_DOMAIN, body_bytes)
}

/// Encode a signed manifest file.
pub fn signed_manifest_bytes(signed: &SignedReleaseManifest) -> Result<Vec<u8>, VerifyError> {
    cord::serialize(signed).map_err(|e| VerifyError::Cord(e.to_string()))
}

/// Verify and decode a signed release manifest using the compiled-in public key.
pub fn verify_signed_manifest(bytes: &[u8]) -> Result<ReleaseManifest, VerifyError> {
    verify_signed_manifest_with_key(bytes, UPDATE_PUBKEY)
}

/// Verify and decode a signed release manifest using an explicit public key.
pub fn verify_signed_manifest_with_key(
    bytes: &[u8],
    expected_public_key: &[u8; 32],
) -> Result<ReleaseManifest, VerifyError> {
    let signed: SignedReleaseManifest =
        cord::deserialize(bytes).map_err(|e| VerifyError::Cord(e.to_string()))?;
    verify_manifest_signature(&signed, expected_public_key)?;
    Ok(signed.body)
}

/// Verify the signature inside a decoded signed manifest.
pub fn verify_manifest_signature(
    signed: &SignedReleaseManifest,
    expected_public_key: &[u8; 32],
) -> Result<(), VerifyError> {
    if signed.signing_public_key.as_slice() != expected_public_key {
        return Err(VerifyError::UnexpectedPublicKey);
    }
    let key = VerifyingKey::from_bytes(expected_public_key)
        .map_err(|e| VerifyError::BadPublicKey(e.to_string()))?;
    let sig = Signature::from_slice(&signed.signature)
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
    let body_bytes = manifest_body_bytes(&signed.body)?;
    let message = manifest_signature_message(&body_bytes);
    key.verify_strict(&message, &sig)
        .map_err(|_| VerifyError::InvalidSignature)
}

/// Verify downloaded release asset bytes against the signed manifest entry.
pub fn verify_artifact_bytes(
    artifact: &ReleaseArtifactV1,
    bytes: &[u8],
) -> Result<(), VerifyError> {
    if bytes.len() as u64 != artifact.size {
        return Err(VerifyError::ArtifactSize {
            expected: artifact.size,
            actual: bytes.len() as u64,
        });
    }
    let digest = Sha256::digest(bytes);
    if digest.as_slice() != artifact.sha256.as_slice() {
        return Err(VerifyError::ArtifactHash {
            artifact: artifact.name.clone(),
        });
    }
    Ok(())
}

/// Transitional verifier for the old prototype `.gz.sig` release layout.
pub fn verify_signed_archive(data: &[u8], signature_bytes: &[u8]) -> Result<(), VerifyError> {
    let sig = Signature::from_slice(signature_bytes)
        .map_err(|e| VerifyError::BadSignature(e.to_string()))?;
    let key = VerifyingKey::from_bytes(UPDATE_PUBKEY)
        .map_err(|e| VerifyError::BadPublicKey(e.to_string()))?;

    let hash = Sha256::digest(data);
    key.verify_strict(&hash, &sig)
        .map_err(|_| VerifyError::InvalidSignature)
}

pub fn sign_manifest_for_tests(
    signing_key: &ed25519_dalek::SigningKey,
    body: ReleaseManifest,
) -> Result<SignedReleaseManifest, VerifyError> {
    let body_bytes = manifest_body_bytes(&body)?;
    let message = manifest_signature_message(&body_bytes);
    let signature = signing_key.sign(&message);
    Ok(SignedReleaseManifest {
        body,
        signing_public_key: signing_key.verifying_key().to_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid Ed25519 signature (public key mismatch or tampered data)")]
    InvalidSignature,
    #[error("manifest was signed by an unexpected public key")]
    UnexpectedPublicKey,
    #[error("invalid signature format: {0}")]
    BadSignature(String),
    #[error("invalid public key: {0}")]
    BadPublicKey(String),
    #[error("cord encode/decode error: {0}")]
    Cord(String),
    #[error("artifact size mismatch: expected {expected}, got {actual}")]
    ArtifactSize { expected: u64, actual: u64 },
    #[error("artifact hash mismatch for {artifact}")]
    ArtifactHash { artifact: String },
}

fn signature_transcript(domain: &str, message: &[u8]) -> Vec<u8> {
    let mut transcript =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + domain.len() + 8 + message.len());
    append_transcript(&mut transcript, SIGNATURE_DOMAIN.as_bytes());
    append_transcript(&mut transcript, domain.as_bytes());
    append_transcript(&mut transcript, message);
    transcript
}

fn append_transcript(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ArtifactTargetV1, ReleaseArtifactV1, ReleaseManifestV1, ReleaseSourceV1, CLI_ARTIFACT_KIND,
    };

    fn test_keypair() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[0xAB; 32])
    }

    fn manifest() -> ReleaseManifest {
        ReleaseManifest::V1(ReleaseManifestV1 {
            version: "0.2.0".to_string(),
            release_epoch: 2,
            published_at: "2026-07-08T00:00:00Z".to_string(),
            source: ReleaseSourceV1 {
                tag: "v0.2.0".to_string(),
                commit: "abc123".to_string(),
                workflow_run_id: "123456".to_string(),
            },
            artifacts: vec![ReleaseArtifactV1 {
                name: "thorax-x86_64-unknown-linux-gnu".to_string(),
                kind: CLI_ARTIFACT_KIND.to_string(),
                format: "raw".to_string(),
                url: None,
                target: ArtifactTargetV1 {
                    triple: "x86_64-unknown-linux-gnu".to_string(),
                    os: "linux".to_string(),
                    arch: "x86_64".to_string(),
                    abi: Some("gnu".to_string()),
                },
                size: 5,
                sha256: Sha256::digest(b"hello").to_vec(),
            }],
            keys: Vec::new(),
        })
    }

    #[test]
    fn verify_accepts_signed_manifest() {
        let sk = test_keypair();
        let signed = sign_manifest_for_tests(&sk, manifest()).unwrap();
        let bytes = signed_manifest_bytes(&signed).unwrap();
        let key = sk.verifying_key().to_bytes();
        let decoded = verify_signed_manifest_with_key(&bytes, &key).unwrap();
        assert_eq!(decoded.v1().version, "0.2.0");
    }

    #[test]
    fn verify_rejects_wrong_manifest_key() {
        let sk = test_keypair();
        let other = ed25519_dalek::SigningKey::from_bytes(&[0xCD; 32])
            .verifying_key()
            .to_bytes();
        let signed = sign_manifest_for_tests(&sk, manifest()).unwrap();
        let bytes = signed_manifest_bytes(&signed).unwrap();
        let err = verify_signed_manifest_with_key(&bytes, &other).unwrap_err();
        assert!(matches!(err, VerifyError::UnexpectedPublicKey));
    }

    #[test]
    fn artifact_verification_checks_size_and_hash() {
        let artifact = manifest().v1().artifacts[0].clone();
        verify_artifact_bytes(&artifact, b"hello").unwrap();

        let err = verify_artifact_bytes(&artifact, b"hell").unwrap_err();
        assert!(matches!(err, VerifyError::ArtifactSize { .. }));

        let err = verify_artifact_bytes(&artifact, b"abcde").unwrap_err();
        assert!(matches!(err, VerifyError::ArtifactHash { .. }));
    }
}
