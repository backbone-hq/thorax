use crate::format::{Bytes, HashValue, IdSeed, UserId, UserIdInputV1, VaultRecordV1};
use crate::Result;
use serde::Serialize;

pub trait CryptoProvider {
    fn hash(&self, domain: &str, canonical_bytes: &[u8]) -> HashValue;

    fn verify_signature(
        &self,
        domain: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool;
}

pub trait RecordSigner {
    fn user_id(&self) -> &UserId;
    fn signing_public_key(&self) -> &[u8];
    fn hpke_public_key(&self) -> &[u8];
    fn sign(&self, domain: &str, message: &[u8]) -> Bytes;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DeterministicCrypto;

impl DeterministicCrypto {
    pub fn sign(&self, domain: &str, public_key: &[u8], message: &[u8]) -> Bytes {
        let mut bytes = Vec::with_capacity(public_key.len() + message.len());
        bytes.extend_from_slice(public_key);
        bytes.extend_from_slice(message);
        self.hash(domain, &bytes).0
    }
}

impl CryptoProvider for DeterministicCrypto {
    fn hash(&self, domain: &str, canonical_bytes: &[u8]) -> HashValue {
        let mut state = [0_u8; 32];
        for (idx, byte) in domain
            .as_bytes()
            .iter()
            .chain([0xff].iter())
            .chain(canonical_bytes.iter())
            .enumerate()
        {
            let lane = idx % 32;
            state[lane] = state[lane]
                .wrapping_mul(31)
                .wrapping_add(*byte)
                .wrapping_add((idx as u8).rotate_left((lane % 7) as u32));
            state[(lane * 7) % 32] ^= byte.rotate_left((idx % 8) as u32);
        }
        HashValue(state.to_vec())
    }

    fn verify_signature(
        &self,
        domain: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        self.sign(domain, public_key, message) == signature
    }
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Bytes> {
    Ok(cord::serialize(value)?)
}

pub fn derive_hash<T: Serialize>(
    crypto: &impl CryptoProvider,
    domain: &str,
    value: &T,
) -> Result<HashValue> {
    Ok(crypto.hash(domain, &canonical_bytes(value)?))
}

pub fn derive_user_id(
    crypto: &impl CryptoProvider,
    signing_public_key: &[u8],
    hpke_public_key: &[u8],
) -> Result<UserId> {
    Ok(UserId(derive_hash(
        crypto,
        "thorax.user.v1",
        &UserIdInputV1 {
            signing_public_key: signing_public_key.to_vec(),
            hpke_public_key: hpke_public_key.to_vec(),
        },
    )?))
}

pub fn derive_seeded_hash(
    crypto: &impl CryptoProvider,
    domain: &str,
    seed: &IdSeed,
) -> Result<HashValue> {
    derive_hash(crypto, domain, seed)
}

pub fn key_hash(crypto: &impl CryptoProvider, public_key: &[u8]) -> Result<HashValue> {
    derive_hash(crypto, "thorax.key.v1", &public_key.to_vec())
}

/// The signing/verification pre-image for a record: the canonical bytes of its body.
///
/// Domain separation is applied by the signing primitive via the `thorax.signed.v1`
/// domain, so it need not be repeated here. The envelope's `signing_public_key` is *not*
/// in the message — it is a lookup hint, and the signer's full identity is bound by the
/// signing-key-uniqueness invariant enforced during validation: a signing public key maps
/// to at most one `UserId`. This matters because a signature only attests to the signing
/// key, while a `UserId` commits to both the signing and HPKE keys (see
/// [`derive_user_id`]); uniqueness is what resolves a record's signature to a single,
/// complete identity.
pub fn signed_record_message(signed: &VaultRecordV1) -> Result<Bytes> {
    canonical_bytes(&signed.body)
}
