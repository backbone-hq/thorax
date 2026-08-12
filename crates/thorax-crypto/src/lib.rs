//! Production crypto provider for Thorax v1.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as HpkeKem, OpModeR, OpModeS, Serializable};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use std::fmt;
use thorax_core::crypto::{derive_user_id, signed_record_message, RecordSigner};
use thorax_core::{Bytes, CryptoProvider, HashValue, IdSeed, UserId, VaultRecordV1};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const SIGNATURE_DOMAIN: &str = "thorax.signature.v1";
pub const SIGNED_RECORD_DOMAIN: &str = "thorax.signed.v1";
pub const HASH_DOMAIN: &str = "thorax.hash.v1";
pub const CONTENT_AEAD_DOMAIN: &str = "thorax.content-aead.v1";
pub const HPKE_INFO_DOMAIN: &str = "thorax.hpke-info.v1";
pub const CONTENT_KEY_LEN: usize = 32;
pub const CONTENT_NONCE_LEN: usize = 12;
pub const ED25519_SECRET_KEY_LEN: usize = 32;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// A Thorax identity is fully determined by one 256-bit master seed; both the Ed25519
/// signing key and the X25519/HPKE key are derived from it via HKDF-SHA256.
pub const MASTER_SEED_LEN: usize = 32;
const IDENTITY_KDF_SALT: &[u8] = b"thorax.identity.v1";
const IDENTITY_KDF_INFO_ED25519: &[u8] = b"thorax.identity.v1.ed25519";
const IDENTITY_KDF_INFO_X25519: &[u8] = b"thorax.identity.v1.x25519";
const HPKE_DERIVE_IKM_LEN: usize = 32;
const RATCHET_MAC_SALT: &[u8] = b"thorax.ratchet-mac.v1";
const RATCHET_MAC_INFO: &[u8] = b"thorax.ratchet-mac.v1.key";

type HpkeAead = HpkeChaCha20Poly1305;
type HpkeKdf = HkdfSha256;
type HpkeSuite = X25519HkdfSha256;
type HpkePublicKey = <HpkeSuite as HpkeKem>::PublicKey;
type HpkePrivateKey = <HpkeSuite as HpkeKem>::PrivateKey;
type HpkeEncappedKey = <HpkeSuite as HpkeKem>::EncappedKey;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("core error: {0}")]
    Core(#[from] thorax_core::CoreError),
    #[error("invalid byte length for {name}: expected {expected}, got {actual}")]
    InvalidLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid Ed25519 public key")]
    InvalidSigningPublicKey,
    #[error("invalid Ed25519 secret key")]
    InvalidSigningSecretKey,
    #[error("invalid Ed25519 signature")]
    InvalidSignature,
    #[error("invalid HPKE public key")]
    InvalidHpkePublicKey,
    #[error("invalid HPKE private key")]
    InvalidHpkePrivateKey,
    #[error("invalid HPKE encapsulated key")]
    InvalidHpkeEncapsulatedKey,
    #[error("HPKE operation failed: {0}")]
    Hpke(String),
    #[error("AEAD operation failed")]
    Aead,
    #[error("ratchet authentication failed")]
    InvalidRatchetMac,
}

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Default, Clone, Copy)]
pub struct Crypto;

impl Crypto {
    pub fn sign(&self, keypair: &SigningKeypair, domain: &str, message: &[u8]) -> Bytes {
        keypair.sign(domain, message)
    }

    pub fn sign_record(&self, keypair: &SigningKeypair, signed: &mut VaultRecordV1) -> Result<()> {
        let message = signed_record_message(signed)?;
        signed.signature = self.sign(keypair, SIGNED_RECORD_DOMAIN, &message);
        Ok(())
    }
}

impl CryptoProvider for Crypto {
    fn hash(&self, domain: &str, canonical_bytes: &[u8]) -> HashValue {
        let mut hasher = Sha256::new();
        update_transcript(&mut hasher, HASH_DOMAIN.as_bytes());
        update_transcript(&mut hasher, domain.as_bytes());
        update_transcript(&mut hasher, canonical_bytes);
        HashValue(hasher.finalize().to_vec())
    }

    fn verify_signature(
        &self,
        domain: &str,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        let Ok(verifying_key) = verifying_key_from_bytes(public_key) else {
            return false;
        };
        let Ok(signature) = signature_from_bytes(signature) else {
            return false;
        };
        verifying_key
            .verify_strict(&signature_transcript(domain, message), &signature)
            .is_ok()
    }
}

pub struct SigningKeypair {
    signing_key: SigningKey,
}

impl SigningKeypair {
    pub fn generate() -> Self {
        let mut secret = [0_u8; ED25519_SECRET_KEY_LEN];
        csprng().fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        secret.zeroize();
        Self { signing_key }
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        let secret = fixed_array::<ED25519_SECRET_KEY_LEN>(bytes, "Ed25519 secret key")?;
        let signing_key = SigningKey::from_bytes(&secret);
        Ok(Self { signing_key })
    }

    pub fn public_key_bytes(&self) -> Bytes {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    pub fn sign(&self, domain: &str, message: &[u8]) -> Bytes {
        self.signing_key
            .sign(&signature_transcript(domain, message))
            .to_bytes()
            .to_vec()
    }
}

impl Clone for SigningKeypair {
    fn clone(&self) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&self.signing_key.to_bytes()),
        }
    }
}

impl fmt::Debug for SigningKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeypair")
            .field("public_key", &self.public_key_bytes())
            .field("secret_key", &"<redacted>")
            .finish()
    }
}

pub struct HpkeKeypair {
    private_key: HpkePrivateKey,
    public_key: HpkePublicKey,
}

impl HpkeKeypair {
    pub fn generate() -> Self {
        let (private_key, public_key) = HpkeSuite::gen_keypair(&mut csprng());
        Self {
            private_key,
            public_key,
        }
    }

    /// Deterministically derive the keypair from input keying material per RFC 9180
    /// `DeriveKeyPair`. Used to derive the HPKE key from a Thorax identity master seed.
    pub fn from_ikm(ikm: &[u8]) -> Self {
        let (private_key, public_key) = HpkeSuite::derive_keypair(ikm);
        Self {
            private_key,
            public_key,
        }
    }

    pub fn public_key_bytes(&self) -> Bytes {
        self.public_key.to_bytes().to_vec()
    }

    pub fn private_key(&self) -> &HpkePrivateKey {
        &self.private_key
    }
}

impl Clone for HpkeKeypair {
    fn clone(&self) -> Self {
        Self {
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
        }
    }
}

impl fmt::Debug for HpkeKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HpkeKeypair")
            .field("public_key", &self.public_key_bytes())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ContentKey {
    bytes: [u8; CONTENT_KEY_LEN],
}

impl ContentKey {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CONTENT_KEY_LEN];
        csprng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            bytes: fixed_array::<CONTENT_KEY_LEN>(bytes, "content key")?,
        })
    }

    pub fn as_bytes(&self) -> &[u8; CONTENT_KEY_LEN] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentNonce {
    bytes: [u8; CONTENT_NONCE_LEN],
}

impl ContentNonce {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; CONTENT_NONCE_LEN];
        csprng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            bytes: fixed_array::<CONTENT_NONCE_LEN>(bytes, "content nonce")?,
        })
    }

    pub fn as_bytes(&self) -> &[u8; CONTENT_NONCE_LEN] {
        &self.bytes
    }

    pub fn to_vec(&self) -> Bytes {
        self.bytes.to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HpkeSealed {
    pub encapsulated_key: Bytes,
    pub ciphertext: Bytes,
}

#[derive(Clone, Debug)]
pub struct IdentityKeys {
    pub signing: SigningKeypair,
    pub hpke: HpkeKeypair,
}

/// Derive the Ed25519 signing key and the HPKE key from a single 256-bit master seed.
///
/// `HKDF-Extract(salt = "thorax.identity.v1")` over the seed, then `HKDF-Expand` with
/// domain-separated info labels gives independent key material for each algorithm. The
/// HPKE side feeds its derived input keying material through RFC 9180 `DeriveKeyPair`.
pub fn derive_identity_keys(master_seed: &[u8]) -> Result<IdentityKeys> {
    if master_seed.len() != MASTER_SEED_LEN {
        return Err(CryptoError::InvalidLength {
            name: "identity master seed",
            expected: MASTER_SEED_LEN,
            actual: master_seed.len(),
        });
    }
    let hk = Hkdf::<Sha256>::new(Some(IDENTITY_KDF_SALT), master_seed);
    let mut sign_seed = Zeroizing::new([0_u8; ED25519_SECRET_KEY_LEN]);
    hk.expand(IDENTITY_KDF_INFO_ED25519, sign_seed.as_mut_slice())
        .map_err(|_| CryptoError::InvalidSigningSecretKey)?;
    let mut hpke_ikm = Zeroizing::new([0_u8; HPKE_DERIVE_IKM_LEN]);
    hk.expand(IDENTITY_KDF_INFO_X25519, hpke_ikm.as_mut_slice())
        .map_err(|_| CryptoError::InvalidHpkePrivateKey)?;
    Ok(IdentityKeys {
        signing: SigningKeypair::from_secret_bytes(sign_seed.as_slice())?,
        hpke: HpkeKeypair::from_ikm(hpke_ikm.as_slice()),
    })
}

#[derive(Clone, Debug)]
pub struct Identity {
    user: UserId,
    keys: IdentityKeys,
    signing_public_key: Bytes,
    hpke_public_key: Bytes,
    master_seed: Zeroizing<Bytes>,
}

impl Identity {
    /// Create a brand-new identity from a fresh random master seed.
    pub fn generate(crypto: &Crypto) -> Result<Self> {
        let seed = random_bytes(MASTER_SEED_LEN);
        Self::from_master_seed(crypto, &seed)
    }

    /// Reconstruct an identity deterministically from its 256-bit master seed.
    pub fn from_master_seed(crypto: &Crypto, master_seed: &[u8]) -> Result<Self> {
        let keys = derive_identity_keys(master_seed)?;
        let signing_public_key = keys.signing.public_key_bytes();
        let hpke_public_key = keys.hpke.public_key_bytes();
        let user = derive_user_id(crypto, &signing_public_key, &hpke_public_key)?;
        Ok(Self {
            user,
            keys,
            signing_public_key,
            hpke_public_key,
            master_seed: Zeroizing::new(master_seed.to_vec()),
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user
    }

    pub fn keys(&self) -> &IdentityKeys {
        &self.keys
    }

    /// The master seed this identity derives from. This is long-lived secret material;
    /// callers (keychains, invites) must protect and zeroize it.
    pub fn master_seed(&self) -> &[u8] {
        &self.master_seed
    }

    pub fn signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    pub fn hpke_public_key(&self) -> &[u8] {
        &self.hpke_public_key
    }
}

impl RecordSigner for Identity {
    fn user_id(&self) -> &UserId {
        &self.user
    }

    fn signing_public_key(&self) -> &[u8] {
        &self.signing_public_key
    }

    fn hpke_public_key(&self) -> &[u8] {
        &self.hpke_public_key
    }

    fn sign(&self, domain: &str, message: &[u8]) -> Bytes {
        self.keys.signing.sign(domain, message)
    }
}

/// Authenticate canonical rollback-ratchet bytes under an identity-derived key.
pub fn ratchet_mac(
    identity: &Identity,
    trusted_root: &HashValue,
    user_id: &UserId,
    ratchet_bytes: &[u8],
) -> Result<Bytes> {
    let key = ratchet_mac_key(identity)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::InvalidRatchetMac)?;
    update_mac_transcript(&mut mac, RATCHET_MAC_SALT);
    update_mac_transcript(&mut mac, &trusted_root.0);
    update_mac_transcript(&mut mac, &(user_id.0).0);
    update_mac_transcript(&mut mac, ratchet_bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn verify_ratchet_mac(
    identity: &Identity,
    trusted_root: &HashValue,
    user_id: &UserId,
    ratchet_bytes: &[u8],
    expected: &[u8],
) -> Result<()> {
    let key = ratchet_mac_key(identity)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::InvalidRatchetMac)?;
    update_mac_transcript(&mut mac, RATCHET_MAC_SALT);
    update_mac_transcript(&mut mac, &trusted_root.0);
    update_mac_transcript(&mut mac, &(user_id.0).0);
    update_mac_transcript(&mut mac, ratchet_bytes);
    mac.verify_slice(expected)
        .map_err(|_| CryptoError::InvalidRatchetMac)
}

fn ratchet_mac_key(identity: &Identity) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(RATCHET_MAC_SALT), identity.master_seed());
    let mut key = Zeroizing::new([0_u8; 32]);
    hk.expand(RATCHET_MAC_INFO, key.as_mut_slice())
        .map_err(|_| CryptoError::InvalidRatchetMac)?;
    Ok(key)
}

fn update_mac_transcript(mac: &mut Hmac<Sha256>, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}

pub fn random_seed() -> IdSeed {
    let mut seed = vec![0_u8; 32];
    csprng().fill_bytes(&mut seed);
    IdSeed::from_bytes(seed)
}

pub fn random_bytes(len: usize) -> Zeroizing<Bytes> {
    let mut bytes = vec![0_u8; len];
    csprng().fill_bytes(&mut bytes);
    Zeroizing::new(bytes)
}

pub fn seal_content(
    key: &ContentKey,
    nonce: &ContentNonce,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Bytes> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    cipher
        .encrypt(
            Nonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)
}

pub fn open_content(
    key: &ContentKey,
    nonce: &ContentNonce,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Bytes>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_bytes()));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce.as_bytes()),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Aead)?;
    Ok(Zeroizing::new(plaintext))
}

pub fn hpke_seal(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeSealed> {
    let public_key = hpke_public_key_from_bytes(recipient_public_key)?;
    let (encapped_key, ciphertext) = hpke::single_shot_seal::<HpkeAead, HpkeKdf, HpkeSuite, _>(
        &OpModeS::Base,
        &public_key,
        &hpke_info(info),
        plaintext,
        aad,
        &mut csprng(),
    )
    .map_err(|error| CryptoError::Hpke(error.to_string()))?;

    Ok(HpkeSealed {
        encapsulated_key: encapped_key.to_bytes().to_vec(),
        ciphertext,
    })
}

pub fn hpke_open(
    recipient_private_key: &HpkeKeypair,
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Bytes>> {
    let encapped_key = hpke_encapped_key_from_bytes(encapsulated_key)?;
    let plaintext = hpke::single_shot_open::<HpkeAead, HpkeKdf, HpkeSuite>(
        &OpModeR::Base,
        recipient_private_key.private_key(),
        &encapped_key,
        &hpke_info(info),
        ciphertext,
        aad,
    )
    .map_err(|error| CryptoError::Hpke(error.to_string()))?;
    Ok(Zeroizing::new(plaintext))
}

pub fn wrap_content_key(
    recipient_public_key: &[u8],
    info: &[u8],
    aad: &[u8],
    content_key: &ContentKey,
) -> Result<HpkeSealed> {
    hpke_seal(recipient_public_key, info, aad, content_key.as_bytes())
}

pub fn unwrap_content_key(
    recipient_private_key: &HpkeKeypair,
    encapsulated_key: &[u8],
    info: &[u8],
    aad: &[u8],
    wrapped_content_key: &[u8],
) -> Result<ContentKey> {
    let bytes = hpke_open(
        recipient_private_key,
        encapsulated_key,
        info,
        aad,
        wrapped_content_key,
    )?;
    ContentKey::from_bytes(&bytes)
}

fn csprng() -> StdRng {
    StdRng::from_os_rng()
}

fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey> {
    let bytes = fixed_array::<ED25519_PUBLIC_KEY_LEN>(bytes, "Ed25519 public key")?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| CryptoError::InvalidSigningPublicKey)
}

fn signature_from_bytes(bytes: &[u8]) -> Result<Signature> {
    let bytes = fixed_array::<ED25519_SIGNATURE_LEN>(bytes, "Ed25519 signature")?;
    Ok(Signature::from_bytes(&bytes))
}

fn hpke_public_key_from_bytes(bytes: &[u8]) -> Result<HpkePublicKey> {
    HpkePublicKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidHpkePublicKey)
}

fn hpke_encapped_key_from_bytes(bytes: &[u8]) -> Result<HpkeEncappedKey> {
    HpkeEncappedKey::from_bytes(bytes).map_err(|_| CryptoError::InvalidHpkeEncapsulatedKey)
}

fn fixed_array<const N: usize>(bytes: &[u8], name: &'static str) -> Result<[u8; N]> {
    bytes.try_into().map_err(|_| CryptoError::InvalidLength {
        name,
        expected: N,
        actual: bytes.len(),
    })
}

fn signature_transcript(domain: &str, message: &[u8]) -> Bytes {
    let mut transcript =
        Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + domain.len() + 8 + message.len());
    append_transcript(&mut transcript, SIGNATURE_DOMAIN.as_bytes());
    append_transcript(&mut transcript, domain.as_bytes());
    append_transcript(&mut transcript, message);
    transcript
}

fn hpke_info(info: &[u8]) -> Bytes {
    let mut transcript = Vec::with_capacity(HPKE_INFO_DOMAIN.len() + 8 + info.len());
    append_transcript(&mut transcript, HPKE_INFO_DOMAIN.as_bytes());
    append_transcript(&mut transcript, info);
    transcript
}

fn update_transcript(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn append_transcript(out: &mut Bytes, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use thorax_core::crypto::{derive_user_id, key_hash};
    use thorax_core::{
        validate_vault, Ratchet, RecordBodyV1, VaultRootRecordV1, VaultStore, VaultStoreV1,
    };

    #[test]
    fn signature_verifies_only_for_same_domain_message_and_key() {
        let crypto = Crypto;
        let signer = SigningKeypair::generate();
        let other = SigningKeypair::generate();
        let signature = signer.sign("domain-a", b"message");

        assert!(crypto.verify_signature(
            "domain-a",
            &signer.public_key_bytes(),
            b"message",
            &signature,
        ));
        assert!(!crypto.verify_signature(
            "domain-b",
            &signer.public_key_bytes(),
            b"message",
            &signature,
        ));
        assert!(!crypto.verify_signature(
            "domain-a",
            &signer.public_key_bytes(),
            b"other",
            &signature,
        ));
        assert!(!crypto.verify_signature(
            "domain-a",
            &other.public_key_bytes(),
            b"message",
            &signature,
        ));
    }

    #[test]
    fn hash_is_domain_separated() {
        let crypto = Crypto;
        assert_eq!(crypto.hash("a", b"x"), crypto.hash("a", b"x"));
        assert_ne!(crypto.hash("a", b"x"), crypto.hash("b", b"x"));
        assert_ne!(crypto.hash("a", b"x"), crypto.hash("a", b"y"));
    }

    #[test]
    fn production_signed_root_validates_with_core() {
        let crypto = Crypto;
        let root_signing = SigningKeypair::generate();
        let root_hpke = HpkeKeypair::generate();
        let root_user = derive_user_id(
            &crypto,
            &root_signing.public_key_bytes(),
            &root_hpke.public_key_bytes(),
        )
        .unwrap();
        let body = RecordBodyV1::VaultRoot(VaultRootRecordV1 {
            id: root_user.clone(),
            hpke_public_key: root_hpke.public_key_bytes(),
        });
        let mut signed = VaultRecordV1 {
            body: cord::Evolving::new(body),
            signing_public_key: root_signing.public_key_bytes(),
            signature: Vec::new(),
        };
        crypto.sign_record(&root_signing, &mut signed).unwrap();

        let vault = VaultStore::V1(VaultStoreV1 {
            records: vec![signed].into(),
        });
        let trust = Ratchet::new(key_hash(&crypto, &root_signing.public_key_bytes()).unwrap());
        let report = validate_vault(&vault, &trust, &crypto).unwrap();
        assert!(report.issues.is_empty(), "{:?}", report.issues);
        assert!(report.effective.root_user_id.is_some());
    }

    #[test]
    fn content_aead_roundtrips_and_binds_aad() {
        let key = ContentKey::generate();
        let nonce = ContentNonce::generate();
        let ciphertext = seal_content(&key, &nonce, b"aad", b"secret").unwrap();

        let plaintext = open_content(&key, &nonce, b"aad", &ciphertext).unwrap();
        assert_eq!(&*plaintext, b"secret");
        assert!(open_content(&key, &nonce, b"wrong", &ciphertext).is_err());
    }

    #[test]
    fn hpke_wrap_roundtrips_and_binds_info_and_aad() {
        let recipient = HpkeKeypair::generate();
        let content_key = ContentKey::generate();
        let sealed = wrap_content_key(
            &recipient.public_key_bytes(),
            b"secret-id",
            b"slot-aad",
            &content_key,
        )
        .unwrap();

        let opened = unwrap_content_key(
            &recipient,
            &sealed.encapsulated_key,
            b"secret-id",
            b"slot-aad",
            &sealed.ciphertext,
        )
        .unwrap();
        assert_eq!(opened.as_bytes(), content_key.as_bytes());
        assert!(unwrap_content_key(
            &recipient,
            &sealed.encapsulated_key,
            b"other-secret-id",
            b"slot-aad",
            &sealed.ciphertext,
        )
        .is_err());
        assert!(unwrap_content_key(
            &recipient,
            &sealed.encapsulated_key,
            b"secret-id",
            b"wrong-aad",
            &sealed.ciphertext,
        )
        .is_err());
    }

    #[test]
    fn identity_is_deterministic_from_master_seed() {
        let crypto = Crypto;
        let seed = [7_u8; MASTER_SEED_LEN];
        let a = Identity::from_master_seed(&crypto, &seed).unwrap();
        let b = Identity::from_master_seed(&crypto, &seed).unwrap();
        assert_eq!(a.user_id(), b.user_id());
        assert_eq!(a.signing_public_key(), b.signing_public_key());
        assert_eq!(a.hpke_public_key(), b.hpke_public_key());
        assert_eq!(a.master_seed(), &seed);

        let different = Identity::from_master_seed(&crypto, &[8_u8; MASTER_SEED_LEN]).unwrap();
        assert_ne!(a.user_id(), different.user_id());
        assert_ne!(a.signing_public_key(), different.signing_public_key());
        assert_ne!(a.hpke_public_key(), different.hpke_public_key());

        // The two derived keys are independent (different domain-separated info labels).
        assert_ne!(a.signing_public_key(), a.hpke_public_key());

        assert!(Identity::from_master_seed(&crypto, &[0_u8; 16]).is_err());
    }

    #[test]
    fn ratchet_mac_binds_identity_root_user_and_bytes() {
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![1; 32]);
        let bytes = b"ratchet";
        let mac = ratchet_mac(&identity, &root, identity.user_id(), bytes).unwrap();
        verify_ratchet_mac(&identity, &root, identity.user_id(), bytes, &mac).unwrap();
        assert!(verify_ratchet_mac(
            &identity,
            &HashValue(vec![2; 32]),
            identity.user_id(),
            bytes,
            &mac
        )
        .is_err());
        assert!(
            verify_ratchet_mac(&identity, &root, identity.user_id(), b"changed", &mac).is_err()
        );
    }
}
