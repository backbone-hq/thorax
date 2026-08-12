//! Identity keychains and local key-release policy for Thorax.
//!
//! This crate gates use of local private identity material. Vault
//! authorization answers "may this Thorax user read the secret"; the keychain
//! answers "may this local process use the human key right now".

use std::{
    env,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use thorax_core::{Bytes, HashValue, SecretSelectorV1, UserId};
use thorax_crypto::{Crypto, Identity};
use thorax_store::{read_file_bounded, remove_file_durable, write_private_atomic, WorkspacePaths};
use zeroize::{Zeroize, Zeroizing};

pub const KEYCHAIN_DIR_ENV: &str = "THORAX_KEYCHAIN_DIR";
const KEYCHAIN_FILE: &str = "keychain.cord";
const IDENTITIES_DIR: &str = "identities";
const CURRENT_USER_FILE: &str = "current-user.cord";
const KEYCHAIN_LOCK_FILE: &str = "keychain.lock";
const MAX_IDENTITY_BYTES: usize = 1024 * 1024;
const MAX_CURRENT_USER_BYTES: usize = 64 * 1024;
const MAX_LEGACY_KEYCHAIN_BYTES: usize = 64 * 1024 * 1024;
const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(100);

const PASSPHRASE_SALT_LEN: usize = 16;
const PASSPHRASE_NONCE_LEN: usize = 12;
const PASSPHRASE_KEY_LEN: usize = 32;
const ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const MIN_ARGON2_MEMORY_COST_KIB: u32 = 8 * 1024;
const MAX_ARGON2_MEMORY_COST_KIB: u32 = 256 * 1024;
const MAX_ARGON2_ITERATIONS: u32 = 10;
const MAX_ARGON2_PARALLELISM: u32 = 8;

pub type Result<T> = std::result::Result<T, KeychainError>;

#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("store error: {0}")]
    Store(#[from] thorax_store::StoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] thorax_crypto::CryptoError),
    #[error("Cord error: {0}")]
    Cord(#[from] cord::CordError),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("identity keychain does not contain {user_id:?}")]
    IdentityNotFound { user_id: UserId },
    #[error("identity material is inconsistent for {user_id:?}")]
    InvalidIdentity { user_id: UserId },
    #[error("identity keychain unlock failed")]
    UnlockFailed,
    #[error("passphrase provider failed: {0}")]
    PassphraseProvider(String),
    #[error("passphrases did not match")]
    PassphraseMismatch,
    #[error("identity provider failed: {0}")]
    IdentityProvider(String),
    #[error("{backend} identity keychain backend is unavailable: {reason}")]
    BackendUnavailable {
        backend: &'static str,
        reason: &'static str,
    },
    #[error("invalid passphrase keychain parameters")]
    InvalidKdfParameters,
    #[error("Argon2 operation failed: {0}")]
    Argon2(String),
    #[error("no safe identity keychain is available for {user_id:?}")]
    NoKeychainAvailable { user_id: UserId },
    #[error("keychain file {path} is invalid: {reason}")]
    InvalidFile { path: PathBuf, reason: &'static str },
    #[error("timed out waiting for keychain lock at {0}")]
    LockTimeout(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputSink {
    Stdout,
    File(PathBuf),
    Clipboard,
    ChildProcess { command: Vec<String> },
    Sdk { caller: String },
    Other(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyUsePurpose {
    DecryptSecret {
        selector: SecretSelectorV1,
        sink: OutputSink,
    },
    RunWithSecrets {
        /// Display strings for the selections being released — the user's requested
        /// queries (when the prompt precedes planning) or resolved selector strings.
        selections: Vec<String>,
        command: Vec<String>,
    },
    SignSecretWrite {
        selector: SecretSelectorV1,
    },
    MoveSecret {
        from: SecretSelectorV1,
        to: SecretSelectorV1,
    },
    SignSecretDelete {
        selector: SecretSelectorV1,
    },
    SignAdminChange {
        summary: String,
    },
    StoreIdentity,
    /// A read-only command anchoring its view to the user's identity: unlock proves
    /// possession, pins the vault root (per-root keychain + AAD), and lets the session
    /// verify membership — without it, status/list-style output would rest on unverifiable
    /// machine-local hints, which is why reads unlock by default.
    InspectVault,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainRequest {
    pub workspace_root: PathBuf,
    pub vault_path: PathBuf,
    pub trusted_root: HashValue,
    pub user_id: UserId,
    pub purpose: KeyUsePurpose,
    pub vault_label: Option<String>,
    pub user_label: Option<String>,
}

impl KeychainRequest {
    pub fn new(
        paths: &WorkspacePaths,
        trusted_root: HashValue,
        user_id: UserId,
        purpose: KeyUsePurpose,
    ) -> Self {
        Self {
            workspace_root: paths.root.clone(),
            vault_path: paths.vault_path.clone(),
            trusted_root,
            user_id,
            purpose,
            vault_label: None,
            user_label: None,
        }
    }

    pub fn with_labels(mut self, vault_label: Option<String>, user_label: Option<String>) -> Self {
        self.vault_label = vault_label;
        self.user_label = user_label;
        self
    }
}

/// The sealed identity payload: just the master seed. The `UserId` and the signing/HPKE
/// public keys all derive from it (`derive_identity_keys` + `derive_user_id`), so storing
/// them would be redundant — the seed is the whole identity.
#[derive(cord::Cord, Clone, PartialEq, Eq)]
pub struct LocalIdentityV1 {
    pub master_seed: Bytes,
}

impl Drop for LocalIdentityV1 {
    fn drop(&mut self) {
        self.master_seed.zeroize();
    }
}

impl std::fmt::Debug for LocalIdentityV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalIdentityV1")
            .field("master_seed", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainIdentityRef {
    pub backend: &'static str,
    pub trusted_root: HashValue,
    pub user_id: UserId,
    pub path: Option<PathBuf>,
}

pub trait IdentityKeychain {
    fn store_identity(
        &self,
        crypto: &Crypto,
        request: &KeychainRequest,
        identity: &Identity,
    ) -> Result<KeychainIdentityRef>;

    fn unlock_identity(&self, crypto: &Crypto, request: &KeychainRequest) -> Result<Identity>;
}

pub trait PassphraseProvider {
    fn request_passphrase(&self, request: &KeychainRequest) -> Result<Zeroizing<String>>;

    fn request_new_passphrase(&self, request: &KeychainRequest) -> Result<Zeroizing<String>> {
        self.request_passphrase(request)
    }
}

pub trait ManualIdentityProvider {
    fn request_identity(&self, request: &KeychainRequest) -> Result<Option<LocalIdentityV1>>;
}

#[derive(Clone, Debug)]
pub struct StdinPassphraseProvider;

impl PassphraseProvider for StdinPassphraseProvider {
    fn request_passphrase(&self, request: &KeychainRequest) -> Result<Zeroizing<String>> {
        let prompt = format!(
            "Unlock Thorax keychain for user \"{}\" in project \"{}\" to {}: ",
            user_for_prompt(request),
            vault_for_prompt(request),
            action_for_prompt(&request.purpose)
        );
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|error| KeychainError::PassphraseProvider(error.to_string()))
    }

    fn request_new_passphrase(&self, request: &KeychainRequest) -> Result<Zeroizing<String>> {
        let prompt = format!(
            "Create Thorax keychain passphrase for user \"{}\" in project \"{}\": ",
            user_for_prompt(request),
            vault_for_prompt(request)
        );
        let first = Zeroizing::new(
            rpassword::prompt_password(prompt)
                .map_err(|error| KeychainError::PassphraseProvider(error.to_string()))?,
        );
        let second = Zeroizing::new(
            rpassword::prompt_password("Confirm Thorax keychain passphrase: ")
                .map_err(|error| KeychainError::PassphraseProvider(error.to_string()))?,
        );
        if *first != *second {
            return Err(KeychainError::PassphraseMismatch);
        }
        Ok(first)
    }
}

#[derive(Clone, Debug)]
pub struct NoManualIdentityProvider;

impl ManualIdentityProvider for NoManualIdentityProvider {
    fn request_identity(&self, _request: &KeychainRequest) -> Result<Option<LocalIdentityV1>> {
        Ok(None)
    }
}

/// A manual identity provider holding one pre-derived identity. Used to inject an identity
/// non-interactively (e.g. CI), where the seed comes from an invite passed via env or file.
pub struct FixedIdentityProvider {
    local: LocalIdentityV1,
    // The seed determines the id; cache it so `user_id()` need not re-derive.
    user_id: UserId,
}

impl FixedIdentityProvider {
    pub fn from_master_seed(crypto: &Crypto, master_seed: &[u8]) -> Result<Self> {
        let identity = Identity::from_master_seed(crypto, master_seed)?;
        Ok(Self {
            user_id: identity.user_id().clone(),
            local: local_identity_from_identity(&identity),
        })
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }
}

impl ManualIdentityProvider for FixedIdentityProvider {
    fn request_identity(&self, _request: &KeychainRequest) -> Result<Option<LocalIdentityV1>> {
        Ok(Some(self.local.clone()))
    }
}

#[derive(Clone)]
pub struct StaticPassphraseProvider {
    passphrase: Zeroizing<String>,
}

impl StaticPassphraseProvider {
    pub fn new(passphrase: impl Into<String>) -> Self {
        Self {
            passphrase: Zeroizing::new(passphrase.into()),
        }
    }
}

impl std::fmt::Debug for StaticPassphraseProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticPassphraseProvider")
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

impl PassphraseProvider for StaticPassphraseProvider {
    fn request_passphrase(&self, _request: &KeychainRequest) -> Result<Zeroizing<String>> {
        Ok(self.passphrase.clone())
    }
}

#[derive(Clone, Debug)]
pub struct PassphraseKeychain<P> {
    base_dir: PathBuf,
    passphrase_provider: P,
}

impl<P> PassphraseKeychain<P> {
    pub fn new(base_dir: impl Into<PathBuf>, passphrase_provider: P) -> Self {
        Self {
            base_dir: base_dir.into(),
            passphrase_provider,
        }
    }

    pub fn default_base_dir() -> Result<PathBuf> {
        if let Some(path) = env::var_os(KEYCHAIN_DIR_ENV) {
            return Ok(PathBuf::from(path));
        }

        #[cfg(windows)]
        {
            if let Some(appdata) = env::var_os("APPDATA") {
                return Ok(PathBuf::from(appdata).join("Thorax"));
            }
        }

        #[cfg(not(windows))]
        {
            if let Some(xdg) = env::var_os("XDG_DATA_HOME") {
                return Ok(PathBuf::from(xdg).join("thorax"));
            }
            if let Some(home) = env::var_os("HOME") {
                return Ok(PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("thorax"));
            }
        }

        Err(KeychainError::BackendUnavailable {
            backend: "passphrase",
            reason: "THORAX_KEYCHAIN_DIR, APPDATA, XDG_DATA_HOME, and HOME are unset",
        })
    }

    /// Legacy combined per-root keychain path. New writes use [`Self::identity_path`] and
    /// [`current_user_path`]; retained so callers can locate pre-split data during migration.
    #[deprecated(note = "use identity_path or current_user_path")]
    pub fn keychain_path(&self, trusted_root: &HashValue) -> PathBuf {
        #[allow(deprecated)]
        keychain_path(&self.base_dir, trusted_root)
    }

    /// `<base>/<root-hex>/identities/<user-hex>.cord`.
    pub fn identity_path(&self, trusted_root: &HashValue, user: &UserId) -> PathBuf {
        identity_path(&self.base_dir, trusted_root, user)
    }

    /// The pre-per-root layout: `<base>/<user-hex>/keychain.cord`, keyed by user only.
    /// Read as a migration fallback when an identity is not found at the per-root path;
    /// never written.
    fn legacy_identity_path(&self, user: &UserId) -> PathBuf {
        self.base_dir
            .join(hex_bytes(&(user.0).0))
            .join(KEYCHAIN_FILE)
    }
}

/// The legacy combined per-root keychain file. New code should use [`identity_path`] or
/// [`current_user_path`].
#[deprecated(note = "use identity_path or current_user_path")]
pub fn keychain_path(base_dir: &Path, trusted_root: &HashValue) -> PathBuf {
    root_keychain_dir(base_dir, trusted_root).join(KEYCHAIN_FILE)
}

pub fn identity_path(base_dir: &Path, trusted_root: &HashValue, user: &UserId) -> PathBuf {
    root_keychain_dir(base_dir, trusted_root)
        .join(IDENTITIES_DIR)
        .join(format!("{}.cord", hex_bytes(&(user.0).0)))
}

pub fn current_user_path(base_dir: &Path, trusted_root: &HashValue) -> PathBuf {
    root_keychain_dir(base_dir, trusted_root).join(CURRENT_USER_FILE)
}

fn root_keychain_dir(base_dir: &Path, trusted_root: &HashValue) -> PathBuf {
    base_dir.join(hex_bytes(&trusted_root.0))
}

/// The machine's keychain base directory: `THORAX_KEYCHAIN_DIR`, else the platform data
/// dir. The standalone form of [`PassphraseKeychain::default_base_dir`], for callers that
/// only need to locate keychain files (e.g. the `CurrentUser` selection record) without
/// constructing a keychain backend.
pub fn default_keychain_dir() -> Result<PathBuf> {
    PassphraseKeychain::<StdinPassphraseProvider>::default_base_dir()
}

impl<P> IdentityKeychain for PassphraseKeychain<P>
where
    P: PassphraseProvider,
{
    fn store_identity(
        &self,
        crypto: &Crypto,
        request: &KeychainRequest,
        identity: &Identity,
    ) -> Result<KeychainIdentityRef> {
        if request.user_id != *identity.user_id() {
            return Err(KeychainError::InvalidIdentity {
                user_id: request.user_id.clone(),
            });
        }
        let local = local_identity_from_identity(identity);
        let sealed = seal_local_identity(
            &self.passphrase_provider.request_new_passphrase(request)?,
            &request.trusted_root,
            identity.user_id(),
            &local,
        )?;
        let path = self.identity_path(&request.trusted_root, identity.user_id());
        let _lock = acquire_keychain_lock(&self.base_dir, &request.trusted_root)?;
        migrate_root_combined_locked(&self.base_dir, &request.trusted_root)?;
        write_identity_exact(&path, &request.trusted_root, identity.user_id(), &sealed)?;

        let restored = identity_from_local(crypto, &local)?;
        if restored.user_id() != identity.user_id() {
            return Err(KeychainError::InvalidIdentity {
                user_id: identity.user_id().clone(),
            });
        }

        Ok(KeychainIdentityRef {
            backend: "passphrase",
            trusted_root: request.trusted_root.clone(),
            user_id: identity.user_id().clone(),
            path: Some(path),
        })
    }

    fn unlock_identity(&self, crypto: &Crypto, request: &KeychainRequest) -> Result<Identity> {
        let path = self.identity_path(&request.trusted_root, &request.user_id);
        let sealed = {
            let _lock = acquire_keychain_lock(&self.base_dir, &request.trusted_root)?;
            migrate_root_combined_locked(&self.base_dir, &request.trusted_root)?;
            if read_identity_at(&path, &request.trusted_root, &request.user_id)?.is_none() {
                migrate_legacy_user_locked(
                    &self.base_dir,
                    &request.trusted_root,
                    &request.user_id,
                    &self.legacy_identity_path(&request.user_id),
                )?;
            }
            read_identity_at(&path, &request.trusted_root, &request.user_id)?.ok_or_else(|| {
                KeychainError::IdentityNotFound {
                    user_id: request.user_id.clone(),
                }
            })?
        };
        let local = open_local_identity(
            &self.passphrase_provider.request_passphrase(request)?,
            &request.trusted_root,
            &request.user_id,
            &sealed,
        )?;
        identity_from_local(crypto, &local)
    }
}

#[derive(Clone, Debug)]
pub struct ManualIdentityKeychain<P> {
    provider: P,
}

impl<P> ManualIdentityKeychain<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> IdentityKeychain for ManualIdentityKeychain<P>
where
    P: ManualIdentityProvider,
{
    fn store_identity(
        &self,
        _crypto: &Crypto,
        _request: &KeychainRequest,
        identity: &Identity,
    ) -> Result<KeychainIdentityRef> {
        Err(KeychainError::NoKeychainAvailable {
            user_id: identity.user_id().clone(),
        })
    }

    fn unlock_identity(&self, crypto: &Crypto, request: &KeychainRequest) -> Result<Identity> {
        let Some(local) = self.provider.request_identity(request)? else {
            return Err(KeychainError::IdentityNotFound {
                user_id: request.user_id.clone(),
            });
        };
        // No AEAD/AAD on the injected path, so derive the identity and confirm it is the one
        // requested (the seed is authoritative).
        let identity = identity_from_local(crypto, &local)?;
        if identity.user_id() != &request.user_id {
            return Err(KeychainError::InvalidIdentity {
                user_id: request.user_id.clone(),
            });
        }
        Ok(identity)
    }
}

#[derive(Clone, Debug)]
pub struct AutoKeychain<P = StdinPassphraseProvider, M = NoManualIdentityProvider> {
    passphrase: PassphraseKeychain<P>,
    manual: ManualIdentityKeychain<M>,
}

impl AutoKeychain<StdinPassphraseProvider, NoManualIdentityProvider> {
    pub fn default_interactive() -> Result<Self> {
        Ok(Self::new(
            PassphraseKeychain::new(
                PassphraseKeychain::<StdinPassphraseProvider>::default_base_dir()?,
                StdinPassphraseProvider,
            ),
            NoManualIdentityProvider,
        ))
    }
}

impl<P, M> AutoKeychain<P, M> {
    pub fn new(passphrase: PassphraseKeychain<P>, manual_provider: M) -> Self {
        Self {
            passphrase,
            manual: ManualIdentityKeychain::new(manual_provider),
        }
    }
}

impl<P, M> IdentityKeychain for AutoKeychain<P, M>
where
    P: PassphraseProvider,
    M: ManualIdentityProvider,
{
    fn store_identity(
        &self,
        crypto: &Crypto,
        request: &KeychainRequest,
        identity: &Identity,
    ) -> Result<KeychainIdentityRef> {
        self.passphrase.store_identity(crypto, request, identity)
    }

    fn unlock_identity(&self, crypto: &Crypto, request: &KeychainRequest) -> Result<Identity> {
        match self.passphrase.unlock_identity(crypto, request) {
            Ok(identity) => return Ok(identity),
            Err(KeychainError::IdentityNotFound { .. }) => {}
            Err(error) => return Err(error),
        }

        match self.manual.unlock_identity(crypto, request) {
            Ok(identity) => Ok(identity),
            Err(KeychainError::IdentityNotFound { .. }) => {
                Err(KeychainError::NoKeychainAvailable {
                    user_id: request.user_id.clone(),
                })
            }
            Err(error) => Err(error),
        }
    }
}

/// On-disk keychain: an outer version envelope wrapping a canonical set of
/// records, mirroring the state store. Each record is wrapped in `Evolving` so a
/// newer binary's record kinds survive a rewrite by an older one byte-for-byte
/// (see the `keychain_preserves_unknown_records_byte_for_byte` test). Records may
/// carry encrypted data — today the only kind is an AEAD-sealed identity.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum KeychainStore {
    #[cord(index = 0)]
    V1(KeychainStoreV1),
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
struct KeychainStoreV1 {
    /// A [`cord::Set`], so cord canonicalizes the file (sorts + rejects duplicates
    /// on serialize, rejects non-canonical input on deserialize) for us.
    records: cord::Set<cord::Evolving<KeychainRecordV1>>,
}

/// One keychain record. Variants are added additively at new indices; an older
/// binary preserves unknown ones as `Evolving::Unknown` rather than dropping them.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
enum KeychainRecordV1 {
    #[cord(index = 0)]
    Identity(SealedIdentityV1),
    #[cord(index = 1)]
    CurrentUser(CurrentUserV1),
}

/// The vault's default identity on this machine — which user unlock flows and acting-user
/// resolution select when none is named explicitly. A plaintext *selector*, not a gate:
/// the real gate is each sealed identity's passphrase, and unlock prompts name the
/// identity (via `handle`) so a tampered selection is visible rather than silent. At most
/// one per keychain; writes replace it.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CurrentUserV1 {
    pub user_id: UserId,
    /// Display label captured at selection time (the user's handle, when one existed).
    /// Names the identity in prompts; never consulted for resolution — the `user_id` is.
    pub handle: Option<String>,
}

/// An AEAD-sealed identity. The cleartext fields locate and bind the ciphertext
/// (they form its AAD); the `master_seed` lives only inside `ciphertext`. The
/// format version is carried structurally by the enclosing enums, so there is no
/// `domain` tag — substitution is still defeated by binding `trusted_root`/`user`
/// into the AAD.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
struct SealedIdentityV1 {
    // `user_id` is the plaintext lookup key (find_sealed_identity matches on it). The
    // signing/HPKE public keys are NOT stored: they derive from the sealed `master_seed`
    // (`UserId = H(signing‖hpke)`), so storing them would be redundant. `kdf` is kept so
    // password-strength params can be raised per-identity (re-seal on next unlock).
    trusted_root: HashValue,
    user_id: UserId,
    kdf: KdfParamsV1,
    salt: Bytes,
    nonce: Bytes,
    ciphertext: Bytes,
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
struct KdfParamsV1 {
    algorithm: String,
    memory_cost_kib: u32,
    iterations: u32,
    parallelism: u32,
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum IdentityStore {
    #[cord(index = 0)]
    V1(SealedIdentityV1),
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum CurrentUserStore {
    #[cord(index = 0)]
    V1(CurrentUserV1),
}

/// The AEAD associated data for a sealed identity: only the context the key derivation does
/// **not** already enforce. `salt`/`kdf` feed the passphrase-derived key (tampering yields a
/// wrong key → AEAD failure), the public keys derive from the sealed seed, and there is no
/// `domain` (the key is single-purpose, so there is no other context to separate from). That
/// leaves `trusted_root` (anti-transplant across vaults) and `user_id` (anti-relabel).
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
struct SealedIdentityAadV1 {
    trusted_root: HashValue,
    user_id: UserId,
}

/// The keychain file's leading magic, so the file identifies itself to humans and tools
/// before any cord parsing — the keychain counterpart of the vault's `thorax-vault\0`
/// prefix. Not a version field: versions live in the `KeychainStore` enum behind it.
pub const KEYCHAIN_MAGIC: &[u8] = b"thorax-keychain\0";
pub const IDENTITY_MAGIC: &[u8] = b"thorax-identity\0";
pub const CURRENT_USER_MAGIC: &[u8] = b"thorax-current-user\0";

/// Decode the keychain file into its record set, preserving unknown records. The
/// `cord::Set` deserializer rejects non-canonical input.
fn decode_keychain_records(bytes: &[u8]) -> Result<cord::Set<cord::Evolving<KeychainRecordV1>>> {
    let Some(payload) = bytes.strip_prefix(KEYCHAIN_MAGIC) else {
        return Err(cord::CordError::ValidationError(
            "not a thorax keychain file (missing magic prefix)",
        )
        .into());
    };
    let KeychainStore::V1(v1) = cord::deserialize(payload)?;
    Ok(v1.records)
}

/// Serialize the record set into a versioned `KeychainStore`; the `cord::Set`
/// field canonicalizes (sorts + rejects duplicates) on serialize.
fn encode_keychain_records(
    records: cord::Set<cord::Evolving<KeychainRecordV1>>,
) -> Result<Vec<u8>> {
    let payload = cord::serialize(&KeychainStore::V1(KeychainStoreV1 { records }))?;
    let mut bytes = Vec::with_capacity(KEYCHAIN_MAGIC.len() + payload.len());
    bytes.extend_from_slice(KEYCHAIN_MAGIC);
    bytes.extend(payload);
    Ok(bytes)
}

/// Read a keychain file into its record set; a missing file is an empty set.
fn read_keychain_records_at(path: &Path) -> Result<cord::Set<cord::Evolving<KeychainRecordV1>>> {
    match read_file_bounded(path, MAX_LEGACY_KEYCHAIN_BYTES) {
        Ok(bytes) => decode_keychain_records(&bytes),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(cord::Set::from(Vec::new()))
        }
        Err(source) => Err(KeychainError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn encode_identity(sealed: &SealedIdentityV1) -> Result<Vec<u8>> {
    let payload = cord::serialize(&IdentityStore::V1(sealed.clone()))?;
    let mut bytes = Vec::with_capacity(IDENTITY_MAGIC.len() + payload.len());
    bytes.extend_from_slice(IDENTITY_MAGIC);
    bytes.extend(payload);
    Ok(bytes)
}

fn decode_identity(path: &Path, bytes: &[u8]) -> Result<SealedIdentityV1> {
    let payload = bytes
        .strip_prefix(IDENTITY_MAGIC)
        .ok_or_else(|| KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "missing identity magic prefix",
        })?;
    let IdentityStore::V1(sealed) = cord::deserialize(payload)?;
    Ok(sealed)
}

fn encode_current_user(current: &CurrentUserV1) -> Result<Vec<u8>> {
    let payload = cord::serialize(&CurrentUserStore::V1(current.clone()))?;
    let mut bytes = Vec::with_capacity(CURRENT_USER_MAGIC.len() + payload.len());
    bytes.extend_from_slice(CURRENT_USER_MAGIC);
    bytes.extend(payload);
    Ok(bytes)
}

fn decode_current_user(path: &Path, bytes: &[u8]) -> Result<CurrentUserV1> {
    let payload =
        bytes
            .strip_prefix(CURRENT_USER_MAGIC)
            .ok_or_else(|| KeychainError::InvalidFile {
                path: path.to_path_buf(),
                reason: "missing current-user magic prefix",
            })?;
    let CurrentUserStore::V1(current) = cord::deserialize(payload)?;
    Ok(current)
}

fn read_identity_at(
    path: &Path,
    trusted_root: &HashValue,
    user: &UserId,
) -> Result<Option<SealedIdentityV1>> {
    let bytes = match read_file_bounded(path, MAX_IDENTITY_BYTES) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(KeychainError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    let sealed = decode_identity(path, &bytes)?;
    if &sealed.trusted_root != trusted_root || &sealed.user_id != user {
        return Err(KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "identity does not match its root and user path",
        });
    }
    Ok(Some(sealed))
}

fn read_current_user_at(path: &Path) -> Result<Option<CurrentUserV1>> {
    let bytes = match read_file_bounded(path, MAX_CURRENT_USER_BYTES) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(KeychainError::Io {
                path: path.to_path_buf(),
                source,
            })
        }
    };
    Ok(Some(decode_current_user(path, &bytes)?))
}

fn write_identity_exact(
    path: &Path,
    trusted_root: &HashValue,
    user: &UserId,
    sealed: &SealedIdentityV1,
) -> Result<()> {
    if &sealed.trusted_root != trusted_root || &sealed.user_id != user {
        return Err(KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "identity does not match its root and user path",
        });
    }
    let bytes = encode_identity(sealed)?;
    if bytes.len() > MAX_IDENTITY_BYTES {
        return Err(KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "identity exceeds the supported size",
        });
    }
    write_private_atomic(path, &bytes)?;
    if read_identity_at(path, trusted_root, user)?.as_ref() != Some(sealed) {
        return Err(KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "identity write verification failed",
        });
    }
    Ok(())
}

fn write_current_user_exact(path: &Path, current: &CurrentUserV1) -> Result<()> {
    let bytes = encode_current_user(current)?;
    if bytes.len() > MAX_CURRENT_USER_BYTES {
        return Err(KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "current-user selector exceeds the supported size",
        });
    }
    write_private_atomic(path, &bytes)?;
    if read_current_user_at(path)?.as_ref() != Some(current) {
        return Err(KeychainError::InvalidFile {
            path: path.to_path_buf(),
            reason: "current-user write verification failed",
        });
    }
    Ok(())
}

struct KeychainLock {
    file: File,
}

impl Drop for KeychainLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn acquire_keychain_lock(base_dir: &Path, trusted_root: &HashValue) -> Result<KeychainLock> {
    acquire_lock_at(&root_keychain_dir(base_dir, trusted_root).join(KEYCHAIN_LOCK_FILE))
}

fn acquire_lock_at(path: &Path) -> Result<KeychainLock> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_private_dir_all(parent)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|source| KeychainError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let started = Instant::now();
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(KeychainLock { file }),
            Err(source) if source.kind() == std::io::ErrorKind::WouldBlock => {
                if started.elapsed() >= LOCK_WAIT {
                    return Err(KeychainError::LockTimeout(path.to_path_buf()));
                }
                thread::sleep(LOCK_POLL);
            }
            Err(source) => {
                return Err(KeychainError::Io {
                    path: path.to_path_buf(),
                    source,
                })
            }
        }
    }
}

fn create_private_dir_all(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| KeychainError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |source| KeychainError::Io {
                path: path.to_path_buf(),
                source,
            },
        )?;
    }
    Ok(())
}

fn migrate_root_combined_locked(base_dir: &Path, trusted_root: &HashValue) -> Result<()> {
    #[allow(deprecated)]
    let source = keychain_path(base_dir, trusted_root);
    if !path_present_no_follow(&source)? {
        return Ok(());
    }
    let records = read_keychain_records_at(&source)?;
    if records.iter().any(cord::Evolving::is_unknown) {
        return Err(KeychainError::InvalidFile {
            path: source,
            reason: "combined keychain has unknown records with no safe split destination",
        });
    }

    let mut identities = Vec::new();
    let mut current = None;
    for record in &records {
        match record {
            cord::Evolving::Known(KeychainRecordV1::Identity(sealed)) => {
                if &sealed.trusted_root != trusted_root {
                    return Err(KeychainError::InvalidFile {
                        path: source,
                        reason: "combined keychain contains an identity for another root",
                    });
                }
                identities.push(sealed.clone());
            }
            cord::Evolving::Known(KeychainRecordV1::CurrentUser(candidate)) => {
                if current.replace(candidate.clone()).is_some() {
                    return Err(KeychainError::InvalidFile {
                        path: source,
                        reason: "combined keychain contains multiple current-user selectors",
                    });
                }
            }
            cord::Evolving::Unknown(_) => unreachable!("unknown records rejected above"),
        }
    }

    for sealed in &identities {
        let path = identity_path(base_dir, trusted_root, &sealed.user_id);
        match read_identity_at(&path, trusted_root, &sealed.user_id)? {
            None => write_identity_exact(&path, trusted_root, &sealed.user_id, sealed)?,
            Some(existing) if existing == *sealed => {}
            Some(_) => {
                return Err(KeychainError::InvalidFile {
                    path,
                    reason: "split identity conflicts with the combined keychain",
                })
            }
        }
    }
    if let Some(current) = &current {
        let path = current_user_path(base_dir, trusted_root);
        match read_current_user_at(&path)? {
            None => write_current_user_exact(&path, current)?,
            Some(existing) if existing == *current => {}
            Some(_) => {
                return Err(KeychainError::InvalidFile {
                    path,
                    reason: "split current-user selector conflicts with the combined keychain",
                })
            }
        }
    }
    for sealed in &identities {
        let path = identity_path(base_dir, trusted_root, &sealed.user_id);
        if read_identity_at(&path, trusted_root, &sealed.user_id)?.as_ref() != Some(sealed) {
            return Err(KeychainError::InvalidFile {
                path,
                reason: "split identity migration verification failed",
            });
        }
    }
    if let Some(current) = &current {
        let path = current_user_path(base_dir, trusted_root);
        if read_current_user_at(&path)?.as_ref() != Some(current) {
            return Err(KeychainError::InvalidFile {
                path,
                reason: "split current-user migration verification failed",
            });
        }
    }
    remove_file_durable(&source)?;
    Ok(())
}

fn migrate_legacy_user_locked(
    base_dir: &Path,
    trusted_root: &HashValue,
    _requested_user: &UserId,
    source: &Path,
) -> Result<()> {
    if !path_present_no_follow(source)? {
        return Ok(());
    }
    let lock_path = source
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(KEYCHAIN_LOCK_FILE);
    let _legacy_lock = acquire_lock_at(&lock_path)?;
    let records = read_keychain_records_at(source)?;
    let migrating: Vec<_> = records
        .iter()
        .filter_map(|record| match record {
            cord::Evolving::Known(KeychainRecordV1::Identity(sealed))
                if &sealed.trusted_root == trusted_root =>
            {
                Some(sealed.clone())
            }
            _ => None,
        })
        .collect();
    for sealed in &migrating {
        let path = identity_path(base_dir, trusted_root, &sealed.user_id);
        match read_identity_at(&path, trusted_root, &sealed.user_id)? {
            None => write_identity_exact(&path, trusted_root, &sealed.user_id, sealed)?,
            Some(existing) if existing == *sealed => {}
            Some(_) => {
                return Err(KeychainError::InvalidFile {
                    path,
                    reason: "split identity conflicts with the legacy user keychain",
                })
            }
        }
    }
    if migrating.is_empty() {
        return Ok(());
    }
    let remaining: cord::Set<_> = records
        .into_iter()
        .filter(|record| {
            !matches!(
                record,
                cord::Evolving::Known(KeychainRecordV1::Identity(sealed))
                    if &sealed.trusted_root == trusted_root
            )
        })
        .collect();
    if remaining.is_empty() {
        remove_file_durable(source)?;
    } else {
        let bytes = encode_keychain_records(remaining.clone())?;
        write_private_atomic(source, &bytes)?;
        if read_keychain_records_at(source)? != remaining {
            return Err(KeychainError::InvalidFile {
                path: source.to_path_buf(),
                reason: "legacy keychain rewrite verification failed",
            });
        }
    }
    Ok(())
}

fn path_present_no_follow(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(KeychainError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// The vault's [`CurrentUserV1`] selection, if one is recorded in
/// `<base_dir>/<root>/current-user.cord`. Plaintext read — no passphrase involved.
pub fn read_current_user(
    base_dir: &Path,
    trusted_root: &HashValue,
) -> Result<Option<CurrentUserV1>> {
    let _lock = acquire_keychain_lock(base_dir, trusted_root)?;
    migrate_root_combined_locked(base_dir, trusted_root)?;
    read_current_user_at(&current_user_path(base_dir, trusted_root))
}

/// Set (or clear, with `None`) the vault's [`CurrentUserV1`] selection without reading or
/// rewriting any identity file.
pub fn write_current_user(
    base_dir: &Path,
    trusted_root: &HashValue,
    current: Option<CurrentUserV1>,
) -> Result<()> {
    let _lock = acquire_keychain_lock(base_dir, trusted_root)?;
    migrate_root_combined_locked(base_dir, trusted_root)?;
    let path = current_user_path(base_dir, trusted_root);
    if let Some(current) = current {
        write_current_user_exact(&path, &current)?;
    } else {
        remove_file_durable(&path)?;
    }
    Ok(())
}

#[cfg(test)]
fn find_sealed_identity<'a>(
    records: &'a cord::Set<cord::Evolving<KeychainRecordV1>>,
    user: &UserId,
) -> Option<&'a SealedIdentityV1> {
    records.iter().find_map(|record| match record {
        cord::Evolving::Known(KeychainRecordV1::Identity(sealed)) if &sealed.user_id == user => {
            Some(sealed)
        }
        _ => None,
    })
}

fn local_identity_from_identity(identity: &Identity) -> LocalIdentityV1 {
    LocalIdentityV1 {
        master_seed: identity.master_seed().to_vec(),
    }
}

fn identity_from_local(crypto: &Crypto, local: &LocalIdentityV1) -> Result<Identity> {
    // The seed is the whole identity; the keys and user id derive from it.
    Ok(Identity::from_master_seed(crypto, &local.master_seed)?)
}

fn seal_local_identity(
    passphrase: &str,
    trusted_root: &HashValue,
    user_id: &UserId,
    local: &LocalIdentityV1,
) -> Result<SealedIdentityV1> {
    let mut salt = vec![0_u8; PASSPHRASE_SALT_LEN];
    let mut nonce = vec![0_u8; PASSPHRASE_NONCE_LEN];
    let mut rng = StdRng::from_os_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);
    let kdf = default_kdf_params();
    let plaintext = Zeroizing::new(cord::serialize(local)?);
    let aad = envelope_aad_bytes(trusted_root, user_id)?;
    let mut key = derive_passphrase_key(passphrase, &salt, &kdf)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher.encrypt(
        Nonce::from_slice(&nonce),
        Payload {
            msg: &plaintext,
            aad: &aad,
        },
    );
    key.zeroize();
    let ciphertext = ciphertext.map_err(|_| KeychainError::UnlockFailed)?;

    Ok(SealedIdentityV1 {
        trusted_root: trusted_root.clone(),
        user_id: user_id.clone(),
        kdf,
        salt,
        nonce,
        ciphertext,
    })
}

fn open_local_identity(
    passphrase: &str,
    trusted_root: &HashValue,
    user: &UserId,
    envelope: &SealedIdentityV1,
) -> Result<LocalIdentityV1> {
    if &envelope.trusted_root != trusted_root
        || &envelope.user_id != user
        || envelope.nonce.len() != PASSPHRASE_NONCE_LEN
    {
        return Err(KeychainError::InvalidIdentity {
            user_id: user.clone(),
        });
    }

    let aad = envelope_aad_bytes(&envelope.trusted_root, &envelope.user_id)?;
    let mut key = derive_passphrase_key(passphrase, &envelope.salt, &envelope.kdf)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher.decrypt(
        Nonce::from_slice(&envelope.nonce),
        Payload {
            msg: &envelope.ciphertext,
            aad: &aad,
        },
    );
    key.zeroize();
    let plaintext = Zeroizing::new(plaintext.map_err(|_| KeychainError::UnlockFailed)?);

    // The AAD binds `user_id`, so a successful decrypt already proves this seed was sealed for
    // the user we looked up — no separate field to cross-check.
    let local: LocalIdentityV1 = cord::deserialize(&plaintext)?;
    Ok(local)
}

fn default_kdf_params() -> KdfParamsV1 {
    KdfParamsV1 {
        algorithm: "argon2id-v1.3".to_string(),
        memory_cost_kib: ARGON2_MEMORY_COST_KIB,
        iterations: ARGON2_ITERATIONS,
        parallelism: ARGON2_PARALLELISM,
    }
}

fn derive_passphrase_key(
    passphrase: &str,
    salt: &[u8],
    kdf: &KdfParamsV1,
) -> Result<[u8; PASSPHRASE_KEY_LEN]> {
    if kdf.algorithm != "argon2id-v1.3"
        || salt.len() != PASSPHRASE_SALT_LEN
        || !(MIN_ARGON2_MEMORY_COST_KIB..=MAX_ARGON2_MEMORY_COST_KIB).contains(&kdf.memory_cost_kib)
        || !(1..=MAX_ARGON2_ITERATIONS).contains(&kdf.iterations)
        || !(1..=MAX_ARGON2_PARALLELISM).contains(&kdf.parallelism)
    {
        return Err(KeychainError::InvalidKdfParameters);
    }
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(PASSPHRASE_KEY_LEN),
    )
    .map_err(|error| KeychainError::Argon2(error.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; PASSPHRASE_KEY_LEN];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| KeychainError::Argon2(error.to_string()))?;
    Ok(key)
}

fn envelope_aad_bytes(trusted_root: &HashValue, user: &UserId) -> Result<Bytes> {
    Ok(cord::serialize(&SealedIdentityAadV1 {
        trusted_root: trusted_root.clone(),
        user_id: user.clone(),
    })?)
}

fn action_for_prompt(purpose: &KeyUsePurpose) -> String {
    match purpose {
        KeyUsePurpose::DecryptSecret { selector, sink } => {
            format!(
                "reveal {} to {}",
                selector_for_prompt(selector),
                sink_for_prompt(sink)
            )
        }
        KeyUsePurpose::RunWithSecrets {
            selections,
            command,
        } => format!(
            "run {} with {}",
            command_for_prompt(command),
            selection_list_for_prompt(selections)
        ),
        KeyUsePurpose::SignSecretWrite { selector } => {
            format!("set {}", selector_for_prompt(selector))
        }
        KeyUsePurpose::MoveSecret { from, to } => {
            format!(
                "move {} to {}",
                selector_for_prompt(from),
                selector_for_prompt(to)
            )
        }
        KeyUsePurpose::SignSecretDelete { selector } => {
            format!("delete {}", selector_for_prompt(selector))
        }
        KeyUsePurpose::SignAdminChange { summary } => summary.clone(),
        KeyUsePurpose::StoreIdentity => "store this identity".to_string(),
        KeyUsePurpose::InspectVault => "verify and inspect the vault".to_string(),
    }
}

fn sink_for_prompt(sink: &OutputSink) -> String {
    match sink {
        OutputSink::Stdout => "stdout".to_string(),
        OutputSink::File(path) => format!("file {}", path.display()),
        OutputSink::Clipboard => "clipboard".to_string(),
        OutputSink::ChildProcess { command } => {
            format!("child process {}", command_for_prompt(command))
        }
        OutputSink::Sdk { caller } => format!("SDK caller {caller}"),
        OutputSink::Other(description) => description.clone(),
    }
}

fn selection_list_for_prompt(selections: &[String]) -> String {
    match selections {
        [] => "no selectors".to_string(),
        [selection] => selection.clone(),
        selections => format!("{} selectors", selections.len()),
    }
}

/// One selector as the unlock prompts display it (`app/prod{env=prod}`). Public so callers
/// building [`KeyUsePurpose::RunWithSecrets`] from resolved selectors render identically.
pub fn selector_display(selector: &SecretSelectorV1) -> String {
    selector_for_prompt(selector)
}

fn selector_for_prompt(selector: &SecretSelectorV1) -> String {
    let tuple = if selector.tuple.is_empty() {
        "<root>".to_string()
    } else {
        selector.tuple.join("/")
    };
    if selector.labels.is_empty() {
        tuple
    } else {
        let labels = selector
            .labels
            .iter()
            .map(|label| format!("{}={}", label.key, label.value))
            .collect::<Vec<_>>()
            .join(",");
        format!("{tuple}{{{labels}}}")
    }
}

fn command_for_prompt(command: &[String]) -> String {
    if command.is_empty() {
        "<empty command>".to_string()
    } else {
        command.join(" ")
    }
}

fn vault_for_prompt(request: &KeychainRequest) -> String {
    if let Some(label) = request
        .vault_label
        .as_deref()
        .filter(|label| !label.is_empty())
    {
        return label.to_string();
    }
    if matches!(request.purpose, KeyUsePurpose::StoreIdentity) {
        if let Some(name) = request
            .workspace_root
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
        {
            return name.to_string();
        }
    }
    short_hex(&hex_bytes(&request.trusted_root.0)).to_string()
}

fn user_for_prompt(request: &KeychainRequest) -> String {
    if let Some(label) = request
        .user_label
        .as_deref()
        .filter(|label| !label.is_empty())
    {
        return label.to_string();
    }
    if matches!(request.purpose, KeyUsePurpose::StoreIdentity) {
        return "this identity".to_string();
    }
    short_hex(&hex_bytes(&(request.user_id.0).0)).to_string()
}

fn short_hex(hex: &str) -> &str {
    hex.get(..8).unwrap_or(hex)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Golden wire-format pin for the keychain file: a sealed identity for the
    /// deterministic master seed 0x07…07, sealed under passphrase "golden fixture"
    /// with fast-but-valid KDF params (8 MiB, 1 iteration), fixed salt 0x01…/nonce
    /// 0x02…, trusted root 0x05…. The companion AAD constant pins the exact AAD bytes the
    /// seal binds (now just `{trusted_root, user_id}`). The sealed plaintext is just the
    /// master seed — the keys and user id derive from it. (Regenerated 2026-06-13 when the
    /// sealed plaintext and AAD were trimmed to essentials.) These tests only fail if the
    /// wire/AAD layout changes.
    const KEYCHAIN_GOLDEN_HEX: &str = "74686f7261782d6b6579636861696e000000000000000001000000c50000000000000020050505050505050505050505050505050505050505050505050505050505050500000020e0f447927df8b70d408d64a81db31444ebd6d7e20589aec941987edcd406e2d60000000d6172676f6e3269642d76312e3300002000000000010000000100000010010101010101010101010101010101010000000c02020202020202020202020200000034e05499bed9f4550e6f0a8fa5d4e29927c128723c3805872ba0e5456e23c15f45e8c49dc77cbf5067bd8f98ce2a9187997d0c605c";
    const AAD_GOLDEN_HEX: &str = "00000020050505050505050505050505050505050505050505050505050505050505050500000020e0f447927df8b70d408d64a81db31444ebd6d7e20589aec941987edcd406e2d6";

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn keychain_wire_format_matches_golden_bytes_and_still_unlocks() {
        let crypto = Crypto;
        let identity = Identity::from_master_seed(&crypto, &[7_u8; 32]).unwrap();
        let trusted_root = HashValue(vec![5; 32]);
        let written = hex_bytes(KEYCHAIN_GOLDEN_HEX);

        // The pinned file still parses, the identity is findable, and the sealed
        // envelope still decrypts — proving the AAD the seal bound is unchanged.
        let records = decode_keychain_records(&written).unwrap();
        let sealed = find_sealed_identity(&records, identity.user_id()).unwrap();
        let local =
            open_local_identity("golden fixture", &trusted_root, identity.user_id(), sealed)
                .unwrap();
        assert_eq!(local.master_seed, vec![7_u8; 32]);

        // The exact AAD bytes are pinned independently of the decrypt above.
        let aad = envelope_aad_bytes(&sealed.trusted_root, &sealed.user_id).unwrap();
        assert_eq!(aad, hex_bytes(AAD_GOLDEN_HEX));

        // Rewriting reproduces the file byte-for-byte.
        let rewritten = encode_keychain_records(records).unwrap();
        assert_eq!(written, rewritten);
    }

    #[test]
    fn keychain_preserves_unknown_records_byte_for_byte() {
        // Simulate a newer binary: a record kind at an index this build's
        // `KeychainRecordV1` does not define, alongside a known identity record.
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
        enum KeychainRecordFuture {
            #[cord(index = 0)]
            Identity(SealedIdentityV1),
            #[cord(index = 2)]
            DeviceBinding { nonce: Bytes },
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        struct StoreFutureV1 {
            records: cord::Set<cord::Evolving<KeychainRecordFuture>>,
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        enum StoreFuture {
            #[cord(index = 0)]
            V1(StoreFutureV1),
        }

        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let local = local_identity_from_identity(&identity);
        let sealed =
            seal_local_identity("pw", &HashValue(vec![5; 32]), identity.user_id(), &local).unwrap();

        // Newer binary writes canonically — the `cord::Set` sorts for us.
        let future = cord::Set::from(vec![
            cord::Evolving::new(KeychainRecordFuture::Identity(sealed)),
            cord::Evolving::new(KeychainRecordFuture::DeviceBinding {
                nonce: vec![1, 2, 3, 4],
            }),
        ]);
        let mut written = KEYCHAIN_MAGIC.to_vec();
        written
            .extend(cord::serialize(&StoreFuture::V1(StoreFutureV1 { records: future })).unwrap());

        // This build reads it: the identity is known and findable, the future-only
        // record is carried opaquely — none are dropped.
        let records = decode_keychain_records(&written).unwrap();
        assert!(find_sealed_identity(&records, identity.user_id()).is_some());
        assert_eq!(records.iter().filter(|r| r.is_unknown()).count(), 1);

        // Rewriting must reproduce the newer binary's bytes exactly — the keychain
        // loses nothing, just like the state ratchet.
        let rewritten = encode_keychain_records(records).unwrap();
        assert_eq!(written, rewritten);
    }

    #[test]
    fn passphrase_keychain_round_trips_identity() {
        let fixture = Fixture::new("passphrase-roundtrip");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![7; 32]);
        let keychain = PassphraseKeychain::new(
            fixture.path.join("keychain"),
            StaticPassphraseProvider::new("correct horse"),
        );

        let stored = keychain
            .store_identity(
                &crypto,
                &store_request(&fixture.paths, &root, identity.user_id()),
                &identity,
            )
            .unwrap();
        let request = request(&fixture.paths, &root, identity.user_id());
        let unlocked = keychain.unlock_identity(&crypto, &request).unwrap();

        assert_eq!(stored.backend, "passphrase");
        assert_eq!(unlocked.user_id(), identity.user_id());
        assert_eq!(unlocked.signing_public_key(), identity.signing_public_key());
        assert_eq!(unlocked.hpke_public_key(), identity.hpke_public_key());
    }

    #[test]
    fn concurrent_identity_writes_do_not_overwrite_each_other() {
        let fixture = Fixture::new("concurrent-identity-writes");
        let crypto = Crypto;
        let first = Identity::generate(&crypto).unwrap();
        let second = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![8; 32]);
        let base = fixture.path.join("keychain");
        std::thread::scope(|scope| {
            for identity in [&first, &second] {
                let base = base.clone();
                let paths = fixture.paths.clone();
                let root = root.clone();
                scope.spawn(move || {
                    PassphraseKeychain::new(base, StaticPassphraseProvider::new("pw"))
                        .store_identity(
                            &crypto,
                            &store_request(&paths, &root, identity.user_id()),
                            identity,
                        )
                        .unwrap();
                });
            }
        });
        let keychain = PassphraseKeychain::new(&base, StaticPassphraseProvider::new("pw"));
        for identity in [&first, &second] {
            assert!(read_identity_at(
                &keychain.identity_path(&root, identity.user_id()),
                &root,
                identity.user_id(),
            )
            .unwrap()
            .is_some());
        }
    }

    #[test]
    fn attacker_controlled_kdf_parameters_are_bounded_before_argon2_runs() {
        let salt = [0_u8; PASSPHRASE_SALT_LEN];
        let mut params = default_kdf_params();
        params.memory_cost_kib = MAX_ARGON2_MEMORY_COST_KIB + 1;
        assert!(matches!(
            derive_passphrase_key("pw", &salt, &params),
            Err(KeychainError::InvalidKdfParameters)
        ));
        params = default_kdf_params();
        params.iterations = MAX_ARGON2_ITERATIONS + 1;
        assert!(matches!(
            derive_passphrase_key("pw", &salt, &params),
            Err(KeychainError::InvalidKdfParameters)
        ));
        params = default_kdf_params();
        params.parallelism = MAX_ARGON2_PARALLELISM + 1;
        assert!(matches!(
            derive_passphrase_key("pw", &salt, &params),
            Err(KeychainError::InvalidKdfParameters)
        ));
    }

    #[test]
    fn passphrase_keychain_rejects_wrong_passphrase() {
        let fixture = Fixture::new("passphrase-wrong");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![9; 32]);
        let keychain_dir = fixture.path.join("keychain");
        PassphraseKeychain::new(&keychain_dir, StaticPassphraseProvider::new("right"))
            .store_identity(
                &crypto,
                &store_request(&fixture.paths, &root, identity.user_id()),
                &identity,
            )
            .unwrap();
        let wrong = PassphraseKeychain::new(keychain_dir, StaticPassphraseProvider::new("wrong"));

        let error = wrong
            .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
            .unwrap_err();

        assert!(matches!(error, KeychainError::UnlockFailed));
    }

    #[test]
    fn auto_keychain_does_not_fall_back_to_env_when_safe_keychain_fails() {
        let fixture = Fixture::new("auto-no-env-fallback");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![11; 32]);
        let keychain_dir = fixture.path.join("keychain");
        PassphraseKeychain::new(&keychain_dir, StaticPassphraseProvider::new("right"))
            .store_identity(
                &crypto,
                &store_request(&fixture.paths, &root, identity.user_id()),
                &identity,
            )
            .unwrap();
        let auto = AutoKeychain::new(
            PassphraseKeychain::new(keychain_dir, StaticPassphraseProvider::new("wrong")),
            NoManualIdentityProvider,
        );

        let error = auto
            .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
            .unwrap_err();

        assert!(matches!(error, KeychainError::UnlockFailed));
    }

    #[test]
    fn auto_keychain_uses_manual_identity_when_passphrase_keychain_is_missing() {
        let fixture = Fixture::new("auto-manual-fallback");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![13; 32]);
        let auto = AutoKeychain::new(
            PassphraseKeychain::new(
                fixture.path.join("missing-keychain"),
                StaticPassphraseProvider::new("unused"),
            ),
            StaticManualIdentityProvider {
                local: local_identity_from_identity(&identity),
            },
        );

        let unlocked = auto
            .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
            .unwrap();

        assert_eq!(unlocked.user_id(), identity.user_id());
        assert_eq!(unlocked.signing_public_key(), identity.signing_public_key());
        assert_eq!(unlocked.hpke_public_key(), identity.hpke_public_key());
    }

    #[test]
    fn current_user_round_trips_and_replaces_alongside_identities() {
        let fixture = Fixture::new("current-user");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![21; 32]);
        let base = fixture.path.join("keychain");
        let keychain = PassphraseKeychain::new(&base, StaticPassphraseProvider::new("pw"));
        keychain
            .store_identity(
                &crypto,
                &store_request(&fixture.paths, &root, identity.user_id()),
                &identity,
            )
            .unwrap();

        assert_eq!(read_current_user(&base, &root).unwrap(), None);

        let identity_path = keychain.identity_path(&root, identity.user_id());
        let identity_bytes = fs::read(&identity_path).unwrap();

        let first = CurrentUserV1 {
            user_id: identity.user_id().clone(),
            handle: Some("alice".to_string()),
        };
        write_current_user(&base, &root, Some(first.clone())).unwrap();
        assert_eq!(read_current_user(&base, &root).unwrap(), Some(first));

        // A second write replaces the selection rather than accumulating records, and the
        // sealed identity rides through every rewrite untouched.
        let second = CurrentUserV1 {
            user_id: identity.user_id().clone(),
            handle: None,
        };
        write_current_user(&base, &root, Some(second.clone())).unwrap();
        assert_eq!(read_current_user(&base, &root).unwrap(), Some(second));
        assert_eq!(fs::read(&identity_path).unwrap(), identity_bytes);
        let unlocked = keychain
            .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
            .unwrap();
        assert_eq!(unlocked.user_id(), identity.user_id());

        write_current_user(&base, &root, None).unwrap();
        assert_eq!(read_current_user(&base, &root).unwrap(), None);
        assert_eq!(fs::read(identity_path).unwrap(), identity_bytes);
    }

    #[test]
    fn corrupt_identity_is_isolated_from_selector_and_other_identities() {
        let fixture = Fixture::new("identity-corruption-isolated");
        let crypto = Crypto;
        let first = Identity::generate(&crypto).unwrap();
        let second = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![22; 32]);
        let base = fixture.path.join("keychain");
        let keychain = PassphraseKeychain::new(&base, StaticPassphraseProvider::new("pw"));
        for identity in [&first, &second] {
            keychain
                .store_identity(
                    &crypto,
                    &store_request(&fixture.paths, &root, identity.user_id()),
                    identity,
                )
                .unwrap();
        }
        let current = CurrentUserV1 {
            user_id: second.user_id().clone(),
            handle: Some("second".into()),
        };
        write_current_user(&base, &root, Some(current.clone())).unwrap();
        write_private_atomic(keychain.identity_path(&root, first.user_id()), b"broken").unwrap();

        assert_eq!(read_current_user(&base, &root).unwrap(), Some(current));
        let unlocked = keychain
            .unlock_identity(&crypto, &request(&fixture.paths, &root, second.user_id()))
            .unwrap();
        assert_eq!(unlocked.user_id(), second.user_id());
    }

    #[test]
    fn combined_root_migration_resumes_from_verified_partial_destinations() {
        let fixture = Fixture::new("root-combined-migration");
        let crypto = Crypto;
        let first = Identity::generate(&crypto).unwrap();
        let second = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![25; 32]);
        let base = fixture.path.join("keychain");
        let keychain = PassphraseKeychain::new(&base, StaticPassphraseProvider::new("pw"));
        let first_sealed = seal_local_identity(
            "pw",
            &root,
            first.user_id(),
            &local_identity_from_identity(&first),
        )
        .unwrap();
        let second_sealed = seal_local_identity(
            "pw",
            &root,
            second.user_id(),
            &local_identity_from_identity(&second),
        )
        .unwrap();
        let current = CurrentUserV1 {
            user_id: second.user_id().clone(),
            handle: Some("second".into()),
        };
        let records = cord::Set::from(vec![
            cord::Evolving::new(KeychainRecordV1::Identity(first_sealed.clone())),
            cord::Evolving::new(KeychainRecordV1::Identity(second_sealed)),
            cord::Evolving::new(KeychainRecordV1::CurrentUser(current.clone())),
        ]);
        #[allow(deprecated)]
        let combined = keychain.keychain_path(&root);
        write_private_atomic(&combined, &encode_keychain_records(records).unwrap()).unwrap();

        // Simulate interruption after the first destination was durably written.
        let first_path = keychain.identity_path(&root, first.user_id());
        write_identity_exact(&first_path, &root, first.user_id(), &first_sealed).unwrap();

        assert_eq!(read_current_user(&base, &root).unwrap(), Some(current));
        assert!(!combined.exists());
        assert!(first_path.exists());
        assert!(keychain.identity_path(&root, second.user_id()).exists());
        for identity in [&first, &second] {
            let unlocked = keychain
                .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
                .unwrap();
            assert_eq!(unlocked.user_id(), identity.user_id());
        }
    }

    #[test]
    fn unknown_combined_record_stops_migration_without_deleting_source() {
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
        enum FutureRecord {
            #[cord(index = 2)]
            DeviceBinding { nonce: Bytes },
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        struct FutureStoreV1 {
            records: cord::Set<cord::Evolving<FutureRecord>>,
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        enum FutureStore {
            #[cord(index = 0)]
            V1(FutureStoreV1),
        }

        let fixture = Fixture::new("unknown-combined-record");
        let root = HashValue(vec![26; 32]);
        let base = fixture.path.join("keychain");
        #[allow(deprecated)]
        let combined = keychain_path(&base, &root);
        let records = cord::Set::from(vec![cord::Evolving::new(FutureRecord::DeviceBinding {
            nonce: vec![1, 2, 3],
        })]);
        let mut bytes = KEYCHAIN_MAGIC.to_vec();
        bytes.extend(cord::serialize(&FutureStore::V1(FutureStoreV1 { records })).unwrap());
        write_private_atomic(&combined, &bytes).unwrap();

        let error = read_current_user(&base, &root).unwrap_err();
        assert!(matches!(error, KeychainError::InvalidFile { .. }));
        assert_eq!(fs::read(&combined).unwrap(), bytes);
    }

    #[test]
    fn conflicting_split_destination_stops_migration_and_preserves_source() {
        let fixture = Fixture::new("conflicting-split-destination");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![27; 32]);
        let base = fixture.path.join("keychain");
        let sealed = seal_local_identity(
            "pw",
            &root,
            identity.user_id(),
            &local_identity_from_identity(&identity),
        )
        .unwrap();
        let records = cord::Set::from(vec![cord::Evolving::new(KeychainRecordV1::Identity(
            sealed,
        ))]);
        #[allow(deprecated)]
        let combined = keychain_path(&base, &root);
        write_private_atomic(&combined, &encode_keychain_records(records).unwrap()).unwrap();

        let conflicting = seal_local_identity(
            "different",
            &root,
            identity.user_id(),
            &local_identity_from_identity(&identity),
        )
        .unwrap();
        let split = identity_path(&base, &root, identity.user_id());
        write_identity_exact(&split, &root, identity.user_id(), &conflicting).unwrap();
        let before = fs::read(&split).unwrap();

        let error = read_current_user(&base, &root).unwrap_err();
        assert!(matches!(error, KeychainError::InvalidFile { .. }));
        assert!(combined.exists());
        assert_eq!(fs::read(split).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn identity_reads_do_not_follow_symlinks() {
        use std::os::unix::fs::symlink;

        let fixture = Fixture::new("identity-symlink");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![28; 32]);
        let base = fixture.path.join("keychain");
        let keychain = PassphraseKeychain::new(&base, StaticPassphraseProvider::new("pw"));
        let path = keychain.identity_path(&root, identity.user_id());
        create_private_dir_all(path.parent().unwrap()).unwrap();
        let target = fixture.path.join("attacker-controlled");
        fs::write(&target, b"not an identity").unwrap();
        symlink(&target, &path).unwrap();

        let error = keychain
            .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
            .unwrap_err();
        assert!(matches!(error, KeychainError::Io { .. }));
    }

    #[test]
    fn unlock_migrates_identities_from_the_legacy_user_keyed_path() {
        let fixture = Fixture::new("legacy-migration");
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![23; 32]);
        let base = fixture.path.join("keychain");
        let keychain = PassphraseKeychain::new(&base, StaticPassphraseProvider::new("pw"));

        // A keychain as the pre-per-root layout wrote it: sealed identity at
        // <base>/<user-hex>/keychain.cord, nothing at the per-root path.
        let local = local_identity_from_identity(&identity);
        let sealed = seal_local_identity("pw", &root, identity.user_id(), &local).unwrap();
        let other_root = HashValue(vec![24; 32]);
        let other_sealed =
            seal_local_identity("pw", &other_root, identity.user_id(), &local).unwrap();
        let records = cord::Set::from(vec![
            cord::Evolving::new(KeychainRecordV1::Identity(sealed)),
            cord::Evolving::new(KeychainRecordV1::Identity(other_sealed)),
        ]);
        let legacy_path = keychain.legacy_identity_path(identity.user_id());
        write_private_atomic(&legacy_path, &encode_keychain_records(records).unwrap()).unwrap();
        assert!(!keychain.identity_path(&root, identity.user_id()).exists());

        // Unlock finds it via the migration fallback and lands it at the per-root path.
        let unlocked = keychain
            .unlock_identity(&crypto, &request(&fixture.paths, &root, identity.user_id()))
            .unwrap();
        assert_eq!(unlocked.user_id(), identity.user_id());
        let migrated_path = keychain.identity_path(&root, identity.user_id());
        assert!(migrated_path.exists());
        assert!(read_identity_at(&migrated_path, &root, identity.user_id())
            .unwrap()
            .is_some());
        // The other root remains in the legacy file until it is migrated in turn.
        assert!(legacy_path.exists());
        let remaining = read_keychain_records_at(&legacy_path).unwrap();
        assert_eq!(remaining.len(), 1);

        // An identity sealed to a *different* root never migrates into this vault's file.
        let unlocked = keychain
            .unlock_identity(
                &crypto,
                &request(&fixture.paths, &other_root, identity.user_id()),
            )
            .unwrap();
        assert_eq!(unlocked.user_id(), identity.user_id());
        assert!(!legacy_path.exists());
    }

    fn request(paths: &WorkspacePaths, root: &HashValue, user: &UserId) -> KeychainRequest {
        KeychainRequest::new(
            paths,
            root.clone(),
            user.clone(),
            KeyUsePurpose::DecryptSecret {
                selector: SecretSelectorV1::tuple(["app", "prod", "db"]),
                sink: OutputSink::Stdout,
            },
        )
    }

    fn store_request(paths: &WorkspacePaths, root: &HashValue, user: &UserId) -> KeychainRequest {
        KeychainRequest::new(
            paths,
            root.clone(),
            user.clone(),
            KeyUsePurpose::StoreIdentity,
        )
    }

    struct Fixture {
        path: PathBuf,
        paths: WorkspacePaths,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = env::temp_dir().join(format!(
                "thorax-keychain-{name}-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            let paths = WorkspacePaths::from_root(path.join("repo"));
            Self { path, paths }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[derive(Clone, Debug)]
    struct StaticManualIdentityProvider {
        local: LocalIdentityV1,
    }

    impl ManualIdentityProvider for StaticManualIdentityProvider {
        fn request_identity(&self, _request: &KeychainRequest) -> Result<Option<LocalIdentityV1>> {
            Ok(Some(self.local.clone()))
        }
    }
}
