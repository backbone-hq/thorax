//! Filesystem and state boundary for Thorax.

mod transaction;

pub use transaction::{
    decode_transaction, encode_transaction, read_transaction, transaction_path,
    write_transaction_atomic, FilePreconditionV1, NativePathV1, TransactionV1,
    MAX_TRANSACTION_BYTES, TRANSACTION_FILE, TRANSACTION_ID_BYTES, TRANSACTION_MAGIC,
};

use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use thorax_core::{
    decode_vault, encode_vault, Bytes, HashValue, Ratchet, RatchetRecordV1, UnknownRatchetRecord,
    UserId, VaultStore,
};

pub const THORAX_DIR: &str = ".thorax";
pub const VAULT_FILE: &str = "vault.cord";
pub const LOCK_FILE: &str = "vault.cord.lock";
pub const RATCHET_FILE: &str = "ratchet.cord";
pub const CACHE_FILE: &str = "cache.cord";
pub const ROOT_STATE_LOCK_FILE: &str = "state.lock";
pub const STATE_DIR_ENV: &str = "THORAX_STATE_DIR";
pub const MAX_RATCHET_BYTES: usize = thorax_core::MAX_VAULT_BYTES;
pub const MAX_VERIFICATION_CACHE_BYTES: usize = 32 * 1024 * 1024;

const LOCK_WAIT: Duration = Duration::from_secs(10);
const LOCK_POLL: Duration = Duration::from_millis(100);

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RatchetSnapshot<Revision> {
    pub ratchet: Ratchet,
    pub revision: Revision,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RatchetCasOutcome<Revision> {
    Stored(RatchetSnapshot<Revision>),
    Conflict,
}

/// Persistence port for rollback state. A backend authenticates and scopes state using
/// its own credential type; compare-and-swap is mandatory so two reconcilers cannot both
/// publish plaintext from divergent watermark histories.
#[allow(async_fn_in_trait)]
pub trait RatchetBackend {
    type Credential;
    type Revision: Clone + Eq + Send;
    type Error;

    async fn load(
        &self,
        trusted_root: &HashValue,
        user_id: &UserId,
        credential: &Self::Credential,
    ) -> std::result::Result<Option<RatchetSnapshot<Self::Revision>>, Self::Error>;

    async fn compare_and_swap(
        &self,
        trusted_root: &HashValue,
        user_id: &UserId,
        credential: &Self::Credential,
        expected_revision: Option<&Self::Revision>,
        ratchet: &Ratchet,
    ) -> std::result::Result<RatchetCasOutcome<Self::Revision>, Self::Error>;
}

/// Existing filesystem behavior behind the persistence port. Files remain root-scoped
/// for compatibility; the user argument is accepted so callers share one backend shape
/// with identity-scoped production stores.
#[derive(Clone, Debug)]
pub struct FileRatchetBackend {
    paths: WorkspacePaths,
}

impl FileRatchetBackend {
    pub fn new(paths: WorkspacePaths) -> Self {
        Self { paths }
    }
}

impl RatchetBackend for FileRatchetBackend {
    type Credential = ();
    type Revision = Vec<u8>;
    type Error = StoreError;

    async fn load(
        &self,
        trusted_root: &HashValue,
        _user_id: &UserId,
        _credential: &Self::Credential,
    ) -> Result<Option<RatchetSnapshot<Self::Revision>>> {
        let _lock = acquire_root_state_shared_lock(&self.paths, trusted_root)?;
        let Some(ratchet) = read_ratchet_for_root(&self.paths, trusted_root)? else {
            return Ok(None);
        };
        let revision = encode_ratchet(&ratchet)?;
        Ok(Some(RatchetSnapshot { ratchet, revision }))
    }

    async fn compare_and_swap(
        &self,
        trusted_root: &HashValue,
        _user_id: &UserId,
        _credential: &Self::Credential,
        expected_revision: Option<&Self::Revision>,
        ratchet: &Ratchet,
    ) -> Result<RatchetCasOutcome<Self::Revision>> {
        if &ratchet.trusted_root != trusted_root {
            return Err(StoreError::TrustRootMismatch {
                stored: ratchet.trusted_root.clone(),
                requested: trusted_root.clone(),
            });
        }
        let _lock = acquire_root_state_lock(&self.paths, trusted_root)?;
        if read_transaction(&self.paths, trusted_root)?.is_some() {
            return Err(StoreError::TransactionPending(transaction_path(
                &self.paths,
                trusted_root,
            )));
        }
        let current = read_ratchet_for_root(&self.paths, trusted_root)?;
        let current_revision = current.as_ref().map(encode_ratchet).transpose()?;
        if current_revision.as_ref() != expected_revision {
            return Ok(RatchetCasOutcome::Conflict);
        }
        write_ratchet_atomic(&self.paths, ratchet)?;
        let revision = encode_ratchet(ratchet)?;
        Ok(RatchetCasOutcome::Stored(RatchetSnapshot {
            ratchet: ratchet.clone(),
            revision,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("vault file is missing at {0}")]
    VaultMissing(PathBuf),
    #[error("vault file {path} is invalid: {source}")]
    InvalidVault {
        path: PathBuf,
        source: thorax_core::CoreError,
    },
    #[error("Cord error: {0}")]
    Cord(#[from] cord::CordError),
    #[error("core error: {0}")]
    Core(#[from] thorax_core::CoreError),
    #[error("workspace not found from {0}")]
    WorkspaceNotFound(PathBuf),
    #[error(
        "ambiguous Thorax workspace from {start}: found nested workspace at {nested} and parent workspace at {parent}; pass an explicit vault path"
    )]
    AmbiguousWorkspace {
        start: PathBuf,
        nested: PathBuf,
        parent: PathBuf,
    },
    #[error("invalid workspace root {0}: missing .thorax directory")]
    MissingThoraxDir(PathBuf),
    #[error("workspace lock is already held at {0}")]
    LockAlreadyHeld(PathBuf),
    #[error("ratchet file {path} is invalid: {source}")]
    InvalidRatchet {
        path: PathBuf,
        source: cord::CordError,
    },
    #[error("transaction file {path} is invalid: {detail}")]
    InvalidTransaction { path: PathBuf, detail: String },
    #[error("a pending transaction at {0} blocks rollback-state writes")]
    TransactionPending(PathBuf),
    #[error("trust root mismatch: file has {stored:?}, requested {requested:?}")]
    TrustRootMismatch {
        stored: HashValue,
        requested: HashValue,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspacePaths {
    pub root: PathBuf,
    pub thorax_dir: PathBuf,
    pub vault_path: PathBuf,
    pub lock_path: PathBuf,
    pub state_dir: PathBuf,
}

impl WorkspacePaths {
    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let thorax_dir = root.join(THORAX_DIR);
        Self::from_root_and_thorax_dir(root, thorax_dir, None)
    }

    pub fn from_vault_path(vault: impl Into<PathBuf>) -> Self {
        let vault = vault.into();
        let thorax_dir = vault
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let root = if thorax_dir.file_name() == Some(OsStr::new(THORAX_DIR)) {
            thorax_dir
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        } else {
            thorax_dir.clone()
        };

        Self::from_root_and_thorax_dir(root, thorax_dir, Some(vault))
    }

    pub fn exists(&self) -> bool {
        self.thorax_dir.is_dir()
    }

    fn from_root_and_thorax_dir(
        root: PathBuf,
        thorax_dir: PathBuf,
        vault: Option<PathBuf>,
    ) -> Self {
        let vault_path = vault.unwrap_or_else(|| thorax_dir.join(VAULT_FILE));
        let lock_path = thorax_dir.join(LOCK_FILE);
        let state_dir = default_state_dir();

        Self {
            root,
            thorax_dir,
            vault_path,
            lock_path,
            state_dir,
        }
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = state_dir.into();
        self
    }
}

pub fn default_vault_path(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(THORAX_DIR).join(VAULT_FILE)
}

pub fn default_thorax_dir(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(THORAX_DIR)
}

pub fn default_state_dir() -> PathBuf {
    if let Some(path) = std::env::var_os(STATE_DIR_ENV) {
        return PathBuf::from(path);
    }

    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            return PathBuf::from(appdata).join("Thorax");
        }
    }

    #[cfg(not(windows))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(xdg).join("thorax");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("thorax");
        }
    }

    #[cfg(unix)]
    {
        // A shared /tmp/thorax fallback lets another local user pre-create or inspect the
        // directory. Scope the last-resort path to the effective uid; private writers also
        // enforce mode 0700 on it before placing state below it.
        std::env::temp_dir().join(format!("thorax-{}", unsafe { libc::geteuid() }))
    }

    #[cfg(windows)]
    std::env::temp_dir().join("Thorax")
}

pub fn find_workspace(start: impl AsRef<Path>) -> Result<WorkspacePaths> {
    let start = start.as_ref();
    let mut cursor = canonical_start_dir(start)?;
    let start = cursor.clone();
    let mut found = Vec::new();

    loop {
        let thorax_dir = cursor.join(THORAX_DIR);
        if thorax_dir.is_dir() {
            found.push(cursor.clone());
        }

        if !cursor.pop() {
            break;
        }
    }

    match found.as_slice() {
        [] => Err(StoreError::WorkspaceNotFound(start)),
        [root] => Ok(WorkspacePaths::from_root(root)),
        [nested, parent, ..] => Err(StoreError::AmbiguousWorkspace {
            start,
            nested: nested.join(THORAX_DIR),
            parent: parent.join(THORAX_DIR),
        }),
    }
}

pub fn require_workspace(paths: &WorkspacePaths) -> Result<()> {
    if paths.thorax_dir.is_dir() {
        Ok(())
    } else {
        Err(StoreError::MissingThoraxDir(paths.root.clone()))
    }
}

pub fn create_workspace_dirs(paths: &WorkspacePaths) -> Result<()> {
    create_dir_all(&paths.thorax_dir)?;
    Ok(())
}

pub fn read_vault(paths: &WorkspacePaths) -> Result<VaultStore> {
    let bytes = read_vault_bytes(paths)?;
    decode_vault(&bytes).map_err(|source| StoreError::InvalidVault {
        path: paths.vault_path.clone(),
        source,
    })
}

/// The vault file's raw bytes. Callers that keep a resolved snapshot use these as the
/// staleness fingerprint: the snapshot is stale iff the bytes on disk differ.
pub fn read_vault_bytes(paths: &WorkspacePaths) -> Result<Vec<u8>> {
    // Open once, inspect that handle, and read through it. A metadata(path) followed by
    // read(path) permits a rename race that swaps in an oversized file between the calls.
    match read_file_bounded(&paths.vault_path, thorax_core::MAX_VAULT_BYTES) {
        Ok(bytes) => Ok(bytes),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            Err(StoreError::VaultMissing(paths.vault_path.clone()))
        }
        Err(source) if source.kind() == io::ErrorKind::InvalidData => {
            Err(StoreError::InvalidVault {
                path: paths.vault_path.clone(),
                source: thorax_core::CoreError::Validation(source.to_string()),
            })
        }
        Err(source) => Err(StoreError::Io {
            path: paths.vault_path.clone(),
            source,
        }),
    }
}

pub fn write_vault_atomic(paths: &WorkspacePaths, vault: &VaultStore) -> Result<()> {
    let bytes = encode_vault(vault)?;
    write_vault_bytes_atomic(paths, &bytes)
}

/// Write already-encoded vault bytes, so a caller that needs the exact on-disk bytes
/// (as a staleness fingerprint) can encode once and keep what it wrote.
pub fn write_vault_bytes_atomic(paths: &WorkspacePaths, bytes: &[u8]) -> Result<()> {
    if bytes.len() > thorax_core::MAX_VAULT_BYTES {
        return Err(StoreError::InvalidVault {
            path: paths.vault_path.clone(),
            source: thorax_core::CoreError::Validation(format!(
                "vault is {} bytes, above the supported maximum of {}",
                bytes.len(),
                thorax_core::MAX_VAULT_BYTES
            )),
        });
    }
    create_workspace_dirs(paths)?;
    write_atomic(&paths.vault_path, bytes)?;
    let reopened = read_vault_bytes(paths)?;
    if reopened != bytes {
        return Err(StoreError::InvalidVault {
            path: paths.vault_path.clone(),
            source: thorax_core::CoreError::Validation(
                "vault bytes differed immediately after atomic write".to_string(),
            ),
        });
    }
    // Re-decode the bytes through the same bounded production path before reporting success.
    decode_vault(&reopened).map_err(|source| StoreError::InvalidVault {
        path: paths.vault_path.clone(),
        source,
    })?;
    Ok(())
}

pub fn ratchet_path(paths: &WorkspacePaths, trusted_root: &HashValue) -> PathBuf {
    paths
        .state_dir
        .join(hex_hash(trusted_root))
        .join(RATCHET_FILE)
}

pub fn root_state_lock_path(paths: &WorkspacePaths, trusted_root: &HashValue) -> PathBuf {
    paths
        .state_dir
        .join(hex_hash(trusted_root))
        .join(ROOT_STATE_LOCK_FILE)
}

pub fn read_ratchet_for_root(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<Option<Ratchet>> {
    let path = ratchet_path(paths, trusted_root);
    let Some(ratchet) = read_ratchet_at(&path)? else {
        return Ok(None);
    };
    if &ratchet.trusted_root == trusted_root {
        Ok(Some(ratchet))
    } else {
        Err(StoreError::TrustRootMismatch {
            stored: ratchet.trusted_root,
            requested: trusted_root.clone(),
        })
    }
}

pub fn write_ratchet_atomic(paths: &WorkspacePaths, ratchet: &Ratchet) -> Result<()> {
    let bytes = encode_ratchet(ratchet)?;
    write_ratchet_bytes_atomic(paths, &ratchet.trusted_root, &bytes)
}

pub fn write_ratchet_bytes_atomic(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    bytes: &[u8],
) -> Result<()> {
    if bytes.len() > MAX_RATCHET_BYTES {
        return Err(StoreError::Io {
            path: ratchet_path(paths, trusted_root),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ratchet is {} bytes, above the supported maximum of {MAX_RATCHET_BYTES}",
                    bytes.len()
                ),
            ),
        });
    }
    let path = ratchet_path(paths, trusted_root);
    let decoded = decode_ratchet(&path, bytes)?;
    if &decoded.trusted_root != trusted_root {
        return Err(StoreError::TrustRootMismatch {
            stored: decoded.trusted_root,
            requested: trusted_root.clone(),
        });
    }
    write_private_atomic(&path, bytes)?;
    let reopened =
        read_file_bounded(&path, MAX_RATCHET_BYTES).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
    if reopened != bytes {
        return Err(StoreError::Io {
            path,
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "ratchet bytes differed immediately after atomic write",
            ),
        });
    }
    decode_ratchet(&path, &reopened)?;
    Ok(())
}

pub fn read_ratchet_bytes_for_root(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<Option<Vec<u8>>> {
    let path = ratchet_path(paths, trusted_root);
    let bytes = match read_file_bounded(&path, MAX_RATCHET_BYTES) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(StoreError::Io { path, source }),
    };
    let ratchet = decode_ratchet(&path, &bytes)?;
    if &ratchet.trusted_root != trusted_root {
        return Err(StoreError::TrustRootMismatch {
            stored: ratchet.trusted_root,
            requested: trusted_root.clone(),
        });
    }
    Ok(Some(bytes))
}

/// The ratchet file's leading magic, so the file identifies itself to humans and tools
/// before any cord parsing — the counterpart of the vault's `thorax-vault\0` prefix
/// (`thorax_core::VAULT_MAGIC`). Not a version field: versions live in the `RatchetStore`
/// enum behind it.
pub const RATCHET_MAGIC: &[u8] = b"thorax-ratchet\0";

pub fn encode_ratchet(ratchet: &Ratchet) -> Result<Vec<u8>> {
    // The `cord::Set` field canonicalizes (sorts + rejects duplicates) on serialize.
    let payload = cord::serialize(&RatchetStore::from(ratchet))?;
    let mut bytes = Vec::with_capacity(RATCHET_MAGIC.len() + payload.len());
    bytes.extend_from_slice(RATCHET_MAGIC);
    bytes.extend(payload);
    Ok(bytes)
}

pub fn decode_ratchet(path: impl AsRef<Path>, bytes: &[u8]) -> Result<Ratchet> {
    let path = path.as_ref();
    let Some(payload) = bytes.strip_prefix(RATCHET_MAGIC) else {
        return Err(StoreError::InvalidRatchet {
            path: path.to_path_buf(),
            source: cord::CordError::ValidationError(
                "not a thorax state file (missing magic prefix)",
            ),
        });
    };
    // The `cord::Set` deserializer rejects non-canonical (unsorted/duplicate) input,
    // surfacing here as `InvalidRatchet` — that is the rollback ratchet's tamper check.
    let store: RatchetStore =
        cord::deserialize(payload).map_err(|source| StoreError::InvalidRatchet {
            path: path.to_path_buf(),
            source,
        })?;
    store
        .into_ratchet()
        .ok_or_else(|| StoreError::InvalidRatchet {
            path: path.to_path_buf(),
            source: cord::CordError::ValidationError(
                "ratchet file missing its trusted-root record",
            ),
        })
}

pub fn write_atomic(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    let path = path.as_ref();
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_dir_all(parent)?;

    let temp_path = temporary_path_for(path);
    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|source| StoreError::Io {
            path: temp_path.clone(),
            source,
        })?;

    if let Err(source) = temp_file.write_all(bytes) {
        let _ = fs::remove_file(&temp_path);
        return Err(StoreError::Io {
            path: temp_path,
            source,
        });
    }

    if let Err(source) = temp_file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(StoreError::Io {
            path: temp_path,
            source,
        });
    }

    drop(temp_file);
    replace_file(&temp_path, path)?;
    sync_parent_directory(path)?;
    Ok(())
}

pub fn write_private_atomic(path: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
    write_private_atomic_inner(path.as_ref(), bytes, true)
}

fn write_private_atomic_inner(path: &Path, bytes: &[u8], private_parent: bool) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if private_parent {
        create_private_dir_all(parent)?;
    } else {
        create_dir_all(parent)?;
    }

    let temp_path = temporary_path_for(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp_file = options.open(&temp_path).map_err(|source| StoreError::Io {
        path: temp_path.clone(),
        source,
    })?;

    if let Err(source) = temp_file.write_all(bytes) {
        let _ = fs::remove_file(&temp_path);
        return Err(StoreError::Io {
            path: temp_path,
            source,
        });
    }

    if let Err(source) = temp_file.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(StoreError::Io {
            path: temp_path,
            source,
        });
    }

    drop(temp_file);
    replace_file(&temp_path, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            StoreError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    sync_parent_directory(path)?;
    Ok(())
}

/// Write a sensitive user-facing artifact with owner-only permissions. Existing files are
/// refused unless the caller explicitly opted into replacement; replacement is atomic and
/// replaces a symlink itself rather than following it.
pub fn write_private_output(path: impl AsRef<Path>, bytes: &[u8], force: bool) -> Result<()> {
    let path = path.as_ref();
    if !force {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        create_dir_all(parent)?;
        let temp_path = temporary_path_for(path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp_path).map_err(|source| StoreError::Io {
            path: temp_path.clone(),
            source,
        })?;
        file.write_all(bytes).map_err(|source| StoreError::Io {
            path: temp_path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| StoreError::Io {
            path: temp_path.clone(),
            source,
        })?;
        drop(file);
        if let Err(source) = fs::hard_link(&temp_path, path) {
            let _ = fs::remove_file(&temp_path);
            return Err(StoreError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
        fs::remove_file(&temp_path).map_err(|source| StoreError::Io {
            path: temp_path,
            source,
        })?;
        sync_parent_directory(path)?;
        return Ok(());
    }
    write_private_atomic_inner(path, bytes, false)
}

/// Read at most `max_bytes` from one opened file handle. The extra byte distinguishes an
/// exactly-full input from a truncated oversized input without trusting path metadata.
pub fn read_file_bounded(path: impl AsRef<Path>, max_bytes: usize) -> io::Result<Vec<u8>> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file is {} bytes, above the supported maximum of {max_bytes}",
                metadata.len()
            ),
        ));
    }
    let mut bytes = Vec::with_capacity((metadata.len() as usize).min(max_bytes));
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds the supported maximum of {max_bytes} bytes"),
        ));
    }
    Ok(bytes)
}

pub fn remove_file_durable(path: impl AsRef<Path>) -> Result<()> {
    let path = path.as_ref();
    match fs::remove_file(path) {
        Ok(()) => sync_parent_directory(path),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn acquire_workspace_lock(paths: &WorkspacePaths) -> Result<WorkspaceLock> {
    create_workspace_dirs(paths)?;
    let lock = acquire_advisory_lock(&paths.lock_path, LockMode::Exclusive, LOCK_WAIT, false)?;
    Ok(WorkspaceLock {
        path: paths.lock_path.clone(),
        _lock: lock,
    })
}

pub fn acquire_root_state_lock(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<RootStateLock> {
    acquire_root_state_lock_with_mode(paths, trusted_root, LockMode::Exclusive, LOCK_WAIT)
}

pub fn acquire_root_state_shared_lock(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<RootStateLock> {
    acquire_root_state_lock_with_mode(paths, trusted_root, LockMode::Shared, LOCK_WAIT)
}

fn acquire_root_state_lock_with_mode(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    mode: LockMode,
    timeout: Duration,
) -> Result<RootStateLock> {
    let path = root_state_lock_path(paths, trusted_root);
    let lock = acquire_advisory_lock(&path, mode, timeout, true)?;
    Ok(RootStateLock { path, _lock: lock })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LockMode {
    Shared,
    Exclusive,
}

#[derive(Debug)]
struct AdvisoryLock {
    file: File,
}

fn acquire_advisory_lock(
    path: &Path,
    mode: LockMode,
    timeout: Duration,
    private_parent: bool,
) -> Result<AdvisoryLock> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if private_parent {
        create_private_dir_all(parent)?;
    } else {
        create_dir_all(parent)?;
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let started = Instant::now();
    loop {
        let result = match mode {
            LockMode::Shared => fs2::FileExt::try_lock_shared(&file),
            LockMode::Exclusive => fs2::FileExt::try_lock_exclusive(&file),
        };
        match result {
            Ok(()) => return Ok(AdvisoryLock { file }),
            Err(source) if source.kind() == io::ErrorKind::WouldBlock => {
                if started.elapsed() >= timeout {
                    return Err(StoreError::LockAlreadyHeld(path.to_path_buf()));
                }
                thread::sleep(LOCK_POLL.min(timeout.saturating_sub(started.elapsed())));
            }
            Err(source) => {
                return Err(StoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        }
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

pub struct WorkspaceLock {
    path: PathBuf,
    _lock: AdvisoryLock,
}

impl WorkspaceLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for WorkspaceLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkspaceLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

pub struct RootStateLock {
    path: PathBuf,
    _lock: AdvisoryLock,
}

impl RootStateLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::fmt::Debug for RootStateLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootStateLock")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum RatchetStore {
    #[cord(index = 0)]
    V1(RatchetStoreV1),
}

/// On-disk ratchet: a derived, unsigned set of records keyed to a trusted root.
/// Unlike the vault, this is not a signed record log — it is a recomputable
/// rollback ratchet. Each record is a typed [`RatchetRecordV1`], wrapped in
/// `Evolving` so a newer binary's record kinds survive a rewrite by an older one
/// (see [`UnknownRatchetRecord`]).
///
/// `records` is a [`cord::Set`], so cord canonicalizes it for us: serialize
/// sorts strictly-ascending by element bytes and rejects duplicates, and the
/// deserializer rejects any non-canonical (unsorted/duplicate) input. That is the
/// rollback ratchet's tamper check — no hand-rolled sort/validation needed.
///
/// The structure mirrors the vault and keychain stores exactly — a version enum over a
/// single `records` set. The trusted root the file is scoped to is itself one of the
/// records ([`RatchetRecordV1::TrustedRoot`]), not a sibling field.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
struct RatchetStoreV1 {
    records: cord::Set<cord::Evolving<RatchetRecordV1>>,
}

impl From<&Ratchet> for RatchetStore {
    fn from(ratchet: &Ratchet) -> Self {
        // The known records (watermarks, the format-version guard, and the trusted-root scope)
        // are the ratchet's canonical encoding; see `Ratchet::to_records`. The trusted root
        // rides in the record set, so the file is a version enum over one `records` set — the
        // same shape as the vault and keychain.
        let mut records: Vec<cord::Evolving<RatchetRecordV1>> = ratchet
            .to_records()
            .into_iter()
            .map(cord::Evolving::new)
            .collect();
        // Carry through record kinds a newer binary wrote that this build cannot parse.
        records.extend(
            ratchet
                .unknown_records
                .iter()
                .map(|unknown| cord::Evolving::Unknown(unknown.0.clone())),
        );
        RatchetStore::V1(RatchetStoreV1 {
            records: cord::Set::from(records),
        })
    }
}

impl RatchetStore {
    /// `None` when the file carries no [`RatchetRecordV1::TrustedRoot`] record — a ratchet
    /// file must name the root it is scoped to, so its absence is corruption.
    fn into_ratchet(self) -> Option<Ratchet> {
        match self {
            RatchetStore::V1(v1) => v1.into_ratchet(),
        }
    }
}

impl RatchetStoreV1 {
    /// Fold the (already-canonical, deserializer-validated) record set back into a [`Ratchet`],
    /// carrying unknown future records through opaquely. `None` when the mandatory
    /// [`RatchetRecordV1::TrustedRoot`] record is absent.
    fn into_ratchet(self) -> Option<Ratchet> {
        // The trusted root scopes the ratchet, so it must be extracted before the ratchet can
        // be constructed; the remaining known records fold in via `Ratchet::absorb_record`,
        // and unparseable future records are carried through opaquely.
        let mut trusted_root = None;
        let mut known = Vec::new();
        let mut unknown_records = Vec::new();
        for record in self.records {
            match record {
                cord::Evolving::Known(RatchetRecordV1::TrustedRoot(fact)) => {
                    trusted_root = Some(fact.trusted_root);
                }
                cord::Evolving::Known(record) => known.push(record),
                cord::Evolving::Unknown(bytes) => {
                    unknown_records.push(UnknownRatchetRecord(bytes));
                }
            }
        }

        let mut ratchet = Ratchet::new(trusted_root?);
        for record in &known {
            ratchet.absorb_record(record);
        }
        ratchet.unknown_records = unknown_records;
        Some(ratchet)
    }
}

// Verification cache — `<state_dir>/<hex(root)>/<hex(user)>/cache.cord`
//
// A PURE cache with the opposite preservation contract of the state and keychain files:
// nothing in it is owed survival. It memoizes which record envelopes' signatures a fully
// validated session already checked, signed by the identity that performed that
// validation. Any mismatch — missing file, bad magic, undecodable, unknown version — reads
// as `None` and the consumer simply re-verifies everything and rewrites it. There is no
// `Evolving` wrapping and no carry-through of unknown content, deliberately: an older
// binary trashing a newer binary's cache costs one slow load, never correctness.
//
// Trust is the consumer's job (thorax-ops): verify `signature` over
// [`verification_cache_message`] under [`CACHE_SIGNATURE_DOMAIN`], check the bindings, and
// possession-check the signer on unlock paths. This layer only moves bytes.

/// The cache file's leading magic, like the vault/state/keychain prefixes. Not a version
/// field: versions live in the `VerificationCacheStore` enum behind it.
pub const CACHE_MAGIC: &[u8] = b"thorax-cache\0";

/// Domain string for the cache signature (`sign(domain, message)`); the message bytes come
/// from [`verification_cache_message`].
pub const CACHE_SIGNATURE_DOMAIN: &str = "thorax.verification-cache.v1";

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum VerificationCacheStore {
    #[cord(index = 0)]
    V1(VerificationCacheV1),
}

/// One identity's attestation of completed signature verifications: every hash in
/// `verified_record_hashes` is a record-hash (`thorax.record-hash.v1`, computed over the
/// **whole** signed envelope — body, signing key, and signature together) whose envelope
/// signature passed a full validation. A hash is therefore a binding commitment to the
/// entire verification triple; presenting any altered envelope changes the hash and misses
/// the cache.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
pub struct VerificationCacheV1 {
    /// Binding: a cache speaks about one vault…
    pub trusted_root: HashValue,
    /// …under one format epoch — a flag-day invalidates every cache.
    pub format_version: u64,
    pub verified_record_hashes: cord::Set<HashValue>,
    /// The producer's Ed25519 key. Identification, never trust: unlock paths trust the
    /// cache only after this equals the unlocked seed-derived key (possession check).
    pub signing_public_key: Bytes,
    /// Ed25519 over [`verification_cache_message`] under [`CACHE_SIGNATURE_DOMAIN`].
    pub signature: Bytes,
}

/// The exact bytes the cache signature covers: the canonical cord serialization of the
/// payload fields (cord is canonical, so reserializing reproduces them byte-for-byte).
pub fn verification_cache_message(
    trusted_root: &HashValue,
    format_version: u64,
    verified_record_hashes: &cord::Set<HashValue>,
) -> Result<Vec<u8>> {
    #[derive(cord::Cord)]
    struct VerificationCacheMessageV1 {
        trusted_root: HashValue,
        format_version: u64,
        verified_record_hashes: cord::Set<HashValue>,
    }
    Ok(cord::serialize(&VerificationCacheMessageV1 {
        trusted_root: trusted_root.clone(),
        format_version,
        verified_record_hashes: verified_record_hashes.clone(),
    })?)
}

pub fn verification_cache_path(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    user: &UserId,
) -> PathBuf {
    paths
        .state_dir
        .join(hex_hash(trusted_root))
        .join(hex_hash(&user.0))
        .join(CACHE_FILE)
}

/// Read the cache, with pure-cache semantics baked in: a missing, unreadable, truncated,
/// mis-prefixed, or unknown-version file all read as `None` — the caller re-verifies and
/// rewrites. Nothing here is trusted yet; see the module note above.
pub fn read_verification_cache(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    user: &UserId,
) -> Option<VerificationCacheV1> {
    let path = verification_cache_path(paths, trusted_root, user);
    let bytes = read_file_bounded(&path, MAX_VERIFICATION_CACHE_BYTES).ok()?;
    let payload = bytes.strip_prefix(CACHE_MAGIC)?;
    match cord::deserialize(payload).ok()? {
        VerificationCacheStore::V1(cache) => Some(cache),
    }
}

pub fn write_verification_cache_atomic(
    paths: &WorkspacePaths,
    user: &UserId,
    cache: &VerificationCacheV1,
) -> Result<()> {
    let payload = cord::serialize(&VerificationCacheStore::V1(cache.clone()))?;
    let mut bytes = Vec::with_capacity(CACHE_MAGIC.len() + payload.len());
    bytes.extend_from_slice(CACHE_MAGIC);
    bytes.extend(payload);
    if bytes.len() > MAX_VERIFICATION_CACHE_BYTES {
        return Err(StoreError::Io {
            path: verification_cache_path(paths, &cache.trusted_root, user),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "verification cache is {} bytes, above the supported maximum of {MAX_VERIFICATION_CACHE_BYTES}",
                    bytes.len()
                ),
            ),
        });
    }
    let path = verification_cache_path(paths, &cache.trusted_root, user);
    write_private_atomic(&path, &bytes)?;
    let reopened = read_file_bounded(&path, MAX_VERIFICATION_CACHE_BYTES).map_err(|source| {
        StoreError::Io {
            path: path.clone(),
            source,
        }
    })?;
    if reopened != bytes {
        return Err(StoreError::Io {
            path,
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "verification cache bytes differed immediately after atomic write",
            ),
        });
    }
    let payload = reopened
        .strip_prefix(CACHE_MAGIC)
        .ok_or_else(|| StoreError::Io {
            path: path.clone(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                "verification cache lost its magic prefix",
            ),
        })?;
    let _: VerificationCacheStore = cord::deserialize(payload)?;
    Ok(())
}

fn canonical_start_dir(start: &Path) -> Result<PathBuf> {
    let canonical = start.canonicalize().map_err(|source| StoreError::Io {
        path: start.to_path_buf(),
        source,
    })?;

    if canonical.is_file() {
        Ok(canonical
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or(canonical))
    } else {
        Ok(canonical)
    }
}

fn create_dir_all(path: &Path) -> Result<()> {
    fs::create_dir_all(path).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn create_private_dir_all(path: &Path) -> Result<()> {
    create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            StoreError::Io {
                path: path.to_path_buf(),
                source,
            }
        })?;
    }
    Ok(())
}

fn replace_file(source_path: &Path, destination: &Path) -> Result<()> {
    match fs::rename(source_path, destination) {
        Ok(()) => Ok(()),
        Err(first_error) if first_error.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(destination).map_err(|source| StoreError::Io {
                path: destination.to_path_buf(),
                source,
            })?;
            fs::rename(source_path, destination).map_err(|source| {
                let _ = fs::remove_file(source_path);
                StoreError::Io {
                    path: destination.to_path_buf(),
                    source,
                }
            })
        }
        Err(source) => {
            let _ = fs::remove_file(source_path);
            Err(StoreError::Io {
                path: destination.to_path_buf(),
                source,
            })
        }
    }
}

fn temporary_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("thorax-write");
    path.with_file_name(format!(".{file_name}.tmp.{:032x}", rand::random::<u128>()))
}

fn read_ratchet_at(path: &Path) -> Result<Option<Ratchet>> {
    let bytes = match read_file_bounded(path, MAX_RATCHET_BYTES) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StoreError::Io {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    decode_ratchet(path, &bytes).map(Some)
}

fn hex_hash(hash: &HashValue) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = &hash.0;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let file = File::open(parent).map_err(|source| StoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        file.sync_all().map_err(|source| StoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    use thorax_core::{
        RecordKey, SecretId, SecretRatchetRecordV1, SecretSelectorV1, TrustedRootRatchetRecordV1,
        UserId, UserRatchetRecordV1, VaultStoreV1,
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn watermark_key(byte: u8) -> RecordKey {
        RecordKey::Secret {
            secret_id: SecretId(hash(byte)),
        }
    }

    fn user_watermark_key(byte: u8) -> RecordKey {
        RecordKey::User {
            user_id: user(byte),
        }
    }

    #[test]
    fn builds_default_workspace_paths() {
        let paths = WorkspacePaths::from_root("/repo").with_state_dir("/machine/thorax/state");

        assert_eq!(paths.root, PathBuf::from("/repo"));
        assert_eq!(paths.thorax_dir, PathBuf::from("/repo/.thorax"));
        assert_eq!(paths.vault_path, PathBuf::from("/repo/.thorax/vault.cord"));
        assert_eq!(
            paths.lock_path,
            PathBuf::from("/repo/.thorax/vault.cord.lock")
        );
        assert_eq!(paths.state_dir, PathBuf::from("/machine/thorax/state"));
        assert_eq!(
            ratchet_path(&paths, &hash(1)),
            PathBuf::from(
                "/machine/thorax/state/0101010101010101010101010101010101010101010101010101010101010101/ratchet.cord"
            )
        );
    }

    #[test]
    fn derives_workspace_from_vault_path() {
        let paths = WorkspacePaths::from_vault_path("/repo/.thorax/vault.cord");

        assert_eq!(paths.root, PathBuf::from("/repo"));
        assert_eq!(paths.thorax_dir, PathBuf::from("/repo/.thorax"));
        assert_eq!(paths.vault_path, PathBuf::from("/repo/.thorax/vault.cord"));
    }

    #[test]
    fn finds_workspace_by_walking_upward() {
        let temp = TestDir::new();
        let root = temp.path().join("repo");
        let child = root.join("a/b/c");
        fs::create_dir_all(root.join(THORAX_DIR)).unwrap();
        fs::create_dir_all(&child).unwrap();

        let paths = find_workspace(&child).unwrap();

        assert_eq!(paths.root, root.canonicalize().unwrap());
        assert_eq!(
            paths.vault_path,
            paths.root.join(THORAX_DIR).join(VAULT_FILE)
        );
    }

    #[test]
    fn rejects_ambiguous_nested_workspace_discovery() {
        let temp = TestDir::new();
        let parent = temp.path().join("repo");
        let nested = parent.join("service");
        let child = nested.join("src");
        fs::create_dir_all(parent.join(THORAX_DIR)).unwrap();
        fs::create_dir_all(nested.join(THORAX_DIR)).unwrap();
        fs::create_dir_all(&child).unwrap();

        let error = find_workspace(&child).unwrap_err();

        assert!(matches!(error, StoreError::AmbiguousWorkspace { .. }));
    }

    #[test]
    fn vault_round_trips_through_atomic_write() {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path());
        let vault = VaultStore::V1(VaultStoreV1 {
            records: Vec::new().into(),
        });

        write_vault_atomic(&paths, &vault).unwrap();
        let loaded = read_vault(&paths).unwrap();

        assert_eq!(loaded, vault);
    }

    #[test]
    fn sensitive_output_is_private_and_refuses_implicit_overwrite() {
        let temp = TestDir::new();
        let path = temp.path().join("invite.thrxi");
        write_private_output(&path, b"first", false).unwrap();
        let error = write_private_output(&path, b"second", false).unwrap_err();
        assert!(matches!(
            error,
            StoreError::Io { source, .. } if source.kind() == io::ErrorKind::AlreadyExists
        ));
        assert_eq!(fs::read(&path).unwrap(), b"first");
        write_private_output(&path, b"second", true).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn bounded_read_refuses_symlinks() {
        use std::os::unix::fs::symlink;
        let temp = TestDir::new();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        fs::write(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_file_bounded(&link, 100).is_err());
    }

    #[test]
    fn ratchet_round_trips_through_atomic_write() {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path())
            .with_state_dir(temp.path().join("machine-state"));
        let root = hash(1);
        let mut trust = Ratchet::new(root.clone());
        trust.watermarks.insert(user_watermark_key(2), 4);
        trust.watermarks.insert(watermark_key(3), 7);
        trust.format_version = 3;

        write_ratchet_atomic(&paths, &trust).unwrap();
        let loaded = read_ratchet_for_root(&paths, &root).unwrap().unwrap();

        assert_eq!(loaded, trust);
    }

    #[test]
    fn ratchet_defaults_when_missing() {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path())
            .with_state_dir(temp.path().join("machine-state"));

        let loaded = read_ratchet_for_root(&paths, &hash(1)).unwrap();

        assert_eq!(loaded, None);
    }

    #[test]
    fn ratchet_root_mismatch_is_rejected() {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path())
            .with_state_dir(temp.path().join("machine-state"));
        let bytes = encode_ratchet(&Ratchet::new(hash(1))).unwrap();
        write_atomic(ratchet_path(&paths, &hash(2)), &bytes).unwrap();
        let error = read_ratchet_for_root(&paths, &hash(2)).unwrap_err();

        assert!(matches!(error, StoreError::TrustRootMismatch { .. }));
    }

    #[test]
    fn ratchet_rejects_unsorted_or_duplicate_records() {
        // A `cord::Set` field can't itself hold duplicates, so craft a non-canonical
        // wire image via a `Vec`-shaped mirror (wire-identical to the `Set` field) and
        // confirm the `Set` deserializer rejects it — the ratchet's tamper check.
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        struct VecStoreV1 {
            records: Vec<cord::Evolving<RatchetRecordV1>>,
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        enum VecStore {
            #[cord(index = 0)]
            V1(VecStoreV1),
        }

        let temp = TestDir::new();
        let path = temp.path().join("ratchet.cord");
        let dup = cord::Evolving::new(RatchetRecordV1::Secret(SecretRatchetRecordV1 {
            id: SecretId(hash(2)),
            counter: 7,
            selector: SecretSelectorV1::tuple(["app", "db"]),
        }));
        let bytes = cord::serialize(&VecStore::V1(VecStoreV1 {
            records: vec![dup.clone(), dup],
        }))
        .unwrap();
        let mut file = RATCHET_MAGIC.to_vec();
        file.extend(bytes);

        let error = decode_ratchet(&path, &file).unwrap_err();

        assert!(matches!(error, StoreError::InvalidRatchet { .. }));
    }

    #[test]
    fn ratchet_preserves_unknown_records_byte_for_byte() {
        // Simulate a newer binary: an extra fact kind at an index this build's
        // `RatchetRecordV1` does not define.
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        enum WatermarkFuture {
            #[cord(index = 0)]
            User(UserRatchetRecordV1),
            #[cord(index = 6)]
            Secret(SecretRatchetRecordV1),
            // Mirrors the real `RatchetRecordV1::TrustedRoot` (idx 9) so the file names its root.
            #[cord(index = 9)]
            TrustedRoot(TrustedRootRatchetRecordV1),
            // An index this build's `RatchetRecordV1` does not define — the unknown fact.
            #[cord(index = 15)]
            VerifiedAdminLogHead { hash: HashValue },
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        struct StoreFuture {
            records: Vec<cord::Evolving<WatermarkFuture>>,
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        enum WireFuture {
            #[cord(index = 0)]
            V1(StoreFuture),
        }

        let path = TestDir::new().path().join("ratchet.cord");
        let mut future_obs = vec![
            cord::Evolving::new(WatermarkFuture::User(UserRatchetRecordV1 {
                id: user(1),
                counter: 4,
            })),
            cord::Evolving::new(WatermarkFuture::Secret(SecretRatchetRecordV1 {
                id: SecretId(hash(3)),
                counter: 5,
                selector: SecretSelectorV1::tuple(["app", "db"]),
            })),
            cord::Evolving::new(WatermarkFuture::TrustedRoot(TrustedRootRatchetRecordV1 {
                trusted_root: hash(0),
            })),
            cord::Evolving::new(WatermarkFuture::VerifiedAdminLogHead { hash: hash(9) }),
        ];
        // Newer binary writes canonically: sorted strictly-ascending by element bytes.
        future_obs.sort_by_key(|a| cord::serialize(a).unwrap());
        let mut written = RATCHET_MAGIC.to_vec();
        written.extend(
            cord::serialize(&WireFuture::V1(StoreFuture {
                records: future_obs,
            }))
            .unwrap(),
        );

        // This build reads it: known facts land in the typed map, the future-only
        // fact is carried opaquely — none are dropped.
        let ratchet = decode_ratchet(&path, &written).unwrap();
        assert_eq!(ratchet.watermarks.get(&user_watermark_key(1)), Some(&4));
        assert_eq!(ratchet.watermarks.get(&watermark_key(3)), Some(&5));
        assert_eq!(ratchet.unknown_records.len(), 1);

        // Rewriting must reproduce the newer binary's bytes exactly — the ratchet
        // loses nothing.
        let rewritten = encode_ratchet(&ratchet).unwrap();
        assert_eq!(written, rewritten);
    }

    /// Golden wire-format pin for the state file. These bytes were produced by the
    /// current encoder for a state holding a user watermark (user 0x01…, counter 4), a
    /// secret watermark (secret id 0x03…, counter 5, remembered selector app/db with no
    /// labels), the trusted-root record (root 0x00…, enum index 9), and an unknown future
    /// fact at enum index 15. Rust-side renames must never change them: cord encodes structs
    /// positionally and enums by index, so this test only fails if the actual wire layout
    /// changes. (Regenerated 2026-06-13 when the ratchet became `Ratchet` / `ratchet.cord` with
    /// magic `thorax-ratchet\0`; the `trusted_root` is a `RatchetRecordV1::TrustedRoot` record,
    /// making the file a version enum over one `records` set — the same shape as vault/keychain.)
    const RATCHET_GOLDEN_HEX: &str = "74686f7261782d726174636865740000000000000000040000002800000009000000200000000000000000000000000000000000000000000000000000000000000000000000280000000f0000002009090909090909090909090909090909090909090909090909090909090909090000003000000000000000200101010101010101010101010101010101010101010101010101010101010101000000000000000400000045000000060000002003030303030303030303030303030303030303030303030303030303030303030000000000000005000000020000000361707000000002646200000000";

    #[test]
    fn ratchet_wire_format_matches_golden_bytes() {
        let written = hex_bytes(RATCHET_GOLDEN_HEX);

        let ratchet = decode_ratchet("golden/ratchet.cord", &written).unwrap();
        assert_eq!(ratchet.trusted_root, hash(0));
        assert_eq!(ratchet.watermarks.get(&user_watermark_key(1)), Some(&4));
        assert_eq!(ratchet.watermarks.get(&watermark_key(3)), Some(&5));
        assert_eq!(ratchet.unknown_records.len(), 1);

        let rewritten = encode_ratchet(&ratchet).unwrap();
        assert_eq!(written, rewritten);
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn workspace_lock_prevents_second_holder_and_releases_on_drop() {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path());

        let lock = acquire_workspace_lock(&paths).unwrap();
        let waiting_paths = paths.clone();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || acquire_workspace_lock(&waiting_paths).unwrap());
        std::thread::sleep(Duration::from_millis(150));
        drop(lock);
        let reacquired = waiter.join().unwrap();
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert_eq!(reacquired.path(), paths.lock_path.as_path());
        assert!(paths.lock_path.exists());
    }

    #[test]
    fn stale_workspace_lock_file_does_not_block_acquisition() {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path());
        create_workspace_dirs(&paths).unwrap();
        fs::write(&paths.lock_path, b"pid=dead\n").unwrap();

        let lock = acquire_workspace_lock(&paths).unwrap();

        assert_eq!(lock.path(), paths.lock_path.as_path());
    }

    #[test]
    fn root_lock_allows_readers_and_excludes_a_writer() {
        let temp = TestDir::new();
        let paths =
            WorkspacePaths::from_root(temp.path()).with_state_dir(temp.path().join("state"));
        let root = hash(7);
        let first = acquire_root_state_shared_lock(&paths, &root).unwrap();
        let second = acquire_root_state_shared_lock(&paths, &root).unwrap();

        let blocked =
            acquire_root_state_lock_with_mode(&paths, &root, LockMode::Exclusive, Duration::ZERO)
                .unwrap_err();
        assert!(matches!(blocked, StoreError::LockAlreadyHeld(_)));

        drop(first);
        drop(second);
        let writer = acquire_root_state_lock(&paths, &root).unwrap();
        assert_eq!(writer.path(), root_state_lock_path(&paths, &root));
    }

    #[test]
    fn file_backend_compare_and_swap_rejects_a_stale_writer() {
        let temp = TestDir::new();
        let paths =
            WorkspacePaths::from_root(temp.path()).with_state_dir(temp.path().join("state"));
        create_workspace_dirs(&paths).unwrap();
        let backend = FileRatchetBackend::new(paths);
        let root = hash(7);
        let identity = user(9);
        let ratchet = Ratchet::new(root.clone());

        let stored = futures::executor::block_on(backend.compare_and_swap(
            &root,
            &identity,
            &(),
            None,
            &ratchet,
        ))
        .unwrap();
        assert!(matches!(stored, RatchetCasOutcome::Stored(_)));

        let stale = futures::executor::block_on(backend.compare_and_swap(
            &root,
            &identity,
            &(),
            None,
            &ratchet,
        ))
        .unwrap();
        assert_eq!(stale, RatchetCasOutcome::Conflict);
        assert!(
            futures::executor::block_on(backend.load(&root, &identity, &()))
                .unwrap()
                .is_some()
        );
    }

    fn hash(byte: u8) -> HashValue {
        HashValue(vec![byte; 32])
    }

    fn user(byte: u8) -> UserId {
        UserId(hash(byte))
    }

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new() -> Self {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!(
                "thorax-store-test-{}-{nanos}-{counter}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
