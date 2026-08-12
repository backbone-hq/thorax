use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

use thorax_core::{Bytes, HashValue};

use super::{
    hex_hash, read_file_bounded, write_private_atomic, Result, StoreError, WorkspacePaths,
    MAX_RATCHET_BYTES,
};

pub const TRANSACTION_FILE: &str = "transaction.cord";
pub const TRANSACTION_MAGIC: &[u8] = b"thorax-transaction\0";
pub const MAX_TRANSACTION_BYTES: usize =
    thorax_core::MAX_VAULT_BYTES + MAX_RATCHET_BYTES + 1024 * 1024;
pub const MAX_TRANSACTION_OPERATION_BYTES: usize = 128;
pub const TRANSACTION_ID_BYTES: usize = 32;

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
enum TransactionStore {
    #[cord(index = 0)]
    V1(TransactionV1),
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
pub struct TransactionV1 {
    pub transaction_id: Bytes,
    pub trusted_root: HashValue,
    pub origin_vault_path: NativePathV1,
    pub operation: String,
    pub vault_before: FilePreconditionV1,
    pub ratchet_before: FilePreconditionV1,
    pub next_vault_bytes: Bytes,
    pub next_ratchet_bytes: Bytes,
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
pub enum FilePreconditionV1 {
    #[cord(index = 0)]
    Missing,
    #[cord(index = 1)]
    Hash(HashValue),
}

/// A canonical path in the native representation of the platform that created it.
/// Windows paths are UTF-16LE bytes; Unix paths are their raw `OsStr` bytes.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
pub enum NativePathV1 {
    #[cord(index = 0)]
    Unix(Bytes),
    #[cord(index = 1)]
    WindowsUtf16Le(Bytes),
}

impl NativePathV1 {
    pub fn canonical(path: &Path) -> Result<Self> {
        let canonical = fs::canonicalize(path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(Self::from_path(&canonical))
    }

    pub fn from_path(path: &Path) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            Self::Unix(path.as_os_str().as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            let mut bytes = Vec::new();
            for unit in path.as_os_str().encode_wide() {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
            Self::WindowsUtf16Le(bytes)
        }
    }

    pub fn to_path_buf(&self) -> Option<PathBuf> {
        match self {
            #[cfg(unix)]
            Self::Unix(bytes) => {
                use std::os::unix::ffi::OsStringExt;
                Some(PathBuf::from(OsString::from_vec(bytes.clone())))
            }
            #[cfg(not(unix))]
            Self::Unix(_) => None,
            #[cfg(windows)]
            Self::WindowsUtf16Le(bytes) => {
                use std::os::windows::ffi::OsStringExt;
                let mut chunks = bytes.chunks_exact(2);
                let units: Vec<u16> = chunks
                    .by_ref()
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                if !chunks.remainder().is_empty() {
                    return None;
                }
                Some(PathBuf::from(OsString::from_wide(&units)))
            }
            #[cfg(not(windows))]
            Self::WindowsUtf16Le(_) => None,
        }
    }

    pub fn matches_canonical(&self, path: &Path) -> Result<bool> {
        Ok(*self == Self::canonical(path)?)
    }
}

pub fn transaction_path(paths: &WorkspacePaths, trusted_root: &HashValue) -> PathBuf {
    paths
        .state_dir
        .join(hex_hash(trusted_root))
        .join(TRANSACTION_FILE)
}

pub fn encode_transaction(transaction: &TransactionV1) -> Result<Vec<u8>> {
    validate_shape(Path::new(TRANSACTION_FILE), transaction)?;
    let payload = cord::serialize(&TransactionStore::V1(transaction.clone()))?;
    let mut bytes = Vec::with_capacity(TRANSACTION_MAGIC.len() + payload.len());
    bytes.extend_from_slice(TRANSACTION_MAGIC);
    bytes.extend(payload);
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(invalid(
            Path::new(TRANSACTION_FILE),
            format!(
                "transaction is {} bytes, above the supported maximum of {MAX_TRANSACTION_BYTES}",
                bytes.len()
            ),
        ));
    }
    Ok(bytes)
}

pub fn decode_transaction(path: &Path, bytes: &[u8]) -> Result<TransactionV1> {
    if bytes.len() > MAX_TRANSACTION_BYTES {
        return Err(invalid(
            path,
            format!(
                "transaction is {} bytes, above the supported maximum of {MAX_TRANSACTION_BYTES}",
                bytes.len()
            ),
        ));
    }
    let payload = bytes
        .strip_prefix(TRANSACTION_MAGIC)
        .ok_or_else(|| invalid(path, "missing thorax transaction magic"))?;
    let TransactionStore::V1(transaction) = cord::deserialize(payload).map_err(|error| {
        invalid(
            path,
            format!("transaction Cord payload is invalid: {error}"),
        )
    })?;
    validate_shape(path, &transaction)?;
    Ok(transaction)
}

pub fn read_transaction(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<Option<TransactionV1>> {
    let path = transaction_path(paths, trusted_root);
    let bytes = match read_file_bounded(&path, MAX_TRANSACTION_BYTES) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(StoreError::Io { path, source }),
    };
    let transaction = decode_transaction(&path, &bytes)?;
    if &transaction.trusted_root != trusted_root {
        return Err(invalid(
            &path,
            "transaction trusted root does not match its state directory",
        ));
    }
    Ok(Some(transaction))
}

pub fn write_transaction_atomic(paths: &WorkspacePaths, transaction: &TransactionV1) -> Result<()> {
    let path = transaction_path(paths, &transaction.trusted_root);
    let bytes = encode_transaction(transaction)?;
    write_private_atomic(&path, &bytes)?;
    let reopened =
        read_file_bounded(&path, MAX_TRANSACTION_BYTES).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
    if reopened != bytes {
        return Err(invalid(
            &path,
            "transaction bytes differed immediately after atomic write",
        ));
    }
    let decoded = decode_transaction(&path, &reopened)?;
    if decoded != *transaction {
        return Err(invalid(
            &path,
            "transaction value differed immediately after atomic write",
        ));
    }
    Ok(())
}

fn validate_shape(path: &Path, transaction: &TransactionV1) -> Result<()> {
    if transaction.transaction_id.len() != TRANSACTION_ID_BYTES {
        return Err(invalid(path, "transaction ID must be exactly 32 bytes"));
    }
    if transaction.operation.is_empty()
        || transaction.operation.len() > MAX_TRANSACTION_OPERATION_BYTES
    {
        return Err(invalid(
            path,
            "transaction operation label is empty or too long",
        ));
    }
    validate_hash(path, &transaction.vault_before)?;
    validate_hash(path, &transaction.ratchet_before)?;
    if transaction.next_vault_bytes.len() > thorax_core::MAX_VAULT_BYTES {
        return Err(invalid(path, "transaction vault after-image is too large"));
    }
    if transaction.next_ratchet_bytes.len() > MAX_RATCHET_BYTES {
        return Err(invalid(
            path,
            "transaction ratchet after-image is too large",
        ));
    }
    if matches!(transaction.origin_vault_path, NativePathV1::WindowsUtf16Le(ref bytes) if bytes.len() % 2 != 0)
    {
        return Err(invalid(
            path,
            "transaction Windows path has odd byte length",
        ));
    }
    Ok(())
}

fn validate_hash(path: &Path, precondition: &FilePreconditionV1) -> Result<()> {
    if let FilePreconditionV1::Hash(hash) = precondition {
        if hash.0.len() != 32 {
            return Err(invalid(path, "transaction file hash must be 32 bytes"));
        }
    }
    Ok(())
}

fn invalid(path: &Path, detail: impl Into<String>) -> StoreError {
    StoreError::InvalidTransaction {
        path: path.to_path_buf(),
        detail: detail.into(),
    }
}
