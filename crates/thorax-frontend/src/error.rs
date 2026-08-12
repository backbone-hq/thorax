//! The shared frontend error type.
//!
//! Every Thorax frontend (CLI, `run`, TUI) surfaces failures as a [`FrontendError`]. The
//! [`crate::diagnostics`] layer maps each variant to a stable code, human message, remediation
//! hint, and process exit code, so no frontend formats an error by hand or leaks internal
//! `Debug` output.

use std::path::PathBuf;

use thorax_ops::{OpsError, SecretState, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum FrontendError {
    #[error("{0}")]
    Ops(#[from] OpsError),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("{0}")]
    Keychain(#[from] thorax_ops::KeychainError),
    #[error("Cord error: {0}")]
    Cord(#[from] cord::CordError),
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invitation file {path} was written, but the vault commit failed: {source}")]
    InertInviteFile {
        path: PathBuf,
        source: Box<OpsError>,
    },
    #[error("I/O error: {0}")]
    Stdio(std::io::Error),
    #[error("{service} error: {message}")]
    ExternalService {
        service: &'static str,
        message: String,
    },
    #[error("invalid selector {selector:?}: {reason}")]
    InvalidSelector {
        selector: String,
        reason: &'static str,
    },
    #[error("invalid {name} hex: {reason}")]
    InvalidHex { name: &'static str, reason: String },
    #[error("expected {name} hex to decode to {expected} bytes, got {actual}")]
    InvalidHexLength {
        name: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("pass at most one of VALUE or --file")]
    AmbiguousSecretInput,
    #[error("secret input exceeds the supported maximum of {max_bytes} bytes")]
    SecretInputTooLarge { max_bytes: usize },
    #[error("pass exactly one of the string or file form")]
    AmbiguousIdentityBundle,
    #[error("invitation string is malformed or has a bad checksum")]
    InvalidBundleString,
    #[error("not the expected Thorax invitation (prefix {0:?}; invitations are thrx1…)")]
    WrongBundlePrefix(String),
    #[error("validation failed with {0} issue(s)")]
    ValidationFailed(usize),
    #[error("environment variable {0} must be valid UTF-8")]
    NonUtf8Env(&'static str),
    #[error("invalid user handle {handle:?}: {reason}")]
    InvalidHandle {
        handle: String,
        reason: &'static str,
    },
    #[error("no default Thorax identity is configured; pass --user once")]
    MissingDefaultUser,
    #[error("group {0:?} does not exist")]
    GroupNotFound(String),
    #[error("group {0:?} is ambiguous")]
    AmbiguousGroup(String),
    #[error("group membership does not exist")]
    GroupMemberNotFound,
    #[error("invalid grantable class {0:?}")]
    InvalidGrantable(String),
    #[error("no user matches {0:?}")]
    UserNotFound(String),
    #[error("user {0:?} is ambiguous")]
    AmbiguousUser(String),
    #[error("no grant matches {0:?}")]
    GrantNotFound(String),
    #[error("grant {0:?} is ambiguous")]
    AmbiguousGrant(String),
    #[error("secret {selector} is not encrypted to you")]
    SecretStale { selector: String },
    #[error("not authorized to read {selector}")]
    SecretUnauthorized { selector: String },
    #[error("no secrets match {selector}")]
    SecretNotFound { selector: String },
    #[error("secret {selector} already exists")]
    SecretAlreadyExists { selector: String },
    #[error("{selector} matches {count} secrets, so it cannot be a single variable {name}")]
    AmbiguousNamedSelector {
        name: String,
        selector: String,
        count: usize,
    },
    #[error("invalid environment variable name {name:?}: {reason}")]
    InvalidEnvName { name: String, reason: &'static str },
    #[error("environment variable {name} is assigned by more than one --secret")]
    DuplicateEnvName { name: String },
    #[error("environment variable(s) already set: {}", .names.join(", "))]
    EnvCollision { names: Vec<String> },
    #[error("secret {selector} cannot be injected as an environment variable: {reason}")]
    SecretNotInjectable {
        selector: String,
        reason: &'static str,
    },
    #[error("failed to execute {command:?}: {source}")]
    ExecFailed {
        command: String,
        source: std::io::Error,
    },
    #[error("refusing to print private identity material to the terminal")]
    BundleSinkRequired,
    #[error("this operation needs confirmation but the session is not interactive")]
    ConfirmationRequired,
    #[error("no clipboard tool is available")]
    ClipboardUnavailable,
    #[error("failed to set git config {key}")]
    GitConfigFailed { key: String },
    #[error("no conflict matches {0:?}")]
    ConflictNotFound(String),
    #[error("no conflict candidate matches {0:?}")]
    ConflictCandidateNotFound(String),
    #[error("conflict candidate {0:?} is ambiguous")]
    AmbiguousConflictCandidate(String),
    #[error("secret {selector} is conflicted and has no current value")]
    SecretConflicted { selector: String },
    #[error("secret {selector} has no field {key:?}")]
    SecretFieldNotFound { selector: String, key: String },
}

/// Re-map a secret-access failure to a selector-aware error so the message can name the actual
/// path (`app/prod/db`) instead of a placeholder. Non-secret errors pass through unchanged.
pub fn map_secret_error(error: OpsError, selector: &str) -> FrontendError {
    match error {
        OpsError::SecretNotDecryptable(SecretState::NotEncryptedForReader) => {
            FrontendError::SecretStale {
                selector: selector.to_string(),
            }
        }
        OpsError::SecretNotDecryptable(SecretState::Unauthorized) => {
            FrontendError::SecretUnauthorized {
                selector: selector.to_string(),
            }
        }
        OpsError::SecretMissing => FrontendError::SecretNotFound {
            selector: selector.to_string(),
        },
        OpsError::SecretConflicted => FrontendError::SecretConflicted {
            selector: selector.to_string(),
        },
        other => FrontendError::Ops(other),
    }
}
