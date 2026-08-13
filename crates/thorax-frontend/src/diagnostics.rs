//! Central error-presentation layer.
//!
//! Every failure the CLI can surface is mapped here to a [`Diagnostic`]: a stable
//! machine code, a human cause, an optional `next:` remediation hint, and a stable
//! process exit code. This is the single place that decides how errors look, so the
//! rest of the CLI never formats an error by hand and never leaks internal `Debug`.

use std::process::ExitCode;

use serde_json::json;
use thorax_ops::{
    KeychainError, OpsError, RecordKey, SecretState, StoreError, ValidationIssue, ValidationWarning,
};

use crate::FrontendError;

/// Stable exit-code taxonomy. These are part of the CLI's contract for scripts and CI.
///
/// Code 2 is deliberately absent: it is reserved for argument-parsing errors, which clap
/// reports (and exits with) itself before any command runs.
///
/// Report-style commands follow the grep convention: `thorax validate` and
/// `thorax conflicts` print their normal, success-shaped report to stdout and still exit
/// non-zero when there is something to act on — [`exit::TAMPERED`] when validation issues
/// exist, [`exit::CONFLICT`] when unresolved conflicts exist — so scripts can branch on the
/// exit code without parsing the report.
///
/// Codes 9–11 deliberately split three failures that demand different script reactions:
/// [`exit::CONFLICT`] means the *state* is contested and needs an authorized resolution,
/// [`exit::AMBIGUOUS`] means the *reference* matched more than one thing and needs to be more
/// specific, and [`exit::BUSY`] means another process holds the lock — transient, so retrying
/// (with backoff) is the right reaction, unlike 9 and 10 where a retry changes nothing.
pub mod exit {
    /// Catch-all failure.
    pub const GENERAL: u8 = 1;
    /// A requested object (workspace, secret, user, group, grant) does not exist.
    pub const NOT_FOUND: u8 = 3;
    /// The command line or an argument value was malformed.
    pub const INVALID_INPUT: u8 = 4;
    /// The vault failed verification: corruption, bad signature, or suspected rollback.
    pub const TAMPERED: u8 = 5;
    /// The acting identity lacks the authority for this operation.
    pub const UNAUTHORIZED: u8 = 6;
    /// The operation is blocked on a recoverable state (stale slots, rotation required).
    pub const NEEDS_REMEDIATION: u8 = 7;
    /// Identity selection or keychain release failed.
    pub const IDENTITY: u8 = 8;
    /// A domain conflict with existing state: a conflicted vault key with no effective
    /// winner (`secret_conflicted`, the `thorax conflicts` grep convention), an env-name
    /// collision in `thorax run`, or an already-initialized vault. Retrying does not help;
    /// the *state* needs an authorized resolution or a different request.
    pub const CONFLICT: u8 = 9;
    /// A reference or argument matched more than one thing (user/grant id prefix, group
    /// name, record-hash prefix, nested workspaces, a NAME= selector covering several
    /// secrets). Retrying does not help; the *reference* needs to be more specific.
    pub const AMBIGUOUS: u8 = 10;
    /// Another Thorax process holds the workspace lock. Transient and retryable — neither
    /// a conflict in the vault nor an ambiguous reference.
    pub const BUSY: u8 = 11;
    /// `thorax run` found the child command but could not execute it (shell convention).
    pub const COMMAND_NOT_EXECUTABLE: u8 = 126;
    /// `thorax run` could not find the child command (shell convention).
    pub const COMMAND_NOT_FOUND: u8 = 127;
}

/// A fully resolved, user-ready description of a failure.
pub struct Diagnostic {
    /// Stable, machine-readable code (snake_case). Safe for scripts to match on.
    pub code: &'static str,
    /// One-line human cause, with no internal type names or layer prefixes.
    pub message: String,
    /// Optional `next:` step the user can take to recover.
    pub hint: Option<String>,
    /// Process exit code from [`exit`].
    pub exit: u8,
}

impl Diagnostic {
    fn new(code: &'static str, exit: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            exit,
        }
    }

    fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// Print `error` to stderr (human or JSON) and return the matching process exit code.
pub fn emit(error: &FrontendError, json: bool) -> ExitCode {
    let diagnostic = diagnose(error);
    if json {
        let payload = json!({
            "error": {
                "code": diagnostic.code,
                "message": diagnostic.message,
                "hint": diagnostic.hint,
            }
        });
        eprintln!("{payload}");
    } else {
        eprintln!("thorax: {}", diagnostic.message);
        if let Some(hint) = &diagnostic.hint {
            eprintln!("  next: {hint}");
        }
    }
    ExitCode::from(diagnostic.exit)
}

/// Map any [`FrontendError`] to a [`Diagnostic`]. Public so tests can assert on codes/hints.
pub fn diagnose(error: &FrontendError) -> Diagnostic {
    match error {
        FrontendError::Ops(error) => diagnose_ops(error),
        FrontendError::Store(error) => diagnose_store(error),
        FrontendError::Keychain(error) => diagnose_keychain(error),
        FrontendError::Cord(error) => Diagnostic::new(
            "encoding",
            exit::TAMPERED,
            format!("the vault could not be decoded: {error}"),
        )
        .with_hint("the file may be corrupt or from an unsupported version; restore it from git"),
        FrontendError::Io { path, source } => Diagnostic::new(
            "io",
            exit::GENERAL,
            format!("cannot access {}: {source}", path.display()),
        ),
        FrontendError::InertInviteFile { path, source } => Diagnostic::new(
            "invite_commit_failed",
            diagnose_ops(source).exit,
            format!(
                "the vault did not accept the invitation, but an inert private file remains at {}: {source}",
                path.display()
            ),
        )
        .with_hint(format!(
            "delete {} before retrying; it does not identify a vault member",
            path.display()
        )),
        FrontendError::Stdio(source) => {
            Diagnostic::new("io", exit::GENERAL, format!("I/O error: {source}"))
        }
        FrontendError::ExternalService { service, message } => Diagnostic::new(
            "external_service",
            exit::GENERAL,
            format!("{service} request failed: {message}"),
        ),
        FrontendError::InvalidSelector { selector, reason } => Diagnostic::new(
            "invalid_selector",
            exit::INVALID_INPUT,
            format!("invalid selector {selector:?}: {reason}"),
        )
        .with_hint("selectors are slash-separated paths, e.g. app/prod/db"),
        FrontendError::InvalidHex { name, reason } => Diagnostic::new(
            "invalid_hex",
            exit::INVALID_INPUT,
            format!("invalid {name}: {reason}"),
        ),
        FrontendError::InvalidHexLength {
            name,
            expected,
            actual,
        } => Diagnostic::new(
            "invalid_hex",
            exit::INVALID_INPUT,
            format!("invalid {name}: expected {expected} bytes, got {actual}"),
        ),
        FrontendError::AmbiguousSecretInput => Diagnostic::new(
            "ambiguous_input",
            exit::INVALID_INPUT,
            "pass at most one of VALUE or --file",
        ),
        FrontendError::SecretInputTooLarge { max_bytes } => Diagnostic::new(
            "input_too_large",
            exit::INVALID_INPUT,
            format!("secret input exceeds the {max_bytes}-byte safety limit"),
        )
        .with_hint("split the value or provide a smaller secret"),
        FrontendError::AmbiguousIdentityBundle => Diagnostic::new(
            "ambiguous_input",
            exit::INVALID_INPUT,
            "pass exactly one of the string or file form",
        ),
        FrontendError::InvalidBundleString => Diagnostic::new(
            "invalid_bundle",
            exit::INVALID_INPUT,
            "the invitation string is malformed or its checksum failed",
        )
        .with_hint("re-copy the whole thrx1… string, or use the invitation file instead"),
        FrontendError::InviteTooLargeForString => Diagnostic::new(
            "invite_too_large_for_string",
            exit::INVALID_INPUT,
            "invitation is too large to display as text; use CLI --invite-file instead",
        )
        .with_hint("run `thorax user invite <handle> --invite-file <path>`"),
        FrontendError::WrongBundlePrefix(prefix) => Diagnostic::new(
            "invalid_bundle",
            exit::INVALID_INPUT,
            format!("that is not a Thorax invitation (prefix {prefix:?}; invitations are thrx1…)"),
        ),
        FrontendError::ValidationFailed(count) => Diagnostic::new(
            "validation_failed",
            exit::TAMPERED,
            format!(
                "the vault failed verification with {count} issue{}",
                plural(*count)
            ),
        )
        .with_hint("run `thorax validate` to see each issue"),
        FrontendError::NonUtf8Env(name) => Diagnostic::new(
            "invalid_env",
            exit::INVALID_INPUT,
            format!("environment variable {name} must be valid UTF-8"),
        ),
        FrontendError::InvalidHandle { handle, reason } => Diagnostic::new(
            "invalid_handle",
            exit::INVALID_INPUT,
            format!("invalid handle {handle:?}: {reason}"),
        ),
        FrontendError::MissingDefaultUser => Diagnostic::new(
            "no_default_user",
            exit::IDENTITY,
            "no default identity is set for this vault",
        )
        .with_hint(
            "set one with `thorax user use <handle>`, or pass --user for this command",
        ),
        FrontendError::GroupNotFound(group) => {
            Diagnostic::new("not_found", exit::NOT_FOUND, format!("no group {group:?}"))
                .with_hint("list groups with `thorax group list`")
        }
        FrontendError::AmbiguousGroup(group) => Diagnostic::new(
            "ambiguous",
            exit::AMBIGUOUS,
            format!("group name {group:?} matches more than one group"),
        )
        .with_hint("refer to it by id; see `thorax group list`"),
        FrontendError::GroupMemberNotFound => Diagnostic::new(
            "not_found",
            exit::NOT_FOUND,
            "that principal is not a member of the group",
        ),
        FrontendError::InvalidGrantable(value) => Diagnostic::new(
            "invalid_input",
            exit::INVALID_INPUT,
            format!("invalid grantable classes {value:?}"),
        )
        .with_hint("use a comma-separated subset of read,write,manage"),
        FrontendError::UserNotFound(value) => {
            Diagnostic::new("not_found", exit::NOT_FOUND, format!("no user matches {value:?}"))
                .with_hint("list users with `thorax user list`")
        }
        FrontendError::AmbiguousUser(value) => Diagnostic::new(
            "ambiguous",
            exit::AMBIGUOUS,
            format!("{value:?} matches more than one user"),
        )
        .with_hint("use a longer id prefix or the @handle"),
        FrontendError::GrantNotFound(value) => {
            Diagnostic::new("not_found", exit::NOT_FOUND, format!("no grant matches {value:?}"))
                .with_hint("list grants with `thorax grant list`")
        }
        FrontendError::AmbiguousGrant(value) => Diagnostic::new(
            "ambiguous",
            exit::AMBIGUOUS,
            format!("{value:?} matches more than one grant"),
        )
        .with_hint("use a longer id prefix; see `thorax grant list`"),
        FrontendError::SecretStale { selector } => Diagnostic::new(
            "not_encrypted",
            exit::NEEDS_REMEDIATION,
            format!("you are authorized for {selector} but the current value is not encrypted to you (unexpected)"),
        )
        .with_hint(format!(
            "ask someone who can write it to pipe a fresh value: printf '%s' \"$SECRET\" | thorax set {selector}"
        )),
        FrontendError::SecretUnauthorized { selector } => Diagnostic::new(
            "unauthorized",
            exit::UNAUTHORIZED,
            format!("you do not have read access to {selector}"),
        )
        .with_hint("ask an admin for a read grant on this selector"),
        FrontendError::SecretNotFound { selector } => Diagnostic::new(
            "not_found",
            exit::NOT_FOUND,
            format!("no secrets match {selector}"),
        )
        .with_hint("list secrets with `thorax list`"),
        FrontendError::SecretAlreadyExists { selector } => Diagnostic::new(
            "already_exists",
            exit::CONFLICT,
            format!("refusing to overwrite existing secret {selector}"),
        )
        .with_hint("delete the destination first, or choose a different destination selector"),
        FrontendError::SecretFieldNotFound { selector, key } => Diagnostic::new(
            "not_found",
            exit::NOT_FOUND,
            format!("secret {selector} has no field {key:?}"),
        )
        .with_hint("list a secret's fields with `thorax field ls <selector>`"),
        FrontendError::AmbiguousNamedSelector {
            name,
            selector,
            count,
        } => Diagnostic::new(
            "ambiguous_selection",
            exit::AMBIGUOUS,
            format!("{selector} matches {count} secrets, so it cannot all be one variable {name}"),
        )
        .with_hint("NAME= needs exactly one match; narrow the selector or drop the name"),
        FrontendError::InvalidEnvName { name, reason } => Diagnostic::new(
            "invalid_env_name",
            exit::INVALID_INPUT,
            format!("invalid environment variable name {name:?}: {reason}"),
        )
        .with_hint("names are letters, digits, and underscores, not starting with a digit"),
        FrontendError::DuplicateEnvName { name } => Diagnostic::new(
            "duplicate_env_name",
            exit::INVALID_INPUT,
            format!("more than one selected secret maps to the environment variable {name}"),
        )
        .with_hint("choose distinct explicit names: NAME=selector"),
        FrontendError::EnvCollision { names } => Diagnostic::new(
            "env_collision",
            exit::CONFLICT,
            format!(
                "refusing to overwrite existing environment variable{}: {}",
                plural(names.len()),
                names.join(", ")
            ),
        )
        .with_hint("re-run with --overwrite to replace, or rename with --secret NAME=selector"),
        FrontendError::SecretNotInjectable { selector, reason } => Diagnostic::new(
            "not_injectable",
            exit::INVALID_INPUT,
            format!("secret {selector} cannot be an environment variable: {reason}"),
        )
        .with_hint(format!(
            "write it to a file instead: thorax get {selector} --out <path>"
        )),
        FrontendError::ExecFailed { command, source } => {
            let (code, exit) = match source.kind() {
                std::io::ErrorKind::NotFound => ("command_not_found", exit::COMMAND_NOT_FOUND),
                _ => ("command_not_executable", exit::COMMAND_NOT_EXECUTABLE),
            };
            let diagnostic = Diagnostic::new(
                code,
                exit,
                format!("cannot run {command:?}: {source}"),
            );
            if source.kind() == std::io::ErrorKind::NotFound {
                diagnostic.with_hint("check the command name and PATH; thorax run does not invoke a shell")
            } else {
                diagnostic
            }
        }
        FrontendError::BundleSinkRequired => Diagnostic::new(
            "bundle_sink_required",
            exit::INVALID_INPUT,
            "refusing to print private identity material to the terminal",
        )
        .with_hint("write it to a file with --invite-file <path>, or pass --print-unsafe to print it anyway"),
        FrontendError::ConfirmationRequired => Diagnostic::new(
            "confirmation_required",
            exit::INVALID_INPUT,
            "this is a destructive operation and the session cannot prompt for confirmation",
        )
        .with_hint("re-run with --yes to confirm, or --dry-run to preview"),
        FrontendError::ClipboardUnavailable => Diagnostic::new(
            "clipboard_unavailable",
            exit::GENERAL,
            "no clipboard tool was found (tried wl-copy, xclip, xsel, pbcopy)",
        )
        .with_hint("install one, or use --out <file> instead"),
        FrontendError::GitConfigFailed { key } => Diagnostic::new(
            "git_config_failed",
            exit::GENERAL,
            format!("failed to set git config {key}"),
        )
        .with_hint("check that git is installed and this workspace is inside a git repository"),
        FrontendError::ConflictNotFound(target) => Diagnostic::new(
            "conflict_not_found",
            exit::NOT_FOUND,
            format!("no conflict matches {target:?}"),
        )
        .with_hint("list the current conflicts and their labels with `thorax conflicts`"),
        FrontendError::ConflictCandidateNotFound(pick) => Diagnostic::new(
            "conflict_candidate_not_found",
            exit::INVALID_INPUT,
            format!("no conflict candidate matches {pick:?}"),
        )
        .with_hint("list the current conflicts and their candidate hashes with `thorax conflicts`"),
        FrontendError::AmbiguousConflictCandidate(pick) => Diagnostic::new(
            "ambiguous_conflict_candidate",
            exit::AMBIGUOUS,
            format!("conflict candidate {pick:?} matches more than one record"),
        )
        .with_hint("use more characters of the record hash from `thorax conflicts`"),
        FrontendError::SecretConflicted { selector } => Diagnostic::new(
            "secret_conflicted",
            exit::CONFLICT,
            format!("secret {selector} is conflicted and has no current value"),
        )
        .with_hint("inspect and resolve it with `thorax conflicts` / `thorax conflicts resolve <record-hash>`, or set a fresh value"),
    }
}

fn diagnose_ops(error: &OpsError) -> Diagnostic {
    match error {
        OpsError::Store(error) => diagnose_store(error),
        OpsError::Keychain(error) => diagnose_keychain(error),
        OpsError::Core(error) => Diagnostic::new(
            "core",
            exit::GENERAL,
            format!("internal validation error: {error}"),
        ),
        OpsError::Crypto(error) => {
            Diagnostic::new("crypto", exit::GENERAL, format!("crypto error: {error}"))
        }
        OpsError::Cord(error) => Diagnostic::new(
            "encoding",
            exit::TAMPERED,
            format!("the vault could not be decoded: {error}"),
        ),
        OpsError::Hazmat(error) => {
            Diagnostic::new("crypto", exit::GENERAL, format!("crypto error: {error}"))
        }
        OpsError::VaultAlreadyInitialized(path) => Diagnostic::new(
            "already_initialized",
            exit::CONFLICT,
            format!("a Thorax vault already exists at {}", path.display()),
        )
        .with_hint("use the existing vault, or remove .thorax to start over"),
        OpsError::MissingRatchet(path) => Diagnostic::new(
            "no_ratchet",
            exit::IDENTITY,
            format!("this machine has no trust state for this vault ({})", path.display()),
        )
        .with_hint("join this vault with `thorax claim <invite>`"),
        OpsError::NotAVaultMember(user) => Diagnostic::new(
            "not_a_member",
            exit::IDENTITY,
            format!(
                "identity {} unlocked, but it is not an effective member of this vault",
                crate::user_hex(user)
            ),
        )
        .with_hint(
            "the vault may have been substituted or your membership removed; \
             re-join with `thorax claim <invite>`",
        ),
        OpsError::ValidationFailed(issues) => Diagnostic::new(
            "validation_failed",
            exit::TAMPERED,
            format!(
                "the vault failed verification with {} issue{}: {}",
                issues.len(),
                plural(issues.len()),
                issues
                    .iter()
                    .map(describe_issue)
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        )
        .with_hint("run `thorax validate` for details; restore from git if it was tampered with"),
        OpsError::OperationNotEffective(reason) => Diagnostic::new(
            "not_effective",
            exit::UNAUTHORIZED,
            format!("the change would not take effect: {reason}"),
        )
        .with_hint("check that the acting user still has the required authority"),
        OpsError::MissingEffectiveRoot => Diagnostic::new(
            "no_root",
            exit::TAMPERED,
            "the vault has no verifiable root record",
        )
        .with_hint("the file may be corrupt; restore it from git"),
        OpsError::MissingTrustedRootCandidate => Diagnostic::new(
            "no_root",
            exit::TAMPERED,
            "the vault has no self-signed root to anchor trust",
        ),
        OpsError::AmbiguousTrustedRootCandidates(_) => Diagnostic::new(
            "ambiguous_root",
            exit::TAMPERED,
            "the vault contains more than one self-signed root",
        ),
        OpsError::SecretMissing => {
            Diagnostic::new("not_found", exit::NOT_FOUND, "no such secret")
                .with_hint("list secrets with `thorax list`")
        }
        OpsError::SecretNotDecryptable(state) => diagnose_secret_state(state),
        OpsError::SecretNotWritable => Diagnostic::new(
            "unauthorized",
            exit::UNAUTHORIZED,
            "you do not have write access to this secret",
        )
        .with_hint("ask an admin for a write grant on this selector"),
        OpsError::RecipientSlotMissing(_) => {
            Diagnostic::new(
                "stale_secret",
                exit::NEEDS_REMEDIATION,
                "this secret's recipients no longer match current access",
            )
            .with_hint("pipe a fresh value to re-encrypt it: printf '%s' \"$SECRET\" | thorax set <selector>")
        }
        OpsError::MissingReaderUser(user)
        | OpsError::MissingWriterUser(user)
        | OpsError::MissingUser(user) => Diagnostic::new(
            "missing_user",
            exit::TAMPERED,
            format!("user {} has no active record in the vault", crate::user_hex(user)),
        ),
        OpsError::UserHandleNotFound(handle) => Diagnostic::new(
            "not_found",
            exit::NOT_FOUND,
            format!("no user with handle @{handle}"),
        )
        .with_hint("list users with `thorax user list`"),
        OpsError::UserHandleTargetMissing { handle, .. } => Diagnostic::new(
            "dangling_handle",
            exit::TAMPERED,
            format!("handle @{handle} points to a user that no longer exists"),
        ),
        OpsError::InvalidUserHandle { handle, reason }
        | OpsError::InvalidVaultHandle { handle, reason }
        | OpsError::InvalidGroupHandle { handle, reason } => Diagnostic::new(
            "invalid_handle",
            exit::INVALID_INPUT,
            format!("invalid name {handle:?}: {reason}"),
        ),
        OpsError::AdministerRequired(_) => Diagnostic::new(
            "unauthorized",
            exit::UNAUTHORIZED,
            "this operation requires administration authority",
        )
        .with_hint("ask an admin to run it, or to grant you `administer`"),
        OpsError::CannotConferGroupAuthority(_) => Diagnostic::new(
            "unauthorized",
            exit::UNAUTHORIZED,
            "you cannot add this member: the group confers access you could not grant directly",
        )
        .with_hint("you can only add members to a group whose permissions you could grant yourself"),
        OpsError::KeychainIdentityMismatch { .. } => Diagnostic::new(
            "identity_mismatch",
            exit::IDENTITY,
            "the unlocked identity does not match the requested user",
        ),
        OpsError::ClaimNotAMember(_) => Diagnostic::new(
            "not_a_member",
            exit::UNAUTHORIZED,
            "this identity is not a current member of this vault",
        )
        .with_hint("check you are in the right repository; you may also have been removed, or the invite may be for a different vault — ask your inviter"),
        OpsError::ClaimRolledBack => Diagnostic::new(
            "rolled_back",
            exit::TAMPERED,
            "this vault is missing a removal your invite expected — it may have been rolled back",
        )
        .with_hint("do not proceed; verify the repository state with whoever invited you"),
        OpsError::InviteRootMismatch => Diagnostic::new(
            "invite_root_mismatch",
            exit::TAMPERED,
            "this invitation is for a different vault",
        )
        .with_hint("open the repository named by your inviter; do not claim against this vault"),
        OpsError::InviteRollbackBaselineRequired => Diagnostic::new(
            "invite_baseline_required",
            exit::TAMPERED,
            "this non-interactive first use requires a rollback-protected invitation",
        )
        .with_hint("provision a full `.thrxi` invitation instead of a compact text invitation"),
        OpsError::ConflictCandidateNotFound(hash) => Diagnostic::new(
            "conflict_candidate_not_found",
            exit::INVALID_INPUT,
            format!(
                "no unresolved conflict has a candidate with record hash {}",
                crate::render::hash_hex(hash)
            ),
        )
        .with_hint("list the current conflicts and their candidate hashes with `thorax conflicts`"),
        OpsError::ConflictNotResolvable(reason) => Diagnostic::new(
            "conflict_not_resolvable",
            exit::UNAUTHORIZED,
            format!("this conflict cannot be resolved: {reason}"),
        )
        .with_hint(
            "the key stays conflicted (no effective value) until a user with the required authority resolves it",
        ),
        OpsError::SecretConflicted => Diagnostic::new(
            "secret_conflicted",
            exit::CONFLICT,
            "this secret is conflicted and has no current value",
        )
        .with_hint("inspect and resolve it with `thorax conflicts` / `thorax conflicts resolve <record-hash>`, or set a fresh value"),
        OpsError::CounterExhausted => Diagnostic::new(
            "counter_exhausted",
            exit::TAMPERED,
            "the vault's version counter is exhausted — a record carries an absurdly high counter, which no legitimate client produces",
        )
        .with_hint("the vault was tampered with; restore .thorax/vault.cord from git history"),
        OpsError::InvalidSecretPlaintext => Diagnostic::new(
            "invalid_secret_plaintext",
            exit::TAMPERED,
            "the decrypted secret payload has an invalid or unsupported Thorax framing",
        )
        .with_hint("do not use the value; restore or rotate this secret with a current Thorax client"),
        OpsError::InvalidJoinCandidate(reason) => Diagnostic::new(
            "invalid_join_candidate",
            exit::TAMPERED,
            format!("the Kubernetes join request is invalid: {reason}"),
        ),
        OpsError::JoinRootMismatch => Diagnostic::new(
            "join_root_mismatch",
            exit::TAMPERED,
            "the Kubernetes join request names a different Thorax root",
        ),
        OpsError::JoinApprovalMismatch => Diagnostic::new(
            "join_approval_mismatch",
            exit::TAMPERED,
            "the Kubernetes join approval does not match its signed request",
        ),
        OpsError::JoinPlanStale => Diagnostic::new(
            "join_plan_stale",
            exit::CONFLICT,
            "the Thorax vault changed while the Kubernetes approval was being created",
        )
        .with_hint("reload the request and approve it again"),
        OpsError::JoinRecoveryConflict => Diagnostic::new(
            "join_recovery_conflict",
            exit::CONFLICT,
            "a prepared Kubernetes enrollment cannot be reconciled with the current local vault state",
        )
        .with_hint("preserve the join-commit journal and inspect the vault/ratchet state before retrying"),
        OpsError::PendingTransaction {
            transaction_id,
            origin,
        } => Diagnostic::new(
            "pending_transaction",
            exit::CONFLICT,
            format!(
                "transaction {transaction_id} from {origin} blocks writes for this vault"
            ),
        )
        .with_hint("run Thorax in the originating workspace to recover it, or explicitly abandon it after unlocking a root-bound identity"),
        OpsError::TransactionRecoveryConflict => Diagnostic::new(
            "transaction_recovery_conflict",
            exit::CONFLICT,
            "transaction recovery found unexpected vault or ratchet bytes",
        )
        .with_hint("preserve the transaction journal and inspect the vault and local ratchet; Thorax did not guess or overwrite the third state"),
        OpsError::TransactionPreconditionChanged(file) => Diagnostic::new(
            "transaction_precondition_changed",
            exit::CONFLICT,
            format!("the {file} changed before the transaction could commit"),
        )
        .with_hint("reload the workspace and retry the operation"),
        OpsError::NoPendingTransaction => Diagnostic::new(
            "no_pending_transaction",
            exit::NOT_FOUND,
            "there is no pending transaction for this vault",
        ),
        OpsError::MultipleRecoveryTransactions => Diagnostic::new(
            "multiple_recovery_transactions",
            exit::CONFLICT,
            "both legacy and current recovery journals exist for this vault",
        )
        .with_hint("preserve both files for diagnosis; Thorax will not guess which transaction supersedes the other"),
    }
}

fn diagnose_secret_state(state: &SecretState) -> Diagnostic {
    match state {
        SecretState::NotEncryptedForReader => Diagnostic::new(
            "not_encrypted",
            exit::NEEDS_REMEDIATION,
            "you are authorized for this secret but the current value is not encrypted to you (unexpected)",
        )
        .with_hint("ask someone who can write it to pipe a fresh value: printf '%s' \"$SECRET\" | thorax set <selector>"),
        SecretState::Unauthorized => Diagnostic::new(
            "unauthorized",
            exit::UNAUTHORIZED,
            "you do not have read access to this secret",
        )
        .with_hint("ask an admin for a read grant on this selector"),
        SecretState::Missing => {
            Diagnostic::new("not_found", exit::NOT_FOUND, "no such secret")
        }
        SecretState::Conflicted => Diagnostic::new(
            "secret_conflicted",
            exit::CONFLICT,
            "this secret is conflicted and has no current value",
        )
        .with_hint("inspect and resolve it with `thorax conflicts` / `thorax conflicts resolve <record-hash>`, or set a fresh value"),
        SecretState::Invalid => Diagnostic::new(
            "invalid_record",
            exit::TAMPERED,
            "the stored secret record is invalid",
        ),
        SecretState::ActiveDecryptable => Diagnostic::new(
            "internal",
            exit::GENERAL,
            "the secret is decryptable but release failed",
        ),
    }
}

fn diagnose_store(error: &StoreError) -> Diagnostic {
    match error {
        StoreError::Io { path, source } => Diagnostic::new(
            "io",
            exit::GENERAL,
            format!("cannot access {}: {source}", path.display()),
        ),
        StoreError::VaultMissing(path) => Diagnostic::new(
            "no_workspace",
            exit::NOT_FOUND,
            format!("no Thorax vault at {}", path.display()),
        )
        .with_hint("create one with `thorax init`"),
        StoreError::InvalidVault { path, source } => Diagnostic::new(
            "corrupt_vault",
            exit::TAMPERED,
            format!("the vault at {} is invalid: {source}", path.display()),
        )
        .with_hint("the file may be corrupt or tampered with; restore it from git"),
        StoreError::Cord(error) | StoreError::InvalidRatchet { source: error, .. } => {
            Diagnostic::new(
                "encoding",
                exit::TAMPERED,
                format!("a Thorax file could not be decoded: {error}"),
            )
        }
        StoreError::InvalidTransaction { path, .. } => Diagnostic::new(
            "invalid_transaction",
            exit::TAMPERED,
            format!("recovery transaction at {} is invalid", path.display()),
        )
        .with_hint("preserve the file for diagnosis; do not remove it manually"),
        StoreError::TransactionPending(path) => Diagnostic::new(
            "pending_transaction",
            exit::CONFLICT,
            format!("a transaction at {} blocks rollback-state writes", path.display()),
        )
        .with_hint("recover it in the originating workspace or explicitly abandon it after unlocking a root-bound identity"),
        StoreError::Core(error) => {
            Diagnostic::new("core", exit::GENERAL, format!("internal error: {error}"))
        }
        StoreError::WorkspaceNotFound(path) => Diagnostic::new(
            "no_workspace",
            exit::NOT_FOUND,
            format!("no Thorax workspace found from {}", path.display()),
        )
        .with_hint("run `thorax init` here, or point at one with --path"),
        StoreError::AmbiguousWorkspace { nested, parent, .. } => Diagnostic::new(
            "ambiguous_workspace",
            exit::AMBIGUOUS,
            format!(
                "found nested workspaces ({} and {})",
                nested.display(),
                parent.display()
            ),
        )
        .with_hint("choose one explicitly with --path"),
        StoreError::MissingThoraxDir(path) => Diagnostic::new(
            "no_workspace",
            exit::NOT_FOUND,
            format!("{} has no .thorax directory", path.display()),
        )
        .with_hint("run `thorax init` to create one"),
        StoreError::LockAlreadyHeld(path) => Diagnostic::new(
            "locked",
            exit::BUSY,
            format!(
                "another Thorax process holds the lock at {}",
                path.display()
            ),
        )
        .with_hint("wait for the active operation to finish; lock ownership is released automatically if its process exits"),
        StoreError::TrustRootMismatch { .. } => Diagnostic::new(
            "trust_root_mismatch",
            exit::TAMPERED,
            "this vault's root does not match the trust state on this machine",
        )
        .with_hint("this can indicate a substituted vault; verify before proceeding"),
    }
}

fn diagnose_keychain(error: &KeychainError) -> Diagnostic {
    match error {
        KeychainError::Store(error) => diagnose_store(error),
        KeychainError::Crypto(error) => {
            Diagnostic::new("crypto", exit::GENERAL, format!("crypto error: {error}"))
        }
        KeychainError::Cord(error) => Diagnostic::new(
            "encoding",
            exit::TAMPERED,
            format!("an identity file could not be decoded: {error}"),
        ),
        KeychainError::Io { path, source } => Diagnostic::new(
            "io",
            exit::GENERAL,
            format!("cannot access {}: {source}", path.display()),
        ),
        KeychainError::IdentityNotFound { user_id } => Diagnostic::new(
            "no_identity",
            exit::IDENTITY,
            format!(
                "no private identity stored for {}",
                crate::user_hex(user_id)
            ),
        )
        .with_hint("re-join with `thorax claim <invite>` to store your identity"),
        KeychainError::InvalidIdentity { .. } => Diagnostic::new(
            "invalid_identity",
            exit::IDENTITY,
            "the stored identity material is inconsistent",
        ),
        KeychainError::UnlockFailed => Diagnostic::new(
            "unlock_failed",
            exit::IDENTITY,
            "could not unlock the identity keychain",
        )
        .with_hint("check the passphrase and try again"),
        KeychainError::PassphraseProvider(reason) => Diagnostic::new(
            "passphrase",
            exit::IDENTITY,
            format!("could not read a passphrase: {reason}"),
        ),
        KeychainError::PassphraseMismatch => Diagnostic::new(
            "passphrase_mismatch",
            exit::IDENTITY,
            "the passphrases did not match",
        ),
        KeychainError::IdentityProvider(reason) => Diagnostic::new(
            "identity_provider",
            exit::IDENTITY,
            format!("identity input failed: {reason}"),
        ),
        KeychainError::BackendUnavailable { backend, reason } => Diagnostic::new(
            "keychain_unavailable",
            exit::IDENTITY,
            format!("the {backend} identity store is unavailable: {reason}"),
        ),
        KeychainError::InvalidKdfParameters => Diagnostic::new(
            "invalid_keychain",
            exit::IDENTITY,
            "the identity keychain has invalid key-derivation parameters",
        ),
        KeychainError::Argon2(reason) => Diagnostic::new(
            "kdf",
            exit::IDENTITY,
            format!("passphrase key derivation failed: {reason}"),
        ),
        KeychainError::NoKeychainAvailable { .. } => Diagnostic::new(
            "no_keychain",
            exit::IDENTITY,
            "no safe identity store is available on this machine",
        )
        .with_hint("configure an OS keychain or passphrase keychain before releasing plaintext"),
        KeychainError::InvalidFile { path, reason } => Diagnostic::new(
            "invalid_keychain",
            exit::TAMPERED,
            format!("identity state at {} is invalid: {reason}", path.display()),
        )
        .with_hint("preserve the file and restore it from a trusted backup; Thorax will not overwrite conflicting identity state"),
        KeychainError::LockTimeout(path) => Diagnostic::new(
            "keychain_busy",
            exit::GENERAL,
            format!("timed out waiting for identity state at {}", path.display()),
        )
        .with_hint("wait for the other Thorax process to finish and retry"),
    }
}

/// Human, non-`Debug` description of a single validation issue.
pub fn describe_issue(issue: &ValidationIssue) -> String {
    match issue {
        ValidationIssue::InvalidStructure(detail) => format!("malformed record: {detail}"),
        ValidationIssue::InvalidSignature(key) => {
            format!("invalid signature on {}", describe_record_key(key))
        }
        ValidationIssue::UnknownSignerKey(key) => format!(
            "a record is signed with key {}, which no introduced identity holds",
            crate::short_hash(key)
        ),
        ValidationIssue::RootNotTrusted => {
            "the vault root is not the one trusted on this machine".to_string()
        }
        ValidationIssue::AmbiguousRoot => "the vault has more than one candidate root".to_string(),
        ValidationIssue::AuthorityDidNotConverge => {
            "the authority graph could not be resolved against the root".to_string()
        }
        ValidationIssue::FormatVersionRegression {
            remembered,
            current,
        } => format!(
            "the vault uses format version {current}, but this machine has already verified \
             version {remembered} for this root — a newer vault re-wrapped in an older envelope \
             is a downgrade, not an honest state"
        ),
    }
}

/// Human description of a single validation warning — surfaced by status/validate views,
/// never a reason to refuse an operation.
pub fn describe_warning(warning: &ValidationWarning) -> String {
    match warning {
        ValidationWarning::UnknownRecords { count } => format!(
            "{} were written by a newer thorax and are inert for this build \
             (preserved, not used) — upgrade thorax to read them",
            crate::count_noun(*count, "record")
        ),
        ValidationWarning::AmbiguousSigningKey(key) => format!(
            "signing key {} is claimed by more than one attested identity — the key holder \
             self-collided; records signed by that key are inert, the rest of the vault is fine",
            crate::short_hash(key)
        ),
    }
}

fn describe_record_key(key: &RecordKey) -> String {
    match key {
        RecordKey::VaultRoot => "the root record".to_string(),
        RecordKey::EntryPoint { user_id, .. } => {
            format!(
                "an entry-point record for user {}",
                crate::short_user_hex(user_id)
            )
        }
        RecordKey::User { user_id } => {
            format!("the record for user {}", crate::short_user_hex(user_id))
        }
        RecordKey::UserHandle { handle_id } => {
            format!("a handle record ({})", crate::short_hash(&handle_id.0))
        }
        RecordKey::Group { group_id } => format!("group {}", crate::short_hash(&group_id.0)),
        RecordKey::GroupMember { group_member_id } => {
            format!("group membership {}", crate::short_hash(&group_member_id.0))
        }
        RecordKey::Grant { grant_id } => format!("grant {}", crate::short_hash(&grant_id.0)),
        RecordKey::Secret { secret_id } => {
            format!("secret record {}", crate::short_hash(&secret_id.0))
        }
        RecordKey::VaultHandle { handle_id } => {
            format!("a vault-name record ({})", crate::short_hash(&handle_id.0))
        }
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn workspace_not_found_is_actionable() {
        let diag = diagnose(&FrontendError::Store(StoreError::WorkspaceNotFound(
            PathBuf::from("/tmp/x"),
        )));
        assert_eq!(diag.code, "no_workspace");
        assert_eq!(diag.exit, exit::NOT_FOUND);
        assert!(diag.hint.as_deref().unwrap().contains("thorax init"));
        assert!(!diag.message.contains("store error"));
    }

    #[test]
    fn not_encrypted_secret_suggests_reset() {
        let diag = diagnose(&FrontendError::Ops(OpsError::SecretNotDecryptable(
            SecretState::NotEncryptedForReader,
        )));
        assert_eq!(diag.code, "not_encrypted");
        assert_eq!(diag.exit, exit::NEEDS_REMEDIATION);
        assert!(diag.hint.as_deref().unwrap().contains("thorax set"));
        assert!(diag.message.contains("authorized"));
    }

    #[test]
    fn conflict_ambiguity_and_lock_contention_have_distinct_exit_codes() {
        // Domain conflict: the state is contested — stays on CONFLICT.
        let conflicted = diagnose(&FrontendError::Ops(OpsError::SecretConflicted));
        assert_eq!(conflicted.exit, exit::CONFLICT);

        // Ambiguous reference: the argument matched more than one thing.
        let ambiguous = diagnose(&FrontendError::AmbiguousUser("ab".into()));
        assert_eq!(ambiguous.exit, exit::AMBIGUOUS);
        let ambiguous_prefix = diagnose(&FrontendError::AmbiguousConflictCandidate("ab".into()));
        assert_eq!(ambiguous_prefix.exit, exit::AMBIGUOUS);

        // Lock contention: transient and retryable.
        let busy = diagnose(&FrontendError::Store(StoreError::LockAlreadyHeld(
            PathBuf::from("/tmp/x/.thorax/vault.cord.lock"),
        )));
        assert_eq!(busy.code, "locked");
        assert_eq!(busy.exit, exit::BUSY);
    }

    #[test]
    fn validation_issues_have_no_debug_formatting() {
        let message = describe_issue(&ValidationIssue::RootNotTrusted);
        assert!(!message.contains("RootNotTrusted"));
        assert!(message.contains("root"));
    }
}
