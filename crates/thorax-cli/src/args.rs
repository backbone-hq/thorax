use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct GitArgs {
    #[command(subcommand)]
    pub(crate) command: GitCommand,
}

#[derive(Subcommand)]
pub enum GitCommand {
    /// Register the git merge driver in this clone (.gitattributes + git config).
    Install,
}

#[derive(Args)]
pub struct MoveArgs {
    /// Current selector (the secret to move).
    #[arg(value_name = "FROM")]
    pub(crate) from: String,
    /// New selector (where to re-encrypt the value).
    #[arg(value_name = "TO")]
    pub(crate) to: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

/// `thorax conflicts` with no subcommand lists the unresolved conflicts; `resolve` picks a
/// winner.
#[derive(Args)]
pub struct ConflictsArgs {
    #[command(subcommand)]
    pub(crate) command: Option<ConflictsCommand>,
}

#[derive(Subcommand)]
pub enum ConflictsCommand {
    /// Resolve a conflict: re-sign the chosen candidate at a fresh counter.
    Resolve(ConflictResolveArgs),
    /// Accept a rollback: this machine forgets the higher counter it remembered for one
    /// key, trusting the currently visible state as-is. Gives up the tamper alarm for
    /// that key only; ties cannot be accepted.
    Accept(ConflictAcceptArgs),
}

#[derive(Args)]
pub struct ConflictAcceptArgs {
    /// The conflict to accept, as shown by `thorax conflicts`: a secret selector
    /// (app/prod/db) or the listed label (@handle, vault name, …).
    #[arg(value_name = "CONFLICT")]
    pub(crate) target: String,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would change without doing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct ConflictResolveArgs {
    /// Record hash (or unique prefix) of the winning candidate, from `thorax conflicts`.
    #[arg(value_name = "RECORD_HASH")]
    pub(crate) pick: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would change without doing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct MergeDriverArgs {
    /// Common-ancestor version of the vault (git %O; may be empty on add/add merges).
    #[arg(value_name = "ANCESTOR")]
    pub(crate) ancestor: PathBuf,
    /// Our version of the vault (git %A); receives the merged result.
    #[arg(value_name = "OURS")]
    pub(crate) ours: PathBuf,
    /// Their version of the vault (git %B).
    #[arg(value_name = "THEIRS")]
    pub(crate) theirs: PathBuf,
}

#[derive(Args)]
pub struct InitArgs {
    /// Handle to assign to the root user. Defaults to root.
    #[arg(long)]
    pub(crate) handle: Option<String>,
    /// Vault name. Defaults to the workspace directory name.
    #[arg(long)]
    pub(crate) name: Option<String>,
    /// Do not assign a root handle.
    #[arg(long, conflicts_with = "handle")]
    pub(crate) no_handle: bool,
    /// Do not assign a vault name.
    #[arg(long, conflicts_with = "name")]
    pub(crate) no_name: bool,
}

#[derive(Args)]
pub struct ListArgs {
    /// Classify access as this Thorax user. Defaults to the current user.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Filter secrets by path prefix (e.g. app/prod).
    #[arg(long)]
    pub(crate) selector: Option<String>,
    /// Filter secrets by label (k=v). Can be repeated.
    #[arg(long)]
    pub(crate) label: Vec<String>,
    /// Filter secrets by state: active, conflict.
    #[arg(long)]
    pub(crate) state: Option<String>,
    /// Output format: table (default), json, csv.
    #[arg(long)]
    pub(crate) format: Option<String>,
}

#[derive(Args)]
pub struct SecretShowArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Classify access as this Thorax user. Defaults to the current user.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

#[derive(Args)]
pub struct SecretSetArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Put a secret directly in argv (unsafe: shell history and process listings may expose it).
    #[arg(long = "value-unsafe", value_name = "VALUE", conflicts_with = "file")]
    pub(crate) positional_value: Option<String>,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Read secret bytes from a file.
    #[arg(long)]
    pub(crate) file: Option<PathBuf>,
    /// Label the write as a rotation in output. Every write already rekeys the secret.
    #[arg(long)]
    pub(crate) rotate: bool,
}

#[derive(Args)]
pub struct SecretGetArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Write plaintext to this file instead of the terminal.
    #[arg(long, value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
    /// Replace an existing --out file. Sensitive output otherwise uses create-new semantics.
    #[arg(long, requires = "out")]
    pub(crate) overwrite: bool,
    /// Copy plaintext to the system clipboard instead of the terminal.
    #[arg(long, conflicts_with = "out")]
    pub(crate) clipboard: bool,
    /// Print plaintext to an interactive terminal without the confirmation guard.
    #[arg(long)]
    pub(crate) force: bool,
}

/// `thorax field` manages a secret's *additional* key→value pairs. The primary value is set
/// and read with `thorax set` / `thorax get`; these operate only on the extra fields.
#[derive(Args)]
pub struct FieldArgs {
    #[command(subcommand)]
    pub(crate) command: FieldCommand,
}

#[derive(Subcommand)]
pub enum FieldCommand {
    /// List a secret's additional field keys.
    #[command(visible_alias = "ls")]
    List(FieldListArgs),
    /// Print one additional field's value.
    Get(FieldGetArgs),
    /// Set (insert or replace) one additional field, preserving the primary value and others.
    Set(FieldSetArgs),
    /// Remove one additional field, preserving the primary value and others.
    #[command(visible_alias = "rm")]
    Delete(FieldDeleteArgs),
}

#[derive(Args)]
pub struct FieldListArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Also print each field's value, not just its key.
    #[arg(long)]
    pub(crate) reveal: bool,
}

#[derive(Args)]
pub struct FieldGetArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Field key to print.
    #[arg(value_name = "KEY")]
    pub(crate) key: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Write the value to this file instead of the terminal.
    #[arg(long, value_name = "FILE")]
    pub(crate) out: Option<PathBuf>,
    /// Replace an existing --out file. Sensitive output otherwise uses create-new semantics.
    #[arg(long, requires = "out")]
    pub(crate) overwrite: bool,
    /// Copy the value to the system clipboard instead of the terminal.
    #[arg(long, conflicts_with = "out")]
    pub(crate) clipboard: bool,
    /// Print the value to an interactive terminal without the confirmation guard.
    #[arg(long)]
    pub(crate) force: bool,
}

#[derive(Args)]
pub struct FieldSetArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Field key to set.
    #[arg(value_name = "KEY")]
    pub(crate) key: String,
    /// Put a field value directly in argv (unsafe: shell history and process listings may expose it).
    #[arg(long = "value-unsafe", value_name = "VALUE", conflicts_with = "file")]
    pub(crate) positional_value: Option<String>,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Read the field value from a file.
    #[arg(long)]
    pub(crate) file: Option<PathBuf>,
}

#[derive(Args)]
pub struct FieldDeleteArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Field key to remove.
    #[arg(value_name = "KEY")]
    pub(crate) key: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(Args)]
pub struct SecretDeleteArgs {
    /// Selector path with optional labels, e.g. app/prod/db or app/prod/db@env=prod.
    #[arg(value_name = "PATH")]
    pub(crate) selector: String,
    /// Acting Thorax user ID as hex or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would change without doing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub(crate) command: TrustCommand,
}

#[derive(Subcommand)]
pub enum TrustCommand {
    /// Re-establish local trust from the current vault, accepting its state. Use this to
    /// deliberately proceed past a suspected rollback (e.g. an intentional historical checkout).
    Reset(TrustResetArgs),
    /// Remove an unrecoverable transaction barrier without editing any clone. The journal's
    /// stronger rollback facts are retained, so rollback conflicts may remain afterward.
    AbandonTransaction(TrustAbandonTransactionArgs),
}

#[derive(Args)]
pub struct TrustResetArgs {
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would be discarded without changing anything.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct TrustAbandonTransactionArgs {
    /// Confirm abandonment of the pending transaction.
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(Args)]
pub struct ClaimArgs {
    /// Path to the invite file your inviter gave you.
    #[arg(value_name = "INVITE_FILE")]
    pub(crate) invite_file: Option<PathBuf>,
    /// The `thrx1…` invitation string from your inviter (alternative to a file).
    #[arg(long)]
    pub(crate) invite: Option<String>,
}

#[derive(Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub(crate) command: UserCommand,
}

#[derive(Subcommand)]
pub enum UserCommand {
    /// Show the current default Thorax user.
    Current,
    /// Set the current default Thorax user.
    Use(UserUseArgs),
    /// List active users.
    List,
    /// Show a user's handles and authority summary.
    Show(UserShowArgs),
    /// Invite a new user and create a private invite.
    Invite(UserInviteArgs),
    /// Delete a user (restorable by re-inviting with the same seed).
    Delete(UserDeleteArgs),
    /// Manage user handles.
    Handle(UserHandleArgs),
}

#[derive(Args)]
pub struct UserUseArgs {
    /// User ID or handle to use by default for this vault.
    pub(crate) user: String,
}

#[derive(Args)]
pub struct UserShowArgs {
    /// User ID as hex or handle.
    pub(crate) user: String,
}

#[derive(Args)]
pub struct UserInviteArgs {
    /// Handle to assign to the invited user.
    pub(crate) handle: String,
    /// Admin user ID or handle used to sign the invite records.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Write the private invite to this file (recommended; deliver it securely).
    #[arg(long, value_name = "FILE")]
    pub(crate) invite_file: Option<PathBuf>,
    /// Print the private invite string to the terminal. Unsafe: it lands in scrollback/history.
    #[arg(long)]
    pub(crate) print_unsafe: bool,
    /// Show the invite as a scannable QR code (for onboarding someone on another device).
    #[arg(long)]
    pub(crate) qr: bool,
    /// Replace an existing invitation file. Sensitive output otherwise refuses overwrite.
    #[arg(long)]
    pub(crate) overwrite: bool,
    /// Omit the first-sync rollback baseline from every output (smaller, but trust-on-first-use).
    #[arg(long, conflicts_with = "with_rollback_baseline")]
    pub(crate) compact: bool,
    /// Include the rollback baseline in every output (text/QR may exceed their size limits).
    #[arg(long, conflicts_with = "compact")]
    pub(crate) with_rollback_baseline: bool,
    /// Grant read access on this selector prefix. Can be repeated.
    #[arg(long = "read")]
    pub(crate) read: Vec<String>,
    /// Grant write access on this selector prefix. Can be repeated.
    #[arg(long = "write")]
    pub(crate) write: Vec<String>,
    /// Grant manage access on this selector prefix. Can be repeated.
    #[arg(long = "manage")]
    pub(crate) manage: Vec<String>,
    /// Also grant vault-wide administration of users and groups.
    #[arg(long)]
    pub(crate) administer: bool,
}

#[derive(Args)]
pub struct UserDeleteArgs {
    /// User ID or handle to delete.
    pub(crate) user_ref: String,
    /// Admin user ID or handle used to sign the deletion.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Human-readable deletion reason.
    #[arg(long)]
    pub(crate) reason: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would change without doing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct UserHandleArgs {
    #[command(subcommand)]
    pub(crate) command: UserHandleCommand,
}

#[derive(Subcommand)]
pub enum UserHandleCommand {
    /// Assign or move a handle to a user.
    Set(UserHandleSetArgs),
}

#[derive(Args)]
pub struct UserHandleSetArgs {
    /// Handle to assign.
    pub(crate) handle: String,
    /// User ID or handle the handle should resolve to.
    #[arg(long)]
    pub(crate) target: String,
    /// Admin user ID or handle used to sign the handle record.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

#[derive(Args)]
pub struct GrantArgs {
    #[command(subcommand)]
    pub(crate) command: GrantCommand,
}

#[derive(Subcommand)]
pub enum GrantCommand {
    /// Grant read access to a user or group.
    Read(KeyspaceGrantArgs),
    /// Grant write access to a user or group.
    Write(KeyspaceGrantArgs),
    /// Grant access-management authority to a user or group.
    Manage(ManageGrantArgs),
    /// Grant vault-wide administration and all keyspace access.
    Admin(AdminGrantArgs),
    /// List active grants.
    List,
    /// Delete an active grant.
    Delete(GrantDeleteArgs),
}

#[derive(Args)]
pub struct KeyspaceGrantArgs {
    /// Subject: @handle or id for a user, or %group (e.g. @alice or %devs).
    #[arg(value_name = "SUBJECT")]
    pub(crate) subject: String,
    /// Keyspace to grant on. A path prefix (e.g. app/prod), or `*` / `/` for the whole vault.
    /// Selectors match by prefix by default (app/prod -> app/prod/*); use `--exact` to restrict to the exact path.
    #[arg(value_name = "SELECTOR")]
    pub(crate) selector: String,
    /// Acting Thorax user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Match only the exact selector instead of a prefix (default is prefix match).
    #[arg(long)]
    pub(crate) exact: bool,
}

#[derive(Args)]
pub struct ManageGrantArgs {
    /// Subject: @handle or id for a user, or %group (e.g. @alice or %devs).
    #[arg(value_name = "SUBJECT")]
    pub(crate) subject: String,
    /// Keyspace to grant on. A path prefix (e.g. app/prod), or `*` / `/` for the whole vault.
    /// Selectors match by prefix by default (app/prod -> app/prod/*); use `--exact` to restrict to the exact path.
    #[arg(value_name = "SELECTOR")]
    pub(crate) selector: String,
    /// Acting Thorax user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Match only the exact selector instead of a prefix (default is prefix match).
    #[arg(long)]
    pub(crate) exact: bool,
    /// Grantable classes, comma-separated. Defaults to read,write.
    #[arg(long, default_value = "read,write")]
    pub(crate) grantable: String,
}

#[derive(Args)]
pub struct AdminGrantArgs {
    /// Subject: @handle or id for a user, or %group (e.g. @alice or %devs).
    #[arg(value_name = "SUBJECT")]
    pub(crate) subject: String,
    /// Acting Thorax user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

#[derive(Args)]
pub struct GrantDeleteArgs {
    /// Grant ID (full hex or a unique short prefix).
    pub(crate) grant: String,
    /// Acting Thorax user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would change without doing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct GroupArgs {
    #[command(subcommand)]
    pub(crate) command: GroupCommand,
}

#[derive(Subcommand)]
pub enum GroupCommand {
    /// List active groups.
    List,
    /// Create a group.
    Create(GroupCreateArgs),
    /// Delete a group.
    Delete(GroupDeleteArgs),
    /// Add a user or group to a group.
    Add(GroupMemberArgs),
    /// Remove a user or group from a group.
    Remove(GroupMemberArgs),
}

#[derive(Args)]
pub struct GroupCreateArgs {
    /// Group display name.
    pub(crate) name: String,
    /// Admin user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

#[derive(Args)]
pub struct GroupDeleteArgs {
    /// Group ID or display name.
    pub(crate) group: String,
    /// Admin user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Show what would change without doing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
}

#[derive(Args)]
pub struct GroupMemberArgs {
    /// Group ID or display name.
    pub(crate) group: String,
    /// Subject: @handle or id for a user, or %group (e.g. @alice or %devs).
    pub(crate) member: String,
    /// Admin user ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

#[derive(Args)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub(crate) command: VaultCommand,
}

#[derive(Subcommand)]
pub enum VaultCommand {
    /// Show trusted root and vault names.
    Show,
    /// Manage vault names.
    Name(VaultNameArgs),
    /// Dump a vault file as human-readable text (for git textconv).
    Dump(CatArgs),
}

#[derive(Args)]
pub struct CatArgs {
    /// Path to the vault.cord file. Defaults to .thorax/vault.cord relative to --path.
    #[arg(default_value = ".thorax/vault.cord")]
    pub(crate) file: PathBuf,
    /// Attempt to decrypt secret values using the current vault's keychain.
    #[arg(long)]
    pub(crate) decrypt: bool,
}

#[derive(Args)]
pub struct VaultNameArgs {
    #[command(subcommand)]
    pub(crate) command: VaultNameCommand,
}

#[derive(Subcommand)]
pub enum VaultNameCommand {
    /// Assign or move a vault name.
    Set(VaultNameSetArgs),
}

#[derive(Args)]
pub struct VaultNameSetArgs {
    /// Vault name to assign.
    pub(crate) name: String,
    /// Admin user ID or handle used to sign the vault name record.
    #[arg(long)]
    pub(crate) user: Option<String>,
}

/// Generate shell completion scripts. Pipe the output into a completion file or eval the
/// shell config snippet printed on stderr:
///
/// Check for updates (`--check`) or update (`thorax update`) the thorax binary.
#[derive(Args)]
pub struct UpdateArgs {
    /// Check for a new version without downloading.
    #[arg(long)]
    pub(crate) check: bool,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
    /// Override the release repository (for testing).
    #[arg(long, hide = true)]
    pub(crate) repo: Option<String>,
}

///   thorax completions bash > /usr/local/share/bash-completion/completions/thorax
///   thorax completions zsh  > /usr/local/share/zsh/site-functions/_thorax
///   thorax completions fish > ~/.config/fish/completions/thorax.fish
///   thorax completions powershell > _thorax.ps1
///   thorax completions elvish  > thorax.elv
#[derive(Args)]
pub struct CompletionsArgs {
    /// Target shell (bash, zsh, fish, powershell, elvish).
    #[arg(value_name = "SHELL")]
    pub shell: clap_complete::Shell,
}

#[derive(Args)]
pub struct KubernetesArgs {
    #[command(subcommand)]
    pub(crate) command: KubernetesCommand,
}

#[derive(Subcommand)]
pub enum KubernetesCommand {
    /// Approve an in-cluster enrollment or trust-restoration request.
    Approve(KubernetesApproveArgs),
    /// Publish this workspace's encrypted vault to a ThoraxVault ConfigMap.
    Publish(KubernetesPublishArgs),
}

#[derive(Args)]
pub struct KubernetesApproveArgs {
    /// ThoraxVault name. Its active request is resolved from status.
    #[arg(value_name = "VAULT")]
    pub(crate) vault: String,
    /// Kubernetes namespace. Defaults to the kubeconfig context namespace.
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    /// Grant read access to a keyspace prefix. Repeat for multiple grants.
    #[arg(long = "read", value_name = "SELECTOR")]
    pub(crate) read: Vec<String>,
    /// Grant read access to exactly one tuple. Repeat for multiple grants.
    #[arg(long = "read-exact", value_name = "SELECTOR")]
    pub(crate) read_exact: Vec<String>,
    /// Existing Thorax identity this enrollment replaces.
    #[arg(long, value_name = "USER")]
    pub(crate) replaces_user: Option<String>,
    /// Acting Thorax administrator ID or handle.
    #[arg(long)]
    pub(crate) user: Option<String>,
    /// Skip the confirmation prompt.
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(Args)]
pub struct KubernetesPublishArgs {
    /// ThoraxVault name. Its immutable source determines the ConfigMap destination.
    #[arg(value_name = "VAULT")]
    pub(crate) vault: String,
    /// Kubernetes namespace. Defaults to the kubeconfig context namespace.
    #[arg(long)]
    pub(crate) namespace: Option<String>,
    /// Seconds to wait for the controller to observe and verify this exact revision.
    #[arg(
        long,
        default_value_t = 120,
        value_name = "SECONDS",
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub(crate) timeout: u64,
}
