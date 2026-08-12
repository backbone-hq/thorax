use std::{path::PathBuf, process::ExitCode};

use clap::Subcommand;
use thorax_frontend::{
    build_keychain, maybe_bootstrap_ci_trust, open_session, open_valid_session,
    recover_workspace_if_present, resolve_cli_user_ref_with_report,
    resolve_optional_cli_user_ref_with_report, CliUser, FrontendError, GlobalArgs,
};
use thorax_ops::{Crypto, KeyUsePurpose, LockedSession, UnlockedSession};

mod access;
mod args;
mod conflicts;
mod kubernetes;
mod merge;
mod output;
mod secrets;
mod trust;
mod update;
mod users;
mod vault;
mod vault_cat;

pub use access::GrantKind;
pub use args::*;

use access::{cmd_grant, cmd_group};
use conflicts::cmd_conflicts;
use kubernetes::cmd_kubernetes;
use merge::{cmd_git, cmd_merge_driver};
use secrets::{
    cmd_field, cmd_list, cmd_secret_delete, cmd_secret_get, cmd_secret_move, cmd_secret_set,
    cmd_show,
};
use trust::cmd_trust;
use update::cmd_update;
use users::{cmd_claim, cmd_user};
use vault::{cmd_init, cmd_status, cmd_validate, cmd_vault};

/// Run the `thorax` CLI surface — every subcommand except the bare TUI and `run`, which the
/// umbrella binary dispatches to their own crates. Global flags and the parsed subcommand arrive
/// already decoded from the top-level parser.
pub fn run_cli(global: GlobalArgs, command: Command) -> Result<ExitCode, FrontendError> {
    let GlobalArgs { path, json } = global;
    let ctx = CliContext { path, json };
    if !matches!(command, Command::MergeDriver(_))
        && recover_workspace_if_present(ctx.path.as_ref())?
    {
        eprintln!("recovered an interrupted Thorax transaction in this workspace");
    }
    let show_update_notice = !ctx.json && command.allows_passive_update_notice();
    // Commands that read an existing workspace need local trust. In CI identity mode, establish it
    // from the injected bundle first. init/claim manage trust themselves; trust-reset must run even
    // when the rollback check would otherwise fail.
    // The merge driver is also excluded: git invokes it on arbitrary temp files mid-merge,
    // and it must never mutate local trust as a side effect.
    if !matches!(
        command,
        Command::Init(_)
            | Command::Claim(_)
            | Command::Trust(_)
            | Command::MergeDriver(_)
            | Command::Update(_)
    ) {
        maybe_bootstrap_ci_trust(ctx.path.as_ref())?;
    }
    let result = match command {
        Command::Init(args) => cmd_init(&ctx, args),
        Command::Status => cmd_status(&ctx),
        Command::Validate => cmd_validate(&ctx),
        Command::List(args) => cmd_list(&ctx, args),
        Command::Show(args) => cmd_show(&ctx, args),
        Command::Set(args) => cmd_secret_set(&ctx, args),
        Command::Get(args) => cmd_secret_get(&ctx, args),
        Command::Delete(args) => cmd_secret_delete(&ctx, args),
        Command::Move(args) => cmd_secret_move(&ctx, args),
        Command::Field(args) => cmd_field(&ctx, args.command),
        Command::Grant(args) => cmd_grant(&ctx, args.command),
        Command::Group(args) => cmd_group(&ctx, args.command),
        Command::Claim(args) => cmd_claim(&ctx, args),
        Command::User(args) => cmd_user(&ctx, args.command),
        Command::Vault(args) => cmd_vault(&ctx, args.command),
        Command::Trust(args) => cmd_trust(&ctx, args.command),
        Command::Conflicts(args) => cmd_conflicts(&ctx, args.command),
        Command::Git(args) => cmd_git(&ctx, args.command),
        Command::MergeDriver(args) => cmd_merge_driver(&ctx, args),
        Command::Kubernetes(args) => cmd_kubernetes(&ctx, args.command),
        Command::Update(args) => cmd_update(&ctx, args),
    };
    if show_update_notice && result.is_ok() {
        if let Some(notice) = thorax_update::passive_update_notice(None) {
            eprintln!("{notice}");
        }
    }
    result
}

pub struct CliContext {
    pub(crate) path: Option<PathBuf>,
    pub(crate) json: bool,
}

impl CliContext {
    /// This command's one workspace resolution + vault load + validation. The session is
    /// returned even when validation found issues, so status/validate can render them.
    pub(crate) fn session(&self) -> Result<LockedSession, FrontendError> {
        open_session(self.path.as_ref())
    }

    /// [`CliContext::session`], failing on any validation issue — the standard prologue for
    /// commands that operate on a valid vault.
    pub(crate) fn valid_session(&self) -> Result<LockedSession, FrontendError> {
        open_valid_session(self.path.as_ref())
    }

    /// The standard prologue for action commands under the unlock-first posture: load a
    /// valid session, resolve the acting user (the explicit `--user` value or the stored
    /// default), and promote through the keychain funnel with the command-specific
    /// purpose — the prompt names the command. The operation then runs on the anchored
    /// [`UnlockedSession`] with no second unlock.
    pub(crate) fn unlock_for_action(
        &self,
        user: Option<&str>,
        purpose: KeyUsePurpose,
    ) -> Result<(UnlockedSession, CliUser), FrontendError> {
        self.promote_for_action(self.valid_session()?, user, purpose)
    }

    /// [`CliContext::unlock_for_action`] for commands that already loaded the session —
    /// e.g. to resolve references or confirm a destructive intent *before* the
    /// passphrase prompt.
    pub(crate) fn promote_for_action(
        &self,
        session: LockedSession,
        user: Option<&str>,
        purpose: KeyUsePurpose,
    ) -> Result<(UnlockedSession, CliUser), FrontendError> {
        let crypto = Crypto;
        let user =
            resolve_cli_user_ref_with_report(session.paths(), session.report(), &crypto, user)?;
        let keychain = build_keychain()?;
        let unlocked = UnlockedSession::promote(
            session,
            &crypto,
            &*keychain,
            &user.resolved.user_id,
            purpose,
        )?;
        Ok((unlocked, user))
    }

    /// Unlock-anchor a (clean) read session: resolve the stored default (or CI-injected)
    /// identity, unlock it once with [`KeyUsePurpose::InspectVault`] — which possession-checks
    /// the verification cache and pins vault membership — and return the anchored session.
    /// Pre-unlock, every machine-local trust anchor is writable by an attacker on this
    /// machine, so the unlock is what earns the output the word "trusted". The acting anchor
    /// is independent of any `--user` display lens a command later applies.
    fn anchor_read(&self, session: LockedSession) -> Result<UnlockedSession, FrontendError> {
        let crypto = Crypto;
        let user = resolve_optional_cli_user_ref_with_report(
            session.paths(),
            session.report(),
            &crypto,
            None,
        )?
        .ok_or(FrontendError::MissingDefaultUser)?;
        let keychain = build_keychain()?;
        Ok(UnlockedSession::promote(
            session,
            &crypto,
            &*keychain,
            &user.resolved.user_id,
            KeyUsePurpose::InspectVault,
        )?)
    }

    /// The standard read prologue: a trust-anchored session over a *valid* vault. Errors on
    /// any validation issue, like [`CliContext::valid_session`]. Every read command except
    /// `status`/`validate` uses this — they cannot meaningfully render a broken vault, only a
    /// clean anchored view, so there is no untrusted tier to fall back to.
    pub(crate) fn read_session(&self) -> Result<UnlockedSession, FrontendError> {
        self.anchor_read(self.valid_session()?)
    }

    /// The read prologue for `status`/`validate` — the only commands whose job is to render a
    /// vault *even when it fails validation*. A clean vault still anchors (trusted); a vault
    /// with issues has no clean state to anchor to and falls back to the untrusted
    /// [`LockedSession`] snapshot, labeled accordingly.
    pub(crate) fn inspect_session(&self) -> Result<CliSession, FrontendError> {
        let session = self.session()?;
        if !session.report().issues.is_empty() {
            return Ok(CliSession::Untrusted(Box::new(session)));
        }
        Ok(CliSession::Trusted(Box::new(self.anchor_read(session)?)))
    }
}

/// A read command's session. Trust-anchored is the norm; the untrusted tier is no longer a
/// user choice but the forced fallback for a vault that fails validation, where there is no
/// clean state to anchor to. The acting identity that anchors the trusted tier is independent
/// of any `--user` display lens a command offers: the anchor proves *this machine's view* of
/// the vault; the lens picks whose access is being rendered.
pub(crate) enum CliSession {
    Trusted(Box<UnlockedSession>),
    /// The vault failed validation — there is no clean state to anchor to, and the
    /// command's job (status/validate) is to show the failure.
    Untrusted(Box<LockedSession>),
}

impl CliSession {
    pub(crate) fn session(&self) -> &LockedSession {
        match self {
            CliSession::Trusted(unlocked) => unlocked.session(),
            CliSession::Untrusted(session) => session,
        }
    }

    pub(crate) fn trusted(&self) -> bool {
        matches!(self, CliSession::Trusted(_))
    }

    /// One stderr line naming the tier, for human output (JSON carries `"trusted"`).
    pub(crate) fn print_trust_banner(&self, json: bool) {
        if json {
            return;
        }
        match self {
            CliSession::Trusted(_) => {}
            CliSession::Untrusted(_) => eprintln!(
                "untrusted view: the vault failed validation; output shows the failure state"
            ),
        }
    }
}

/// The `thorax` subcommand surface, minus the bare-TUI default and `run` (those are dispatched by
/// the umbrella binary). Made public and `Subcommand` so the umbrella can flatten it into the
/// top-level parser, keeping a single unified `--help`.
#[derive(Subcommand)]
pub enum Command {
    /// Initialize a Thorax vault in this workspace.
    Init(InitArgs),
    /// Show workspace health: identity, vault verification, and anything needing attention.
    Status,
    /// Verify the vault and local trust state.
    Validate,
    /// List secrets.
    #[command(visible_alias = "ls")]
    List(ListArgs),
    /// Show secret metadata without revealing plaintext.
    Show(SecretShowArgs),
    /// Create or update a secret (use --rotate to label it a rotation).
    Set(SecretSetArgs),
    /// Print a secret value.
    #[command(visible_alias = "cat")]
    Get(SecretGetArgs),
    /// Delete a secret.
    #[command(visible_alias = "rm")]
    Delete(SecretDeleteArgs),
    /// Move a secret to a new selector (path or labels have changed).
    #[command(visible_alias = "mv", alias = "relabel")]
    Move(MoveArgs),
    /// Manage a secret's additional key→value fields.
    Field(FieldArgs),
    /// Manage access grants.
    Grant(GrantArgs),
    /// Manage groups.
    Group(GroupArgs),
    /// Join a vault using an invite from an admin.
    Claim(ClaimArgs),
    /// Manage Thorax users and local user selection.
    User(UserArgs),
    /// Show and name the current Thorax vault.
    Vault(VaultArgs),
    /// Manage this machine's local trust state.
    Trust(TrustArgs),
    /// List unresolved conflicts (ties, suspected rollbacks) and resolve them.
    Conflicts(ConflictsArgs),
    /// Git integration (merge-driver registration).
    Git(GitArgs),
    /// Git merge driver plumbing (registered by `thorax git install`; git invokes it during merges — not for direct use).
    #[command(hide = true)]
    MergeDriver(MergeDriverArgs),
    /// Kubernetes enrollment administration.
    Kubernetes(KubernetesArgs),
    /// Check for updates or update the thorax binary.
    Update(UpdateArgs),
}

impl Command {
    fn allows_passive_update_notice(&self) -> bool {
        !matches!(self, Command::MergeDriver(_) | Command::Update(_))
    }
}
