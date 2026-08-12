//! Shared runtime glue for workspace resolution, keychains, CI bootstrap, confirmations, and clipboard.

use std::{
    env,
    io::{self, IsTerminal, Write},
    path::PathBuf,
    process::Stdio,
};

use thorax_ops::{
    ensure_ratchet_from_invite, find_workspace, AutoKeychain, Crypto, FixedIdentityProvider,
    IdentityKeychain, InvitationMaterial, Invite, InviteV1, LockedSession, ManualIdentityKeychain,
    NoManualIdentityProvider, PassphraseKeychain, StaticPassphraseProvider, UserId, WorkspacePaths,
    INVITE_MAGIC, MAX_INVITE_BYTES,
};

use crate::bundle;
use crate::FrontendError;

/// The passphrase used to unlock the encrypted identity keychain, supplied out-of-band for
/// non-interactive use. Marked unsafe because it is held in the environment.
pub const UNSAFE_KEYCHAIN_PASSPHRASE_ENV: &str = "THORAX_UNSAFE_KEYCHAIN_PASSPHRASE";

/// An invite (the `thrx1…` string or an invite file) given directly to the process, used to
/// run non-interactively — e.g. CI. The invite's seed fully determines the identity.
pub const INVITE_ENV: &str = "THORAX_UNSAFE_INVITE";
pub const INVITE_FILE_ENV: &str = "THORAX_UNSAFE_INVITE_FILE";

pub fn explicit_or_current_root(path: Option<&PathBuf>) -> Result<PathBuf, FrontendError> {
    match path {
        Some(path) => Ok(path.clone()),
        None => env::current_dir().map_err(FrontendError::Stdio),
    }
}

pub fn workspace_paths(
    path: Option<&PathBuf>,
    init: bool,
) -> Result<WorkspacePaths, FrontendError> {
    match path {
        Some(path) => Ok(WorkspacePaths::from_root(path.clone())),
        None if init => Ok(WorkspacePaths::from_root(
            env::current_dir().map_err(FrontendError::Stdio)?,
        )),
        None => Ok(find_workspace(
            env::current_dir().map_err(FrontendError::Stdio)?,
        )?),
    }
}

/// Resolve the workspace and load its [`LockedSession`] — the single read + decode +
/// validation a frontend command performs. The session is returned even when validation
/// found issues, so status/validate-style commands can render `session.report().issues`.
pub fn open_session(path: Option<&PathBuf>) -> Result<LockedSession, FrontendError> {
    let paths = workspace_paths(path, false)?;
    Ok(LockedSession::load(&paths, &Crypto)?)
}

/// [`open_session`], then fail on any validation issue — the standard prologue for
/// commands that operate on a valid vault.
pub fn open_valid_session(path: Option<&PathBuf>) -> Result<LockedSession, FrontendError> {
    let session = open_session(path)?;
    session.ensure_valid()?;
    Ok(session)
}

/// Recover a transaction in the current workspace before command dispatch, including for
/// commands such as `update` that do not otherwise open a vault session. No workspace is a
/// normal no-op; malformed or conflicting state in an existing workspace remains an error.
pub fn recover_workspace_if_present(path: Option<&PathBuf>) -> Result<bool, FrontendError> {
    let paths = match path {
        Some(path) => WorkspacePaths::from_root(path.clone()),
        None => {
            let start = env::current_dir().map_err(FrontendError::Stdio)?;
            match find_workspace(&start) {
                Ok(paths) => paths,
                Err(thorax_ops::StoreError::WorkspaceNotFound(_)) => return Ok(false),
                Err(error) => return Err(error.into()),
            }
        }
    };
    if !paths.vault_path.exists() {
        return Ok(false);
    }
    Ok(thorax_ops::recover_current_workspace_if_needed(
        &paths, &Crypto,
    )?)
}

/// Decode the injected invite from the environment, if either form is set. The string form
/// holds the `thrx1…` invite; the file form holds its path.
pub fn ci_invite() -> Result<Option<InvitationMaterial>, FrontendError> {
    let string = match env::var_os(INVITE_ENV) {
        Some(value) => Some(
            value
                .into_string()
                .map_err(|_| FrontendError::NonUtf8Env(INVITE_ENV))?,
        ),
        None => None,
    };
    let file = env::var_os(INVITE_FILE_ENV).map(PathBuf::from);
    match (string, file) {
        (None, None) => Ok(None),
        (Some(_), Some(_)) => Err(FrontendError::AmbiguousIdentityBundle),
        (Some(value), None) => Ok(Some(read_invite(Some(value), None)?)),
        (None, Some(path)) => Ok(Some(read_invite(None, Some(path))?)),
    }
}

/// The user id of the injected CI identity, if any. In CI mode this is the implicit acting user,
/// so commands work without `--user` and without a stored default.
pub fn ci_identity_user() -> Result<Option<UserId>, FrontendError> {
    match ci_invite()? {
        Some(invite) => {
            let provider = FixedIdentityProvider::from_master_seed(&Crypto, &invite.master_seed)
                .map_err(FrontendError::Keychain)?;
            Ok(Some(provider.user_id().clone()))
        }
        None => Ok(None),
    }
}

pub fn build_keychain() -> Result<Box<dyn IdentityKeychain>, FrontendError> {
    // Non-interactive identity injection (CI): the invite yields a fixed identity, no keychain dir or
    // passphrase needed. Takes precedence over the passphrase/interactive keychains.
    if let Some(invite) = ci_invite()? {
        let provider = FixedIdentityProvider::from_master_seed(&Crypto, &invite.master_seed)
            .map_err(FrontendError::Keychain)?;
        return Ok(Box::new(ManualIdentityKeychain::new(provider)));
    }
    if let Some(passphrase) = env::var_os(UNSAFE_KEYCHAIN_PASSPHRASE_ENV) {
        let passphrase = passphrase
            .into_string()
            .map_err(|_| FrontendError::NonUtf8Env(UNSAFE_KEYCHAIN_PASSPHRASE_ENV))?;
        let base_dir = PassphraseKeychain::<StaticPassphraseProvider>::default_base_dir()?;
        let keychain = AutoKeychain::new(
            PassphraseKeychain::new(base_dir, StaticPassphraseProvider::new(passphrase)),
            NoManualIdentityProvider,
        );
        Ok(Box::new(keychain))
    } else {
        Ok(Box::new(AutoKeychain::default_interactive()?))
    }
}

/// Build a keychain from a passphrase the caller already collected (e.g. a TUI unlock modal) rather
/// than from the environment or an interactive stdin prompt. A CI invite still takes
/// precedence (so a headless `thorax` works), matching [`build_keychain`]; otherwise this unlocks the
/// on-disk encrypted keychain with the supplied passphrase. Keeps keychain construction on the one shared
/// path so frontends don't hand-roll backend selection.
pub fn build_keychain_with_passphrase(
    passphrase: String,
) -> Result<Box<dyn IdentityKeychain>, FrontendError> {
    if let Some(invite) = ci_invite()? {
        let provider = FixedIdentityProvider::from_master_seed(&Crypto, &invite.master_seed)
            .map_err(FrontendError::Keychain)?;
        return Ok(Box::new(ManualIdentityKeychain::new(provider)));
    }
    let base_dir = PassphraseKeychain::<StaticPassphraseProvider>::default_base_dir()?;
    Ok(Box::new(AutoKeychain::new(
        PassphraseKeychain::new(base_dir, StaticPassphraseProvider::new(passphrase)),
        NoManualIdentityProvider,
    )))
}

/// In CI invite mode (`THORAX_UNSAFE_INVITE[_FILE]`), a fresh checkout has no local
/// trust state, so any workspace command would fail with "no trust state". Bootstrap it from the
/// bundle (the trust half of `claim`) before running the command. No-op when not in CI mode, when
/// there's no workspace/vault yet, or when trust already exists.
pub fn maybe_bootstrap_ci_trust(path: Option<&PathBuf>) -> Result<(), FrontendError> {
    let Some(invite) = ci_invite()? else {
        return Ok(());
    };
    let Ok(paths) = workspace_paths(path, false) else {
        return Ok(());
    };
    if !paths.vault_path.exists() {
        return Ok(());
    }
    ensure_ratchet_from_invite(&paths, &Crypto, &invite)?;
    Ok(())
}

/// Gate a destructive action. `action` is a human description of what will change, e.g.
/// "delete secret app/prod/db". Returns `true` to proceed.
///
/// - `--dry-run`: report and stop.
/// - `--yes`: proceed without asking.
/// - interactive terminal: prompt `[y/N]`.
/// - non-interactive without `--yes`: fail closed rather than guess.
pub fn confirm_destructive(action: &str, yes: bool, dry_run: bool) -> Result<bool, FrontendError> {
    if dry_run {
        eprintln!("dry run: would {action}");
        return Ok(false);
    }
    if yes {
        return Ok(true);
    }
    if !io::stdin().is_terminal() {
        return Err(FrontendError::ConfirmationRequired);
    }
    eprint!("About to {action}. Proceed? [y/N] ");
    io::stderr().flush().map_err(FrontendError::Stdio)?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(FrontendError::Stdio)?;
    if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
        Ok(true)
    } else {
        eprintln!("aborted");
        Ok(false)
    }
}

/// Copy bytes to the system clipboard via the first available platform tool. Returns
/// [`FrontendError::ClipboardUnavailable`] if none is installed.
pub fn copy_to_clipboard(data: &[u8]) -> Result<(), FrontendError> {
    const CANDIDATES: &[(&str, &[&str])] = &[
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
        ("pbcopy", &[]),
    ];
    for (command, args) in CANDIDATES {
        let mut process = std::process::Command::new(command);
        process
            .args(*args)
            // Clipboard programs receive the secret on stdin. They do not also need the
            // caller's invite, keychain passphrase, cloud credentials, or arbitrary CI env.
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        for name in [
            "PATH",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "DISPLAY",
            "XAUTHORITY",
            "DBUS_SESSION_BUS_ADDRESS",
        ] {
            if let Some(value) = std::env::var_os(name) {
                process.env(name, value);
            }
        }
        let Ok(mut child) = process.spawn() else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data).map_err(FrontendError::Stdio)?;
        }
        if child.wait().map_err(FrontendError::Stdio)?.success() {
            return Ok(());
        }
    }
    Err(FrontendError::ClipboardUnavailable)
}

/// Encode an invite as the pasteable `thrx1…` string (the inverse of [`read_invite`]'s string
/// form). Used by frontends that produce an invite to display.
pub fn encode_invite(invite: &InviteV1) -> Result<String, FrontendError> {
    let bytes = cord::serialize(&Invite::V1(invite.clone()))?;
    Ok(bundle::encode(&bytes))
}

/// Encode an invite as compact cord bytes for writing to a file (`--invite-file`).
pub fn invite_bytes(invite: &InviteV1) -> Result<Vec<u8>, FrontendError> {
    let payload = cord::serialize(&Invite::V1(invite.clone()))?;
    let mut bytes = Vec::with_capacity(INVITE_MAGIC.len() + payload.len());
    bytes.extend_from_slice(INVITE_MAGIC);
    bytes.extend(payload);
    if bytes.len() > MAX_INVITE_BYTES {
        return Err(FrontendError::SecretInputTooLarge {
            max_bytes: MAX_INVITE_BYTES,
        });
    }
    Ok(bytes)
}

pub fn read_invite(
    invite_string: Option<String>,
    invite_file: Option<PathBuf>,
) -> Result<InvitationMaterial, FrontendError> {
    let bytes = match (invite_string, invite_file) {
        (Some(_), Some(_)) | (None, None) => return Err(FrontendError::AmbiguousIdentityBundle),
        (Some(value), None) => bundle::decode(&value).map_err(map_bundle_error)?,
        (None, Some(path)) => {
            let bytes = thorax_ops::read_file_bounded(&path, MAX_INVITE_BYTES)
                .map_err(|source| FrontendError::Io { path, source })?;
            bytes
                .strip_prefix(INVITE_MAGIC)
                .ok_or(FrontendError::InvalidBundleString)?
                .to_vec()
        }
    };
    match cord::deserialize::<Invite>(&bytes)? {
        Invite::V1(invite) => Ok(invite),
    }
}

fn map_bundle_error(error: bundle::BundleStringError) -> FrontendError {
    match error {
        bundle::BundleStringError::WrongPrefix(prefix) => FrontendError::WrongBundlePrefix(prefix),
        _ => FrontendError::InvalidBundleString,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use thorax_ops::{HashValue, RatchetBaselineV1};

    fn invitation() -> InviteV1 {
        InviteV1 {
            master_seed: vec![7; 32],
            trusted_root: HashValue(vec![9; 32]),
            rollback_baseline: RatchetBaselineV1 { records: vec![] },
        }
    }

    #[test]
    fn self_contained_invitation_round_trips_as_text() {
        let invite = invitation();
        let text = encode_invite(&invite).unwrap();
        assert!(text.starts_with("thrx1"));
        assert_eq!(read_invite(Some(text), None).unwrap(), invite);
    }

    #[test]
    fn invitation_file_has_magic_and_round_trips() {
        let invite = invitation();
        let bytes = invite_bytes(&invite).unwrap();
        assert!(bytes.starts_with(INVITE_MAGIC));
        let path = std::env::temp_dir().join(format!(
            "thorax-invite-test-{}-{}.cord",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        thorax_ops::write_private_output(&path, &bytes, false).unwrap();
        let decoded = read_invite(None, Some(path.clone())).unwrap();
        let _ = std::fs::remove_file(path);
        assert_eq!(decoded, invite);
    }
}
