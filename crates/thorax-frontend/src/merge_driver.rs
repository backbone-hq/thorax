//! Git merge-driver registration.
//!
//! Registration has two halves: a committed `.gitattributes` entry that marks the vault as
//! `merge=thorax-merge`, and the per-clone `[merge "thorax-merge"]` git config that maps that name to
//! the `thorax merge-driver` command. Git config cannot be committed — every custom merge
//! driver shares that limitation — so `init` installs both, and `claim`/`status` detect a
//! clone where the config half is missing.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::FrontendError;

/// The `.gitattributes` entry for the merge driver, relative to the workspace root.
pub const GITATTRIBUTES_MERGE_LINE: &str = ".thorax/vault.cord merge=thorax-merge";
/// The `.gitattributes` entry for the diff/textconv driver.
pub const GITATTRIBUTES_DIFF_LINE: &str = ".thorax/vault.cord diff=thorax-textconv";
/// Deprecated alias for `GITATTRIBUTES_MERGE_LINE`.
pub const GITATTRIBUTES_LINE: &str = GITATTRIBUTES_MERGE_LINE;
const DRIVER_NAME: &str = "Thorax vault merge";
const DRIVER_COMMAND: &str = "thorax merge-driver %O %A %B";
const DIFF_DRIVER_COMMAND: &str = "thorax vault cat";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeDriverStatus {
    /// Both halves present: merges of the vault go through `thorax merge-driver`.
    Registered,
    /// The committed `.gitattributes` entry exists but this clone lacks the `[merge
    /// "thorax"]` config — the state every fresh clone starts in.
    MissingGitConfig,
    /// The clone is configured but the workspace `.gitattributes` entry is missing.
    MissingAttributes,
    MissingBoth,
    NotAGitRepo,
    /// `git` is not on PATH (or failed to run), so registration state is unknowable.
    GitUnavailable,
}

impl MergeDriverStatus {
    /// A one-line remediation hint for the states a user should act on, if any.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            MergeDriverStatus::Registered
            | MergeDriverStatus::NotAGitRepo
            | MergeDriverStatus::GitUnavailable => None,
            MergeDriverStatus::MissingGitConfig
            | MergeDriverStatus::MissingAttributes
            | MergeDriverStatus::MissingBoth => {
                Some("git merge driver is not registered in this clone; run `thorax git install`")
            }
        }
    }

    /// The stable, machine-readable status value (snake_case, like every JSON enum value).
    pub fn name(&self) -> &'static str {
        match self {
            MergeDriverStatus::Registered => "registered",
            MergeDriverStatus::MissingGitConfig => "missing_git_config",
            MergeDriverStatus::MissingAttributes => "missing_gitattributes",
            MergeDriverStatus::MissingBoth => "missing",
            MergeDriverStatus::NotAGitRepo => "not_a_git_repo",
            MergeDriverStatus::GitUnavailable => "git_unavailable",
        }
    }
}

pub fn merge_driver_status(workspace: &Path) -> MergeDriverStatus {
    match git_ok(workspace, &["rev-parse", "--git-dir"]) {
        Some(true) => {}
        Some(false) => return MergeDriverStatus::NotAGitRepo,
        None => return MergeDriverStatus::GitUnavailable,
    }
    let config = matches!(
        git_ok(workspace, &["config", "--get", "merge.thorax-merge.driver"]),
        Some(true)
    );
    let attributes = attributes_entry_present(workspace);
    match (attributes, config) {
        (true, true) => MergeDriverStatus::Registered,
        (true, false) => MergeDriverStatus::MissingGitConfig,
        (false, true) => MergeDriverStatus::MissingAttributes,
        (false, false) => MergeDriverStatus::MissingBoth,
    }
}

#[derive(Clone, Debug)]
pub struct MergeDriverInstall {
    pub wrote_attributes: bool,
    pub wrote_config: bool,
    pub attributes_path: PathBuf,
}

/// Install whichever half of the registration is missing. Errors only on actual write/run
/// failures; calling on an already-registered clone is a no-op.
pub fn install_merge_driver(workspace: &Path) -> Result<MergeDriverInstall, FrontendError> {
    let attributes_path = workspace.join(".gitattributes");
    let mut install = MergeDriverInstall {
        wrote_attributes: false,
        wrote_config: false,
        attributes_path: attributes_path.clone(),
    };

    if !attributes_entry_present(workspace) {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&attributes_path)
            .map_err(|source| FrontendError::Io {
                path: attributes_path.clone(),
                source,
            })?;
        let needs_newline = fs::read(&attributes_path)
            .map(|bytes| !bytes.is_empty() && !bytes.ends_with(b"\n"))
            .unwrap_or(false);
        write!(
            file,
            "{}{}\n{}\n",
            if needs_newline { "\n" } else { "" },
            GITATTRIBUTES_MERGE_LINE,
            GITATTRIBUTES_DIFF_LINE,
        )
        .map_err(|source| FrontendError::Io {
            path: attributes_path.clone(),
            source,
        })?;
        install.wrote_attributes = true;
    }

    let merge_ready = matches!(
        git_ok(workspace, &["config", "--get", "merge.thorax-merge.driver"]),
        Some(true)
    );
    if !merge_ready {
        git_set_config(workspace, "merge.thorax-merge.name", DRIVER_NAME)?;
        git_set_config(workspace, "merge.thorax-merge.driver", DRIVER_COMMAND)?;
        install.wrote_config = true;
    }

    if !matches!(
        git_ok(
            workspace,
            &["config", "--get", "diff.thorax-textconv.textconv"]
        ),
        Some(true)
    ) {
        git_set_config(
            workspace,
            "diff.thorax-textconv.textconv",
            DIFF_DRIVER_COMMAND,
        )?;
        install.wrote_config = true;
    }

    Ok(install)
}

fn attributes_entry_present(workspace: &Path) -> bool {
    let Ok(contents) = fs::read_to_string(workspace.join(".gitattributes")) else {
        return false;
    };
    contents.lines().any(|line| {
        let line = line.trim();
        !line.starts_with('#')
            && line.contains(".thorax/vault.cord")
            && (line.contains("merge=") || line.contains("diff="))
    })
}

/// Run git in `workspace`: `Some(success)` when git ran, `None` when it could not run at all.
fn git_ok(workspace: &Path, args: &[&str]) -> Option<bool> {
    Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()
        .map(|status| status.success())
}

fn git_set_config(workspace: &Path, key: &str, value: &str) -> Result<(), FrontendError> {
    match git_ok(workspace, &["config", key, value]) {
        Some(true) => Ok(()),
        _ => Err(FrontendError::GitConfigFailed {
            key: key.to_string(),
        }),
    }
}
