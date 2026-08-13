use std::{fs, path::PathBuf, process::ExitCode};

use serde_json::json;
use thorax_frontend::{
    self as frontend, candidate_summary, conflict_kind_summary, conflict_label,
    install_merge_driver, merge_driver_status, record_key_kind, short_hash, workspace_paths,
    FrontendError, MergeDriverStatus,
};
use thorax_ops::{
    check_merged_vault, decode_vault, encode_vault, merge_vaults, record_hash, Crypto,
    MergeOutcome, MergeRefusal, VaultRecordV1, VaultStore, WorkspacePaths,
};

use crate::args::{GitCommand, MergeDriverArgs};
use crate::output::issue_string;
use crate::CliContext;

/// `thorax merge` — git merge integration (driver registration). The conflict porcelain
/// lives under `thorax conflicts`.
pub(crate) fn cmd_git(cli: &CliContext, command: GitCommand) -> Result<ExitCode, FrontendError> {
    match command {
        GitCommand::Install => cmd_merge_install(cli),
    }
}

/// The git merge driver plumbing. Writes the record-set union to OURS whenever the sides are
/// structurally sound, then signals git from the *validator's* answer — the same authority-aware
/// conflict set `thorax conflicts` shows — so the driver can never call something a conflict that
/// the resolution surface won't: exit 0 only when the union validates with no conflicts and no
/// issues; otherwise non-zero so git keeps the path unmerged, with the valid union already on disk.
/// Conflicted keys in the union are inert (nothing at them effective, reads of them
/// failing) until resolved.
pub(crate) fn cmd_merge_driver(
    cli: &CliContext,
    args: MergeDriverArgs,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let read = |path: &PathBuf| {
        fs::read(path).map_err(|source| FrontendError::Io {
            path: path.clone(),
            source,
        })
    };
    let ancestor_bytes = read(&args.ancestor)?;
    let ours_bytes = read(&args.ours)?;
    let theirs_bytes = read(&args.theirs)?;

    let decode_side = |name: &str, bytes: &[u8]| match decode_vault(bytes) {
        Ok(vault) => Some(vault),
        Err(_) => {
            eprintln!(
                "thorax merge-driver: refusing — the {name} side is not a decodable Thorax vault"
            );
            eprintln!("the working tree keeps your version; this path stays conflicted");
            None
        }
    };
    // An empty ancestor is git's add/add merge (no common base), not a corrupt vault.
    let ancestor = if ancestor_bytes.is_empty() {
        None
    } else {
        match decode_side("ancestor", &ancestor_bytes) {
            Some(vault) => Some(vault),
            None => return Ok(ExitCode::FAILURE),
        }
    };
    let Some(ours) = decode_side("our", &ours_bytes) else {
        return Ok(ExitCode::FAILURE);
    };
    let Some(theirs) = decode_side("their", &theirs_bytes) else {
        return Ok(ExitCode::FAILURE);
    };

    let outcome = merge_vaults(ancestor.as_ref(), &ours, &theirs)
        .map_err(|error| FrontendError::Ops(error.into()))?;
    let merged = match outcome {
        MergeOutcome::Refused(refusal) => {
            let reason = match refusal {
                MergeRefusal::MissingRoot => "a side carries no vault root record",
                MergeRefusal::RootMismatch => {
                    "the sides belong to different trusted roots (vault substitution, not a merge)"
                }
            };
            eprintln!("thorax merge-driver: refusing — {reason}");
            eprintln!("the working tree keeps your version; this path stays conflicted");
            return Ok(ExitCode::FAILURE);
        }
        MergeOutcome::Merged { merged } => merged,
    };

    // Always leave the (valid) union in the working tree, ties or not: both tied candidates
    // coexist in the record set, so the conflict state itself is in-format.
    let merged_bytes = encode_vault(&merged).map_err(|error| FrontendError::Ops(error.into()))?;
    fs::write(&args.ours, merged_bytes).map_err(|source| FrontendError::Io {
        path: args.ours.clone(),
        source,
    })?;

    // Trust-aware validation, best effort: the driver may run on a machine with no local
    // state for this vault (fresh CI clone), in which case rollback is unverifiable but
    // signature/authority validation still runs against fresh trust.
    let paths = workspace_paths(cli.path.as_ref(), false).unwrap_or_else(|_| {
        WorkspacePaths::from_root(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    });
    let check = check_merged_vault(&paths, &merged, &crypto)?;

    if check.conflicts.is_empty() && check.issues.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }

    eprintln!("thorax merge-driver: the merged vault was written, but this path needs attention:");
    if !check.ratchet_checked {
        eprintln!("  note: no local trust state on this machine — rollback was not checked");
    }
    for issue in &check.issues {
        eprintln!("  issue: {}", issue_string(issue));
    }
    if !check.conflicts.is_empty() {
        eprintln!(
            "  {} need an explicit winner (the conflicted keys have no effective value until then):",
            thorax_frontend::count_noun(check.conflicts.len(), "conflict")
        );
        for conflict in &check.conflicts {
            eprintln!(
                "    {} {} ({})",
                record_key_kind(&conflict.key),
                conflict_label(conflict),
                conflict_kind_summary(conflict),
            );
            for candidate in &conflict.candidates {
                let hash = record_hash(&crypto, candidate)
                    .map_err(|error| FrontendError::Ops(error.into()))?;
                eprintln!(
                    "      {}  {}  [{}]",
                    short_hash(&hash),
                    candidate
                        .body
                        .known()
                        .map(candidate_summary)
                        .unwrap_or_else(|| "unknown record".to_string()),
                    candidate_sides(candidate, ancestor.as_ref(), &ours, &theirs),
                );
            }
        }
        eprintln!("  pick winners with `thorax` (Conflicts tab) or `thorax conflicts resolve <record-hash>`,");
        eprintln!("  then mark this path resolved with git add");
    }
    Ok(ExitCode::FAILURE)
}

fn cmd_merge_install(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let paths = workspace_paths(cli.path.as_ref(), false)?;
    match merge_driver_status(&paths.root) {
        MergeDriverStatus::NotAGitRepo => {
            return Ok(install_refused(
                cli,
                "not_a_git_repo",
                "this workspace is not inside a git repository; nothing to install",
                "run `git init` first, or skip the merge driver outside git",
            ));
        }
        MergeDriverStatus::GitUnavailable => {
            return Ok(install_refused(
                cli,
                "git_unavailable",
                "git is not available on this machine; cannot install the merge driver",
                "install git (or put it on PATH) and re-run `thorax git install`",
            ));
        }
        _ => {}
    }
    let install = install_merge_driver(&paths.root)?;
    if cli.json {
        println!(
            "{}",
            json!({
                "gitattributes": install.attributes_path.display().to_string(),
                "wrote_gitattributes": install.wrote_attributes,
                "wrote_git_config": install.wrote_config,
                "status": merge_driver_status(&paths.root).name(),
            })
        );
    } else {
        if install.wrote_attributes {
            println!(
                "added to {}: {} / {}",
                install.attributes_path.display(),
                frontend::GITATTRIBUTES_MERGE_LINE,
                frontend::GITATTRIBUTES_DIFF_LINE,
            );
            println!(
                "(commit this file so every clone routes vault merges and diffs through Thorax)"
            );
        }
        if install.wrote_config {
            println!("git config set: merge.thorax-merge.driver, diff.thorax-textconv.textconv");
        }
        if !install.wrote_attributes && !install.wrote_config {
            println!("git drivers already registered");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// An install refusal is an error, not a result: under `--json` it must wear the standard
/// `{"error":{code,message,hint}}` envelope on stderr (the contract every other failure
/// keeps), and in human mode it reads like one. Always exits with the catch-all code.
fn install_refused(cli: &CliContext, code: &str, message: &str, hint: &str) -> ExitCode {
    if cli.json {
        eprintln!(
            "{}",
            json!({
                "error": {
                    "code": code,
                    "message": message,
                    "hint": hint,
                }
            })
        );
    } else {
        eprintln!("thorax: {message}");
        eprintln!("  next: {hint}");
    }
    ExitCode::FAILURE
}

/// Which merge side(s) a tied candidate came from. Transient provenance for the driver's
/// conflict summary only — the union does not record sides, by design.
fn candidate_sides(
    candidate: &VaultRecordV1,
    ancestor: Option<&VaultStore>,
    ours: &VaultStore,
    theirs: &VaultStore,
) -> String {
    let contains = |vault: &VaultStore| {
        let VaultStore::V1(v1) = vault;
        v1.records.contains(candidate)
    };
    let mut sides = Vec::new();
    if contains(ours) {
        sides.push("ours");
    }
    if contains(theirs) {
        sides.push("theirs");
    }
    if ancestor.is_some_and(contains) {
        sides.push("base");
    }
    if sides.is_empty() {
        sides.push("unknown");
    }
    sides.join("+")
}
