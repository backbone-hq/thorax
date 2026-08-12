use std::process::ExitCode;

use serde_json::json;
use thorax_frontend::{
    build_keychain, explicit_or_current_root, hash_hex, install_merge_driver, merge_driver_status,
    parse_handle_name, remember_user_if_explicit, short_hash, short_user_hex, user_hex,
    write_current_user_for_root, FrontendError, MergeDriverStatus,
};
use thorax_ops::{
    init_vault, key_hash, normalize_handle, save_identity_with_keychain_labeled, Crypto, Identity,
    KeyUsePurpose, LockedSession, OpsError, UnlockedSession, ValidationReport, WorkspacePaths,
};

use crate::args::{CatArgs, InitArgs, VaultCommand, VaultNameCommand, VaultNameSetArgs};
use crate::output::{handle_display, handle_ref, print_workspace_report};
use crate::users::user_label;
use crate::CliContext;

pub(crate) fn cmd_init(cli: &CliContext, args: InitArgs) -> Result<ExitCode, FrontendError> {
    let root_path = explicit_or_current_root(cli.path.as_ref())?;
    let paths = WorkspacePaths::from_root(root_path);
    if paths.vault_path.exists() {
        return Err(OpsError::VaultAlreadyInitialized(paths.vault_path.clone()).into());
    }

    let crypto = Crypto;
    let root = Identity::generate(&crypto).map_err(OpsError::from)?;
    let root_signing_public_key_hash =
        key_hash(&crypto, root.signing_public_key()).map_err(OpsError::from)?;
    let handle_name = if args.no_handle {
        None
    } else {
        Some(parse_handle_name(args.handle.as_deref().unwrap_or("root"))?)
    };
    let vault_name = if args.no_name {
        None
    } else {
        let name = args.name.unwrap_or_else(|| default_vault_name(&paths));
        Some(parse_handle_name(&name)?)
    };
    let keychain = build_keychain()?;
    let stored = save_identity_with_keychain_labeled(
        &paths,
        &crypto,
        &*keychain,
        &root_signing_public_key_hash,
        &root,
        vault_name.clone(),
        handle_name.clone(),
    )?;
    let initialized = init_vault(&paths, &crypto, &root)?;
    // One session for the optional handle/name commits that complete an init — anchored
    // to the freshly generated root identity (possession by construction).
    let mut session = UnlockedSession::with_identity(
        LockedSession::load(&paths, &crypto)?,
        &crypto,
        root.clone(),
    )?;
    let handle = if let Some(handle) = handle_name {
        let handle_id =
            session.set_user_handle(&crypto, handle.clone(), initialized.root_user_id.clone())?;
        Some((handle, handle_id))
    } else {
        None
    };
    let vault_handle = if let Some(name) = vault_name {
        let handle_id = session.set_vault_handle(&crypto, name.clone())?;
        Some((name, handle_id))
    } else {
        None
    };
    let default_user = handle
        .as_ref()
        .map(|(handle, _)| handle.clone())
        .unwrap_or_else(|| user_hex(&initialized.root_user_id));
    write_current_user_for_root(
        &initialized.root_signing_public_key_hash,
        &initialized.root_user_id,
        handle.as_ref().map(|(handle, _)| handle.clone()),
    )?;

    // Register the git merge driver while we are here (best effort — a vault outside a git
    // repository is fine, and a config failure should not fail the init that already
    // committed). `thorax git install` redoes this any time.
    let merge_install = match merge_driver_status(&paths.root) {
        MergeDriverStatus::NotAGitRepo | MergeDriverStatus::GitUnavailable => None,
        _ => install_merge_driver(&paths.root).ok(),
    };

    if cli.json {
        println!(
            "{}",
            json!({
                "vault": initialized.paths.vault_path.display().to_string(),
                "root_user": user_hex(&initialized.root_user_id),
                "trusted_root": hash_hex(&initialized.root_signing_public_key_hash),
                "identity_backend": stored.backend,
                "identity_path": stored.path.map(|path| path.display().to_string()),
                "handle": handle.as_ref().map(|(handle, _)| handle_display(handle)),
                "handle_id": handle.as_ref().map(|(_, handle_id)| hash_hex(&handle_id.0)),
                "vault_name": vault_handle.as_ref().map(|(handle, _)| handle_display(handle)),
                "vault_handle_id": vault_handle.as_ref().map(|(_, handle_id)| hash_hex(&handle_id.0)),
                "default_user": &default_user,
                "merge_driver": merge_driver_status(&paths.root).name(),
            })
        );
    } else {
        println!(
            "initialized Thorax vault: {}",
            vault_handle
                .as_ref()
                .map(|(handle, _)| handle_ref(handle))
                .unwrap_or_else(|| short_hash(&initialized.root_signing_public_key_hash))
        );
        println!("vault file: {}", initialized.paths.vault_path.display());
        println!(
            "root user: {}",
            handle
                .as_ref()
                .map(|(handle, _)| handle_ref(handle))
                .unwrap_or_else(|| short_user_hex(&initialized.root_user_id))
        );
        println!("keychain: {}", stored.backend);
        println!("default user: {}", handle_ref(&default_user));
        if let Some(install) = &merge_install {
            if install.wrote_attributes || install.wrote_config {
                println!("git merge driver: registered (commit .gitattributes with the vault)");
            }
        }
        println!();
        println!("next steps:");
        println!("  set a secret:      printf '%s' \"$SECRET\" | thorax set app/prod/db");
        println!(
            "  invite a teammate: thorax user invite <handle> --read app --invite-file invite.thrx"
        );
    }

    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_status(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let cs = cli.inspect_session()?;
    cs.print_trust_banner(cli.json);
    print_workspace_report(cli.json, cs.session(), false, cs.trusted());
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_validate(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let cs = cli.inspect_session()?;
    cs.print_trust_banner(cli.json);
    let session = cs.session();
    let issue_count = session.report().issues.len();
    print_workspace_report(cli.json, session, true, cs.trusted());
    if issue_count == 0 {
        Ok(ExitCode::SUCCESS)
    } else if cli.json {
        // Grep convention: the JSON report above is the output; the exit code carries the
        // verdict, and it must match human mode's `ValidationFailed` → TAMPERED.
        Ok(ExitCode::from(thorax_frontend::exit::TAMPERED))
    } else {
        Err(FrontendError::ValidationFailed(issue_count))
    }
}

pub(crate) fn cmd_vault(
    cli: &CliContext,
    command: VaultCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        VaultCommand::Show => cmd_vault_show(cli),
        VaultCommand::Name(args) => cmd_vault_name(cli, args.command),
        VaultCommand::Dump(args) => cmd_vault_cat(cli, args),
    }
}

fn cmd_vault_show(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let session = cli.read_session()?;
    let names = session
        .effective()
        .vault_handles
        .values()
        .map(|record| {
            json!({
                "name": handle_display(&normalize_handle(&record.handle)),
            })
        })
        .collect::<Vec<_>>();

    if cli.json {
        println!(
            "{}",
            json!({
                "trusted": true,
                "trusted_root": session.effective().root_signing_public_key_hash.as_ref().map(hash_hex),
                "names": names,
            })
        );
        return Ok(ExitCode::SUCCESS);
    }

    if let Some(root) = &session.effective().root_signing_public_key_hash {
        println!("trusted root: {}", hash_hex(root));
    }
    let mut records = session
        .effective()
        .vault_handles
        .values()
        .collect::<Vec<_>>();
    records.sort_by_key(|record| normalize_handle(&record.handle));
    for record in records {
        println!("name: {}", handle_ref(&normalize_handle(&record.handle)),);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_vault_name(cli: &CliContext, command: VaultNameCommand) -> Result<ExitCode, FrontendError> {
    match command {
        VaultNameCommand::Set(args) => cmd_vault_name_set(cli, args),
    }
}

fn cmd_vault_name_set(cli: &CliContext, args: VaultNameSetArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let name = parse_handle_name(&args.name)?;
    let (mut unlocked, admin) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: format!("set vault name {name}"),
        },
    )?;
    let handle_id = unlocked.set_vault_handle(&crypto, name.clone())?;
    remember_user_if_explicit(unlocked.paths(), &admin)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "name": handle_display(&name),
                "name_id": hash_hex(&handle_id.0),
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("vault name: {}", handle_ref(&name));
        println!("signed by: {}", user_label(&admin.resolved));
    }
    Ok(ExitCode::SUCCESS)
}

fn default_vault_name(paths: &WorkspacePaths) -> String {
    paths
        .root
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("thorax")
        .to_string()
}

pub(crate) fn cmd_vault_cat(cli: &CliContext, args: CatArgs) -> Result<ExitCode, FrontendError> {
    // Resolve the vault file path. If --path was given, use it as the base;
    // otherwise, the file argument is resolved relative to cwd.
    let path = cli
        .path
        .as_ref()
        .map(|base| base.join(&args.file))
        .unwrap_or_else(|| args.file.clone());

    let decrypt = if args.decrypt {
        // Try to open a read session for the workspace. If this fails (no TTY,
        // wrong key, vault not found), silently fall back to metadata-only.
        cli.read_session().ok()
    } else {
        None
    };

    let text = crate::vault_cat::cat_vault_with_decrypt(&path, decrypt.as_ref())?;

    println!("{text}");
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn primary_vault_name(report: &ValidationReport) -> Option<String> {
    report
        .effective
        .vault_handles
        .values()
        .min_by(|left, right| normalize_handle(&left.handle).cmp(&normalize_handle(&right.handle)))
        .map(|record| handle_display(&normalize_handle(&record.handle)))
}
