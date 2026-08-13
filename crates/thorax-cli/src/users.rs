use std::process::ExitCode;

use serde_json::json;
use thorax_frontend::{
    build_keychain, bundle, confirm_destructive, encode_invite, hash_hex, invite_bytes,
    merge_driver_status, parse_handle_name, read_invite, remember_user_if_explicit,
    report_root_key_hash, resolve_cli_user_ref_in_report, selector_string, short_hash,
    short_user_hex, stored_default_user, user_config_ref, user_hex, workspace_paths,
    write_current_user_for_root, FrontendError, InviteBaselinePolicy,
};
use thorax_ops::{
    claim_invite_with_keychain, normalize_handle, write_private_output, Crypto, GrantPermissionV1,
    KeyUsePurpose, KeyspaceGrantClassV1, ManageKeyspaceGrantV1, ResolvedUserRef, UserId,
    ValidationReport,
};

use crate::access::parse_keyspace_selector;
use crate::args::{
    ClaimArgs, UserCommand, UserDeleteArgs, UserHandleCommand, UserHandleSetArgs, UserInviteArgs,
    UserShowArgs, UserUseArgs,
};
use crate::output::{handle_display, handle_ref, print_reconcile_warning};
use crate::vault::primary_vault_name;
use crate::CliContext;

pub(crate) fn cmd_user(cli: &CliContext, command: UserCommand) -> Result<ExitCode, FrontendError> {
    match command {
        UserCommand::Current => cmd_user_current(cli),
        UserCommand::Use(args) => cmd_user_use(cli, args),
        UserCommand::List => cmd_user_list(cli),
        UserCommand::Show(args) => cmd_user_show(cli, args),
        UserCommand::Invite(args) => cmd_user_invite(cli, args),
        UserCommand::Delete(args) => cmd_user_delete(cli, args),
        UserCommand::Handle(args) => cmd_user_handle(cli, args.command),
    }
}

fn cmd_user_current(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.read_session()?;
    let root_signing_public_key_hash = report_root_key_hash(session.report())?;
    let current = stored_default_user(session.paths(), &root_signing_public_key_hash)?;
    let resolved = current.as_ref().and_then(|value| {
        resolve_cli_user_ref_in_report(session.report(), &crypto, &value.user_ref).ok()
    });

    if cli.json {
        println!(
            "{}",
            json!({
                "default_user": current.as_ref().map(|value| value.display.as_str()),
                "user": resolved.as_ref().map(|user| user_hex(&user.user_id)),
                "resolved_handle": resolved.as_ref().and_then(|user| user.handle.as_ref()).map(|handle| handle_display(handle)),
            })
        );
    } else if let Some(user) = resolved {
        println!("default user: {}", user_label(&user));
    } else if let Some(current) = current {
        println!("default user: {}", current.display);
    } else {
        println!("default user: none");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_use(cli: &CliContext, args: UserUseArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let user = resolve_cli_user_ref_in_report(session.report(), &crypto, &args.user)?;
    write_current_user_for_root(
        &report_root_key_hash(session.report())?,
        &user.user_id,
        user.handle.clone(),
    )?;

    if cli.json {
        println!(
            "{}",
            json!({
                "default_user": user_config_ref(&user),
                "user": user_hex(&user.user_id),
                "handle": user.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("default user: {}", user_label(&user));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_list(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let session = cli.read_session()?;

    if cli.json {
        let users = session
            .effective()
            .users
            .keys()
            .map(|user| {
                let handles = handles_for_user(session.report(), user)
                    .into_iter()
                    .map(|record| {
                        json!({
                            "handle": handle_display(&normalize_handle(&record.handle)),
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "user": user_hex(user),
                    "handles": handles,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", json!({ "users": users }));
        return Ok(ExitCode::SUCCESS);
    }

    for user in session.effective().users.keys() {
        let handles = handles_for_user(session.report(), user)
            .into_iter()
            .map(|record| handle_ref(&normalize_handle(&record.handle)))
            .collect::<Vec<_>>();
        if handles.is_empty() {
            println!("{}", short_user_hex(user));
        } else {
            println!("{}\t{}", handles.join(", "), short_user_hex(user));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_show(cli: &CliContext, args: UserShowArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.read_session()?;
    let user = resolve_cli_user_ref_in_report(session.report(), &crypto, &args.user)?;
    let authority = session.effective().authority_for_user(&user.user_id);
    let handles = handles_for_user(session.report(), &user.user_id)
        .into_iter()
        .map(|record| {
            json!({
                "handle": handle_display(&normalize_handle(&record.handle)),
            })
        })
        .collect::<Vec<_>>();

    if cli.json {
        println!(
            "{}",
            json!({
                "user": user_hex(&user.user_id),
                "resolved_handle": user.handle.as_ref().map(|handle| handle_display(handle)),
                "handles": handles,
                "administer": authority.administer,
            })
        );
    } else {
        println!("user: {}", short_user_hex(&user.user_id));
        if let Some(handle) = &user.handle {
            println!("resolved handle: {}", handle_ref(handle));
        }
        println!(
            "vault administration: {}",
            if authority.administer { "yes" } else { "no" }
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_invite(cli: &CliContext, args: UserInviteArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let handle = parse_handle_name(&args.handle)?;
    let grants = invite_grants_from_args(&args)?;
    if !cli.json && args.invite_file.is_none() && !args.print_unsafe && !args.qr {
        return Err(FrontendError::BundleSinkRequired);
    }
    let (mut session, admin) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: format!("invite user {handle}"),
        },
    )?;
    let prepared = session.prepare_invite_user(&crypto, Some(handle.clone()), grants)?;
    // File invitations carry compact Cord bytes and do not need to fit Bech32m's text limit.
    // Encode before committing only when the caller explicitly requested a text/QR sink, so an
    // oversized string can never leave behind a member whose private invitation was not emitted.
    let text_policy = if args.with_rollback_baseline {
        InviteBaselinePolicy::Include
    } else {
        InviteBaselinePolicy::Omit
    };
    let file_policy = if args.compact {
        InviteBaselinePolicy::Omit
    } else {
        InviteBaselinePolicy::Include
    };
    let bundle_string = if args.print_unsafe || args.qr {
        Some(encode_invite(prepared.invite(), text_policy)?)
    } else {
        None
    };
    let bundle_file = match &args.invite_file {
        Some(path) => {
            let bytes = invite_bytes(prepared.invite(), file_policy)?;
            write_private_output(path, &bytes, args.overwrite)?;
            let verified = thorax_ops::read_file_bounded(path, thorax_ops::MAX_INVITE_BYTES)
                .map_err(|source| FrontendError::Io {
                    path: path.clone(),
                    source,
                })?;
            if verified != bytes {
                return Err(FrontendError::InvalidBundleString);
            }
            Some(path.clone())
        }
        None => None,
    };
    let invited = match session.commit_invite_user(&crypto, prepared) {
        Ok(invited) => invited,
        Err(source) => {
            if let Some(path) = bundle_file {
                return Err(FrontendError::InertInviteFile {
                    path,
                    source: Box::new(source),
                });
            }
            return Err(source.into());
        }
    };
    remember_user_if_explicit(session.paths(), &admin)?;

    // Invite converges its own grants: ops re-encrypts existing secrets the admin can read so the
    // new user gets a slot, under the same unlock as the invite. The result rides along on the
    // output — the frontend no longer sequences (or can forget) a separate reconcile.
    let reconciled = &invited.reconcile;
    let encrypted = &reconciled.encrypted;

    if cli.json {
        let mut output = json!({
            "user": user_hex(&invited.user_id),
            "handle": handle_display(&handle),
            "handle_id": invited.handle.as_ref().map(|handle| hash_hex(&handle.0)),
            "grants": invited.grants.iter().map(|grant| hash_hex(&grant.0)).collect::<Vec<_>>(),
                "invite_file": bundle_file.as_ref().map(|path| path.display().to_string()),
                "invite_file_rollback_protected": bundle_file.as_ref().map(|_| matches!(file_policy, InviteBaselinePolicy::Include)),
            "encrypted": encrypted.iter().map(selector_string).collect::<Vec<_>>(),
            "rotation_required": reconciled.needs_rotation.iter().map(selector_string).collect::<Vec<_>>(),
            "admin": user_hex(&admin.resolved.user_id),
            "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
        });
        if args.print_unsafe {
            output["invite"] = json!(bundle_string.as_deref().expect("encoded above"));
            output["invite_rollback_protected"] =
                json!(matches!(text_policy, InviteBaselinePolicy::Include));
        }
        println!("{output}");
        return Ok(ExitCode::SUCCESS);
    }

    println!(
        "invited {} ({})",
        handle_ref(&handle),
        short_user_hex(&invited.user_id)
    );
    println!("signed by: {}", user_label(&admin.resolved));
    if !invited.grants.is_empty() {
        println!("grants: {}", invited.grants.len());
    }

    if let Some(path) = &bundle_file {
        println!();
        println!("invite written to {}", path.display());
        println!(
            "this file holds {}'s private key — send it over a secure channel and delete it afterward.",
            handle_ref(&handle)
        );
        println!(
            "first-sync rollback baseline: {}",
            if matches!(file_policy, InviteBaselinePolicy::Include) {
                "included"
            } else {
                "omitted (rollback protection begins after claim)"
            }
        );
        println!(
            "{} joins by running:  thorax claim {}",
            handle_ref(&handle),
            path.display()
        );
    }
    if args.print_unsafe {
        println!();
        println!("invite (private key — handle securely, do not paste into chat/logs):");
        println!("{}", bundle_string.as_deref().expect("encoded above"));
        if matches!(text_policy, InviteBaselinePolicy::Omit) {
            println!("note: compact invite — rollback protection begins after claim");
        }
        println!(
            "{} joins by running:  thorax claim --invite <invite>",
            handle_ref(&handle)
        );
    }
    if args.qr {
        println!();
        if matches!(text_policy, InviteBaselinePolicy::Omit) {
            println!("compact invite — rollback protection begins after claim");
        }
        match bundle::qr(bundle_string.as_deref().expect("encoded above")) {
            Ok(rendered) => {
                println!(
                    "scan to claim — this encodes {}'s private key; show it only on a trusted screen:",
                    handle_ref(&handle)
                );
                println!("{}", rendered.trim_end());
                println!("then run:  thorax claim --invite <scanned string>");
            }
            Err(_) => {
                println!("(invite too large to render as a QR code; use --invite-file instead)")
            }
        }
    }
    if !encrypted.is_empty() {
        println!();
        println!(
            "encrypted {} so {} can read them",
            thorax_frontend::count_noun(encrypted.len(), "secret"),
            handle_ref(&handle)
        );
    }
    print_reconcile_warning(reconciled);
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_claim(cli: &CliContext, args: ClaimArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let paths = workspace_paths(cli.path.as_ref(), false)?;
    let invite = read_invite(args.invite, args.invite_file)?;

    // Root pinning, rollback verification, membership, trust seeding, and keychain storage all
    // live in thorax-ops so the security path is shared rather than reimplemented here.
    let keychain = build_keychain()?;
    let claimed = claim_invite_with_keychain(&paths, &crypto, &*keychain, &invite)?;

    let resolved =
        resolve_cli_user_ref_in_report(&claimed.report, &crypto, &user_hex(&claimed.user_id))?;
    let default_ref = user_config_ref(&resolved);
    write_current_user_for_root(
        &claimed.trusted_root,
        &resolved.user_id,
        resolved.handle.clone(),
    )?;

    // A fresh clone is exactly where the per-clone merge-driver config is missing, so the
    // claim that onboards it surfaces the same registration hint `status` gives (a hint,
    // never a failure — the claim itself already committed).
    let driver_status = merge_driver_status(&paths.root);

    if cli.json {
        println!(
            "{}",
            json!({
                "user": user_hex(&claimed.user_id),
                "handle": resolved.handle.as_ref().map(|handle| handle_display(handle)),
                "trusted_root": hash_hex(&claimed.trusted_root),
                "identity_backend": claimed.stored.backend,
                "default_user": default_ref,
                "vault_name": primary_vault_name(&claimed.report),
                "baseline_checked": claimed.rollback_protected,
                "merge_driver": driver_status.name(),
            })
        );
        return Ok(ExitCode::SUCCESS);
    }

    let db_label =
        primary_vault_name(&claimed.report).unwrap_or_else(|| short_hash(&claimed.trusted_root));
    println!("joined @{db_label} as {}", user_label(&resolved));
    println!("identity stored in: {}", claimed.stored.backend);
    println!("default user set for this vault");
    if !claimed.rollback_protected {
        println!("note: compact invite — rollback protection begins from this claimed state");
    }
    if let Some(hint) = driver_status.hint() {
        println!();
        println!("note: {hint}");
    }
    println!();
    println!("next: `thorax list` to see what you can read, then `thorax get <selector>`");
    Ok(ExitCode::SUCCESS)
}

fn cmd_user_delete(cli: &CliContext, args: UserDeleteArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let target = resolve_cli_user_ref_in_report(session.report(), &crypto, &args.user_ref)?;
    // Confirm intent before the unlock prompt.
    if !confirm_destructive(
        &format!("delete user {}", user_label(&target)),
        args.yes,
        args.dry_run,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let (mut session, admin) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "delete user".to_string(),
        },
    )?;
    let deleted = session.delete_user(&crypto, target.user_id.clone(), args.reason)?;
    remember_user_if_explicit(session.paths(), &admin)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "user": user_hex(&deleted),
                "user_handle": target.handle.as_ref().map(|handle| handle_display(handle)),
                "deleted": true,
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("deleted user: {}", user_label(&target));
        println!("signed by: {}", user_label(&admin.resolved));
        println!("their access to future values ends at the next change to each secret");
    }
    Ok(ExitCode::SUCCESS)
}

fn invite_grants_from_args(args: &UserInviteArgs) -> Result<Vec<GrantPermissionV1>, FrontendError> {
    let mut grants = Vec::new();
    for selector in &args.read {
        grants.push(GrantPermissionV1::ReadKeyspace(parse_keyspace_selector(
            selector, false,
        )?));
    }
    for selector in &args.write {
        grants.push(GrantPermissionV1::WriteKeyspace(parse_keyspace_selector(
            selector, false,
        )?));
    }
    for selector in &args.manage {
        grants.push(GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
            selector: parse_keyspace_selector(selector, false)?,
            grantable: vec![KeyspaceGrantClassV1::Read, KeyspaceGrantClassV1::Write],
        }));
    }
    if args.administer {
        grants.push(GrantPermissionV1::Administer);
    }
    Ok(grants)
}

fn cmd_user_handle(
    cli: &CliContext,
    command: UserHandleCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        UserHandleCommand::Set(args) => cmd_user_handle_set(cli, args),
    }
}

fn cmd_user_handle_set(
    cli: &CliContext,
    args: UserHandleSetArgs,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let target = resolve_cli_user_ref_in_report(session.report(), &crypto, &args.target)?;
    let handle = parse_handle_name(&args.handle)?;
    let (mut session, admin) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: format!("set user handle {handle}"),
        },
    )?;
    let handle_id = session.set_user_handle(&crypto, handle.clone(), target.user_id.clone())?;
    remember_user_if_explicit(session.paths(), &admin)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "handle": handle_display(&handle),
                "handle_id": hash_hex(&handle_id.0),
                "target": user_hex(&target.user_id),
                "target_handle": target.handle.as_ref().map(|handle| handle_display(handle)),
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("{} -> {}", handle_ref(&handle), user_label(&target));
        println!("signed by: {}", user_label(&admin.resolved));
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn user_label(user: &ResolvedUserRef) -> String {
    match &user.handle {
        Some(handle) => format!("{} ({})", handle_ref(handle), short_user_hex(&user.user_id)),
        None => short_user_hex(&user.user_id),
    }
}

pub(crate) fn handles_for_user<'a>(
    report: &'a ValidationReport,
    user: &UserId,
) -> Vec<&'a thorax_ops::UserHandleRecordV1> {
    let mut handles = report
        .effective
        .handles
        .values()
        .filter(|record| &record.user_id == user)
        .collect::<Vec<_>>();
    handles.sort_by_key(|record| normalize_handle(&record.handle));
    handles
}
