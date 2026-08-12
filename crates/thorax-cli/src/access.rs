use std::process::ExitCode;

use serde_json::json;
use thorax_frontend::{
    confirm_destructive, decode_hex_exact, escape_tuple, hash_hex, normalize_hex_prefix,
    parse_secret_selector, remember_user_if_explicit, resolve_cli_user_ref_in_report,
    selector_string, short_hash, short_user_hex, user_hex, FrontendError,
};
use thorax_ops::{
    normalize_handle, selector_matches, Crypto, GrantId, GrantPermissionV1, GroupId, HashValue,
    KeyUsePurpose, KeyspaceGrantClassV1, KeyspaceSelectorV1, ManageKeyspaceGrantV1, OpsError,
    PrincipalRefV1, TupleMatcherV1, ValidationReport,
};

use crate::args::{
    GrantCommand, GrantDeleteArgs, GroupCommand, GroupCreateArgs, GroupDeleteArgs, GroupMemberArgs,
    ManageGrantArgs,
};
use crate::output::{handle_display, handle_ref, print_reconcile_notes};
use crate::users::{handles_for_user, user_label};
use crate::CliContext;

pub(crate) fn cmd_grant(
    cli: &CliContext,
    command: GrantCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        GrantCommand::Read(args) => cmd_grant_keyspace(
            cli,
            args.selector,
            args.subject,
            args.user,
            args.exact,
            GrantKind::Read,
        ),
        GrantCommand::Write(args) => cmd_grant_keyspace(
            cli,
            args.selector,
            args.subject,
            args.user,
            args.exact,
            GrantKind::Write,
        ),
        GrantCommand::Manage(args) => cmd_grant_manage(cli, args),
        GrantCommand::Admin(args) => {
            cmd_grant_admin(cli, args.subject, args.user, GrantPermissionV1::Administer)
        }
        GrantCommand::List => cmd_grant_list(cli),
        GrantCommand::Delete(args) => cmd_grant_delete(cli, args),
    }
}

pub enum GrantKind {
    Read,
    Write,
}

fn cmd_grant_keyspace(
    cli: &CliContext,
    selector: String,
    to: String,
    user: Option<String>,
    exact: bool,
    kind: GrantKind,
) -> Result<ExitCode, FrontendError> {
    let keyspace = parse_keyspace_selector(&selector, exact)?;
    let permission = match kind {
        GrantKind::Read => GrantPermissionV1::ReadKeyspace(keyspace),
        GrantKind::Write => GrantPermissionV1::WriteKeyspace(keyspace),
    };
    cmd_grant_permission(cli, to, user, permission)
}

fn cmd_grant_manage(cli: &CliContext, args: ManageGrantArgs) -> Result<ExitCode, FrontendError> {
    let permission = GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
        selector: parse_keyspace_selector(&args.selector, args.exact)?,
        grantable: parse_grantable_classes(&args.grantable)?,
    });
    cmd_grant_permission(cli, args.subject, args.user, permission)
}

fn cmd_grant_admin(
    cli: &CliContext,
    to: String,
    user: Option<String>,
    permission: GrantPermissionV1,
) -> Result<ExitCode, FrontendError> {
    cmd_grant_permission(cli, to, user, permission)
}

fn cmd_grant_permission(
    cli: &CliContext,
    to: String,
    user: Option<String>,
    permission: GrantPermissionV1,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let subject = resolve_principal_ref(session.report(), &crypto, &to)?;
    let (mut session, issuer) = cli.promote_for_action(
        session,
        user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "grant access".to_string(),
        },
    )?;
    // One intent op: the grant is appended *and* existing secrets are re-encrypted to the
    // new reader. The convergence obligation lives in ops, so there is no separate
    // reconcile to remember (and no way for a frontend to forget it).
    let granted = session.grant_permission(&crypto, subject.clone(), permission.clone())?;
    remember_user_if_explicit(session.paths(), &issuer)?;
    let reconciled = &granted.reconcile;

    let (matching_count, selector_display) = match &permission {
        GrantPermissionV1::ReadKeyspace(s) | GrantPermissionV1::WriteKeyspace(s) => {
            let secrets = session.effective().secret_records();
            let count = secrets
                .iter()
                .filter(|r| selector_matches(s, &r.value.selector))
                .count();
            (count, keyspace_selector_string(s))
        }
        GrantPermissionV1::ManageKeyspace(manage) => {
            let secrets = session.effective().secret_records();
            let count = secrets
                .iter()
                .filter(|r| selector_matches(&manage.selector, &r.value.selector))
                .count();
            (count, keyspace_selector_string(&manage.selector))
        }
        GrantPermissionV1::Administer => {
            let secrets = session.effective().secret_records();
            (secrets.len(), "*".to_string())
        }
    };

    if cli.json {
        println!(
            "{}",
            json!({
                "grant": hash_hex(&granted.output.0),
                "subject": principal_json(session.report(), &subject),
                "permission": grant_permission_string(&permission),
                "matches": matching_count,
                "selector": selector_display,
                "encrypted": reconciled.encrypted.iter().map(selector_string).collect::<Vec<_>>(),
                "rotation_required": reconciled.needs_rotation.iter().map(selector_string).collect::<Vec<_>>(),
                "issuer": user_hex(&issuer.resolved.user_id),
                "issuer_handle": issuer.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("grant: {}", short_hash(&granted.output.0));
        println!("subject: {}", principal_label(session.report(), &subject));
        println!("permission: {}", grant_permission_string(&permission));
        if matching_count > 0 {
            println!(
                "matches: {} secret(s) under {}",
                matching_count, selector_display
            );
        }
        println!("signed by: {}", user_label(&issuer.resolved));
        print_reconcile_notes(reconciled);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_grant_list(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let session = cli.read_session()?;
    let mut grants = session.effective().grants.iter().collect::<Vec<_>>();
    grants.sort_by(|(left_id, left), (right_id, right)| {
        principal_label(session.report(), &left.subject_id)
            .cmp(&principal_label(session.report(), &right.subject_id))
            .then_with(|| {
                grant_permission_string(&left.permission)
                    .cmp(&grant_permission_string(&right.permission))
            })
            .then_with(|| left_id.cmp(right_id))
    });

    if cli.json {
        let grants = grants
            .into_iter()
            .map(|(grant, record)| {
                json!({
                    "grant": hash_hex(&grant.0),
                    "subject": principal_json(session.report(), &record.subject_id),
                    "permission": grant_permission_string(&record.permission),
                })
            })
            .collect::<Vec<_>>();
        println!("{}", json!({ "grants": grants }));
        return Ok(ExitCode::SUCCESS);
    }

    for (grant, record) in grants {
        println!(
            "{}\t{}\t{}",
            short_hash(&grant.0),
            principal_label(session.report(), &record.subject_id),
            grant_permission_string(&record.permission)
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_grant_delete(cli: &CliContext, args: GrantDeleteArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let grant = resolve_grant_ref(session.report(), &args.grant)?;
    // Cloned: the record is rendered after the deletion commit replaces the session state.
    let active = session
        .effective()
        .grants
        .get(&grant)
        .cloned()
        .ok_or(OpsError::OperationNotEffective("grant is not active"))?;
    // Confirm intent before the unlock prompt: a declined confirmation should never have
    // cost a passphrase entry.
    if !confirm_destructive(
        &format!(
            "delete grant {} ({} — {})",
            short_hash(&grant.0),
            principal_label(session.report(), &active.subject_id),
            grant_permission_string(&active.permission)
        ),
        args.yes,
        args.dry_run,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let (mut session, issuer) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "delete grant".to_string(),
        },
    )?;
    let deleted = session.delete_grant(&crypto, grant.clone())?;
    remember_user_if_explicit(session.paths(), &issuer)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "grant": hash_hex(&deleted.0),
                "deleted": true,
                "subject": principal_json(session.report(), &active.subject_id),
                "permission": grant_permission_string(&active.permission),
                "issuer": user_hex(&issuer.resolved.user_id),
                "issuer_handle": issuer.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("deleted grant: {}", short_hash(&deleted.0));
        println!(
            "subject: {}",
            principal_label(session.report(), &active.subject_id)
        );
        println!(
            "permission: {}",
            grant_permission_string(&active.permission)
        );
        println!("signed by: {}", user_label(&issuer.resolved));
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_group(
    cli: &CliContext,
    command: GroupCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        GroupCommand::List => cmd_group_list(cli),
        GroupCommand::Create(args) => cmd_group_create(cli, args),
        GroupCommand::Delete(args) => cmd_group_delete(cli, args),
        GroupCommand::Add(args) => cmd_group_add(cli, args),
        GroupCommand::Remove(args) => cmd_group_remove(cli, args),
    }
}

fn cmd_group_list(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let session = cli.read_session()?;
    let mut groups = session.effective().groups.iter().collect::<Vec<_>>();
    groups.sort_by(|(left_id, left), (right_id, right)| {
        normalize_handle(&left.handle)
            .cmp(&normalize_handle(&right.handle))
            .then_with(|| left_id.cmp(right_id))
    });

    if cli.json {
        let groups = groups
            .into_iter()
            .map(|(group, record)| {
                let members = group_members(session.report(), group)
                    .into_iter()
                    .map(|member| {
                        json!({
                            "membership": hash_hex(&member.id.0),
                            "member": principal_json(session.report(), &member.member_id),
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "group": hash_hex(&group.0),
                    "group_handle": &record.handle,
                    "members": members,
                })
            })
            .collect::<Vec<_>>();
        println!("{}", json!({ "groups": groups }));
        return Ok(ExitCode::SUCCESS);
    }

    for (group, record) in groups {
        let members = group_members(session.report(), group);
        println!(
            "{}\t{}\t{} member(s)",
            short_hash(&group.0),
            format_args!("%{}", record.handle),
            members.len()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_group_create(cli: &CliContext, args: GroupCreateArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let (mut session, admin) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: format!("create group {}", args.name),
        },
    )?;
    let group_id = session.create_group(&crypto, args.name.clone())?;
    remember_user_if_explicit(session.paths(), &admin)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "group": hash_hex(&group_id.0),
                "group_handle": args.name,
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("group: %{} ({})", args.name, short_hash(&group_id.0));
        println!("signed by: {}", user_label(&admin.resolved));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_group_delete(cli: &CliContext, args: GroupDeleteArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let group = resolve_group_ref(session.report(), &args.group)?;
    let handle = group_label(session.report(), &group);
    // Confirm intent before the unlock prompt.
    if !confirm_destructive(
        &format!("delete group {handle} ({})", short_hash(&group.0)),
        args.yes,
        args.dry_run,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let (mut session, admin) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "delete group".to_string(),
        },
    )?;
    let deleted = session.delete_group(&crypto, group.clone())?;
    remember_user_if_explicit(session.paths(), &admin)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "group": hash_hex(&deleted.0),
                "group_handle": handle,
                "deleted": true,
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("deleted group: %{handle} ({})", short_hash(&deleted.0));
        println!("signed by: {}", user_label(&admin.resolved));
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_group_add(cli: &CliContext, args: GroupMemberArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let group = resolve_group_ref(session.report(), &args.group)?;
    let member = resolve_principal_ref(session.report(), &crypto, &args.member)?;
    let (mut session, admin) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "add group member".to_string(),
        },
    )?;
    // Conferring membership confers the group's read grants, so ops re-encrypts existing
    // secrets for the new member in the same op — convergence rides along on the result.
    let added = session.add_group_member(&crypto, group.clone(), member.clone())?;
    remember_user_if_explicit(session.paths(), &admin)?;
    let reconciled = &added.reconcile;

    if cli.json {
        println!(
            "{}",
            json!({
                "membership": hash_hex(&added.output.0),
                "group": hash_hex(&group.0),
                "group_handle": group_label(session.report(), &group),
                "member": principal_json(session.report(), &member),
                "encrypted": reconciled.encrypted.iter().map(selector_string).collect::<Vec<_>>(),
                "rotation_required": reconciled.needs_rotation.iter().map(selector_string).collect::<Vec<_>>(),
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!(
            "added {} to {}",
            principal_label(session.report(), &member),
            group_label(session.report(), &group)
        );
        println!("membership: {}", short_hash(&added.output.0));
        println!("signed by: {}", user_label(&admin.resolved));
        print_reconcile_notes(reconciled);
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_group_remove(cli: &CliContext, args: GroupMemberArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;
    let group = resolve_group_ref(session.report(), &args.group)?;
    let member = resolve_principal_ref(session.report(), &crypto, &args.member)?;
    let is_member = session
        .effective()
        .memberships
        .values()
        .any(|record| record.group_id == group && record.member_id == member);
    if !is_member {
        return Err(FrontendError::GroupMemberNotFound);
    }
    let (mut session, admin) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "remove group member".to_string(),
        },
    )?;
    let deleted = session.delete_group_member(&crypto, group.clone(), member.clone())?;
    remember_user_if_explicit(session.paths(), &admin)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "membership": hash_hex(&deleted.0),
                "deleted": true,
                "group": hash_hex(&group.0),
                "group_handle": group_label(session.report(), &group),
                "member": principal_json(session.report(), &member),
                "admin": user_hex(&admin.resolved.user_id),
                "admin_handle": admin.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!(
            "removed {} from {}",
            principal_label(session.report(), &member),
            group_label(session.report(), &group)
        );
        println!("membership: {}", short_hash(&deleted.0));
        println!("signed by: {}", user_label(&admin.resolved));
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn parse_keyspace_selector(
    value: &str,
    exact: bool,
) -> Result<KeyspaceSelectorV1, FrontendError> {
    // The root keyspace — every secret in the vault. `/` (filesystem-root intuition), `*`
    // (glob-all), and `.` are accepted spellings.
    if matches!(value, "*" | "." | "/") {
        return Ok(KeyspaceSelectorV1::all());
    }
    let selector = parse_secret_selector(value)?;
    if exact {
        Ok(KeyspaceSelectorV1::exact(selector.tuple))
    } else {
        Ok(KeyspaceSelectorV1::prefix(selector.tuple))
    }
}

fn keyspace_selector_string(selector: &KeyspaceSelectorV1) -> String {
    match &selector.tuple {
        TupleMatcherV1::Any => "*".to_string(),
        TupleMatcherV1::Exact(parts) => format!("={}", escape_tuple(parts)),
        TupleMatcherV1::Prefix(parts) if parts.is_empty() => "*".to_string(),
        TupleMatcherV1::Prefix(parts) => format!("{}/*", escape_tuple(parts)),
    }
}

fn grant_permission_string(permission: &GrantPermissionV1) -> String {
    match permission {
        GrantPermissionV1::ReadKeyspace(selector) => {
            format!("read {}", keyspace_selector_string(selector))
        }
        GrantPermissionV1::WriteKeyspace(selector) => {
            format!("write {}", keyspace_selector_string(selector))
        }
        GrantPermissionV1::ManageKeyspace(manage) => {
            let grantable = manage
                .grantable
                .iter()
                .map(grant_class_name)
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "manage {} [{}]",
                keyspace_selector_string(&manage.selector),
                grantable
            )
        }
        GrantPermissionV1::Administer => "administer".to_string(),
    }
}

fn grant_class_name(class: &KeyspaceGrantClassV1) -> &'static str {
    match class {
        KeyspaceGrantClassV1::Read => "read",
        KeyspaceGrantClassV1::Write => "write",
        KeyspaceGrantClassV1::Manage => "manage",
    }
}

fn parse_grantable_classes(value: &str) -> Result<Vec<KeyspaceGrantClassV1>, FrontendError> {
    let mut read = false;
    let mut write = false;
    let mut manage = false;
    for part in value.split(',') {
        match part.trim().to_ascii_lowercase().as_str() {
            "read" => read = true,
            "write" => write = true,
            "manage" => manage = true,
            "" => {}
            other => return Err(FrontendError::InvalidGrantable(other.to_string())),
        }
    }

    let mut out = Vec::new();
    if read {
        out.push(KeyspaceGrantClassV1::Read);
    }
    if write {
        out.push(KeyspaceGrantClassV1::Write);
    }
    if manage {
        out.push(KeyspaceGrantClassV1::Manage);
    }
    if out.is_empty() {
        return Err(FrontendError::InvalidGrantable(value.to_string()));
    }
    Ok(out)
}

fn resolve_grant_ref(report: &ValidationReport, value: &str) -> Result<GrantId, FrontendError> {
    if let Ok(grant) = parse_grant_id(value) {
        if report.effective.grants.contains_key(&grant) {
            return Ok(grant);
        }
        return Err(FrontendError::GrantNotFound(value.to_string()));
    }
    let needle = normalize_hex_prefix(value)
        .ok_or_else(|| FrontendError::GrantNotFound(value.to_string()))?;
    let matches = report
        .effective
        .grants
        .keys()
        .filter(|grant| hash_hex(&grant.0).starts_with(&needle))
        .cloned()
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(FrontendError::GrantNotFound(value.to_string())),
        1 => Ok(matches.into_iter().next().expect("one grant")),
        _ => Err(FrontendError::AmbiguousGrant(value.to_string())),
    }
}

fn parse_grant_id(value: &str) -> Result<GrantId, FrontendError> {
    Ok(GrantId(HashValue(decode_hex_exact(value, "grant ID", 32)?)))
}

fn parse_group_id(value: &str) -> Result<GroupId, FrontendError> {
    Ok(GroupId(HashValue(decode_hex_exact(value, "group ID", 32)?)))
}

fn resolve_principal_ref(
    report: &ValidationReport,
    crypto: &Crypto,
    value: &str,
) -> Result<PrincipalRefV1, FrontendError> {
    if let Some(group) = strip_group_prefix(value) {
        Ok(PrincipalRefV1::Group(resolve_group_ref(report, group)?))
    } else {
        Ok(PrincipalRefV1::User(
            resolve_cli_user_ref_in_report(report, crypto, value)?.user_id,
        ))
    }
}

/// A leading `%` marks a group reference (`%devs`) — the sudoers/Unix-group convention, and
/// shell-safe unquoted. `group:` is also accepted as a longer, equally unambiguous form.
fn strip_group_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix('%')
        .or_else(|| value.strip_prefix("group:"))
}

fn resolve_group_ref(report: &ValidationReport, value: &str) -> Result<GroupId, FrontendError> {
    // Tolerate an optional `%`/`group:` prefix even in group-only positionals, so `%devs` works
    // everywhere a group can be named.
    let value = strip_group_prefix(value).unwrap_or(value);
    if let Ok(group) = parse_group_id(value) {
        if report.effective.groups.contains_key(&group) {
            return Ok(group);
        }
        return Err(FrontendError::GroupNotFound(value.to_string()));
    }

    if let Some(needle) = normalize_hex_prefix(value) {
        let matches = report
            .effective
            .groups
            .keys()
            .filter(|group| hash_hex(&group.0).starts_with(&needle))
            .cloned()
            .collect::<Vec<_>>();
        match matches.len() {
            0 => {}
            1 => return Ok(matches.into_iter().next().expect("one group")),
            _ => return Err(FrontendError::AmbiguousGroup(value.to_string())),
        }
    }

    let normalized = normalize_handle(value);
    let matches = report
        .effective
        .groups
        .iter()
        .filter(|(_, record)| normalize_handle(&record.handle) == normalized)
        .map(|(group, _)| group.clone())
        .collect::<Vec<_>>();
    match matches.len() {
        0 => Err(FrontendError::GroupNotFound(value.to_string())),
        1 => Ok(matches.into_iter().next().expect("one group")),
        _ => Err(FrontendError::AmbiguousGroup(value.to_string())),
    }
}

fn group_label(report: &ValidationReport, group: &GroupId) -> String {
    report
        .effective
        .groups
        .get(group)
        .map(|record| record.handle.clone())
        .unwrap_or_else(|| hash_hex(&group.0))
}

pub(crate) fn principal_label(report: &ValidationReport, principal: &PrincipalRefV1) -> String {
    match principal {
        PrincipalRefV1::User(user) => {
            let handles = handles_for_user(report, user);
            if let Some(handle) = handles.first() {
                format!(
                    "{} ({})",
                    handle_ref(&normalize_handle(&handle.handle)),
                    short_user_hex(user)
                )
            } else {
                short_user_hex(user)
            }
        }
        PrincipalRefV1::Group(group) => {
            format!("%{} ({})", group_label(report, group), short_hash(&group.0))
        }
    }
}

fn principal_json(report: &ValidationReport, principal: &PrincipalRefV1) -> serde_json::Value {
    match principal {
        PrincipalRefV1::User(user) => {
            let handle = handles_for_user(report, user)
                .first()
                .map(|record| handle_display(&normalize_handle(&record.handle)));
            json!({
                "kind": "user",
                "user": user_hex(user),
                "handle": handle,
            })
        }
        PrincipalRefV1::Group(group) => json!({
            "kind": "group",
            "group": hash_hex(&group.0),
            "handle": group_label(report, group),
        }),
    }
}

fn group_members<'a>(
    report: &'a ValidationReport,
    group: &GroupId,
) -> Vec<&'a thorax_ops::GroupMemberRecordV1> {
    let mut members = report
        .effective
        .memberships
        .values()
        .filter(|record| &record.group_id == group)
        .collect::<Vec<_>>();
    members.sort_by(|left, right| {
        principal_label(report, &left.member_id)
            .cmp(&principal_label(report, &right.member_id))
            .then_with(|| left.id.cmp(&right.id))
    });
    members
}
