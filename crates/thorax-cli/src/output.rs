use serde_json::json;
use thorax_frontend::{
    self as frontend, conflict_kind_summary, conflict_label, hash_hex, merge_driver_status,
    record_key_kind, resolve_cli_user_ref_in_report, selector_string, short_hash,
    stored_default_user, user_hex,
};
use thorax_ops::{
    ConflictKind, Crypto, LockedSession, ReconcileOutput, SecretState, ValidationIssue,
};

use crate::secrets::active_secret_selector;
use crate::vault::primary_vault_name;

pub(crate) fn print_workspace_report(
    json_output: bool,
    session: &LockedSession,
    validation_command: bool,
    trusted: bool,
) {
    let record_count = match session.vault() {
        thorax_ops::VaultStore::V1(v1) => v1.records.len(),
    };
    let report = session.report();
    let issue_strings = report.issues.iter().map(issue_string).collect::<Vec<_>>();
    let warning_strings = report
        .warnings
        .iter()
        .map(frontend::describe_warning)
        .collect::<Vec<_>>();
    let valid = issue_strings.is_empty();
    let default_user = stored_default_user(session.paths(), &session.ratchet().trusted_root)
        .ok()
        .flatten();
    let secret_records = report.effective.secret_records();
    let active_secrets = secret_records.len();
    let conflicts = report.effective.conflicted.len();
    let rollback_conflicts = report
        .effective
        .conflicted
        .values()
        .filter(|conflict| matches!(conflict.kind, ConflictKind::Rollback { .. }))
        .count();
    let driver_status = merge_driver_status(&session.paths().root);
    let pending_transaction = session.pending_transaction();

    // Classify active secrets for the default user so status/validate can surface what
    // needs attention (stale slots, rotation) instead of leaving the user to discover it
    // on a later failed `get`.
    let crypto = Crypto;
    let default_user_ref = default_user
        .as_ref()
        .and_then(|value| resolve_cli_user_ref_in_report(report, &crypto, &value.user_ref).ok());
    let mut not_encrypted = Vec::new();
    if let Some(user) = &default_user_ref {
        for record in &secret_records {
            let selector = active_secret_selector(record);
            if matches!(
                report
                    .effective
                    .classify_secret_for_user(selector, &user.user_id, &crypto,),
                SecretState::NotEncryptedForReader
            ) {
                not_encrypted.push(selector_string(selector));
            }
        }
    }

    if json_output {
        println!(
            "{}",
            json!({
                "vault": session.paths().vault_path.display().to_string(),
                "trusted": trusted,
                "valid": valid,
                "root_user": report.effective.root_user_id.as_ref().map(user_hex),
                "trusted_root": report.effective.root_signing_public_key_hash.as_ref().map(hash_hex),
                "vault_name": primary_vault_name(report),
                "default_user": default_user.as_ref().map(|value| value.display.as_str()),
                "records": record_count,
                "users": report.effective.users.len(),
                "handles": report.effective.handles.len(),
                "vault_names": report.effective.vault_handles.len(),
                "secrets": active_secrets,
                "groups": report.effective.groups.len(),
                "memberships": report.effective.memberships.len(),
                "grants": report.effective.grants.len(),
                "deleted_users": report.effective.deleted_users.len(),
                "deleted_groups": report.effective.deleted_groups.len(),
                "deleted_grants": report.effective.deleted_grants.len(),
                "not_encrypted": not_encrypted,
                "conflicts": conflicts,
                "rollback_conflicts": rollback_conflicts,
                "merge_driver": driver_status.name(),
                "issues": issue_strings,
                "warnings": warning_strings,
                "pending_transaction": pending_transaction.map(|pending| json!({
                    "transaction_id": frontend::hex_bytes(&pending.transaction_id),
                    "operation": pending.operation,
                    "origin": pending.origin.as_ref().map(|path| path.display().to_string()),
                    "recoverable_here": pending.recoverable_here,
                })),
            })
        );
        return;
    }

    let attention = not_encrypted.len() + conflicts;
    if validation_command {
        println!("validation: {}", if valid { "ok" } else { "failed" });
    } else {
        match (
            primary_vault_name(report),
            &report.effective.root_signing_public_key_hash,
        ) {
            (Some(name), Some(root)) => println!("vault: @{name}  (root {})", short_hash(root)),
            (Some(name), None) => println!("vault: @{name}"),
            (None, Some(root)) => println!("vault: root {}", short_hash(root)),
            (None, None) => println!("vault: {}", session.paths().vault_path.display()),
        }
        if let Some(default_user) = &default_user {
            println!("you: {}", default_user.display);
        }
        let health = if !valid {
            "needs attention (validation failed)".to_string()
        } else if attention > 0 {
            format!("needs attention ({attention} item(s))")
        } else {
            "ok".to_string()
        };
        println!("status: {health}");
        println!();
        println!("secrets: {active_secrets} active");
        println!(
            "access: {} user(s), {} group(s), {} grant(s)",
            report.effective.users.len(),
            report.effective.groups.len(),
            report.effective.grants.len(),
        );
    }
    if !not_encrypted.is_empty() {
        println!();
        println!(
            "attention: {} secret(s) you're authorized for aren't encrypted to you (unexpected)",
            not_encrypted.len()
        );
        println!("  ask someone who can write them to set them again:");
        for selector in &not_encrypted {
            println!("    {selector}");
        }
    }
    if conflicts > 0 {
        println!();
        println!(
            "attention: {conflicts} unresolved conflict(s) — these keys have no effective value until resolved; see thorax conflicts"
        );
        for conflict in report.effective.conflicted.values() {
            println!(
                "    {} {}: {}",
                record_key_kind(&conflict.key),
                conflict_label(conflict),
                conflict_kind_summary(conflict)
            );
        }
        if rollback_conflicts > 0 {
            println!(
                "  a rollback conflict means the vault is missing something this machine already verified (often a removal)."
            );
            println!(
                "  resolve it in place, or — if this is an intentional historical checkout — run `thorax trust reset`"
            );
        }
    }
    if let Some(pending) = pending_transaction {
        println!();
        println!(
            "pending transaction: {} ({})",
            frontend::hex_bytes(&pending.transaction_id),
            pending.operation
        );
        if let Some(origin) = &pending.origin {
            println!("  origin: {}", origin.display());
        }
        if pending.recoverable_here {
            println!("  this workspace will recover it automatically on the next load");
        } else {
            println!(
                "  writes are blocked; recover it in the origin or run `thorax trust abandon-transaction --yes` after verifying that workspace is unavailable"
            );
        }
    }
    if let Some(hint) = driver_status.hint() {
        println!();
        println!("note: {hint}");
    }
    for issue in issue_strings {
        println!("issue: {issue}");
    }
    for warning in warning_strings {
        println!("warning: {warning}");
    }
}

/// Print the human-readable result of an automatic reader reconciliation, if anything
/// happened. Shared by every access-changing command.
pub(crate) fn print_reconcile_notes(reconciled: &ReconcileOutput) {
    if !reconciled.encrypted.is_empty() {
        println!(
            "encrypted {} secret(s) to the current readers",
            reconciled.encrypted.len()
        );
    }
    print_reconcile_warning(reconciled);
}

/// Safety-net warning for secrets the actor could not encrypt to a new reader. With the
/// capability hierarchy and group-confer checks this set is always empty in normal operation;
/// a non-empty one signals an unexpected vault state, not a routine remediation.
pub(crate) fn print_reconcile_warning(reconciled: &ReconcileOutput) {
    if !reconciled.needs_rotation.is_empty() {
        println!(
            "note: {} secret(s) could not be encrypted to the new reader because you cannot decrypt them (unexpected — verify your authority)",
            reconciled.needs_rotation.len()
        );
    }
}

pub(crate) fn handle_display(handle: &str) -> String {
    handle.to_string()
}

/// A user handle rendered as a reference the user can type back (`@handle`). Used in human output
/// only; JSON keeps the bare handle via [`handle_display`].
pub(crate) fn handle_ref(handle: &str) -> String {
    format!("@{handle}")
}

pub(crate) fn issue_string(issue: &ValidationIssue) -> String {
    frontend::describe_issue(issue)
}
