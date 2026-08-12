use std::process::ExitCode;

use serde_json::json;
use thorax_frontend::{
    build_keychain, confirm_destructive, hash_hex, short_hash, short_user_hex, workspace_paths,
    FrontendError,
};
use thorax_ops::{
    abandon_transaction_with_keychain, default_keychain_dir, read_current_user, read_vault,
    reset_ratchet_with_keychain, AbandonTransactionOutput, Crypto, RecordKey, ResetRatchetOutput,
    UserId,
};

use crate::args::{TrustAbandonTransactionArgs, TrustCommand, TrustResetArgs};
use crate::CliContext;

pub(crate) fn cmd_trust(
    cli: &CliContext,
    command: TrustCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        TrustCommand::Reset(args) => cmd_trust_reset(cli, args),
        TrustCommand::AbandonTransaction(args) => cmd_abandon_transaction(cli, args),
    }
}

fn cmd_abandon_transaction(
    cli: &CliContext,
    args: TrustAbandonTransactionArgs,
) -> Result<ExitCode, FrontendError> {
    if !confirm_destructive(
        "abandon the pending transaction without editing its originating clone; its stronger rollback watermarks will be retained",
        args.yes,
        false,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let crypto = Crypto;
    let paths = workspace_paths(cli.path.as_ref(), false)?;
    let user_id = trust_reset_identity(&paths, &crypto)?;
    let keychain = build_keychain()?;
    let output = abandon_transaction_with_keychain(&paths, &crypto, &*keychain, &user_id)?;
    print_abandoned_transaction(cli, &output);
    Ok(ExitCode::SUCCESS)
}

fn print_abandoned_transaction(cli: &CliContext, output: &AbandonTransactionOutput) {
    let transaction_id = hash_hex(&thorax_ops::HashValue(output.transaction_id.clone()));
    if cli.json {
        println!(
            "{}",
            json!({
                "trusted_root": hash_hex(&output.trusted_root),
                "transaction_id": transaction_id,
                "operation": output.operation,
                "origin": output.origin.as_ref().map(|path| path.display().to_string()),
                "abandoned": true,
            })
        );
        return;
    }
    println!(
        "abandoned transaction {transaction_id} ({})",
        output.operation
    );
    println!(
        "retained its strongest rollback watermarks; inspect `thorax status` for remaining conflicts"
    );
}

fn cmd_trust_reset(cli: &CliContext, args: TrustResetArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let paths = workspace_paths(cli.path.as_ref(), false)?;
    // Discarding rollback memory is unlock-gated: the identity comes from the keychain's
    // CurrentUser selection (an exact id, resolvable even when the vault itself is the
    // thing under suspicion — no validated report is required to find it).
    let user_id = trust_reset_identity(&paths, &crypto)?;
    let keychain = build_keychain()?;

    if args.dry_run {
        let output = reset_ratchet_with_keychain(&paths, &crypto, &*keychain, &user_id, true)?;
        print_trust_reset(cli, &output, true);
        return Ok(ExitCode::SUCCESS);
    }
    if !confirm_destructive(
        "reset local trust for this vault — only do this for an intentional rollback (e.g. a historical checkout); it discards remembered removals the vault no longer shows",
        args.yes,
        false,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let output = reset_ratchet_with_keychain(&paths, &crypto, &*keychain, &user_id, false)?;
    print_trust_reset(cli, &output, false);
    Ok(ExitCode::SUCCESS)
}

/// The identity that authorizes a trust reset: the vault's `CurrentUser` selection. Found
/// from the vault's root candidate alone — resets run exactly when validation is blocked,
/// so nothing here may depend on a clean report.
fn trust_reset_identity(
    paths: &thorax_ops::WorkspacePaths,
    crypto: &Crypto,
) -> Result<UserId, FrontendError> {
    let vault = read_vault(paths).map_err(thorax_ops::OpsError::from)?;
    let trusted_root = thorax_ops::trusted_root_candidate(&vault, crypto)?;
    let current = read_current_user(&default_keychain_dir()?, &trusted_root)?
        .ok_or(FrontendError::MissingDefaultUser)?;
    Ok(current.user_id)
}

fn print_trust_reset(cli: &CliContext, output: &ResetRatchetOutput, dry_run: bool) {
    if cli.json {
        println!(
            "{}",
            json!({
                "trusted_root": hash_hex(&output.trusted_root),
                "applied": output.applied,
                "dropped_watermarks": output.dropped_watermarks.iter().map(watermark_label).collect::<Vec<_>>(),
            })
        );
        return;
    }

    let verb = if dry_run {
        "would discard"
    } else {
        "discarded"
    };
    if output.dropped_watermarks.is_empty() {
        println!("local trust matches the current vault; nothing to discard");
        return;
    }
    if dry_run {
        println!("resetting local trust would accept the vault's older state for:");
    } else {
        println!("reset local trust from the current vault");
    }
    for key in &output.dropped_watermarks {
        println!(
            "  {verb} newer remembered state for {}",
            watermark_label(key)
        );
    }
}

fn watermark_label(key: &RecordKey) -> String {
    match key {
        RecordKey::User { user_id } => format!("user {}", short_user_hex(user_id)),
        RecordKey::Grant { grant_id } => format!("grant {}", short_hash(&grant_id.0)),
        RecordKey::Group { group_id } => format!("group {}", short_hash(&group_id.0)),
        RecordKey::GroupMember { group_member_id } => {
            format!("group membership {}", short_hash(&group_member_id.0))
        }
        RecordKey::Secret { secret_id } => format!("secret {}", short_hash(&secret_id.0)),
        other => format!("{other:?}"),
    }
}
