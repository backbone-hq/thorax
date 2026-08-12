use std::process::ExitCode;

use serde_json::json;
use thorax_frontend::{
    self as frontend, candidate_summary, confirm_destructive, conflict_kind_name,
    conflict_kind_summary, conflict_label, hash_hex, normalize_hex_prefix, parse_secret_selector,
    record_key_kind, remember_user_if_explicit, resolve_optional_cli_user_ref_with_report,
    short_hash, user_hex, FrontendError,
};
use thorax_ops::{
    ensure_can_resolve_conflict, normalize_handle, record_hash, ConflictKind, ConflictReport,
    Crypto, KeyUsePurpose, OpsError, PrincipalRefV1, RecordBodyV1,
};

use crate::access::principal_label;
use crate::args::{ConflictAcceptArgs, ConflictResolveArgs, ConflictsCommand};
use crate::output::handle_display;
use crate::users::handles_for_user;
use crate::CliContext;

/// `thorax conflicts` — the conflict porcelain. Bare invocation lists the unresolved
/// conflicts (ties and suspected rollbacks alike) from the session's validation report;
/// `resolve` ratifies a chosen candidate. The git merge driver lives under `thorax merge`.
pub(crate) fn cmd_conflicts(
    cli: &CliContext,
    command: Option<ConflictsCommand>,
) -> Result<ExitCode, FrontendError> {
    match command {
        None => cmd_conflicts_list(cli),
        Some(ConflictsCommand::Resolve(args)) => cmd_conflicts_resolve(cli, args),
        Some(ConflictsCommand::Accept(args)) => cmd_conflicts_accept(cli, args),
    }
}

fn cmd_conflicts_list(cli: &CliContext) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let cs = cli.inspect_session()?;
    cs.print_trust_banner(cli.json);
    let session = cs.session();
    let conflicts: Vec<&ConflictReport> = session.effective().conflicted.values().collect();
    let resolver =
        resolve_optional_cli_user_ref_with_report(session.paths(), session.report(), &crypto, None)
            .ok()
            .flatten();

    if cli.json {
        let mut conflict_views = Vec::new();
        for conflict in &conflicts {
            let mut candidates = Vec::new();
            for candidate in &conflict.candidates {
                let hash = record_hash(&crypto, candidate)
                    .map_err(|error| FrontendError::Ops(error.into()))?;
                let signer = session
                    .effective()
                    .user_for_signing_key(&candidate.signing_public_key);
                candidates.push(json!({
                    "record_hash": hash_hex(&hash),
                    "signer": signer.map(user_hex),
                    "signer_handle": signer.and_then(|signer| {
                        handles_for_user(session.report(), signer)
                            .first()
                            .map(|record| handle_display(&normalize_handle(&record.handle)))
                    }),
                    "summary": candidate.body.known().map(candidate_summary),
                }));
            }
            let resolvable = resolver.as_ref().is_some_and(|user| {
                conflict
                    .candidates
                    .first()
                    .and_then(|c| c.body.known())
                    .is_some_and(|body| {
                        ensure_can_resolve_conflict(
                            session.effective(),
                            &user.resolved.user_id,
                            conflict,
                            body,
                        )
                        .is_ok()
                    })
            });
            let remembered_counter = match &conflict.kind {
                ConflictKind::Rollback { remembered_counter } => Some(*remembered_counter),
                ConflictKind::Tie => None,
            };
            conflict_views.push(json!({
                "kind": record_key_kind(&conflict.key),
                "conflict": conflict_kind_name(&conflict.kind),
                "label": conflict_label(conflict),
                "counter": conflict.counter,
                "remembered_counter": remembered_counter,
                "resolvable_by_default_user": resolvable,
                "candidates": candidates,
            }));
        }
        println!("{}", json!({ "conflicts": conflict_views }));
        // Grep convention: the report is the output; unresolved conflicts exit with the
        // same taxonomy code a read of a conflicted secret gets.
        return Ok(if conflicts.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(thorax_frontend::exit::CONFLICT)
        });
    }

    if conflicts.is_empty() {
        println!("no unresolved conflicts");
        return Ok(ExitCode::SUCCESS);
    }

    println!("{} unresolved conflict(s)", conflicts.len());
    for conflict in &conflicts {
        println!();
        println!(
            "{} {} ({})",
            record_key_kind(&conflict.key),
            conflict_label(conflict),
            conflict_kind_summary(conflict),
        );
        for candidate in &conflict.candidates {
            let hash = record_hash(&crypto, candidate)
                .map_err(|error| FrontendError::Ops(error.into()))?;
            println!(
                "  {}  {}  by {}",
                short_hash(&hash),
                candidate
                    .body
                    .known()
                    .map(candidate_summary)
                    .unwrap_or_else(|| "unknown record".to_string()),
                session
                    .effective()
                    .user_for_signing_key(&candidate.signing_public_key)
                    .map(|signer| principal_label(
                        session.report(),
                        &PrincipalRefV1::User(signer.clone())
                    ))
                    .unwrap_or_else(|| "an unknown signer".to_string()),
            );
        }
        if conflict.candidates.is_empty() {
            println!(
                "  no surviving candidates — set a fresh value (thorax set {0} …), or accept the rollback: thorax conflicts accept {0}",
                conflict_label(conflict)
            );
        } else if let Some(user) = &resolver {
            let blocked = conflict
                .candidates
                .first()
                .and_then(|candidate| candidate.body.known())
                .map(|body| {
                    ensure_can_resolve_conflict(
                        session.effective(),
                        &user.resolved.user_id,
                        conflict,
                        body,
                    )
                })
                .and_then(Result::err);
            match blocked {
                None => println!("  resolve: thorax conflicts resolve <record-hash>"),
                Some(error) => println!(
                    "  you cannot resolve this conflict: {}",
                    frontend::diagnose(&FrontendError::Ops(error)).message
                ),
            }
            if matches!(conflict.kind, ConflictKind::Rollback { .. }) {
                println!(
                    "  or accept the rollback (machine-local, no record written): thorax conflicts accept {}",
                    conflict_label(conflict)
                );
            }
        }
    }
    println!();
    println!("until resolved, conflicted keys have no effective value: reads of them fail and listings flag them");
    println!(
        "after resolving: git add {}",
        session.paths().vault_path.display()
    );
    Ok(ExitCode::from(thorax_frontend::exit::CONFLICT))
}

fn cmd_conflicts_resolve(
    cli: &CliContext,
    args: ConflictResolveArgs,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.valid_session()?;

    let prefix = normalize_hex_prefix(&args.pick)
        .ok_or_else(|| FrontendError::ConflictCandidateNotFound(args.pick.clone()))?;
    let mut matches = Vec::new();
    for conflict in session.effective().conflicted.values() {
        for candidate in &conflict.candidates {
            let hash = record_hash(&crypto, candidate)
                .map_err(|error| FrontendError::Ops(error.into()))?;
            if hash_hex(&hash).starts_with(&prefix) {
                matches.push((conflict.clone(), candidate.clone(), hash));
            }
        }
    }
    let (conflict, candidate, hash) = match matches.len() {
        0 => return Err(FrontendError::ConflictCandidateNotFound(args.pick)),
        1 => matches.remove(0),
        _ => return Err(FrontendError::AmbiguousConflictCandidate(args.pick)),
    };
    let body =
        candidate
            .body
            .known()
            .ok_or(FrontendError::Ops(OpsError::ConflictNotResolvable(
                "candidate body is not readable by this build",
            )))?;

    // Confirm intent before the unlock prompt.
    if !confirm_destructive(
        &format!(
            "resolve the conflict at {} {}: make \"{}\" the winner (re-signs it at a fresh counter; the other candidate(s) lose)",
            record_key_kind(&conflict.key),
            conflict_label(&conflict),
            candidate_summary(body),
        ),
        args.yes,
        args.dry_run,
    )? {
        return Ok(ExitCode::SUCCESS);
    }

    // The unlock purpose names what ratifying this candidate signs.
    let purpose = match body {
        RecordBodyV1::Secret(record) => KeyUsePurpose::SignSecretWrite {
            selector: record.selector.clone(),
        },
        RecordBodyV1::SecretDeleted(record) => KeyUsePurpose::SignSecretDelete {
            selector: record.selector.clone(),
        },
        _ => KeyUsePurpose::SignAdminChange {
            summary: "resolve conflict".to_string(),
        },
    };
    let (mut session, user) = cli.promote_for_action(session, args.user.as_deref(), purpose)?;
    let resolved = session.resolve_conflict(&crypto, &hash)?;
    remember_user_if_explicit(session.paths(), &user)?;
    let remaining = session.effective().conflicted.len();

    if cli.json {
        println!(
            "{}",
            json!({
                "resolved": record_key_kind(&resolved.key),
                "label": conflict_label(&conflict),
                "counter": resolved.counter,
                "record_hash": hash_hex(&resolved.record_hash),
                "resolver": user_hex(&user.resolved.user_id),
                "remaining_conflicts": remaining,
            })
        );
    } else {
        println!(
            "resolved: {} {} -> \"{}\" (re-signed at counter {})",
            record_key_kind(&conflict.key),
            conflict_label(&conflict),
            candidate_summary(body),
            resolved.counter,
        );
        if remaining > 0 {
            println!("{remaining} conflict(s) remain — see thorax conflicts");
        } else {
            println!("no conflicts remain");
            println!(
                "mark the merge resolved: git add {}",
                session.paths().vault_path.display()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Accept a rollback by name: the fail-open, machine-local alternative to ratifying — no
/// record is written, this machine just forgets the higher counter it remembered for the
/// one key. The target is matched as a secret selector first (the common case), then
/// against the labels `thorax conflicts` lists.
fn cmd_conflicts_accept(
    cli: &CliContext,
    args: ConflictAcceptArgs,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let mut session = cli.session()?;

    let by_selector = parse_secret_selector(&args.target)
        .ok()
        .and_then(|selector| {
            session
                .effective()
                .secret_conflict(&selector, &crypto)
                .ok()
                .flatten()
                .cloned()
        });
    let conflict = match by_selector {
        Some(conflict) => conflict,
        None => session
            .effective()
            .conflicted
            .values()
            .find(|conflict| conflict_label(conflict) == args.target)
            .cloned()
            .ok_or_else(|| FrontendError::ConflictNotFound(args.target.clone()))?,
    };
    let ConflictKind::Rollback { remembered_counter } = conflict.kind else {
        return Err(FrontendError::Ops(OpsError::ConflictNotResolvable(
            "only rollback conflicts can be accepted — resolve a tie by picking a winner",
        )));
    };

    if !confirm_destructive(
        &format!(
            "accept the rollback at {} {}: this machine forgets it ever verified counter {remembered_counter} here, and the currently visible state becomes trusted as-is",
            record_key_kind(&conflict.key),
            conflict_label(&conflict),
        ),
        args.yes,
        args.dry_run,
    )? {
        return Ok(ExitCode::SUCCESS);
    }

    let accepted = session.accept_rollback(&crypto, &conflict.key)?;
    let remaining = session.effective().conflicted.len();

    if cli.json {
        println!(
            "{}",
            json!({
                "accepted": record_key_kind(&accepted.key),
                "label": conflict_label(&conflict),
                "remembered_counter": accepted.remembered_counter,
                "accepted_counter": accepted.accepted_counter,
                "remaining_conflicts": remaining,
            })
        );
    } else {
        println!(
            "accepted: {} {} (forgot counter {}, now trusting {})",
            record_key_kind(&accepted.key),
            conflict_label(&conflict),
            accepted.remembered_counter,
            if accepted.accepted_counter == 0 {
                "that it never existed".to_string()
            } else {
                format!("counter {}", accepted.accepted_counter)
            },
        );
        if remaining > 0 {
            println!("{remaining} conflict(s) remain — see thorax conflicts");
        } else {
            println!("no conflicts remain");
        }
    }
    Ok(ExitCode::SUCCESS)
}
