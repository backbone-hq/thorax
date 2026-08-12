use thorax_frontend::{build_keychain_with_passphrase, copy_to_clipboard};
use thorax_ops::{
    init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity, LockedSession,
    UnlockedSession,
};
use zeroize::Zeroizing;

use crate::project;

use super::model::{op_error, MergeRevealValue, Model, RevealedField, SessionState};
use super::msg::{Effect, GetPurpose, Message};

/// Perform one effect, optionally producing a follow-up message for the loop to feed back into
/// `update`. Ops calls are methods on the model's [`UnlockedSession`] — the anchored session the
/// unlock gate established, which acts as the unlocked identity without any further keychain
/// round trip. After a successful mutation the projections are refreshed from the
/// already-current session — there is no reload, and a reveal/copy costs zero validations.
pub fn run_effect(model: &mut Model, effect: Effect) -> Option<Message> {
    match effect {
        Effect::Quit => None,
        Effect::Reload => {
            model.reload();
            None
        }
        Effect::CopyToClipboard(bytes) => match copy_to_clipboard(&bytes) {
            Ok(()) => None,
            Err(e) => Some(Message::OpFailed(op_error(e))),
        },
        Effect::GetSecret { selector, purpose } => {
            let Some(session) = model.session.unlocked_mut() else {
                // The eager fields load is best-effort: never nag when locked.
                if purpose == GetPurpose::Fields {
                    return None;
                }
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.get_secret(&model.crypto, selector.clone()) {
                Ok(plaintext) => {
                    if purpose == GetPurpose::Fields {
                        let fields = plaintext
                            .fields
                            .iter()
                            .map(|field| RevealedField {
                                key: field.key.clone(),
                                value: Zeroizing::new(field.value.to_vec()),
                                is_utf8: field.is_utf8(),
                            })
                            .collect();
                        return Some(Message::SecretFieldsLoaded { selector, fields });
                    }
                    let bytes = Zeroizing::new(plaintext.plaintext.to_vec());
                    // Bytes are opaque now: decide text-vs-binary from the value itself.
                    let is_utf8 = plaintext.is_utf8();
                    match purpose {
                        GetPurpose::Fields => unreachable!("handled above"),
                        GetPurpose::Edit if !is_utf8 => Some(Message::OpFailed(
                            "binary secret — edit it via the CLI or a file, not the text editor"
                                .to_string(),
                        )),
                        GetPurpose::Edit => Some(Message::SecretForEdit {
                            selector,
                            plaintext: bytes,
                        }),
                        _ => Some(Message::SecretRevealed {
                            selector,
                            plaintext: bytes,
                            is_utf8,
                            copy: purpose == GetPurpose::Copy,
                        }),
                    }
                }
                Err(e) => {
                    // The eager fields load must not be destructive: a failure here just leaves
                    // the fields box empty, it does not relock the session. Cache the (empty)
                    // result for this selector so the dispatch loop does not retry it endlessly.
                    if purpose == GetPurpose::Fields {
                        model.secret_fields = Some(super::model::SecretFields {
                            selector,
                            fields: Vec::new(),
                        });
                        return None;
                    }
                    // A decrypt failure may mean a stale anchor; relock so the next attempt
                    // re-establishes the session rather than silently failing again.
                    model.relock();
                    Some(Message::OpFailed(op_error(e)))
                }
            }
        }
        Effect::SetSecret {
            selector,
            plaintext,
            label,
        } => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.set_secret(&model.crypto, selector, &plaintext) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk(format!("saved {label}")))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::Join { bundle, passphrase } => {
            let invite = match thorax_frontend::read_invite(Some(bundle), None) {
                Ok(invite) => invite,
                Err(e) => return Some(Message::OpFailed(op_error(e))),
            };
            // Joining establishes this machine's identity, so it builds its own keychain from the
            // entered passphrase (there is no unlocked session yet) — same path init uses.
            let keychain = match build_keychain_with_passphrase(passphrase) {
                Ok(v) => v,
                Err(e) => return Some(Message::OpFailed(op_error(e))),
            };
            // The invitation itself pins the intended root and carries the first-sync rollback
            // baseline; the TUI uses the same claim path as every other frontend.
            match thorax_ops::claim_invite_with_keychain(
                &model.paths,
                &model.crypto,
                &*keychain,
                &invite,
            ) {
                Ok(out) => {
                    let _ = thorax_frontend::write_current_user_for_root(
                        &out.trusted_root,
                        &out.user_id,
                        None,
                    );
                    // Cache the just-claimed identity so the session is immediately usable (no
                    // re-prompt), mirroring init. The identity is derived from the invite seed.
                    if let Ok(identity) =
                        thorax_ops::Identity::from_master_seed(&model.crypto, &invite.master_seed)
                    {
                        model.unlock_session.set_cached(identity);
                    }
                    // Joining is the one mutation with no live session to commit through
                    // (claim bootstraps trust + identity), so it ends in a full load — which
                    // also promotes to the just-cached identity.
                    model.reload();
                    Some(Message::OpOk("joined vault".to_string()))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::DeleteSecret(selector) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            let label = project::selector_path(&selector);
            match session.delete_secret(&model.crypto, selector) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk(format!("deleted {label}")))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::Relabel { old, new } => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            let label = project::selector_path(&new);
            // Re-key (decrypt old → seal at new → tombstone old) is a single ops operation. The
            // new value is sealed to the new selector's current readers, so it is
            // self-converging — no reconcile step.
            match session.relabel_secret(&model.crypto, old, new) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk(format!("moved to {label}")))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::DeleteGrant(grant) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.delete_grant(&model.crypto, grant) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk("deleted grant".to_string()))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::DeleteGroup(group) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.delete_group(&model.crypto, group) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk("deleted group".to_string()))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::Invite(handle) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.invite_user(&model.crypto, Some(handle.clone()), Vec::new()) {
                Ok(out) => match thorax_frontend::encode_invite(&out.invite) {
                    Ok(encoded) => {
                        model.refresh_from_session();
                        Some(Message::ShowBundle(encoded))
                    }
                    Err(e) => Some(Message::OpFailed(op_error(e))),
                },
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::DeleteUser(user) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.delete_user(&model.crypto, user, None) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk("deleted user".to_string()))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::Init(passphrase) => {
            if model.paths.vault_path.exists() {
                return Some(Message::OpFailed("a vault already exists here".to_string()));
            }
            let crypto = Crypto;
            let root = match Identity::generate(&crypto) {
                Ok(r) => r,
                Err(e) => return Some(Message::OpFailed(op_error(thorax_ops::OpsError::from(e)))),
            };
            let root_hash = match key_hash(&crypto, root.signing_public_key()) {
                Ok(h) => h,
                Err(e) => return Some(Message::OpFailed(op_error(thorax_ops::OpsError::from(e)))),
            };
            let keychain = match build_keychain_with_passphrase(passphrase) {
                Ok(v) => v,
                Err(e) => return Some(Message::OpFailed(op_error(e))),
            };
            let db_name = model
                .paths
                .root
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("thorax")
                .to_string();
            if let Err(e) = save_identity_with_keychain_labeled(
                &model.paths,
                &crypto,
                &*keychain,
                &root_hash,
                &root,
                Some(db_name),
                Some("root".to_string()),
            ) {
                return Some(Message::OpFailed(op_error(e)));
            }
            let initialized = match init_vault(&model.paths, &crypto, &root) {
                Ok(i) => i,
                Err(e) => return Some(Message::OpFailed(op_error(e))),
            };
            // One session load for the handle commit that completes an init (mirrors the CLI),
            // anchored to the freshly generated root identity (possession by construction);
            // it then becomes the model's live session — no extra reload.
            let session = match LockedSession::load(&model.paths, &crypto) {
                Ok(s) => s,
                Err(e) => return Some(Message::OpFailed(op_error(e))),
            };
            let mut session = match UnlockedSession::with_identity(session, &crypto, root.clone()) {
                Ok(s) => s,
                Err(e) => return Some(Message::OpFailed(op_error(e))),
            };
            // Set the conventional "root" handle and remember it as this machine's identity, so the
            // acting user resolves to @root. Best effort, like the current-user pointer.
            let _ = session.set_user_handle(&crypto, "root", initialized.root_user_id.clone());
            let _ = thorax_frontend::write_current_user_for_root(
                &initialized.root_signing_public_key_hash,
                &initialized.root_user_id,
                Some("root".to_string()),
            );
            model.session = SessionState::Unlocked(Box::new(session));
            model.refresh_from_session();
            // Cache the freshly created identity so a later reload re-promotes without a re-KDF.
            model.unlock_session.set_cached(root.clone());
            Some(Message::OpOk("initialized a new Thorax vault".to_string()))
        }
        Effect::CreateGroup(name) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.create_group(&model.crypto, name) {
                Ok(_) => {
                    model.refresh_from_session();
                    Some(Message::OpOk("created group".to_string()))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::AddMember { group, member } => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            // Conferring membership confers the group's read grants; ops re-encrypts existing
            // secrets to the new member in the same op, so the convergence rides along on
            // the result — no separate reconcile to sequence here.
            match session.add_group_member(&model.crypto, group, member) {
                Ok(added) => {
                    model.refresh_from_session();
                    Some(Message::OpOk(if added.reconcile.encrypted.is_empty() {
                        "added member".to_string()
                    } else {
                        format!(
                            "added member ╱ re-encrypted {} secret(s)",
                            added.reconcile.encrypted.len()
                        )
                    }))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::GrantPermission {
            subject,
            permission,
        } => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            // The grant is appended *and* existing secrets are re-sealed to the new reader in
            // one op — ops owns that convergence, so the TUI just renders the outcome.
            match session.grant_permission(&model.crypto, subject, permission) {
                Ok(granted) => {
                    model.refresh_from_session();
                    Some(Message::OpOk(if granted.reconcile.encrypted.is_empty() {
                        "granted access".to_string()
                    } else {
                        format!(
                            "granted access ╱ re-encrypted {} secret(s) to the new reader",
                            granted.reconcile.encrypted.len()
                        )
                    }))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::ResolveConflict(pick) => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.resolve_conflict(&model.crypto, &pick) {
                Ok(_) => {
                    // The committed session is post-resolution; the refresh recomputes the
                    // remaining conflicts from it.
                    model.refresh_from_session();
                    let remaining = model.conflicts.len();
                    Some(Message::OpOk(if remaining > 0 {
                        format!("conflict resolved — {remaining} left")
                    } else {
                        "all conflicts resolved — git add the vault to finish the merge".to_string()
                    }))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::AcceptRollback(key) => {
            // Machine-local and fail-open: adjusts this machine's watermark memory only —
            // no record is written, and it works at either session tier (recovery must not
            // require a membership pin a rolled-back vault may be unable to grant).
            let label = model
                .conflicts
                .iter()
                .find(|conflict| conflict.key == key)
                .map(thorax_frontend::conflict_label)
                .unwrap_or_else(|| "this key".to_string());
            let accepted = match &mut model.session {
                SessionState::None => {
                    return Some(Message::OpFailed("no workspace loaded".to_string()))
                }
                SessionState::Locked(session) => session.accept_rollback(&model.crypto, &key),
                SessionState::Unlocked(session) => session.accept_rollback(&model.crypto, &key),
            };
            match accepted {
                Ok(_) => {
                    // The op revalidated in place; the refresh recomputes the remaining
                    // conflicts from the session (the tab disappears with the last one).
                    model.refresh_from_session();
                    Some(Message::OpOk(format!("accepted rollback at {label}")))
                }
                Err(e) => Some(Message::OpFailed(op_error(e))),
            }
        }
        Effect::RevealConflictCandidates { picks } => {
            let Some(session) = model.session.unlocked_mut() else {
                return Some(Message::OpFailed("session is locked".to_string()));
            };
            match session.reveal_conflict_candidates(&model.crypto, &picks) {
                Ok(values) => Some(Message::ConflictCandidatesRevealed {
                    values: values
                        .into_iter()
                        .map(|(pick, plaintext)| MergeRevealValue {
                            pick,
                            is_utf8: plaintext.is_utf8(),
                            plaintext: Zeroizing::new(plaintext.plaintext.to_vec()),
                        })
                        .collect(),
                }),
                Err(e) => {
                    // A decrypt failure may mean a stale anchor; relock so the next attempt
                    // re-establishes the session rather than silently failing again.
                    model.relock();
                    Some(Message::OpFailed(op_error(e)))
                }
            }
        }
    }
}
