// `update` is one big match where most arms early-return their effect list; the explicit `return`
// keeps every arm visually uniform and is clearer than threading a tail expression through.
#![allow(clippy::needless_return)]

use std::time::{Duration, Instant};

use crossterm::event::KeyCode;
use ratatui::layout::Rect;

use thorax_ops::{ConflictKind, HashValue, PrincipalRefV1, RecordKey, SecretState};
use zeroize::Zeroizing;

use crate::project;

use super::model::{
    vault_file_fingerprint, AccessRow, AccessTab, Focus, ListKind, MergeReveal, MergeRow, Model,
    Reveal, Row, Status, CLIPBOARD_CLEAR_SECS, FRESHNESS_INTERVAL, IDLE_TIMEOUT, REVEAL_SECS,
    STATUS_ERROR_SECS, STATUS_INFO_SECS,
};
use super::msg::{
    ConfirmAction, Effect, Form, FormField, FormThen, GetPurpose, GrantForm, GrantSubject,
    MemberForm, Message, Modal, View,
};

// ── update ──────────────────────────────────────────────────────────────────

/// Apply a message to the model, returning effects for the loop to run.
pub fn update(model: &mut Model, msg: Message) -> Vec<Effect> {
    model.now = Instant::now();
    // Any real input counts as activity for the idle-relock timer.
    if !matches!(msg, Message::Tick) {
        model.last_active = model.now;
    }
    match msg {
        Message::Tick => {
            // Auto-remask revealed values and clear the clipboard.
            if let Some(reveal) = &model.reveal {
                if model.now >= reveal.expires_at {
                    model.reveal = None;
                }
            }
            if let Some(reveal) = &model.merge_reveal {
                if model.now >= reveal.expires_at {
                    model.merge_reveal = None;
                }
            }
            let mut effects = Vec::new();
            if let Some(at) = model.clipboard_clear_at {
                if model.now >= at {
                    model.clipboard_clear_at = None;
                    effects.push(Effect::CopyToClipboard(Zeroizing::new(Vec::new())));
                }
            }
            // Auto-relock after inactivity, then the unlock gate takes over the screen.
            if !model.unlock_session.is_locked()
                && model.now.duration_since(model.last_active) >= IDLE_TIMEOUT
            {
                model.relock();
                model.status = Status::info("locked after inactivity");
            }
            // External-change freshness: at most every FRESHNESS_INTERVAL, stat the vault file
            // and reload on change (a git pull, another process). Correctness doesn't depend on
            // this — commits byte-compare under the lock — it just keeps the view current.
            if model.session.exists()
                && model.now.duration_since(model.last_freshness_check) >= FRESHNESS_INTERVAL
            {
                model.last_freshness_check = model.now;
                if vault_file_fingerprint(&model.paths) != model.vault_fingerprint {
                    effects.push(Effect::Reload);
                }
            }
            // Auto-dismiss the transient status: (re)arm the timer whenever the visible text changes,
            // then clear it once due, so an error doesn't pin to the footer until the next message.
            if model.status.text != model.status_seen {
                model.status_seen = model.status.text.clone();
                model.status_expires = (!model.status.text.is_empty()).then(|| {
                    let secs = if model.status.is_error {
                        STATUS_ERROR_SECS
                    } else {
                        STATUS_INFO_SECS
                    };
                    model.now + Duration::from_secs(secs)
                });
            }
            if model.status_expires.is_some_and(|at| model.now >= at) {
                model.status = Status::default();
                model.status_seen.clear();
                model.status_expires = None;
            }
            return effects;
        }
        Message::Quit => {
            model.should_quit = true;
            return vec![Effect::Quit];
        }
        Message::OpenHelp => {
            model.modal = Some(Modal::Help);
            return vec![];
        }
        Message::OpenHealth => {
            model.modal = Some(Modal::Health);
            return vec![];
        }
        Message::CloseModal => {
            model.modal = None;
            return vec![];
        }
        Message::LockNow => {
            model.relock();
            model.status = Status::info("locked");
            return vec![];
        }
        Message::UnlockChar(c) => {
            model.unlock_input.push(c);
            return vec![];
        }
        Message::UnlockBackspace => {
            model.unlock_input.pop();
            return vec![];
        }
        Message::UnlockClear => {
            // Ctrl-U / Ctrl-W / Ctrl-Backspace: clear the whole entry (a passphrase has no words).
            model.unlock_input.clear();
            model.unlock_error = None;
            return vec![];
        }
        Message::UnlockSubmit => {
            let passphrase = std::mem::take(&mut model.unlock_input);
            let Some(acting) = model.acting.clone() else {
                model.unlock_error = Some("no identity selected".to_string());
                return vec![];
            };
            let Some(root) = model
                .session
                .session()
                .and_then(|s| s.effective().root_signing_public_key_hash.clone())
            else {
                model.unlock_error = Some("no trusted root".to_string());
                return vec![];
            };
            // Runs the Argon2 KDF once and caches the unlocked identity for the session.
            match model.unlock_session.unlock(
                passphrase,
                &model.crypto,
                &model.paths,
                &acting,
                &root,
            ) {
                Ok(_identity) => {
                    // Promote before anything renders: possession-check the verifications
                    // (rebuilding them if the cache wasn't ours) and pin membership
                    // ([`UnlockedSession`]). The pre-unlock load was untrusted; the
                    // workspace behind the gate must not be. On failure the promotion
                    // relocked the gate and set `unlock_error`.
                    model.promote_session_if_unlocked();
                    if !model.unlock_session.is_locked() {
                        model.unlock_error = None;
                        model.status = Status::info("unlocked");
                        model.refresh_from_session();
                    }
                }
                Err(err) => {
                    model.unlock_session.lock();
                    model.unlock_error = Some(err);
                }
            }
            return vec![];
        }
        Message::SwitchView(view) => {
            // The Merge view only exists while conflicts do; the tab disappears with the last one.
            if view == View::Merge && model.merge.is_empty() {
                model.status = Status::info("no unresolved conflicts");
                return vec![];
            }
            model.view = view;
            model.focus = Focus::List;
            return vec![];
        }
        Message::CycleAccessTab => {
            model.access_tab = match model.access_tab {
                AccessTab::Users => AccessTab::Groups,
                AccessTab::Groups => AccessTab::Users,
            };
            model.access_selected = 0;
            // Keep focus where it is (so switching from the tab bar stays on the tab bar).
            return vec![];
        }
        Message::SetAccessTab(tab) => {
            model.view = View::Access;
            model.access_tab = tab;
            model.access_selected = 0;
            model.focus = Focus::List;
            return vec![];
        }
        Message::FocusNext => {
            // Tab cycles: list → each action button → back to the list. Users/Groups are top-level
            // tabs now (reached by 1/2/3 or a click), so they are not part of the Tab focus ring.
            let n = model.view_buttons().len();
            model.focus = match model.focus {
                Focus::List if n > 0 => Focus::Button(0),
                Focus::List => Focus::List,
                Focus::Button(i) if i + 1 < n => Focus::Button(i + 1),
                Focus::Button(_) => Focus::List,
            };
            return vec![];
        }
        Message::FocusList => {
            model.focus = Focus::List;
            return vec![];
        }
        Message::ButtonPrev => {
            if let Focus::Button(i) = model.focus {
                model.focus = if i == 0 {
                    Focus::List
                } else {
                    Focus::Button(i - 1)
                };
            }
            return vec![];
        }
        Message::ButtonNext => {
            if let Focus::Button(i) = model.focus {
                let n = model.view_buttons().len();
                if i + 1 < n {
                    model.focus = Focus::Button(i + 1);
                }
            }
            return vec![];
        }
        Message::ActivateButton => {
            if let Focus::Button(i) = model.focus {
                if let Some(action) = model.view_buttons().get(i).copied() {
                    return update(model, action.into_message());
                }
            }
            return vec![];
        }
        Message::MoveUp => {
            if matches!(model.focus, Focus::Button(_)) {
                model.focus = Focus::List;
            } else {
                model.move_selection(-1);
            }
            return vec![];
        }
        Message::MoveDown => {
            if matches!(model.focus, Focus::List) {
                model.move_selection(1);
            }
            return vec![];
        }
        Message::MoveTop => {
            model.move_selection(isize::MIN / 2);
            return vec![];
        }
        Message::MoveBottom => {
            model.move_selection(isize::MAX / 2);
            return vec![];
        }
        Message::PageUp => {
            model.move_selection(-10);
            return vec![];
        }
        Message::PageDown => {
            model.move_selection(10);
            return vec![];
        }
        Message::Open => {
            if model.view == View::Access {
                model.toggle_access();
                return vec![];
            }
            // In the Merge view, → on a conflict header steps into its first candidate.
            if model.view == View::Merge {
                if matches!(model.selected_merge_row(), Some(MergeRow::Conflict { .. })) {
                    model.move_selection(1);
                }
                return vec![];
            }
            // Only folders expand here. Enter/→ on a secret does NOT reveal — revealing plaintext
            // is always an explicit `r` (or the Reveal button), so it never happens by accident.
            if model.view == View::Secrets && model.selected_leaf().is_some() {
                return vec![];
            }
            model.toggle_open();
            return vec![];
        }
        Message::Close => {
            if model.view == View::Access {
                model.collapse_access();
            } else if model.view == View::Merge {
                // ← on a candidate jumps back up to its conflict header.
                if let Some(MergeRow::Candidate { conflict, .. }) = model.selected_merge_row() {
                    let rows = model.merge_rows();
                    if let Some(header) = rows
                        .iter()
                        .position(|row| row == &MergeRow::Conflict { conflict })
                    {
                        model.merge_selected = header;
                    }
                }
            } else {
                model.collapse();
            }
            return vec![];
        }
        Message::Reveal => {
            // Merge view: reveal the whole conflict at once — every candidate the user can
            // decrypt (each gated like any get: the record must carry a slot for them) —
            // so the competing values can be compared, on one shared countdown.
            if model.view == View::Merge {
                if model.is_selected_merge_revealed() {
                    model.merge_reveal = None;
                    model.status = Status::info("hidden");
                    return vec![];
                }
                let Some((conflict, candidate)) = model.selected_merge_candidate() else {
                    return vec![];
                };
                if !candidate.decryptable {
                    model.status = Status::error("this candidate is not decryptable by you");
                    return vec![];
                }
                let picks: Vec<HashValue> = conflict
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.decryptable)
                    .map(|candidate| candidate.pick.clone())
                    .collect();
                return vec![Effect::RevealConflictCandidates { picks }];
            }
            if model.is_selected_revealed() {
                model.reveal = None;
                model.status = Status::info("hidden");
                return vec![];
            }
            return request_get(model, GetPurpose::Reveal);
        }
        Message::HideReveal => {
            model.reveal = None;
            model.merge_reveal = None;
            model.status = Status::info("hidden");
            return vec![];
        }
        Message::Copy => return request_get(model, GetPurpose::Copy),
        Message::StartEdit => return request_get(model, GetPurpose::Edit),
        Message::StartRelabel => {
            let Some(leaf) = model.selected_leaf() else {
                return vec![];
            };
            model.modal = Some(Modal::Form(Box::new(Form {
                title: "Move secret".to_string(),
                fields: vec![
                    FormField::prefilled("Path", project::selector_path(&leaf.selector)),
                    FormField::prefilled("Labels", project::selector_label_pairs(&leaf.selector)),
                ],
                focus: 0,
                error: None,
                note: Some("re-keys the secret; readers may change".to_string()),
                submit_verb: "move".to_string(),
                then: FormThen::Relabel(leaf.selector.clone()),
            })));
            return vec![];
        }
        Message::StartNewSecret => {
            if model.view == View::Secrets {
                model.modal = Some(Modal::Form(Box::new(Form {
                    title: "New secret".to_string(),
                    fields: vec![
                        FormField::text("Path", "app/prod/db"),
                        FormField::text("Labels", "env=prod&region=us  (optional)"),
                    ],
                    focus: 0,
                    error: None,
                    note: None,
                    submit_verb: "next: enter value".to_string(),
                    then: FormThen::NewSecret,
                })));
            }
            return vec![];
        }
        Message::StartClaim => {
            model.modal = Some(Modal::Form(Box::new(Form {
                title: "Join vault with an invite".to_string(),
                fields: vec![
                    FormField::text("Bundle", "paste the thrx1… invite string"),
                    FormField::secret("Passphrase", "to protect your identity on this machine"),
                ],
                focus: 0,
                error: None,
                note: None,
                submit_verb: "join".to_string(),
                then: FormThen::Claim,
            })));
            return vec![];
        }
        Message::StartInvite => {
            model.modal = Some(Modal::Form(Box::new(Form {
                title: "Invite user".to_string(),
                fields: vec![FormField::text("Handle", "e.g. alice")],
                focus: 0,
                error: None,
                note: None,
                submit_verb: "invite".to_string(),
                then: FormThen::Invite,
            })));
            return vec![];
        }
        Message::InitSubmit => {
            // The init gate captures the passphrase inline (in `unlock_input`, the shared gate
            // buffer). Empty is rejected in place; otherwise create the new vault with it.
            let passphrase = std::mem::take(&mut model.unlock_input);
            if passphrase.is_empty() {
                model.unlock_error = Some("passphrase cannot be empty".to_string());
                return vec![];
            }
            model.unlock_error = None;
            return vec![Effect::Init(passphrase)];
        }
        Message::StartGroup => {
            model.modal = Some(Modal::Form(Box::new(Form {
                title: "New group".to_string(),
                fields: vec![FormField::text("Name", "e.g. devs")],
                focus: 0,
                error: None,
                note: None,
                submit_verb: "create".to_string(),
                then: FormThen::Group,
            })));
            return vec![];
        }
        Message::StartGrant => {
            let subjects = model.grant_subjects();
            if subjects.is_empty() {
                model.status = Status::error("no users or groups to grant to yet");
                return vec![];
            }
            // Pre-fill the keyspace from the selection in the Secrets view: a namespace's path, or
            // the tuple of the selected secret (delegating on that specific secret).
            let keyspace = model
                .selected_branch_path()
                .or_else(|| model.selected_leaf().map(|l| l.selector.tuple.clone()))
                .map(|p| p.join("/"))
                .unwrap_or_default();
            // Pre-select the subject when granting from a selected principal in the Access view.
            let subject_idx = model
                .selected_principal()
                .and_then(|p| subjects.iter().position(|s| s.principal == p))
                .unwrap_or(0);
            model.modal = Some(Modal::Grant(Box::new(GrantForm {
                subjects,
                subject_idx,
                class_idx: 0,
                keyspace,
                field: 0,
                error: None,
            })));
            return vec![];
        }
        Message::GrantFormKey(key) => return grant_form_key(model, key),
        Message::StartAddMember => {
            let Some(group) = model.selected_group() else {
                return vec![];
            };
            let group_label = model
                .access
                .groups
                .iter()
                .find(|g| g.group_id == group)
                .map(|g| format!("%{}", g.handle))
                .unwrap_or_else(|| "%group".to_string());
            let candidates: Vec<GrantSubject> = model
                .grant_subjects()
                .into_iter()
                .filter(|s| s.principal != PrincipalRefV1::Group(group.clone()))
                .collect();
            if candidates.is_empty() {
                model.status = Status::error("no principals to add");
                return vec![];
            }
            model.modal = Some(Modal::Member(Box::new(MemberForm {
                group_id: group,
                group_label,
                candidates,
                idx: 0,
                error: None,
            })));
            return vec![];
        }
        Message::MemberFormKey(key) => return member_form_key(model, key),
        Message::MouseClick(col, row) => return handle_click(model, col, row),
        Message::RequestUserDelete => {
            if let Some(user) = model.selected_user() {
                if model.effective().and_then(|s| s.root_user_id.as_ref()) == Some(&user) {
                    model.status = Status::error("cannot delete the root user");
                    return vec![];
                }
                let label = model.user_label(&user);
                model.modal = Some(Modal::Confirm {
                    title: "Delete this user?".to_string(),
                    lines: vec![
                        label,
                        String::new(),
                        "Removes the user and their grants and memberships.".to_string(),
                        "Existing readable secrets stay readable until rotated.".to_string(),
                        "Re-inviting creates a fresh identity — old access is lost.".to_string(),
                    ],
                    action: ConfirmAction::DeleteUser(user),
                });
            }
            return vec![];
        }
        Message::OpenFacetFilter => {
            if model.view != View::Secrets {
                return vec![];
            }
            // The filter narrows the tree by a secret label. With no labels in the namespace there's
            // nothing to filter by — say so, rather than opening an empty picker.
            if model.facets.keys.is_empty() {
                model.status =
                    Status::info("no labels to filter by — give secrets labels like env=prod");
                return vec![];
            }
            model.modal = Some(Modal::Facet { focus: 0 });
            return vec![];
        }
        Message::FacetFormKey(key) => return facet_form_key(model, key),
        Message::OpenSearch => {
            // Focus the bar, keeping any existing query so `/` re-opens to edit it. The list keeps
            // its current selection; typing reprojects and resets it.
            model.searching = true;
            model.focus = Focus::List;
            return vec![];
        }
        Message::SearchChar(c) => {
            model.search.push(c);
            model.reproject();
            model.select_first_leaf();
            return vec![];
        }
        Message::SearchBackspace => {
            model.search.pop();
            model.reproject();
            model.select_first_leaf();
            return vec![];
        }
        Message::SearchApply => {
            // Keep the query applied; hand the keyboard back to list navigation.
            model.searching = false;
            return vec![];
        }
        Message::SearchCancel => {
            model.searching = false;
            if !model.search.is_empty() {
                model.search.clear();
                model.selected_row = 0;
                model.reproject();
            }
            return vec![];
        }
        Message::RequestAccessDelete => {
            // Delete the selected grant child, or (on a group header) the group itself.
            if let Some(grant) = model.selected_grant() {
                model.modal = Some(Modal::Confirm {
                    title: "Delete this grant?".to_string(),
                    lines: vec![
                        "Revokes this grant.".to_string(),
                        "Recreate it later if needed.".to_string(),
                    ],
                    action: ConfirmAction::DeleteGrant(grant),
                });
            } else if let Some(group) = model.selected_group() {
                model.modal = Some(Modal::Confirm {
                    title: "Delete this group?".to_string(),
                    lines: vec![
                        "Deletes this group.".to_string(),
                        "Members lose the access this group granted.".to_string(),
                    ],
                    action: ConfirmAction::DeleteGroup(group),
                });
            }
            return vec![];
        }
        Message::ShowBundle(encoded) => {
            model.modal = Some(Modal::InviteBundle { encoded });
            return vec![];
        }
        Message::CopyInviteBundle => {
            let Some(Modal::InviteBundle { encoded }) = &model.modal else {
                return vec![];
            };
            let bytes = Zeroizing::new(encoded.as_bytes().to_vec());
            model.clipboard_clear_at = Some(model.now + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
            model.status = Status::info(format!(
                "copied invite bundle to clipboard (clears in {}s)",
                CLIPBOARD_CLEAR_SECS
            ));
            return vec![Effect::CopyToClipboard(bytes)];
        }
        Message::RequestDeleteSecret => {
            if let Some(leaf) = model.selected_leaf() {
                model.modal = Some(Modal::Confirm {
                    title: "Delete this secret?".to_string(),
                    lines: vec![
                        project::selector_display(&leaf.selector),
                        String::new(),
                        "Marks the secret as deleted.".to_string(),
                        "History is preserved in the vault.".to_string(),
                    ],
                    action: ConfirmAction::DeleteSecret(leaf.selector),
                });
            }
            return vec![];
        }
        Message::RequestResolveConflict => {
            if matches!(model.selected_merge_row(), Some(MergeRow::Conflict { .. })) {
                model.status = Status::info("pick a candidate below this conflict first");
                return vec![];
            }
            let Some((conflict, candidate)) = model.selected_merge_candidate() else {
                return vec![];
            };
            if let Some(reason) = conflict.blocked.clone() {
                model.status = Status::error(format!("you cannot resolve this conflict: {reason}"));
                return vec![];
            }
            let consequence = if candidate.selector.is_some() && conflict.kind == "secret" {
                "The secret is re-encrypted for current readers."
            } else {
                "The record is re-signed under your identity."
            };
            let what = format!("{} {}", conflict.kind, conflict.label);
            let winner = format!("    {}  (by {})", candidate.summary, candidate.signer);
            let losers = conflict.candidates.len() - 1;
            let pick = candidate.pick.clone();
            model.modal = Some(Modal::Confirm {
                title: "Make this candidate the winner?".to_string(),
                lines: vec![
                    format!("The conflict at {what} will be resolved to:"),
                    String::new(),
                    winner,
                    String::new(),
                    consequence.to_string(),
                    format!(
                        "The other {} permanently discarded.",
                        if losers == 1 {
                            "candidate is".to_string()
                        } else {
                            format!("{losers} candidates are")
                        }
                    ),
                ],
                action: ConfirmAction::ResolveConflict(pick),
            });
            return vec![];
        }
        Message::RequestAcceptRollback => {
            // `a` on a conflict header row. Accepting is machine-local and fail-open (this
            // machine gives up its tamper alarm for the key), so it sits behind an explicit
            // confirm; a tie is a real ambiguity in the vault itself and must pick a winner.
            let Some(conflict) = model.selected_conflict_header() else {
                return vec![];
            };
            let key = conflict.key.clone();
            let label = format!(
                "{} {}",
                thorax_frontend::record_key_kind(&key),
                thorax_frontend::conflict_label(conflict)
            );
            let ConflictKind::Rollback { remembered_counter } = conflict.kind.clone() else {
                model.status = Status::error(
                    "only a rollback can be accepted — resolve a tie by picking a winner",
                );
                return vec![];
            };
            model.modal = Some(Modal::Confirm {
                title: "Accept this rollback?".to_string(),
                lines: vec![
                    label,
                    String::new(),
                    format!(
                        "This machine forgets it ever verified counter {remembered_counter} here —"
                    ),
                    "The current vault state is trusted as-is.".to_string(),
                    "No record is written to the vault.".to_string(),
                ],
                action: ConfirmAction::AcceptRollback(key),
            });
            return vec![];
        }
        Message::StartSetFresh => {
            // `s` on a rollback at a secret key: an ordinary set lands above the remembered
            // watermark and clears the conflict, so this only opens the existing set flow
            // with the selector prefilled — from a surviving candidate's claimed selector,
            // else the whole selector the ratchet remembered for the key.
            let Some(conflict) = model.selected_conflict_header() else {
                return vec![];
            };
            if !matches!(conflict.kind, ConflictKind::Rollback { .. })
                || !matches!(conflict.key, RecordKey::Secret { .. })
            {
                return vec![];
            }
            let Some(selector) = project::rollback_set_selector(conflict) else {
                return vec![];
            };
            model.modal = Some(Modal::Form(Box::new(Form {
                title: "Set a fresh value".to_string(),
                fields: vec![
                    FormField::prefilled("Path", project::selector_path(&selector)),
                    FormField::prefilled("Labels", project::selector_label_pairs(&selector)),
                ],
                focus: 0,
                error: None,
                note: Some(
                    "an ordinary set — it lands above the remembered counter and clears the rollback"
                        .to_string(),
                ),
                submit_verb: "next: enter value".to_string(),
                then: FormThen::NewSecret,
            })));
            return vec![];
        }
        Message::ConfirmYes => {
            let Some(Modal::Confirm { action, .. }) = model.modal.take() else {
                return vec![];
            };
            // The session is always unlocked here (the unlock gate blocks input while locked).
            match action {
                ConfirmAction::DeleteSecret(selector) => {
                    return vec![Effect::DeleteSecret(selector)]
                }
                ConfirmAction::DeleteUser(user) => return vec![Effect::DeleteUser(user)],
                ConfirmAction::DeleteGrant(grant) => return vec![Effect::DeleteGrant(grant)],
                ConfirmAction::DeleteGroup(group) => return vec![Effect::DeleteGroup(group)],
                ConfirmAction::ResolveConflict(pick) => return vec![Effect::ResolveConflict(pick)],
                ConfirmAction::AcceptRollback(key) => return vec![Effect::AcceptRollback(key)],
            }
        }
        Message::EditorKey(key) => {
            if let Some(Modal::Editor { textarea, .. }) = &mut model.modal {
                edit_textarea(textarea, key);
            }
            return vec![];
        }
        Message::EditorSubmit => {
            let Some(Modal::Editor {
                selector, textarea, ..
            }) = model.modal.take()
            else {
                return vec![];
            };
            let text = textarea.lines().join("\n");
            let plaintext = Zeroizing::new(text.into_bytes());
            // Land on this secret after the save reloads the tree.
            model.select_target = Some(selector.clone());
            return vec![Effect::SetSecret {
                label: project::selector_path(&selector),
                selector,
                plaintext,
            }];
        }
        Message::FormKey(key) => return form_key(model, key),
        Message::SecretForEdit {
            selector,
            plaintext,
        } => {
            let initial = String::from_utf8_lossy(&plaintext).to_string();
            let mut textarea =
                ratatui_textarea::TextArea::from(initial.lines().collect::<Vec<_>>());
            textarea.set_cursor_line_style(ratatui::style::Style::default());
            model.modal = Some(Modal::Editor {
                title: format!("Edit {}", project::selector_path(&selector)),
                selector,
                textarea: Box::new(textarea),
            });
            return vec![];
        }
        Message::SecretRevealed {
            selector,
            plaintext,
            is_utf8,
            copy,
        } => {
            if copy {
                let bytes = Zeroizing::new(plaintext.to_vec());
                model.clipboard_clear_at =
                    Some(model.now + Duration::from_secs(CLIPBOARD_CLEAR_SECS));
                model.status = Status::info(format!(
                    "copied {} to clipboard (clears in {}s)",
                    project::selector_path(&selector),
                    CLIPBOARD_CLEAR_SECS
                ));
                return vec![Effect::CopyToClipboard(bytes)];
            }
            model.reveal = Some(Reveal {
                selector,
                plaintext,
                is_utf8,
                expires_at: model.now + Duration::from_secs(REVEAL_SECS),
            });
            return vec![];
        }
        Message::SecretFieldsLoaded { selector, fields } => {
            model.secret_fields = Some(super::model::SecretFields { selector, fields });
            return vec![];
        }
        Message::ConflictCandidatesRevealed { values } => {
            model.merge_reveal = Some(MergeReveal {
                values,
                expires_at: model.now + Duration::from_secs(REVEAL_SECS),
            });
            return vec![];
        }
        Message::OpOk(text) => {
            // No reload here: a mutation's session is already post-commit and `run_effect`
            // refreshed the projections before producing this message.
            model.status = Status::info(text);
            return vec![];
        }
        Message::OpFailed(text) => {
            model.status = Status::error(text);
            return vec![];
        }
    }
}

/// A reveal/copy/edit request on the selected secret: it must be decryptable. The session is
/// already unlocked here — the unlock gate blocks input while locked.
fn request_get(model: &mut Model, purpose: GetPurpose) -> Vec<Effect> {
    if model.view != View::Secrets {
        return vec![];
    }
    let Some(leaf) = model.selected_leaf() else {
        return vec![];
    };
    if leaf.state != SecretState::ActiveDecryptable {
        model.status = Status::error(format!(
            "{}: {}",
            project::selector_path(&leaf.selector),
            state_reason(&leaf.state)
        ));
        return vec![];
    }
    vec![Effect::GetSecret {
        selector: leaf.selector,
        purpose,
    }]
}

/// Combine a Path field and a Labels field into the spec [`project::parse_selector`] accepts: the
/// tuple, then `@` and the `&`-separated label section when labels are present.
fn combine_selector_spec(path: &str, labels: &str) -> String {
    if labels.is_empty() {
        path.to_string()
    } else {
        format!("{path}@{labels}")
    }
}

/// Set the error line on the active form (no-op if it isn't a form).
fn form_error(model: &mut Model, message: impl Into<String>) {
    if let Some(Modal::Form(form)) = &mut model.modal {
        form.error = Some(message.into());
    }
}

/// Apply a key to the in-memory value editor. tui-textarea ships Emacs-style bindings; this adds the
/// editor shortcuts terminals send with Ctrl/Alt — Ctrl-Backspace / Ctrl-Delete to delete a word,
/// Ctrl-←/→ to move by word, Ctrl-Home/End to jump to the document ends — falling through to the
/// built-in handling for everything else (arrows, Home/End, Ctrl-W/K/U, typing, …).
fn edit_textarea(
    textarea: &mut ratatui_textarea::TextArea<'static>,
    key: crossterm::event::KeyEvent,
) {
    use crossterm::event::KeyModifiers;
    use ratatui_textarea::CursorMove;
    let word = key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    match key.code {
        KeyCode::Backspace if word => {
            textarea.delete_word();
        }
        KeyCode::Delete if word => {
            textarea.delete_next_word();
        }
        KeyCode::Left if word => {
            textarea.move_cursor(CursorMove::WordBack);
        }
        KeyCode::Right if word => {
            textarea.move_cursor(CursorMove::WordForward);
        }
        KeyCode::Home if ctrl => {
            textarea.move_cursor(CursorMove::Top);
            textarea.move_cursor(CursorMove::Head);
        }
        KeyCode::End if ctrl => {
            textarea.move_cursor(CursorMove::Bottom);
            textarea.move_cursor(CursorMove::End);
        }
        _ => {
            textarea.input(key);
        }
    }
}

/// Delete the trailing word from a single-line field value (the field has no cursor, so editing is
/// at the end): drop trailing whitespace, then the run of non-whitespace before it.
fn delete_word_end(value: &mut String) {
    while value.chars().next_back().is_some_and(char::is_whitespace) {
        value.pop();
    }
    while value
        .chars()
        .next_back()
        .is_some_and(|c| !c.is_whitespace())
    {
        value.pop();
    }
}

fn form_key(model: &mut Model, key: crossterm::event::KeyEvent) -> Vec<Effect> {
    if key.code == KeyCode::Enter {
        return submit_form(model);
    }
    let Some(Modal::Form(form)) = &mut model.modal else {
        return vec![];
    };
    let n = form.fields.len().max(1);
    let word = key
        .modifiers
        .intersects(crossterm::event::KeyModifiers::CONTROL | crossterm::event::KeyModifiers::ALT);
    match key.code {
        KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % n,
        KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + n - 1) % n,
        KeyCode::Backspace => {
            if let Some(field) = form.fields.get_mut(form.focus) {
                if word {
                    delete_word_end(&mut field.value);
                } else {
                    field.value.pop();
                }
                form.error = None;
            }
        }
        KeyCode::Char(c) if !word => {
            if let Some(field) = form.fields.get_mut(form.focus) {
                field.value.push(c);
                form.error = None;
            }
        }
        _ => {}
    }
    vec![]
}

/// Handle submission of a [`Modal::Form`], dispatching on its [`FormThen`].
fn submit_form(model: &mut Model) -> Vec<Effect> {
    let Some(Modal::Form(form)) = &model.modal else {
        return vec![];
    };
    let then = form.then.clone();
    match then {
        FormThen::NewSecret => {
            let spec = combine_selector_spec(&form.value(0), &form.value(1));
            match project::parse_selector(&spec) {
                Ok(selector) => {
                    let mut textarea = ratatui_textarea::TextArea::default();
                    textarea.set_cursor_line_style(ratatui::style::Style::default());
                    model.modal = Some(Modal::Editor {
                        title: format!("New {}", project::selector_path(&selector)),
                        selector,
                        textarea: Box::new(textarea),
                    });
                    vec![]
                }
                Err(err) => {
                    form_error(model, err);
                    vec![]
                }
            }
        }
        FormThen::Claim => {
            let bundle = form.value(0);
            let passphrase = form.value(1);
            if bundle.is_empty() {
                form_error(model, "paste an invite");
                return vec![];
            }
            if passphrase.is_empty() {
                form_error(model, "set a passphrase to protect your identity");
                return vec![];
            }
            model.modal = None;
            vec![Effect::Join { bundle, passphrase }]
        }
        FormThen::Invite => {
            let handle = form.value(0);
            if handle.is_empty() {
                form_error(model, "handle cannot be empty");
                return vec![];
            }
            model.modal = None;
            vec![Effect::Invite(handle)]
        }
        FormThen::Group => {
            let name = form.value(0);
            if name.is_empty() {
                form_error(model, "group name cannot be empty");
                return vec![];
            }
            model.modal = None;
            vec![Effect::CreateGroup(name)]
        }
        FormThen::Relabel(old) => {
            let spec = combine_selector_spec(&form.value(0), &form.value(1));
            let new = match project::parse_selector(&spec) {
                Ok(selector) => selector,
                Err(err) => {
                    form_error(model, err);
                    return vec![];
                }
            };
            if new == old {
                model.modal = None;
                model.status = Status::info("selector unchanged");
                return vec![];
            }
            // Refuse to clobber a different secret that already lives at the new selector.
            let collides = model
                .effective()
                .map(|s| project::value_selectors(s).contains(&new))
                .unwrap_or(false);
            if collides {
                form_error(model, "a secret already exists at that selector");
                return vec![];
            }
            model.modal = None;
            vec![Effect::Relabel { old, new }]
        }
    }
}

fn rect_contains(r: Rect, x: u16, y: u16) -> bool {
    x >= r.x && x < r.x.saturating_add(r.width) && y >= r.y && y < r.y.saturating_add(r.height)
}

/// Route a left-click: a button/tab fires its action; a list row selects it (and toggles a folder).
fn handle_click(model: &mut Model, col: u16, row: u16) -> Vec<Effect> {
    let clicked = model
        .buttons
        .iter()
        .find(|b| rect_contains(b.rect, col, row))
        .map(|b| b.action);
    if let Some(action) = clicked {
        return update(model, action.into_message());
    }
    if let Some(region) = model.list_region {
        if rect_contains(region.rect, col, row) {
            let idx = region.offset + (row - region.rect.y) as usize;
            match region.kind {
                ListKind::Secrets => {
                    let rows = model.visible_rows();
                    if idx < rows.len() {
                        model.selected_row = idx;
                        model.focus = Focus::List;
                        if matches!(rows[idx], Row::Branch { .. }) {
                            model.toggle_open();
                        }
                    }
                }
                ListKind::Access => {
                    let rows = model.access_rows();
                    if idx < rows.len() {
                        model.access_selected = idx;
                        model.focus = Focus::List;
                        // Clicking a principal header toggles its grants.
                        if matches!(rows[idx], AccessRow::User { .. } | AccessRow::Group { .. }) {
                            model.toggle_access();
                        }
                    }
                }
                ListKind::Merge => {
                    if idx < model.merge_rows().len() {
                        model.merge_selected = idx;
                        model.focus = Focus::List;
                    }
                }
            }
        }
    }
    vec![]
}

fn state_reason(state: &SecretState) -> &'static str {
    match state {
        SecretState::ActiveDecryptable => "decryptable",
        SecretState::NotEncryptedForReader => "not encrypted to you (stale); re-set the value",
        SecretState::Unauthorized => "not authorized to read",
        SecretState::Missing => "no value",
        SecretState::Conflicted => {
            "conflicted — no effective value; resolve it in the Conflicts tab"
        }
        SecretState::Invalid => "invalid record",
    }
}

/// Handle a key in the label filter picker: ↑↓ pick a label key, ←→ cycle its value (incl. "any"),
/// `c` clears all, Enter/Esc closes. Edits apply live so the tree (behind the modal) is already
/// filtered when the picker closes.
fn facet_form_key(model: &mut Model, key: crossterm::event::KeyEvent) -> Vec<Effect> {
    let n = model.facets.keys.len();
    let focus = match &model.modal {
        Some(Modal::Facet { focus }) => *focus,
        _ => return vec![],
    };
    if n == 0 {
        model.modal = None;
        return vec![];
    }
    match key.code {
        KeyCode::Enter => model.modal = None,
        KeyCode::Up | KeyCode::BackTab => set_facet_focus(model, (focus + n - 1) % n),
        KeyCode::Down | KeyCode::Tab => set_facet_focus(model, (focus + 1) % n),
        KeyCode::Left => cycle_facet_value(model, focus, -1),
        KeyCode::Right => cycle_facet_value(model, focus, 1),
        KeyCode::Char('c') => {
            model.facet_filter.constraints.clear();
            model.selected_row = 0;
            model.reproject();
        }
        _ => {}
    }
    vec![]
}

fn set_facet_focus(model: &mut Model, next: usize) {
    if let Some(Modal::Facet { focus }) = &mut model.modal {
        *focus = next;
    }
}

/// Step the focused label key's value: `any → v0 → v1 → … → any` (and the reverse), then reproject.
fn cycle_facet_value(model: &mut Model, key_idx: usize, dir: isize) {
    let Some(key) = model.facets.keys.get(key_idx).cloned() else {
        return;
    };
    let values = model.facets.values.get(&key).cloned().unwrap_or_default();
    if values.is_empty() {
        return;
    }
    // -1 represents "any" (no constraint); 0..len index into `values`.
    let len = values.len() as isize;
    let cur = match model.facet_filter.constraints.get(&key) {
        None => -1,
        Some(v) => values
            .iter()
            .position(|x| x == v)
            .map_or(-1, |i| i as isize),
    };
    let next = match cur + dir {
        n if n < -1 => len - 1,
        n if n >= len => -1,
        n => n,
    };
    if next < 0 {
        model.facet_filter.constraints.remove(&key);
    } else {
        model
            .facet_filter
            .constraints
            .insert(key, values[next as usize].clone());
    }
    model.selected_row = 0;
    model.reproject();
}

/// Handle a key in the add-member form: ←→ pick a principal, Enter adds.
fn member_form_key(model: &mut Model, key: crossterm::event::KeyEvent) -> Vec<Effect> {
    if key.code == KeyCode::Enter {
        let picked = match &model.modal {
            Some(Modal::Member(form)) => form
                .candidates
                .get(form.idx)
                .map(|c| (form.group_id.clone(), c.principal.clone())),
            _ => None,
        };
        if let Some((group, member)) = picked {
            model.modal = None;
            return vec![Effect::AddMember { group, member }];
        }
        return vec![];
    }
    let Some(Modal::Member(form)) = &mut model.modal else {
        return vec![];
    };
    let n = form.candidates.len().max(1);
    match key.code {
        KeyCode::Left | KeyCode::Up | KeyCode::Char('h') | KeyCode::Char('k') => {
            form.idx = (form.idx + n - 1) % n
        }
        KeyCode::Right | KeyCode::Down | KeyCode::Char('l') | KeyCode::Char('j') => {
            form.idx = (form.idx + 1) % n
        }
        _ => {}
    }
    vec![]
}

/// Handle a key in the grant form: arrows/Tab move between fields and options, typing edits the
/// keyspace, Enter submits.
fn grant_form_key(model: &mut Model, key: crossterm::event::KeyEvent) -> Vec<Effect> {
    if key.code == KeyCode::Enter {
        let built = match &model.modal {
            Some(Modal::Grant(form)) => form.build(),
            _ => return vec![],
        };
        return match built {
            Ok((subject, permission)) => {
                model.modal = None;
                vec![Effect::GrantPermission {
                    subject,
                    permission,
                }]
            }
            Err(e) => {
                if let Some(Modal::Grant(form)) = &mut model.modal {
                    form.error = Some(e);
                }
                vec![]
            }
        };
    }
    let Some(Modal::Grant(form)) = &mut model.modal else {
        return vec![];
    };
    let n = form.subjects.len().max(1);
    let word = key
        .modifiers
        .intersects(crossterm::event::KeyModifiers::CONTROL | crossterm::event::KeyModifiers::ALT);
    match key.code {
        KeyCode::Up | KeyCode::BackTab => form.field = (form.field + 2) % 3,
        KeyCode::Down | KeyCode::Tab => form.field = (form.field + 1) % 3,
        KeyCode::Left => match form.field {
            0 => form.subject_idx = (form.subject_idx + n - 1) % n,
            1 => form.class_idx = (form.class_idx + 3) % 4,
            _ => {}
        },
        KeyCode::Right => match form.field {
            0 => form.subject_idx = (form.subject_idx + 1) % n,
            1 => form.class_idx = (form.class_idx + 1) % 4,
            _ => {}
        },
        KeyCode::Char(c) if form.field == 2 && !word => form.keyspace.push(c),
        KeyCode::Backspace if form.field == 2 => {
            if word {
                delete_word_end(&mut form.keyspace);
            } else {
                form.keyspace.pop();
            }
        }
        _ => {}
    }
    vec![]
}
