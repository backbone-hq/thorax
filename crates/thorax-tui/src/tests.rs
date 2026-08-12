//! Tests for the TUI: pure key/projection/update logic, headless `TestBackend` render checks, and
//! one real-workspace decrypt that drives the shared ops path through `run_effect`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

use crate::app::{
    run_effect, update, ButtonAction, Effect, Focus, GetPurpose, Message, Modal, Model, View,
};
use crate::event::map_key;
use crate::project;

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A bare KeyEvent for feeding into form key handlers.
fn form_key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// A model with no workspace (load fails) — enough to exercise navigation/modal logic.
fn empty_model(dir: &std::path::Path) -> Model {
    use thorax_ops::WorkspacePaths;
    let paths = WorkspacePaths::from_root(dir.join("missing")).with_state_dir(dir.join("state"));
    Model::load(paths)
}

/// Write one secret through the public ops surface, the way a CLI action would: open an
/// [`thorax_ops::UnlockedSession`] through the keychain funnel, run the op, drop the session.
fn set_secret_via_keychain(
    paths: &thorax_ops::WorkspacePaths,
    keychain: &dyn thorax_ops::IdentityKeychain,
    user: &thorax_ops::UserId,
    selector: thorax_ops::SecretSelectorV1,
    plaintext: &[u8],
) {
    let crypto = thorax_ops::Crypto;
    let mut unlocked = thorax_ops::UnlockedSession::open(
        paths,
        &crypto,
        keychain,
        user,
        thorax_ops::KeyUsePurpose::SignSecretWrite {
            selector: selector.clone(),
        },
    )
    .unwrap();
    unlocked.set_secret(&crypto, selector, plaintext).unwrap();
}

fn render_to_string(model: &mut Model) -> String {
    render_to_string_sized(model, 100, 30)
}

fn render_to_string_sized(model: &mut Model, w: u16, h: u16) -> String {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| crate::ui::render(model, f)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    buffer.content().iter().map(|c| c.symbol()).collect()
}

#[test]
fn tiny_terminal_shows_a_resize_notice_instead_of_a_broken_screen() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    // Below the minimum, every layout would clip its own instructions: show one clear next step.
    let screen = render_to_string_sized(&mut model, 30, 6);
    assert!(
        screen.contains("Terminal too small"),
        "a sub-minimum terminal must show the resize notice"
    );
    // And at a usable size the guard is gone (the init gate renders instead).
    let ok = render_to_string_sized(&mut model, 100, 30);
    assert!(!ok.contains("Terminal too small"));
}

#[test]
fn key_mapping_covers_core_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());

    // No-workspace state: the init gate captures the passphrase inline (typed chars feed the gate
    // buffer; Enter submits). There is no separate `i`/`q` step.
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('i'))),
        Some(Message::UnlockChar('i'))
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Enter)),
        Some(Message::InitSubmit)
    ));

    // Pretend a workspace is loaded so the Secrets keymap applies.
    model.workspace_error = None;
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('j'))),
        Some(Message::MoveDown)
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('k'))),
        Some(Message::MoveUp)
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('r'))),
        Some(Message::Reveal)
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('e'))),
        Some(Message::StartEdit)
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('?'))),
        Some(Message::OpenHelp)
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Char('H'))),
        Some(Message::OpenHealth)
    ));
    assert!(matches!(
        map_key(&model, key(KeyCode::Tab)),
        Some(Message::FocusNext)
    ));
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert!(matches!(map_key(&model, ctrl_c), Some(Message::Quit)));
}

#[test]
fn help_modal_opens_and_closes_and_views_switch() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());

    update(&mut model, Message::OpenHelp);
    assert!(matches!(model.modal, Some(Modal::Help)));
    // While a modal is open, keys route to the modal (q/Esc close it).
    assert!(matches!(
        map_key(&model, key(KeyCode::Esc)),
        Some(Message::CloseModal)
    ));
    update(&mut model, Message::CloseModal);
    assert!(model.modal.is_none());

    update(&mut model, Message::SwitchView(View::Access));
    assert_eq!(model.view, View::Access);
    update(&mut model, Message::SwitchView(View::Secrets));
    assert_eq!(model.view, View::Secrets);

    // Health is now a modal (opened with H), not a top-level view.
    update(&mut model, Message::OpenHealth);
    assert!(matches!(model.modal, Some(Modal::Health)));
    update(&mut model, Message::CloseModal);
    assert!(model.modal.is_none());

    let effects = update(&mut model, Message::Quit);
    assert!(model.should_quit);
    assert!(matches!(effects.first(), Some(Effect::Quit)));
}

#[test]
fn invite_bundle_modal_can_copy_and_release_terminal_selection() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    model.workspace_error = None;
    let encoded = "thrx1testinvitebundle00000000000000000000000000000000".to_string();

    let effects = update(&mut model, Message::ShowBundle(encoded.clone()));
    assert!(effects.is_empty());
    assert!(matches!(model.modal, Some(Modal::InviteBundle { .. })));
    assert!(model.terminal_selection_enabled());

    let screen = render_to_string(&mut model);
    assert!(screen.contains("Invite bundle"), "{screen}");
    assert!(screen.contains(&encoded), "{screen}");
    assert!(screen.contains("y copy"), "{screen}");

    assert!(matches!(
        map_key(&model, key(KeyCode::Char('y'))),
        Some(Message::CopyInviteBundle)
    ));
    let effects = update(&mut model, Message::CopyInviteBundle);
    match effects.as_slice() {
        [Effect::CopyToClipboard(bytes)] => assert_eq!(bytes.as_slice(), encoded.as_bytes()),
        _ => panic!("copying the bundle should emit exactly one clipboard effect"),
    }
    assert!(model
        .status
        .text
        .contains("copied invite bundle to clipboard"));
    assert!(model.clipboard_clear_at.is_some());

    assert!(matches!(
        map_key(&model, key(KeyCode::Esc)),
        Some(Message::CloseModal)
    ));
    update(&mut model, Message::CloseModal);
    assert!(!model.terminal_selection_enabled());
}

#[test]
fn reveal_while_locked_opens_the_passphrase_modal() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    // No workspace → no selectable leaf → reveal is a no-op (and never leaks).
    let effects = update(&mut model, Message::Reveal);
    assert!(effects.is_empty());
    assert!(model.modal.is_none());
}

#[test]
fn parse_selector_handles_tuple_and_labels() {
    let s = project::parse_selector("app/prod/db@env=prod&region=us").unwrap();
    assert_eq!(s.tuple, vec!["app", "prod", "db"]);
    assert_eq!(s.labels.len(), 2);
    assert_eq!(s.labels[0].key, "env");
    assert_eq!(s.labels[1].key, "region");
    assert!(project::parse_selector("").is_err());
    assert!(project::parse_selector("app@bad-label").is_err());
    // Quoting carries structural characters into a segment, round-tripping through the renderer.
    let quoted = project::parse_selector("\"app/v2\"/db").unwrap();
    assert_eq!(quoted.tuple, vec!["app/v2", "db"]);
    assert_eq!(
        project::parse_selector(&project::selector_path(&quoted)).unwrap(),
        quoted
    );
}

#[test]
fn block_reason_flags_blocking_issues_and_shows_the_block_screen() {
    use thorax_ops::{EffectiveState, RecordKey, ValidationIssue, ValidationReport};
    let report = ValidationReport {
        effective: EffectiveState::default(),
        ratchet_update: Default::default(),
        issues: vec![ValidationIssue::InvalidSignature(RecordKey::VaultRoot)],
        warnings: Vec::new(),
    };
    let reason = project::block_reason(&report).expect("an invalid signature should block");
    assert_eq!(
        reason,
        project::BlockReason::BadSignature(RecordKey::VaultRoot)
    );

    // The locked view takes over the body (rollback no longer blocks — it shows as a
    // conflict instead — but every remaining ValidationIssue still does).
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    model.workspace_error = None;
    model.block = Some(reason);
    let screen = render_to_string(&mut model);
    assert!(screen.contains("Invalid signature"), "got: {screen}");
    assert!(screen.contains("Refusing to operate"), "got: {screen}");
}

#[test]
fn action_buttons_are_focusable_and_activate() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    model.workspace_error = None; // pretend a usable workspace so view logic applies

    // With nothing selected, the Secrets bar is just "+ New" (Reveal/Edit/Delete are selection-
    // aware). Tab moves focus onto it; activating it opens the new-secret prompt.
    assert_eq!(model.view_buttons().first(), Some(&ButtonAction::NewSecret));
    update(&mut model, Message::FocusNext);
    assert!(matches!(model.focus, Focus::Button(0)));
    update(&mut model, Message::ActivateButton);
    assert!(
        matches!(model.modal, Some(Modal::Form(_))),
        "activating + New opens the new-secret prompt"
    );
}

#[test]
fn clicking_a_button_fires_its_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    model.workspace_error = None;
    // Render so the action bar records its hit-rects.
    let _ = render_to_string(&mut model);
    let new_button = model
        .buttons
        .iter()
        .find(|b| b.action == ButtonAction::NewSecret)
        .copied()
        .expect("a + New button was drawn");
    update(
        &mut model,
        Message::MouseClick(new_button.rect.x, new_button.rect.y),
    );
    assert!(matches!(model.modal, Some(Modal::Form(_))));
}

#[test]
fn no_workspace_screen_renders_the_init_gate() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    let screen = render_to_string(&mut model);
    assert!(screen.contains("NEW VAULT"), "got: {screen}");
    assert!(
        screen.contains("PASSPHRASE"),
        "the init gate asks for a passphrase inline"
    );
    assert!(
        screen.contains("create vault"),
        "the create-vault hint is shown"
    );
    // No header/view-tabs chrome on this full-terminal gate.
    assert!(
        !screen.contains("1 Secrets"),
        "no view tabs behind the gate"
    );

    // Typing feeds the inline passphrase buffer; there is no button/modal step.
    update(&mut model, Message::UnlockChar('p'));
    assert_eq!(model.unlock_input, "p");
    assert!(model.modal.is_none(), "the init gate is inline — no modal");
}

// `THORAX_KEYCHAIN_DIR` is process-global, so the keychain-using tests must not run their env mutations
// concurrently. Serialize them.
static KEYCHAIN_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn with_keychain_dir<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
    let _guard = KEYCHAIN_ENV.lock().unwrap_or_else(|p| p.into_inner());
    std::env::set_var("THORAX_KEYCHAIN_DIR", dir);
    let result = f();
    std::env::remove_var("THORAX_KEYCHAIN_DIR");
    result
}

/// Drain effects through the runner exactly like the live loop's `dispatch`.
fn drain(model: &mut Model, mut effects: Vec<Effect>) {
    while let Some(effect) = effects.pop() {
        if let Some(next) = run_effect(model, effect) {
            effects.extend(update(model, next));
        }
    }
}

/// Send one message and drain its effects (the live loop's `dispatch`).
fn drain_with(model: &mut Model, msg: Message) {
    let effects = update(model, msg);
    drain(model, effects);
}

/// Unlock the session through the gate (types the passphrase + submits), as the UI does.
fn unlock(model: &mut Model, passphrase: &str) {
    for c in passphrase.chars() {
        update(model, Message::UnlockChar(c));
    }
    update(model, Message::UnlockSubmit);
}

/// End-to-end through the shared ops path: build a real workspace, load it, confirm classification
/// + masking, decrypt via `run_effect`, and confirm a binary secret refuses the text editor.
#[test]
fn real_workspace_loads_classifies_reveals_and_guards_binary_edit() {
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        // Mirror real init/claim: record this machine's identity for the root so `load` resolves
        // an acting user (otherwise the workspace shows the join screen).
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        let text = project::parse_selector("app/prod/db").unwrap();
        set_secret_via_keychain(&paths, &keychain, root.user_id(), text.clone(), b"s3cret");
        let blob = project::parse_selector("app/bin/blob").unwrap();
        set_secret_via_keychain(
            &paths,
            &keychain,
            root.user_id(),
            blob.clone(),
            &[0xff, 0xfe, 0x00],
        );

        let mut model = Model::load(paths.clone());
        // A usable workspace is locked at startup (the full-screen unlock gate); unlock to proceed.
        assert!(model.is_unlock_gate());
        unlock(&mut model, "pw");
        assert!(!model.is_unlock_gate());
        assert!(model.session.exists());
        assert!(model.block.is_none());
        assert_eq!(model.tree.total, 2);
        assert_eq!(
            first_leaf(&model.tree).unwrap().state,
            thorax_ops::SecretState::ActiveDecryptable
        );

        // Masked by default: the value box shows the reveal hint, not the plaintext.
        expand_all_and_select_leaf(&mut model);
        let screen = render_to_string(&mut model);
        assert!(
            screen.contains("press r to reveal"),
            "value box shows the reveal hint while masked"
        );
        assert!(
            !screen.contains("s3cret"),
            "plaintext must not render while masked"
        );

        // On a narrow terminal the access table degrades to single-letter headers instead of
        // overflowing the `principal` column and wrapping `manage` onto a second line.
        let narrow = render_to_string_sized(&mut model, 58, 24);
        assert!(
            narrow.contains("principal       r   w   m"),
            "narrow access table should use compact r/w/m headers"
        );
        // And on a wide pane the principal column flexes to absorb the spare width (full-details
        // rule), instead of clamping at ~18 chars: at 100 cols the detail pane leaves 51 for the
        // table, so `principal` pads to 51 − 3×8 = 27 before the three fixed boolean columns.
        let wide = render_to_string(&mut model);
        assert!(
            wide.contains(&format!(
                "{:<27}{:<8}{:<8}manage",
                "principal", "read", "write"
            )),
            "wide access table should let the principal column absorb the spare width"
        );

        // The Health modal (H): clean verification, the Trust section (pinned root fingerprint +
        // rollback-ratchet size), and the acting identity.
        update(&mut model, Message::OpenHealth);
        let health = render_to_string(&mut model);
        assert!(
            health.contains("✓ clean — signatures and trust verified"),
            "a verified vault shows the clean verification line"
        );
        assert!(
            health.contains(&format!("root {}", thorax_frontend::short_hash(&root_hash))),
            "the Trust section shows the pinned trusted-root fingerprint"
        );
        assert!(
            health.contains("remembered watermark"),
            "the Trust section shows the rollback ratchet size"
        );
        // This vault has no handle record, so the acting label falls back to the identity's hex
        // (the same fallback the header uses), which wraps past the "acting as" lead-in — assert
        // the lead-in and the start of the identity separately.
        assert!(
            health.contains("acting as"),
            "the Identity section names the acting user"
        );
        assert!(
            health.contains(&format!("@{}", thorax_frontend::user_hex(root.user_id()))),
            "the Identity section carries the full acting identity"
        );
        update(&mut model, Message::CloseModal);

        // Warnings are advisory: they render under Verification in warn styling while the clean
        // line stands (a warned vault is still verified — warnings never block).
        model.health.warnings = vec!["2 record(s) were written by a newer thorax".to_string()];
        update(&mut model, Message::OpenHealth);
        let warned = render_to_string(&mut model);
        assert!(
            warned.contains("✓ clean — signatures and trust verified"),
            "warnings must not displace the clean verification line"
        );
        assert!(
            warned.contains("! 2 record(s) were written by a newer thorax"),
            "validation warnings render in the Health modal"
        );
        update(&mut model, Message::CloseModal);

        // Already unlocked above; decrypt through the shared ops path.
        match run_effect(
            &mut model,
            Effect::GetSecret {
                selector: text,
                purpose: GetPurpose::Reveal,
            },
        ) {
            Some(Message::SecretRevealed {
                plaintext, is_utf8, ..
            }) => {
                assert!(is_utf8);
                assert_eq!(&plaintext[..], b"s3cret");
            }
            _ => panic!("expected SecretRevealed"),
        }

        // Enter / → on a selected leaf must NOT reveal — only explicit `r` does.
        expand_all_and_select_leaf(&mut model);
        assert!(model.reveal.is_none());
        let effects = update(&mut model, Message::Open);
        drain(&mut model, effects);
        assert!(model.reveal.is_none(), "Open on a leaf must not reveal");
        // `r` reveals; `r` again (toggle) hides.
        let effects = update(&mut model, Message::Reveal);
        drain(&mut model, effects);
        assert!(model.reveal.is_some(), "r reveals");
        assert!(model.is_selected_revealed());
        update(&mut model, Message::Reveal);
        assert!(model.reveal.is_none(), "r again hides");

        // The guided grant form lists root as a subject and emits a grant effect on submit.
        update(&mut model, Message::StartGrant);
        assert!(matches!(model.modal, Some(Modal::Grant(_))));
        // Move focus to the keyspace field (Subject → Access → Keyspace) and type a path.
        update(&mut model, Message::GrantFormKey(form_key(KeyCode::Down)));
        update(&mut model, Message::GrantFormKey(form_key(KeyCode::Down)));
        for c in "app/prod".chars() {
            update(
                &mut model,
                Message::GrantFormKey(form_key(KeyCode::Char(c))),
            );
        }
        let effects = update(&mut model, Message::GrantFormKey(form_key(KeyCode::Enter)));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::GrantPermission { .. })),
            "submitting the grant form emits a grant effect"
        );
        drain(&mut model, effects);

        // Startup: a fresh load of a usable workspace is gated by the full-screen unlock, which
        // verifies the passphrase (wrong → stays gated with an error; right → unlocks).
        let mut fresh = Model::load(paths.clone());
        assert!(fresh.is_unlock_gate(), "startup should gate on unlock");
        for c in "wrong".chars() {
            update(&mut fresh, Message::UnlockChar(c));
        }
        update(&mut fresh, Message::UnlockSubmit);
        assert!(
            fresh.unlock_session.is_locked(),
            "a wrong passphrase keeps it locked"
        );
        assert!(fresh.unlock_error.is_some());
        assert!(fresh.is_unlock_gate());
        for c in "pw".chars() {
            update(&mut fresh, Message::UnlockChar(c));
        }
        update(&mut fresh, Message::UnlockSubmit);
        assert!(
            !fresh.unlock_session.is_locked(),
            "the correct passphrase unlocks"
        );
        assert!(!fresh.is_unlock_gate());
        // Binary secret refuses the text editor (no lossy corruption).
        match run_effect(
            &mut model,
            Effect::GetSecret {
                selector: blob,
                purpose: GetPurpose::Edit,
            },
        ) {
            Some(Message::OpFailed(msg)) => assert!(msg.contains("binary"), "got: {msg}"),
            _ => panic!("expected OpFailed for binary edit"),
        }
    });
}

/// Moving a secret re-keys it: the old selector disappears, the new one carries the same
/// plaintext, and it remains decryptable by the actor.
#[test]
fn move_rekeys_a_secret_preserving_its_value() {
    use crate::app::{FormThen, GetPurpose, Modal};
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        // Mirror real init/claim: record this machine's identity for the root so `load` resolves
        // an acting user (otherwise the workspace shows the join screen).
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();
        let old = project::parse_selector("app/prod/db").unwrap();
        set_secret_via_keychain(&paths, &keychain, root.user_id(), old.clone(), b"s3cret");

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");
        expand_all_and_select_leaf(&mut model);

        // Open the move form: it should pre-fill the Path field (no labels yet).
        drain_with(&mut model, Message::StartRelabel);
        match &model.modal {
            Some(Modal::Form(form)) => {
                assert_eq!(form.fields[0].value, "app/prod/db");
                assert_eq!(form.fields[1].value, "");
                assert!(matches!(form.then, FormThen::Relabel(_)));
            }
            _ => panic!("StartRelabel should open the move form"),
        }
        if let Some(Modal::Form(form)) = &mut model.modal {
            form.fields[0].value = "app/prod/vault".to_string();
            form.fields[1].value = "env=prod".to_string();
        }
        let effects = update(&mut model, Message::FormKey(form_key(KeyCode::Enter)));
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Relabel { .. })),
            "submitting the move form emits a Relabel effect"
        );
        drain(&mut model, effects);

        // After reload: exactly one live secret, at the new selector; the old one is a tombstone.
        let new = project::parse_selector("app/prod/vault@env=prod").unwrap();
        let selectors = project::value_selectors(model.effective().unwrap());
        assert_eq!(selectors.len(), 1, "exactly one live secret after move");
        assert!(selectors.contains(&new), "new selector present");
        assert!(!selectors.contains(&old), "old selector removed");
        // The browse tree hides the move tombstone — only the live secret is shown.
        assert_eq!(model.tree.total, 1, "tombstone is not shown in the tree");

        // The value survived the re-key and is still decryptable.
        match run_effect(
            &mut model,
            Effect::GetSecret {
                selector: new,
                purpose: GetPurpose::Reveal,
            },
        ) {
            Some(Message::SecretRevealed { plaintext, .. }) => {
                assert_eq!(&plaintext[..], b"s3cret");
            }
            _ => panic!("moved secret should still decrypt to its original value"),
        }

        // The moved secret carries env=prod, so the filter picker opens and ←→ applies it live.
        update(&mut model, Message::OpenFacetFilter);
        assert!(
            matches!(model.modal, Some(Modal::Facet { .. })),
            "f opens the filter picker when labels exist"
        );
        update(&mut model, Message::FacetFormKey(form_key(KeyCode::Right)));
        assert_eq!(
            model
                .facet_filter
                .constraints
                .get("env")
                .map(String::as_str),
            Some("prod"),
            "←→ sets the env=prod constraint"
        );
        assert_eq!(model.tree.total, 1, "the env=prod secret still matches");
    });
}

/// The live fuzzy search filters the keyspace by `/`-joined path: typing narrows the tree (fuzzily,
/// so a subsequence across segments matches), Enter keeps the query applied while handing the
/// keyboard back, and Esc clears it back to the full tree.
#[test]
fn fuzzy_search_filters_the_keyspace_tree() {
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        let db = project::parse_selector("app/prod/db").unwrap();
        set_secret_via_keychain(&paths, &keychain, root.user_id(), db, b"s3cret");
        let blob = project::parse_selector("app/bin/blob").unwrap();
        set_secret_via_keychain(&paths, &keychain, root.user_id(), blob, b"data");

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");
        assert_eq!(model.tree.total, 2, "both secrets present before searching");

        // `/` focuses the bar; typing reprojects live. A fuzzy subsequence across segments hits.
        update(&mut model, Message::OpenSearch);
        assert!(model.searching, "/ opens the search bar");
        for c in "apdb".chars() {
            update(&mut model, Message::SearchChar(c));
        }
        assert_eq!(
            model.tree.total, 1,
            "“apdb” fuzzily matches only app/prod/db"
        );
        // The selection lands on the matching leaf — not the auto-expanded parent branch — so the
        // handoff gives the list something `r`/`e`/`d` can act on.
        let leaf = model
            .selected_leaf()
            .expect("a typed query selects the matching leaf");
        assert_eq!(leaf.selector.tuple, vec!["app", "prod", "db"]);

        // While typing, the bar advertises the handoff and renders no `/` next to a `╱` separator.
        let screen = render_to_string(&mut model);
        assert!(
            screen.contains("Enter to act"),
            "the search bar advertises the Enter handoff"
        );
        assert!(
            !screen.contains("╱ /"),
            "no double-slash while searching: {screen:?}"
        );

        // Enter keeps the query applied but hands the keyboard back to the list, still on the hit.
        update(&mut model, Message::SearchApply);
        assert!(!model.searching, "Enter closes the bar");
        assert_eq!(model.tree.total, 1, "the applied query keeps filtering");
        assert!(
            model.selected_leaf().is_some(),
            "the list keeps the hit selected after handoff"
        );

        // Applied state: the edit hint is bracketed (`[/]`), never a bare `/` abutting `╱`.
        let screen = render_to_string(&mut model);
        assert!(
            screen.contains("[/] edit"),
            "applied bar shows the bracketed edit hint"
        );
        assert!(
            !screen.contains("╱ /"),
            "no double-slash in the applied state: {screen:?}"
        );

        // The footer key hints (shown once the transient status clears) bracket the search key too.
        model.status.text.clear();
        let screen = render_to_string(&mut model);
        assert!(
            screen.contains("[/] search"),
            "footer shows the bracketed search hint"
        );
        assert!(
            !screen.contains("╱ /"),
            "no double-slash in the footer hints: {screen:?}"
        );

        // Esc clears it: the full tree is back and the saved expansion set is untouched.
        update(&mut model, Message::SearchCancel);
        assert!(model.search.is_empty(), "Esc clears the query");
        assert_eq!(
            model.tree.total, 2,
            "clearing search restores the full tree"
        );
    });
}

/// Pressing `f` with no labels in the namespace reports it instead of opening an empty picker.
#[test]
fn facet_filter_reports_when_no_labels() {
    let tmp = tempfile::tempdir().unwrap();
    let mut model = empty_model(tmp.path());
    model.workspace_error = None; // pretend a usable (but unlabeled) workspace
    update(&mut model, Message::OpenFacetFilter);
    assert!(model.modal.is_none(), "no picker opens without labels");
    assert!(
        model.status.text.contains("no labels"),
        "got: {}",
        model.status.text
    );
}

/// Creating a group then adding a member: the member picker opens with candidates, and submitting
/// emits an AddMember effect that, once run, lands the principal in the group's membership.
#[test]
fn add_member_picker_adds_a_principal_to_a_group() {
    use crate::app::{AccessTab, View};
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        // Mirror real init/claim: record this machine's identity for the root so `load` resolves
        // an acting user (otherwise the workspace shows the join screen).
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");

        // Create a group through the guided flow (button → input → submit → reload).
        drain_with(&mut model, Message::StartGroup);
        if let Some(Modal::Form(form)) = &mut model.modal {
            form.fields[0].value.push_str("oncall");
        }
        let effects = update(&mut model, Message::FormKey(form_key(KeyCode::Enter)));
        drain(&mut model, effects);
        assert_eq!(
            model.access.groups.len(),
            1,
            "the group appears after reload"
        );

        // Select the group header in the Groups tab, then open the member picker.
        model.view = View::Access;
        model.access_tab = AccessTab::Groups;
        model.access_selected = 0;
        assert!(model.selected_group().is_some());

        drain_with(&mut model, Message::StartAddMember);
        let candidate = match &model.modal {
            Some(Modal::Member(form)) => {
                assert!(!form.candidates.is_empty(), "root should be a candidate");
                form.candidates[form.idx].label.clone()
            }
            _ => panic!("StartAddMember should open the Member modal"),
        };
        assert!(candidate.starts_with('@') || !candidate.is_empty());

        // Submit the picker → AddMember effect → run + reload.
        let effects = update(&mut model, Message::MemberFormKey(form_key(KeyCode::Enter)));
        assert!(
            effects
                .iter()
                .any(|e| matches!(e, Effect::AddMember { .. })),
            "submitting the picker emits an AddMember effect"
        );
        drain(&mut model, effects);
        assert!(model.modal.is_none(), "picker closes after submit");
        assert_eq!(
            model.access.groups[0].members.len(),
            1,
            "the principal is now a member of the group"
        );

        // Adding the same principal again is rejected by the ops guard (no duplicate membership).
        drain_with(&mut model, Message::StartAddMember);
        let effects = update(&mut model, Message::MemberFormKey(form_key(KeyCode::Enter)));
        drain(&mut model, effects);
        assert!(
            model.status.is_error,
            "a second add of the same member reports an error"
        );
        assert_eq!(
            model.access.groups[0].members.len(),
            1,
            "membership is unchanged — no duplicate record"
        );
    });
}

/// The TUI can initialize a workspace when none is found: type a passphrase into the inline init
/// gate, then InitSubmit creates the vault.
#[test]
fn tui_init_creates_a_workspace() {
    use thorax_ops::WorkspacePaths;

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        // No vault yet → the init gate; typing feeds the inline passphrase, Enter submits.
        let mut model = Model::load(paths.clone());
        assert!(model.workspace_error.is_some());
        assert!(!model.session.exists());
        assert!(matches!(
            map_key(&model, key(KeyCode::Enter)),
            Some(Message::InitSubmit)
        ));

        for c in "pw".chars() {
            update(&mut model, Message::UnlockChar(c));
        }
        let effects = update(&mut model, Message::InitSubmit);
        drain(&mut model, effects);

        assert!(model.session.exists(), "workspace should now load");
        assert!(model.workspace_error.is_none());
        assert!(model.block.is_none());
        assert!(
            model.acting.is_some(),
            "acting identity resolved after init"
        );
        assert!(
            !model.unlock_session.is_locked(),
            "init unlocks the session"
        );
        assert!(paths.vault_path.exists(), "vault.cord written");

        // Immediately create a secret through the editor flow; it must appear after reload.
        update(&mut model, Message::StartNewSecret);
        if let Some(Modal::Form(form)) = &mut model.modal {
            form.fields[0].value.push_str("app/prod/token");
        }
        let effects = update(&mut model, Message::FormKey(form_key(KeyCode::Enter)));
        drain(&mut model, effects);
        assert!(
            matches!(model.modal, Some(Modal::Editor { .. })),
            "selector submit opens the value editor"
        );
        if let Some(Modal::Editor { textarea, .. }) = &mut model.modal {
            textarea.insert_str("tok-abc123");
        }
        let effects = update(&mut model, Message::EditorSubmit);
        drain(&mut model, effects);
        assert!(model.modal.is_none(), "editor closes after save");
        assert_eq!(model.tree.total, 1, "the new secret appears after reload");
        // Creating a secret navigates to it: the new leaf is selected (ancestors auto-expanded).
        assert_eq!(
            model
                .selected_leaf()
                .map(|l| project::selector_path(&l.selector)),
            Some("app/prod/token".to_string()),
            "the newly created secret is selected after reload"
        );
    });
}

/// A successful set-secret commits through the model's live `LockedSession` and leaves it at the
/// post-commit state: the new secret is visible immediately, and neither the effect's follow-up
/// nor its `OpOk` message produces an `Effect::Reload` (mutations never re-read the vault).
#[test]
fn set_secret_updates_model_without_reload_effect() {
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };
    use zeroize::Zeroizing;

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");
        assert_eq!(model.tree.total, 0);

        let selector = project::parse_selector("app/prod/db").unwrap();
        let follow_up = run_effect(
            &mut model,
            Effect::SetSecret {
                selector: selector.clone(),
                plaintext: Zeroizing::new(b"s3cret".to_vec()),
                label: "app/prod/db".to_string(),
            },
        );
        // The session committed in place: the model is already showing the post-commit state
        // before any follow-up message is processed — no reload happened or is pending.
        assert_eq!(model.tree.total, 1, "the new secret is visible immediately");
        let msg = match follow_up {
            Some(msg @ Message::OpOk(_)) => msg,
            _ => panic!("expected OpOk from a successful set-secret"),
        };
        let effects = update(&mut model, msg);
        assert!(
            !effects.iter().any(|e| matches!(e, Effect::Reload)),
            "a successful mutation must not produce a reload effect"
        );
    });
}

/// A vault exists but this machine has no recorded identity for it → the join gate, not the
/// unlock gate; `c`/Enter opens a 2-field (bundle + passphrase) form that emits an `Effect::Join`.
#[test]
fn no_local_identity_shows_join_gate() {
    use crate::app::{FormThen, Modal};
    use thorax_ops::{init_vault, key_hash, Crypto, Identity, WorkspacePaths};

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let _ = key_hash(&crypto, root.signing_public_key()).unwrap();
        // Deliberately do NOT write a last-identity pointer: this machine has never joined.

        let mut model = Model::load(paths.clone());
        assert!(model.is_join_gate(), "no local identity → join gate");
        assert!(!model.is_unlock_gate());
        assert!(model.acting.is_none());
        assert!(matches!(
            map_key(&model, key(KeyCode::Char('c'))),
            Some(Message::StartClaim)
        ));

        update(&mut model, Message::StartClaim);
        match &model.modal {
            Some(Modal::Form(form)) => {
                assert_eq!(form.fields.len(), 2, "bundle + passphrase");
                assert!(matches!(form.then, FormThen::Claim));
            }
            _ => panic!("StartClaim should open the join form"),
        }
        // An empty passphrase is rejected; a full form emits a Join effect.
        if let Some(Modal::Form(form)) = &mut model.modal {
            form.fields[0].value = "thrx1example".to_string();
        }
        let effects = update(&mut model, Message::FormKey(form_key(KeyCode::Enter)));
        assert!(effects.is_empty(), "passphrase required");
        if let Some(Modal::Form(form)) = &mut model.modal {
            form.fields[1].value = "pw".to_string();
        }
        let effects = update(&mut model, Message::FormKey(form_key(KeyCode::Enter)));
        assert!(
            effects.iter().any(|e| matches!(e, Effect::Join { .. })),
            "completed join form emits an Effect::Join"
        );
    });
}

fn first_leaf(tree: &project::SecretTree) -> Option<project::SecretLeaf> {
    fn walk(node: &project::TreeNode) -> Option<project::SecretLeaf> {
        if let Some(leaf) = node.leaves.first() {
            return Some(leaf.clone());
        }
        node.children.iter().find_map(walk)
    }
    tree.roots.iter().find_map(walk)
}

fn expand_all_and_select_leaf(model: &mut Model) {
    fn collect(node: &project::TreeNode, out: &mut Vec<Vec<String>>) {
        out.push(node.path.clone());
        for child in &node.children {
            collect(child, out);
        }
    }
    let mut paths = Vec::new();
    for root in &model.tree.roots {
        collect(root, &mut paths);
    }
    model.expanded.extend(paths);
    let rows = model.visible_rows();
    for (i, row) in rows.iter().enumerate() {
        if matches!(row, crate::app::Row::Leaf { .. }) {
            model.selected_row = i;
            break;
        }
    }
}

/// End-to-end merge resolution: a vault holding a same-counter tie summons the alert-colored
/// Conflicts tab; the tied secret has no effective value (it reads as conflicted, absent from
/// `secret_records`); the conflict→candidate tree renders full candidate details; revealing one
/// candidate reveals the whole conflict on one countdown; Enter resolves in place through the
/// shared ops path; the tab disappears with the last conflict.
#[test]
fn merge_tab_appears_for_conflicts_and_resolution_clears_them() {
    use thorax_ops::{
        decode_vault, encode_vault, init_vault, key_hash, merge_vaults, ratchet_path,
        save_identity_with_keychain_labeled, Crypto, Identity, MergeOutcome, PassphraseKeychain,
        WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        // Two "clones" (same identity, restored vault + trust state) write the same secret
        // from the same base, so both records carry the same Lamport counter.
        let selector = project::parse_selector("app/prod/db").unwrap();
        // A fresh session per write: the test swaps vault/trust files between writes to fake the
        // two clones, so each commit must observe the on-disk state as a new process would.
        let set = |value: &[u8]| {
            set_secret_via_keychain(&paths, &keychain, root.user_id(), selector.clone(), value);
        };
        set(b"base-value");
        let base_bytes = std::fs::read(&paths.vault_path).unwrap();
        let trust_file = ratchet_path(&paths, &root_hash);
        let trust_snapshot = std::fs::read(&trust_file).unwrap();
        set(b"value-a");
        let ours_bytes = std::fs::read(&paths.vault_path).unwrap();
        std::fs::write(&paths.vault_path, &base_bytes).unwrap();
        std::fs::write(&trust_file, &trust_snapshot).unwrap();
        set(b"value-b");
        let theirs_bytes = std::fs::read(&paths.vault_path).unwrap();

        // The driver's union lands in the working tree; whether it is conflicted is the
        // validator's answer, asserted on the loaded model below.
        let MergeOutcome::Merged { merged } = merge_vaults(
            Some(&decode_vault(&base_bytes).unwrap()),
            &decode_vault(&ours_bytes).unwrap(),
            &decode_vault(&theirs_bytes).unwrap(),
        )
        .unwrap() else {
            panic!("union merge must not be refused");
        };
        std::fs::write(&paths.vault_path, encode_vault(&merged).unwrap()).unwrap();

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");
        assert_eq!(model.merge.len(), 1);
        assert_eq!(model.merge[0].conflict_kind, "tie");
        assert!(model.merge[0].blocked.is_none(), "root can resolve");

        // The tied key has no effective value: it is absent from the live set, listed in
        // `secret_conflicts`, and classifies as Conflicted for the acting user.
        {
            let state = model.effective().unwrap();
            assert!(
                state.secret_records().is_empty(),
                "a tied secret must not read as live"
            );
            assert_eq!(state.secret_conflicts().len(), 1);
            assert_eq!(
                state.classify_secret_for_user(&selector, root.user_id(), &crypto),
                thorax_ops::SecretState::Conflicted
            );
        }
        // It still shows in the browse tree, flagged as the conflict it is.
        assert_eq!(
            first_leaf(&model.tree).unwrap().state,
            thorax_ops::SecretState::Conflicted
        );

        // The alert tab exists, and `4` switches to it. The tree shows the conflict header
        // with its candidates nested below; the header detail explains the tie.
        let screen = render_to_string(&mut model);
        assert!(
            screen.contains("[4] Conflicts"),
            "conflicts tab missing:\n{screen}"
        );
        let switch = map_key(&model, key(KeyCode::Char('4'))).unwrap();
        drain_with(&mut model, switch);
        assert_eq!(model.view, View::Merge);
        assert_eq!(model.merge_rows().len(), 3); // conflict + 2 candidates
        let screen = render_to_string(&mut model);
        assert!(screen.contains("unresolved conflict"));
        assert!(
            screen.contains("concurrent writes tied"),
            "conflict summary missing:\n{screen}"
        );
        assert!(
            screen.contains("no effective value"),
            "no-winner copy missing:\n{screen}"
        );

        // A tie is a real ambiguity in the vault itself: `a` (accept) is refused on its
        // header — no confirm opens, the conflict stays — and the footer never offers it.
        assert!(
            !screen.contains("a accept the rollback"),
            "a tie must not hint at accept:\n{screen}"
        );
        assert_eq!(model.merge_selected, 0, "the header row is selected");
        let refuse = map_key(&model, key(KeyCode::Char('a'))).unwrap();
        assert!(matches!(refuse, Message::RequestAcceptRollback));
        drain_with(&mut model, refuse);
        assert!(
            model.modal.is_none(),
            "accept must not open a confirm for a tie"
        );
        assert!(model.status.is_error, "{}", model.status.text);
        assert_eq!(model.conflicts.len(), 1, "the tie is untouched");

        // There is no implicit favorite — pick the first candidate explicitly (the tied
        // bodies differ only in their sealed payloads; either is a legitimate winner).
        let pick_index = 0;
        model.merge_selected = 1 + pick_index;
        assert!(model.selected_merge_candidate().is_some());

        // Full candidate details render, and the gated reveal opens the WHOLE conflict:
        // both candidates' values, one shared countdown — so they can be compared.
        let screen = render_to_string(&mut model);
        assert!(screen.contains("sealed to"), "details missing:\n{screen}");
        assert!(screen.contains("press r to reveal"), "{screen}");
        let reveal = map_key(&model, key(KeyCode::Char('r'))).unwrap();
        drain_with(&mut model, reveal);
        let reveal_state = model
            .merge_reveal
            .as_ref()
            .expect("conflict values should be revealed");
        assert_eq!(reveal_state.values.len(), 2);
        let mut shown: Vec<Vec<u8>> = reveal_state
            .values
            .iter()
            .map(|value| value.plaintext.to_vec())
            .collect();
        shown.sort();
        assert_eq!(shown, vec![b"value-a".to_vec(), b"value-b".to_vec()]);
        let screen = render_to_string(&mut model);
        assert!(screen.contains("hides in"), "{screen}");
        // The OTHER candidate of the same conflict is revealed too, same countdown.
        model.merge_selected = 1 + (1 - pick_index);
        let screen = render_to_string(&mut model);
        assert!(screen.contains("hides in"), "{screen}");
        model.merge_selected = 1 + pick_index;

        // Resolve in place, keyboard only: Enter on the candidate opens the confirm, Enter
        // again commits (the confirm modal's default). No button focus involved.
        let resolve = map_key(&model, key(KeyCode::Enter)).unwrap();
        assert!(matches!(resolve, Message::RequestResolveConflict));
        drain_with(&mut model, resolve);
        assert!(matches!(model.modal, Some(Modal::Confirm { .. })));
        let confirm = map_key(&model, key(KeyCode::Enter)).unwrap();
        assert!(matches!(confirm, Message::ConfirmYes));
        drain_with(&mut model, confirm);

        // The conflict is gone, the tab with it, and the footer points at `git add`.
        assert!(model.conflicts.is_empty(), "status: {}", model.status.text);
        assert_eq!(model.view, View::Secrets);
        assert!(
            model.status.text.contains("git add"),
            "{}",
            model.status.text
        );
        let screen = render_to_string(&mut model);
        assert!(!screen.contains("[4] Conflicts"));
    });
}

/// A suspected rollback (the vault restored to an older snapshot while local trust remembers
/// the newer counter) is accepted in place: `a` on the conflict header opens the question
/// confirm, Enter accepts through the machine-local op — the conflict clears with no record
/// written (the vault bytes are untouched).
#[test]
fn accept_rollback_in_place_clears_the_conflict_without_writing() {
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        // v1, snapshot, v2, restore: the vault shows v1 while local trust remembers v2's
        // counter — a rollback conflict with v1 as the surviving candidate.
        let selector = project::parse_selector("app/prod/db").unwrap();
        let set = |value: &[u8]| {
            set_secret_via_keychain(&paths, &keychain, root.user_id(), selector.clone(), value);
        };
        set(b"v1");
        let snapshot = std::fs::read(&paths.vault_path).unwrap();
        set(b"v2");
        std::fs::write(&paths.vault_path, &snapshot).unwrap();

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");
        assert_eq!(model.conflicts.len(), 1);
        assert_eq!(model.merge[0].conflict_kind, "rollback");
        assert!(
            !model.merge[0].candidates.is_empty(),
            "v1 survives as the rolled-back-to candidate"
        );

        drain_with(&mut model, Message::SwitchView(View::Merge));
        assert_eq!(model.merge_selected, 0, "the header row is selected");
        // The footer offers both in-place outs on a rollback-at-a-secret header (the hint
        // line only shows while no transient status occupies the footer).
        model.status = crate::app::Status::default();
        let screen = render_to_string(&mut model);
        assert!(screen.contains("a accept the rollback"), "{screen}");
        assert!(screen.contains("s set a fresh value"), "{screen}");

        let accept = map_key(&model, key(KeyCode::Char('a'))).unwrap();
        assert!(matches!(accept, Message::RequestAcceptRollback));
        drain_with(&mut model, accept);
        match &model.modal {
            Some(Modal::Confirm { title, lines, .. }) => {
                assert_eq!(title, "Accept this rollback?");
                assert!(
                    lines.iter().any(|l| l.contains("No record is written")),
                    "{lines:?}"
                );
            }
            _ => panic!("a on a rollback header opens the accept confirm"),
        }
        let confirm = map_key(&model, key(KeyCode::Enter)).unwrap();
        assert!(matches!(confirm, Message::ConfirmYes));
        drain_with(&mut model, confirm);

        // Machine-local: the conflict cleared, the tab is gone, the vault is untouched.
        assert!(model.conflicts.is_empty(), "status: {}", model.status.text);
        assert!(
            model.status.text.contains("accepted rollback"),
            "{}",
            model.status.text
        );
        assert_eq!(
            model.view,
            View::Secrets,
            "the tab disappeared with the last conflict"
        );
        assert_eq!(
            std::fs::read(&paths.vault_path).unwrap(),
            snapshot,
            "accepting writes no record"
        );
    });
}

/// A candidate-less rollback (a secret created after the snapshot is erased by restoring it)
/// names the in-place keys, and `s` opens the existing set form prefilled from the remembered
/// origin tuple — the ordinary set flow then clears the conflict.
#[test]
fn candidateless_rollback_set_opens_prefilled_form() {
    use crate::app::FormThen;
    use thorax_ops::{
        init_vault, key_hash, save_identity_with_keychain_labeled, Crypto, Identity,
        PassphraseKeychain, WorkspacePaths,
    };

    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let keychain_dir = tmp.path().join("keychain");
    let paths = WorkspacePaths::from_root(repo).with_state_dir(tmp.path().join("state"));

    with_keychain_dir(&keychain_dir, || {
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let root_hash = key_hash(&crypto, root.signing_public_key()).unwrap();
        let keychain = PassphraseKeychain::new(
            &keychain_dir,
            thorax_ops::StaticPassphraseProvider::new("pw"),
        );
        save_identity_with_keychain_labeled(
            &paths,
            &crypto,
            &keychain,
            &root_hash,
            &root,
            Some("repo".to_string()),
            Some("root".to_string()),
        )
        .unwrap();
        thorax_frontend::write_current_user_for_root(&root_hash, root.user_id(), None).unwrap();

        // Snapshot, create a brand-new secret, restore: the key's records are erased
        // entirely, so the rollback has no candidates — only the remembered origin tuple.
        let snapshot = std::fs::read(&paths.vault_path).unwrap();
        set_secret_via_keychain(
            &paths,
            &keychain,
            root.user_id(),
            project::parse_selector("app/prod/api-key").unwrap(),
            b"shh",
        );
        std::fs::write(&paths.vault_path, &snapshot).unwrap();

        let mut model = Model::load(paths.clone());
        unlock(&mut model, "pw");
        assert_eq!(model.conflicts.len(), 1);
        assert_eq!(model.merge[0].conflict_kind, "rollback");
        assert!(model.merge[0].candidates.is_empty());
        // The hint names the in-place keys instead of pointing away.
        let blocked = model.merge[0].blocked.clone().unwrap();
        assert!(blocked.contains("s set a fresh value"), "{blocked}");
        assert!(blocked.contains("a accept the rollback"), "{blocked}");

        drain_with(&mut model, Message::SwitchView(View::Merge));
        let set_msg = map_key(&model, key(KeyCode::Char('s'))).unwrap();
        assert!(matches!(set_msg, Message::StartSetFresh));
        drain_with(&mut model, set_msg);
        match &model.modal {
            Some(Modal::Form(form)) => {
                assert_eq!(
                    form.fields[0].value, "app/prod/api-key",
                    "prefilled from the remembered origin"
                );
                assert_eq!(form.fields[1].value, "");
                assert!(matches!(form.then, FormThen::NewSecret));
            }
            _ => panic!("s should open the prefilled set form"),
        }

        // From here it is the ordinary new-secret flow: submit → editor → save clears the
        // conflict (the fresh write lands above the remembered watermark).
        let effects = update(&mut model, Message::FormKey(form_key(KeyCode::Enter)));
        drain(&mut model, effects);
        match &mut model.modal {
            Some(Modal::Editor { textarea, .. }) => {
                textarea.insert_str("fresh-value");
            }
            _ => panic!("the set form feeds the value editor"),
        }
        let effects = update(&mut model, Message::EditorSubmit);
        drain(&mut model, effects);
        assert!(
            model.conflicts.is_empty(),
            "a fresh set clears the rollback: {}",
            model.status.text
        );
        assert_eq!(model.tree.total, 1, "the fresh secret is live");
    });
}

/// Confirm-dialog panel is 70-char wide with borders + gutter = 66 content
/// chars. Lines over this wrap. This test flags future text additions so the
/// author keeps them tight or explicitly accepts the extra visual rows.
const CONFIRM_LINE_BUDGET: usize = 66;

const CONFIRM_DIALOG_LINES: &[&str] = &[
    // Delete user
    "Removes the user and their grants and memberships.",
    "Existing readable secrets stay readable until rotated.",
    "Re-inviting creates a fresh identity — old access is lost.",
    // Delete grant
    "Revokes this grant.",
    "Recreate it later if needed.",
    // Delete group
    "Deletes this group.",
    "Members lose the access this group granted.",
    // Delete secret
    "Marks the secret as deleted.",
    "History is preserved in the vault.",
    // Accept rollback
    "The current vault state is trusted as-is.",
    "No record is written.",
];

#[test]
fn confirm_dialog_text_fits_panel_width() {
    let mut failed = Vec::new();
    for line in CONFIRM_DIALOG_LINES {
        if line.chars().count() > CONFIRM_LINE_BUDGET {
            failed.push((line.chars().count(), *line));
        }
    }
    assert!(
        failed.is_empty(),
        "{} line(s) exceed the {}-char panel width:\n{}",
        failed.len(),
        CONFIRM_LINE_BUDGET,
        failed
            .iter()
            .map(|(len, line)| format!("  {len} chars: {line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    );
}
