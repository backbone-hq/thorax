//! Mode-aware key mapping: a `KeyEvent` becomes a [`Message`] based on the active modal, the
//! locked/blocked state, and the current view. Pure (takes `&Model`) so it can be unit-tested.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{AccessTab, Focus, Message, Modal, Model, View};

pub fn map_key(model: &Model, mut key: KeyEvent) -> Option<Message> {
    // With the kitty keyboard protocol enabled (for the editor's Ctrl-shortcuts), Shift-Tab arrives
    // as Tab+SHIFT rather than the legacy BackTab. Normalise it so every downstream handler — and
    // the keys forwarded into forms — keeps seeing BackTab.
    if key.code == KeyCode::Tab && key.modifiers.contains(KeyModifiers::SHIFT) {
        key.code = KeyCode::BackTab;
        key.modifiers.remove(KeyModifiers::SHIFT);
    }

    // Ctrl-C always quits.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Message::Quit);
    }

    // The unlock gate: while the session is locked, the only inputs are the passphrase (and quit).
    // Every other action is blocked so the user can't attempt ops that would fail on a locked keychain.
    if model.is_unlock_gate() {
        return gate_key(key, Message::UnlockSubmit);
    }

    // A modal owns the keyboard.
    if let Some(modal) = &model.modal {
        return map_modal(modal, key);
    }

    // The live search bar (Secrets view) owns the keyboard while open: every printable key edits
    // the query, ↑↓ walks the live results, Enter applies, Esc clears. Sits above the view maps so
    // letters like `n`/`d` are typed into the query rather than firing their command shortcuts.
    if model.searching {
        return search_key(key);
    }

    // Fail-closed / blocked: only quit.
    if model.block.is_some() {
        return match key.code {
            KeyCode::Char('q') => Some(Message::Quit),
            _ => None,
        };
    }

    // No vault found (here or in any parent): the init gate captures a passphrase inline and
    // creates the vault on Enter. Like the unlock gate, only the passphrase (and Ctrl-C) — so a
    // 'q' is a passphrase character, not quit.
    if model.workspace_error.is_some() {
        return gate_key(key, Message::InitSubmit);
    }

    // A vault exists but this machine has no identity for it yet: offer to join with an invite.
    if model.is_join_gate() {
        return match key.code {
            KeyCode::Char('c') | KeyCode::Enter => Some(Message::StartClaim),
            KeyCode::Char('?') => Some(Message::OpenHelp),
            KeyCode::Char('q') => Some(Message::Quit),
            _ => None,
        };
    }

    // Global keys.
    match key.code {
        KeyCode::Char('q') => return Some(Message::Quit),
        KeyCode::Char('?') => return Some(Message::OpenHelp),
        KeyCode::Char('1') => return Some(Message::SwitchView(View::Secrets)),
        KeyCode::Char('2') => return Some(Message::SetAccessTab(AccessTab::Users)),
        KeyCode::Char('3') => return Some(Message::SetAccessTab(AccessTab::Groups)),
        // The Merge tab exists only while conflicts do; `update` ignores the switch otherwise.
        KeyCode::Char('4') => return Some(Message::SwitchView(View::Merge)),
        KeyCode::Char('H') => return Some(Message::OpenHealth),
        KeyCode::Char('L') => return Some(Message::LockNow),
        KeyCode::BackTab => return Some(Message::FocusList),
        KeyCode::Tab => return Some(Message::FocusNext),
        _ => {}
    }

    // When an action button has focus, arrows move between buttons and Enter activates it.
    // (Typed shortcuts like n/r/e/d still fall through and work.)
    if matches!(model.focus, Focus::Button(_)) {
        match key.code {
            KeyCode::Left | KeyCode::Char('h') => return Some(Message::ButtonPrev),
            KeyCode::Right | KeyCode::Char('l') => return Some(Message::ButtonNext),
            KeyCode::Up | KeyCode::Char('k') => return Some(Message::FocusList),
            KeyCode::Enter | KeyCode::Char(' ') => return Some(Message::ActivateButton),
            KeyCode::Esc => return Some(Message::FocusList),
            _ => {}
        }
    }

    // List navigation shared by every view's list.
    match key.code {
        KeyCode::Home | KeyCode::Char('g') => return Some(Message::MoveTop),
        KeyCode::End | KeyCode::Char('G') => return Some(Message::MoveBottom),
        KeyCode::PageUp => return Some(Message::PageUp),
        KeyCode::PageDown => return Some(Message::PageDown),
        _ => {}
    }

    match model.view {
        View::Secrets => map_secrets(key),
        View::Access => {
            // `n` is "new" in context: invite a user (Users) or create a group (Groups).
            if matches!(key.code, KeyCode::Char('n')) {
                return Some(match model.access_tab {
                    AccessTab::Users => Message::StartInvite,
                    AccessTab::Groups => Message::StartGroup,
                });
            }
            map_access(key)
        }
        View::Merge => map_merge(key),
    }
}

/// Merge view: ↑↓ walk the conflict→candidate tree, →/← step into/out of a conflict,
/// `r` reveals a secret candidate's value, Enter resolves to the selected candidate. On a
/// rollback header, `a` accepts the rollback in place and `s` sets a fresh value at the key
/// (`update` refuses/ignores both elsewhere).
fn map_merge(key: KeyEvent) -> Option<Message> {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Message::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Message::MoveUp),
        KeyCode::Char('l') | KeyCode::Right => Some(Message::Open),
        KeyCode::Char('h') | KeyCode::Left => Some(Message::Close),
        KeyCode::Char('r') => Some(Message::Reveal),
        KeyCode::Char('a') => Some(Message::RequestAcceptRollback),
        KeyCode::Char('s') => Some(Message::StartSetFresh),
        KeyCode::Enter | KeyCode::Char('R') => Some(Message::RequestResolveConflict),
        _ => None,
    }
}

/// Keymap for the full-screen passphrase gates (unlock / init): type the passphrase, Backspace to
/// delete a char, Ctrl-Backspace / Ctrl-U / Ctrl-W to clear it, Enter to `submit`. Modified chars
/// (Ctrl/Alt) are swallowed rather than typed, and Ctrl-C still quits (handled globally above).
fn gate_key(key: KeyEvent, submit: Message) -> Option<Message> {
    let word = key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
    match key.code {
        KeyCode::Enter => Some(submit),
        KeyCode::Backspace if word => Some(Message::UnlockClear),
        KeyCode::Char('u' | 'w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(Message::UnlockClear)
        }
        KeyCode::Backspace => Some(Message::UnlockBackspace),
        KeyCode::Char(c) if !word => Some(Message::UnlockChar(c)),
        _ => None,
    }
}

fn map_modal(modal: &Modal, key: KeyEvent) -> Option<Message> {
    match modal {
        Modal::Help | Modal::Health => match key.code {
            KeyCode::Esc
            | KeyCode::Enter
            | KeyCode::Char('q')
            | KeyCode::Char('?')
            | KeyCode::Char('H') => Some(Message::CloseModal),
            _ => None,
        },
        Modal::InviteBundle { .. } => match key.code {
            KeyCode::Char('y') => Some(Message::CopyInviteBundle),
            KeyCode::Esc
            | KeyCode::Enter
            | KeyCode::Char('q')
            | KeyCode::Char('?')
            | KeyCode::Char('H') => Some(Message::CloseModal),
            _ => None,
        },
        Modal::Confirm { .. } => match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => Some(Message::ConfirmYes),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => Some(Message::CloseModal),
            _ => None,
        },
        Modal::Form(_) => {
            if key.code == KeyCode::Esc {
                Some(Message::CloseModal)
            } else {
                Some(Message::FormKey(key))
            }
        }
        Modal::Editor { .. } => {
            // Ctrl-S saves, Esc discards; everything else edits the in-memory buffer.
            if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
                Some(Message::EditorSubmit)
            } else if key.code == KeyCode::Esc {
                Some(Message::CloseModal)
            } else {
                Some(Message::EditorKey(key))
            }
        }
        Modal::Grant(_) => {
            if key.code == KeyCode::Esc {
                Some(Message::CloseModal)
            } else {
                Some(Message::GrantFormKey(key))
            }
        }
        Modal::Member(_) => {
            if key.code == KeyCode::Esc {
                Some(Message::CloseModal)
            } else {
                Some(Message::MemberFormKey(key))
            }
        }
        Modal::Facet { .. } => {
            if key.code == KeyCode::Esc {
                Some(Message::CloseModal)
            } else {
                Some(Message::FacetFormKey(key))
            }
        }
    }
}

fn map_secrets(key: KeyEvent) -> Option<Message> {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Message::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Message::MoveUp),
        KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => Some(Message::Open),
        KeyCode::Char('h') | KeyCode::Left => Some(Message::Close),
        KeyCode::Char('r') => Some(Message::Reveal),
        KeyCode::Char('y') => Some(Message::Copy),
        KeyCode::Char('e') => Some(Message::StartEdit),
        KeyCode::Char('n') => Some(Message::StartNewSecret),
        KeyCode::Char('d') => Some(Message::RequestDeleteSecret),
        KeyCode::Char('f') => Some(Message::OpenFacetFilter),
        KeyCode::Char('/') => Some(Message::OpenSearch),
        // Esc clears an applied search (a no-op when none is active).
        KeyCode::Esc => Some(Message::SearchCancel),
        _ => None,
    }
}

/// Keymap for the live search bar: printable keys edit the query, ↑↓ walk the live results so you
/// can land on one before applying, Enter keeps the query and returns to the list, Esc clears it.
/// Modified chars (Ctrl/Alt) are swallowed rather than typed (Ctrl-C still quits, handled above).
fn search_key(key: KeyEvent) -> Option<Message> {
    match key.code {
        KeyCode::Esc => Some(Message::SearchCancel),
        KeyCode::Enter => Some(Message::SearchApply),
        KeyCode::Backspace => Some(Message::SearchBackspace),
        KeyCode::Down => Some(Message::MoveDown),
        KeyCode::Up => Some(Message::MoveUp),
        KeyCode::Char(c)
            if !key
                .modifiers
                .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
        {
            Some(Message::SearchChar(c))
        }
        _ => None,
    }
}

fn map_access(key: KeyEvent) -> Option<Message> {
    match key.code {
        KeyCode::Char('j') | KeyCode::Down => Some(Message::MoveDown),
        KeyCode::Char('k') | KeyCode::Up => Some(Message::MoveUp),
        KeyCode::Char('l') | KeyCode::Right | KeyCode::Enter => Some(Message::Open),
        KeyCode::Char('h') | KeyCode::Left => Some(Message::Close),
        KeyCode::Char('[') | KeyCode::Char(']') => Some(Message::CycleAccessTab),
        KeyCode::Char('i') => Some(Message::StartInvite),
        KeyCode::Char('V') => Some(Message::RequestUserDelete),
        KeyCode::Char('d') => Some(Message::RequestAccessDelete),
        _ => None,
    }
}
