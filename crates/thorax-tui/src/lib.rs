//! Interactive secrets editor — the bare `thorax` entrypoint.
//!
//! A ratatui app over [`thorax_frontend`] / [`thorax_ops`]: it renders the verified
//! `EffectiveState`, submits intents through the shared `*_with_keychain` ops path, and never adds
//! its own security logic.

use std::process::ExitCode;
use std::time::Duration;

use crossterm::event::{
    self as cevent, DisableMouseCapture, EnableMouseCapture, Event, KeyEventKind,
};
use crossterm::execute;
use thorax_frontend::{explicit_or_current_root, workspace_paths, FrontendError, GlobalArgs};
use thorax_ops::WorkspacePaths;

mod app;
mod event;
mod project;
mod session;
mod terminal;
mod theme;
mod ui;

#[cfg(test)]
mod tests;

use crate::app::{run_effect, update, Message, Model, Status};

const TICK: Duration = Duration::from_millis(250);

/// Launch the interactive TUI editor. Receives the global flags from the umbrella binary.
pub fn run_tui(global: GlobalArgs) -> Result<ExitCode, FrontendError> {
    // Resolve the workspace. If discovery fails we still open, on a "no vault" screen, so the
    // user gets a real next step instead of a bare error.
    let paths = match workspace_paths(global.path.as_ref(), false) {
        Ok(paths) => paths,
        Err(_) => WorkspacePaths::from_root(explicit_or_current_root(global.path.as_ref())?),
    };

    terminal::install_panic_hook();
    let mut guard = terminal::TerminalGuard::new().map_err(FrontendError::Stdio)?;
    let mut model = Model::load(paths);
    if let Some(notice) = thorax_update::passive_update_notice(None) {
        model.status = Status::info(notice);
    }

    let result = event_loop(&mut guard, &mut model);
    drop(guard); // restore terminal before propagating any error
    result?;
    Ok(ExitCode::SUCCESS)
}

fn event_loop(guard: &mut terminal::TerminalGuard, model: &mut Model) -> Result<(), FrontendError> {
    // Only repaint when something actually changed (a handled input, a tick, or a resize). Mouse
    // capture emits a stream of move events while the cursor travels; redrawing on each one made the
    // chrome shimmer under the pointer, so those (and any other no-op events) leave `dirty` false.
    let mut dirty = true;
    // Mouse capture lets us route clicks to buttons/rows, but it also stops the terminal's own
    // text selection. While sensitive text is intentionally exposed, release capture so the user
    // can drag-select it with the terminal, then re-grab it once the exposure is gone.
    let mut mouse_captured = true;
    loop {
        let want_capture = !model.terminal_selection_enabled();
        if want_capture != mouse_captured {
            let mut out = std::io::stdout();
            if want_capture {
                execute!(out, EnableMouseCapture).map_err(FrontendError::Stdio)?;
            } else {
                execute!(out, DisableMouseCapture).map_err(FrontendError::Stdio)?;
            }
            mouse_captured = want_capture;
            dirty = true;
        }
        if dirty {
            guard
                .terminal()
                .draw(|frame| ui::render(model, frame))
                .map_err(FrontendError::Stdio)?;
            dirty = false;
        }
        if model.should_quit {
            return Ok(());
        }
        if cevent::poll(TICK).map_err(FrontendError::Stdio)? {
            match cevent::read().map_err(FrontendError::Stdio)? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if let Some(msg) = event::map_key(model, key) {
                        // The unlock KDF (Argon2id) blocks the loop for ~1–2s. Rather than freeze on
                        // the passphrase prompt, paint one "deriving key" frame of the jack-in gate
                        // first, so assuming an identity reads as a deliberate act, not a hang.
                        if matches!(msg, Message::UnlockSubmit | Message::InitSubmit)
                            && !model.unlock_input.is_empty()
                        {
                            model.deriving = true;
                            guard
                                .terminal()
                                .draw(|frame| ui::render(model, frame))
                                .map_err(FrontendError::Stdio)?;
                        }
                        dispatch(model, msg);
                        model.deriving = false;
                        dirty = true;
                    }
                }
                Event::Mouse(mouse) => {
                    if matches!(
                        mouse.kind,
                        cevent::MouseEventKind::Down(cevent::MouseButton::Left)
                    ) {
                        dispatch(model, Message::MouseClick(mouse.column, mouse.row));
                        dirty = true;
                    }
                }
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        } else {
            dispatch(model, Message::Tick);
            dirty = true;
        }
    }
}

/// Run a message through `update`, then drain the resulting effects, feeding any follow-up
/// messages back through `update` until the queue is empty.
fn dispatch(model: &mut Model, msg: Message) {
    let mut effects = update(model, msg);
    loop {
        while let Some(effect) = effects.pop() {
            if let Some(next) = run_effect(model, effect) {
                effects.extend(update(model, next));
            }
        }
        // Once the queue settles the selection, eagerly load the selected secret's additional
        // fields (shown in plaintext without a reveal step). The load caches its result — even a
        // failure — for the selector, so this re-checks at most once per selection and terminates.
        match model.fields_sync_effect() {
            Some(effect) => effects.push(effect),
            None => break,
        }
    }
}
