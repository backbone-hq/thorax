//! Terminal setup/teardown and a panic hook.
//!
//! The TUI runs on the alternate screen, so revealed plaintext never lands in the primary
//! scrollback. [`TerminalGuard`] restores the terminal on drop — including on early returns and
//! errors — and [`install_panic_hook`] guarantees the same on a panic, before the default hook
//! prints, so a crash can't dump a revealed secret onto the normal screen.

use std::io::{self, Stdout};

use crossterm::{
    event::{
        DisableMouseCapture, EnableMouseCapture, KeyboardEnhancementFlags,
        PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, supports_keyboard_enhancement, Clear, ClearType,
        EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use ratatui::{backend::CrosstermBackend, Terminal};

pub type Tui = Terminal<CrosstermBackend<Stdout>>;

/// Owns the terminal's raw-mode + alternate-screen state and restores it on drop.
pub struct TerminalGuard {
    terminal: Tui,
}

impl TerminalGuard {
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        // Disambiguate modified keys (e.g. Ctrl-Backspace vs Backspace, Ctrl-Left vs Left) via the
        // kitty keyboard protocol where the terminal supports it, so the editor's word-wise
        // shortcuts work. Unsupported terminals ignore it and fall back to legacy key reporting.
        if matches!(supports_keyboard_enhancement(), Ok(true)) {
            let _ = execute!(
                stdout,
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            );
        }
        let terminal = Terminal::new(CrosstermBackend::new(stdout))?;
        Ok(Self { terminal })
    }

    pub fn terminal(&mut self) -> &mut Tui {
        &mut self.terminal
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = restore();
    }
}

/// Leave the alternate screen, clear it, and disable raw mode. Idempotent enough to call from both
/// the guard's Drop and the panic hook.
pub fn restore() -> io::Result<()> {
    let mut stdout = io::stdout();
    // Pop the keyboard-enhancement flags first (no-op if we never pushed / unsupported).
    let _ = execute!(stdout, PopKeyboardEnhancementFlags);
    let _ = execute!(
        stdout,
        DisableMouseCapture,
        Clear(ClearType::All),
        LeaveAlternateScreen
    );
    disable_raw_mode()
}

/// Install a panic hook that restores the terminal before the previous hook runs. Without this a
/// panic mid-render would leave the terminal in raw mode on the alternate screen with plaintext
/// possibly visible.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore();
        previous(info);
    }));
}
