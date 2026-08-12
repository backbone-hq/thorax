//! TUI color roles.

use ratatui::style::Color;

/// Neutral grey — the resting structural colour (rules, edges, separators). No hue, so it recedes.
pub const STRUCT: Color = Color::Rgb(112, 112, 112);
/// A darker neutral grey for de-emphasised structure (selection bar, rule baseline, faded lattice).
pub const STRUCT_DIM: Color = Color::Rgb(56, 56, 56);
/// Amber — the single signature accent: attention, focus, action, authority, *and* live/active.
/// Aliveness is brightness + pulse, not a separate colour.
pub const AUTHORITY: Color = Color::Rgb(255, 178, 38);
/// "Live / verified / decryptable" — the same amber. Kept as a named role for legibility at call
/// sites; intensity (and the pulse in the header pip) is what distinguishes it from resting amber.
pub const LIVE: Color = AUTHORITY;
/// Breach red — rollback, bad signature, lockdown. The only colour outside the grey/amber spine.
pub const BREACH: Color = Color::Rgb(255, 74, 62);
/// Burnt amber — non-blocking issues / warnings. Dimmer + desaturated vs the bright accent, and
/// always paired with a `!` glyph so it never reads as the live amber.
pub const WARN: Color = Color::Rgb(201, 138, 42);
/// Primary readable text — neutral off-white.
pub const TEXT: Color = Color::Rgb(212, 212, 212);
/// Faint text — fingerprints, hints, placeholders. The recessive neutral grey.
pub const FAINT: Color = Color::Rgb(112, 112, 112);
