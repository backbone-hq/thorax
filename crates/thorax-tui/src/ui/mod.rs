//! All rendering. Pure view over [`Model`]; emits no effects and mutates nothing.

mod access;
mod forms;
mod gates;
mod health;
mod merge;
mod secrets;

use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Padding, Paragraph, Wrap},
    Frame,
};

use crate::app::{AccessTab, Button, ButtonAction, Focus, Model, View};
use crate::theme;

use self::access::render_access;
use self::forms::render_modal;
use self::gates::{render_init_gate, render_join, render_locked, render_unlock_gate};
use self::merge::render_merge;
use self::secrets::render_secrets;

// The Fusion palette (see `crate::theme`), kept under the existing short names so the whole UI
// shares one language: amber = authority/attention/live, grey = structure, red = breach.
const ACCENT: Color = theme::AUTHORITY;
const OK: Color = theme::LIVE;
const WARN: Color = theme::WARN;
const BAD: Color = theme::BREACH;
const DIM: Color = theme::FAINT;

/// The smallest terminal the chrome can lay out legibly: the header readout plus a couple of body
/// rows. Below this we paint a single "resize" notice instead of a clipped, unusable screen.
const MIN_COLS: u16 = 50;
const MIN_ROWS: u16 = 12;

pub fn render(model: &mut Model, frame: &mut Frame) {
    let area = frame.area();
    // The renderer re-records clickable regions every frame.
    model.buttons.clear();
    model.list_region = None;

    // Below a usable size, every layout below would clip its own instructions; show one clear
    // next step (resize) rather than a broken screen.
    if area.width < MIN_COLS || area.height < MIN_ROWS {
        render_too_small(frame, area);
        return;
    }

    // The unlock gate takes over the whole terminal — no header, views, or footer behind it.
    if model.is_unlock_gate() {
        render_unlock_gate(model, frame, area);
        return;
    }

    // Likewise, the "no vault" screen is a full-terminal takeover: the init gate asks for a
    // passphrase inline and creates the vault, so there's no separate dialog or modal.
    if model.workspace_error.is_some() {
        render_init_gate(model, frame, area);
        return;
    }

    // A vault exists but this machine has no identity for it yet: a full-terminal join screen
    // (claim an invite), not the unlock gate — your identity is established here, up front.
    if model.is_join_gate() {
        render_join(model, frame, area);
        if let Some(modal) = &model.modal {
            render_modal(model, modal, frame, area);
        }
        return;
    }

    // Blank spacer rows frame the body above and below — no dividers.
    let rows = Layout::vertical([
        Constraint::Length(1), // header
        Constraint::Length(1), // spacer
        Constraint::Min(0),    // body
        Constraint::Length(1), // action bar
        Constraint::Length(1), // spacer
        Constraint::Length(1), // footer
    ])
    .split(area);
    let (header, body, action_bar, footer) = (rows[0], rows[2], rows[3], rows[5]);

    render_header(model, frame, header);

    if model.block.is_some() {
        render_locked(model, frame, body);
    } else {
        match model.view {
            View::Secrets => render_secrets(model, frame, body),
            View::Access => render_access(model, frame, body),
            View::Merge => render_merge(model, frame, body),
        }
    }

    render_action_bar(model, frame, action_bar);
    render_footer(model, frame, footer);

    if let Some(modal) = &model.modal {
        render_modal(model, modal, frame, area);
    }
}

/// The clickable, keyboard-focusable action bar for the current screen.
fn render_action_bar(model: &mut Model, frame: &mut Frame, area: Rect) {
    // The no-workspace screen is a full-terminal takeover with its own in-dialog button, so the
    // action bar is never reached there. A blocked workspace offers no actions at all.
    let actions: Vec<ButtonAction> = if model.block.is_some() {
        Vec::new()
    } else {
        model.view_buttons()
    };

    let mut x = area.x + 1;
    let mut drawn = 0;
    for (i, action) in actions.iter().enumerate() {
        let text = format!("[ {} ]", action.label());
        let w = text.chars().count() as u16;
        // Reserve a column for the "…more" marker while actions remain unplaced, so the overflow
        // hint never itself overflows.
        let reserve = if i + 1 < actions.len() { 2 } else { 0 };
        if x + w + reserve > area.x + area.width {
            break;
        }
        let rect = Rect {
            x,
            y: area.y,
            width: w,
            height: 1,
        };
        // Outlined buttons; the focused one is highlighted (reversed + bold).
        let style = if model.focus == Focus::Button(i) {
            Style::new()
                .fg(ACCENT)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::new().fg(ACCENT)
        };
        frame.render_widget(Paragraph::new(Span::styled(text, style)), rect);
        model.buttons.push(crate::app::Button {
            rect,
            action: *action,
        });
        x += w + 1;
        drawn += 1;
    }
    // Signal hidden actions rather than dropping them silently (they stay keyboard-reachable).
    if drawn < actions.len() && x < area.x + area.width {
        frame.render_widget(
            Paragraph::new(Span::styled("…", Style::new().fg(DIM))),
            Rect {
                x,
                y: area.y,
                width: 1,
                height: 1,
            },
        );
    }
}

/// A minimal "your terminal is too small" notice, shown below [`MIN_COLS`]×[`MIN_ROWS`].
fn render_too_small(frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::from(Span::styled(
            "Terminal too small",
            Style::new().fg(WARN).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(
            format!("Resize to at least {MIN_COLS}×{MIN_ROWS}."),
            Style::new().fg(DIM),
        )),
    ];
    let rect = centered(area, 32, 5);
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        rect,
    );
}

// ── header / footer ──────────────────────────────────────────────────────────

/// The right-aligned top-level tabs and their selected state. Shared by the width reservation (so
/// the header readout can be sized to never collide) and the actual render.
fn header_tabs(model: &Model) -> Vec<(&'static str, bool, ButtonAction)> {
    let in_access = model.view == View::Access;
    let mut tabs: Vec<(&'static str, bool, ButtonAction)> = vec![
        (
            " [1] Secrets ",
            model.view == View::Secrets,
            ButtonAction::SwitchView(View::Secrets),
        ),
        (
            " [2] Users ",
            in_access && model.access_tab == AccessTab::Users,
            ButtonAction::AccessTab(AccessTab::Users),
        ),
        (
            " [3] Groups ",
            in_access && model.access_tab == AccessTab::Groups,
            ButtonAction::AccessTab(AccessTab::Groups),
        ),
    ];
    if !model.merge.is_empty() {
        tabs.push((
            " [4] Conflicts ",
            model.view == View::Merge,
            ButtonAction::SwitchView(View::Merge),
        ));
    }
    tabs
}

/// Total columns the tab strip occupies (labels plus one-column gaps between them).
fn header_tabs_width(model: &Model) -> u16 {
    header_tabs(model)
        .iter()
        .map(|(l, _, _)| l.chars().count() as u16 + 1)
        .sum::<u16>()
        .saturating_sub(1)
}

fn render_header(model: &mut Model, frame: &mut Frame, area: Rect) {
    // The vault's trust-anchor fingerprint and the acting user's fingerprint — each shown in
    // parens after the name it identifies.
    let root_hex = model
        .effective()
        .and_then(|s| s.root_signing_public_key_hash.as_ref())
        .map(thorax_frontend::short_hash);
    let user_hex = model.acting.as_ref().map(thorax_frontend::short_user_hex);
    // Cloned out so the fit closure below owns it and doesn't borrow `model` (the tab loop needs
    // `model` mutably to record hit-rects).
    let acting_label = model.acting_label.clone();

    let dim = Style::new().fg(DIM);
    let sep = || Span::styled("  ╱  ", Style::new().fg(theme::STRUCT_DIM));

    // A clinical readout: THORAX ╱ <db> (root) ╱ @user (uid). The brand word broadcasts trust at a
    // glance via its colour — a steady amber status light when unlocked and clean, grey when locked,
    // warn/breach otherwise. The separators carry the geometric motif; fingerprints faint.
    let blocked = model.block.is_some();
    let clean = model.verified();
    let pip_color = if blocked {
        BAD
    } else if !clean {
        WARN
    } else if model.unlock_session.is_locked() {
        theme::STRUCT
    } else {
        OK
    };

    // Build the readout at a chosen detail level so it can shed weight to fit: full (with both
    // fingerprints) → no fingerprints → a truncated vault name. The fingerprints are faint and
    // recoverable elsewhere, so they go first; the identity labels are the last thing to give.
    let build = |hexes: bool, name: &str| -> Line<'static> {
        let mut spans = vec![
            Span::styled(
                "THORAX",
                Style::new().fg(pip_color).add_modifier(Modifier::BOLD),
            ),
            sep(),
            Span::styled(name.to_string(), Style::new().fg(theme::TEXT)),
        ];
        if hexes {
            if let Some(hex) = &root_hex {
                spans.push(Span::styled(format!(" {hex}"), dim));
            }
        }
        spans.push(sep());
        match (&acting_label, &user_hex) {
            (Some(label), hex) => {
                spans.push(Span::styled(
                    format!("@{label}"),
                    Style::new().fg(theme::TEXT),
                ));
                if hexes {
                    if let Some(hex) = hex {
                        spans.push(Span::styled(format!(" {hex}"), dim));
                    }
                }
            }
            (None, Some(hex)) => {
                spans.push(Span::styled(hex.clone(), Style::new().fg(theme::TEXT)))
            }
            (None, None) => spans.push(Span::styled("no identity", dim)),
        }
        Line::from(spans)
    };

    // Reserve the right edge for the tabs (plus a 2-col gap) and fit the readout into what's left,
    // so the two can never paint over each other.
    let tabs_w = header_tabs_width(model);
    let budget = area.width.saturating_sub(tabs_w + 2);
    let mut line = build(true, &model.vault_name);
    if line.width() as u16 > budget {
        line = build(false, &model.vault_name);
    }
    if line.width() as u16 > budget {
        let mut name = model.vault_name.clone();
        while line.width() as u16 > budget && name.chars().count() > 3 {
            name = truncate(&name, name.chars().count() - 1);
            line = build(false, &name);
        }
    }
    let left = Rect {
        x: area.x,
        y: area.y,
        width: budget,
        height: 1,
    };
    frame.render_widget(Paragraph::new(line), left);

    // Clickable top-level tabs, right-aligned: Secrets ╱ Users ╱ Groups (╱ Conflicts). Users/Groups
    // select the Access view's respective list directly (no nested sub-tabs). Each records a
    // hit-rect. The Conflicts tab is conditional and alert-colored: it exists only while the loaded
    // vault carries unresolved conflicts, and it renders in breach red so a conflicted
    // merge cannot be missed.
    let tabs = header_tabs(model);
    let total = header_tabs_width(model);
    let mut x = area.x + area.width.saturating_sub(total);
    for (label, active, action) in tabs {
        let w = label.chars().count() as u16;
        let rect = Rect {
            x,
            y: area.y,
            width: w,
            height: 1,
        };
        let is_merge = action == ButtonAction::SwitchView(View::Merge);
        // Selected tab: white text on the amber pill (lighter than the dark-on-amber reverse).
        // The Conflicts tab swaps amber for breach red — the alert axis, not the accent.
        let style = match (active, is_merge) {
            (true, true) => Style::new()
                .bg(BAD)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            (true, false) => Style::new()
                .bg(ACCENT)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            (false, true) => Style::new().fg(BAD).add_modifier(Modifier::BOLD),
            (false, false) => Style::new().fg(DIM),
        };
        frame.render_widget(Paragraph::new(Span::styled(label, style)), rect);
        model.buttons.push(Button { rect, action });
        x += w + 1;
    }
}

fn render_footer(model: &Model, frame: &mut Frame, area: Rect) {
    // Pinned bottom-right: two independent indicators — integrity (the validation verdict) and the
    // session lock state. Kept visually separate (each with its own glyph) since they answer
    // different questions: do we trust the data, vs. can you act on it right now.
    let (verdict, vcolor) = if model.block.is_some() {
        ("BLOCKED", BAD)
    } else if model.verified() {
        ("VERIFIED", OK)
    } else {
        ("ISSUES", WARN)
    };
    let (lock_text, lock_color) = if model.unlock_session.is_locked() {
        ("LOCKED", DIM)
    } else {
        ("UNLOCKED", OK)
    };
    // Plain uppercase indicators, no glyphs — the colour carries the state, a faint slash divides them.
    let bold = |text: &str, color: Color| {
        Span::styled(
            text.to_string(),
            Style::new().fg(color).add_modifier(Modifier::BOLD),
        )
    };
    let right = Line::from(vec![
        bold(verdict, vcolor),
        Span::styled(" ╱ ", Style::new().fg(theme::STRUCT_DIM)),
        bold(lock_text, lock_color),
    ]);
    let rw = right.width() as u16;
    let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(rw)]).split(area);
    frame.render_widget(Paragraph::new(right).alignment(Alignment::Right), cols[1]);
    let area = cols[0];

    if !model.status.text.is_empty() {
        let color = if model.status.is_error { BAD } else { OK };
        let prefix = if model.status.is_error {
            "✗ "
        } else {
            "› "
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![Span::styled(
                format!("{prefix}{}", model.status.text),
                Style::new().fg(color),
            )])),
            area,
        );
        return;
    }
    // Left: key hints for the current screen, ordered most- to least-essential. `fit_hints` keeps
    // the trailing `? help` and fills the rest from the front for the available width, so a narrow
    // terminal drops low-priority hints whole instead of clipping the line mid-word.
    let hints: Vec<&str> = if model.block.is_some() {
        vec!["q quit"]
    } else {
        match model.view {
            View::Secrets if model.searching => vec![
                "type to filter",
                "↑↓ pick",
                "Enter to act",
                "Esc clear",
                "? help",
                "q quit",
            ],
            View::Secrets => vec![
                "↑↓ move",
                "→ open/reveal",
                "[/] search",
                "n new",
                "e edit",
                "d delete",
                "f filter",
                "H health",
                "? help",
                "q quit",
            ],
            View::Access => vec![
                "↑↓ move",
                "→ expand",
                "n new",
                "i invite",
                "V delete user",
                "d delete",
                "H health",
                "? help",
                "q quit",
            ],
            // A rollback's header row offers the in-place outs (accept; a fresh set on
            // secret keys); every other selection keeps the ratify keys.
            View::Merge => match model.selected_conflict_view() {
                Some(view) if view.acceptable => {
                    let mut v = vec!["↑↓ move"];
                    if view.settable {
                        v.push("s set a fresh value");
                    }
                    v.push("a accept the rollback");
                    v.push("? help");
                    v.push("q quit");
                    v
                }
                _ => vec![
                    "↑↓ move",
                    "r reveal",
                    "Enter resolve candidate",
                    "then: git add the vault",
                    "? help",
                    "q quit",
                ],
            },
        }
    };
    frame.render_widget(Paragraph::new(fit_hints(&hints, area.width)), area);
}

/// Join `segments` with ` ╱ ` for the given width, always keeping the last segment (`? help`) and
/// greedily filling from the front. Hints that don't fit are dropped whole, never clipped mid-word.
fn fit_hints(segments: &[&str], width: u16) -> Line<'static> {
    let Some((help, body)) = segments.split_last() else {
        return Line::default();
    };
    const SEP: usize = 3; // " ╱ "
    let mut used = help.chars().count();
    let mut kept: Vec<&str> = Vec::new();
    for seg in body {
        let add = seg.chars().count() + SEP;
        if used + add <= width as usize {
            used += add;
            kept.push(seg);
        } else {
            break;
        }
    }
    kept.push(help);
    Line::from(slashed(&kept.join(" ╱ "), Style::new().fg(DIM)))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(max - 1).collect::<String>())
    }
}

fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        title.to_string(),
        Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
    ))
}

/// The standard inner inset for every bordered block: one blank cell off the left and right border,
/// none top/bottom (the border row already supplies vertical breathing space). The horizontal inset
/// is **never zero** — content must not hug the border.
pub(super) const GUTTER: Padding = Padding {
    left: 1,
    right: 1,
    top: 0,
    bottom: 0,
};

/// A bordered content panel in the resting structural grey, carrying the standard [`GUTTER`]. Pass
/// an empty `title` for an untitled box. Blocks that need a non-structural border colour or a
/// styled/dynamic title build their own `Block`, but still apply [`GUTTER`] for the same inset.
pub(super) fn panel(title: &str) -> Block<'static> {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme::STRUCT))
        .padding(GUTTER);
    if title.is_empty() {
        block
    } else {
        block.title(format!(" {title} "))
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn key_span(label: &str) -> Span<'static> {
    Span::styled(format!("{label:<10}"), Style::new().fg(DIM))
}

fn kv(label: &str, value: &str) -> Line<'static> {
    let mut spans = vec![key_span(label)];
    spans.extend(slashed(value, Style::default()));
    Line::from(spans)
}

/// Split `text` on the ` ╱ ` separator into spans where the text runs use `base` and the separators
/// are muted (`STRUCT_DIM`), so inline slashes recede the way the header's separators do. A `text`
/// with no separator yields a single span, so this is a safe wrapper for any styled string.
fn slashed(text: &str, base: Style) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    for (i, part) in text.split(" ╱ ").enumerate() {
        if i > 0 {
            spans.push(Span::styled(" ╱ ", Style::new().fg(theme::STRUCT_DIM)));
        }
        spans.push(Span::styled(part.to_string(), base));
    }
    spans
}

fn hex(bytes: &[u8]) -> String {
    thorax_frontend::hex_bytes(bytes)
}

/// Title for a revealed value pane. The `(hex)` suffix flags the hex transform so a binary
/// value's hex is never read as the literal secret. Shared by every reveal renderer.
fn value_title(is_utf8: bool) -> &'static str {
    if is_utf8 {
        "value"
    } else {
        "value (hex)"
    }
}

/// Border style for a list pane: accent when it holds keyboard focus, dim otherwise.
/// A centered rect `width` columns wide and `height` rows tall (clamped to `area`).
fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(2)).max(10);
    let h = height.min(area.height.saturating_sub(2)).max(3);
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod layout_tests {
    use super::fit_hints;

    /// The flattened text of a hint line (separators included), for substring assertions.
    fn text(line: &ratatui::text::Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn fit_hints_keeps_everything_when_wide() {
        let segs = ["↑↓ move", "→ open/reveal", "n new", "? help"];
        let got = text(&fit_hints(&segs, 100));
        for s in segs {
            assert!(got.contains(s), "wide line should keep {s:?}: {got:?}");
        }
    }

    #[test]
    fn fit_hints_drops_low_priority_but_always_keeps_help() {
        // Width fits "↑↓ move ╱ ? help" but not the middle hints — they drop whole, help survives.
        let segs = ["↑↓ move", "→ open/reveal", "n new", "e edit", "? help"];
        let got = text(&fit_hints(&segs, 16));
        assert!(got.contains("? help"), "help must always remain: {got:?}");
        assert!(
            !got.contains("e edit"),
            "low-priority hint should drop: {got:?}"
        );
        // Never clipped mid-word: every rendered segment is whole.
        for kept in got.split(" ╱ ") {
            assert!(
                segs.contains(&kept),
                "rendered segment {kept:?} must be a whole hint"
            );
        }
    }

    #[test]
    fn fit_hints_keeps_help_even_when_nothing_else_fits() {
        let segs = ["↑↓ move", "→ open/reveal", "? help"];
        assert_eq!(text(&fit_hints(&segs, 4)), "? help");
    }
}
