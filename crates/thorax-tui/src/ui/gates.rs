use ratatui::{
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::app::Model;
use crate::project::BlockReason;
use crate::theme;

use super::{centered, slashed, truncate, ACCENT, BAD, DIM, GUTTER, WARN};

// ── locked / message screens ───────────────────────────────────────────────

pub(super) fn render_locked(model: &Model, frame: &mut Frame, area: Rect) {
    let reason = model
        .block
        .as_ref()
        .expect("locked view requires a block reason");
    let (title, detail) = describe_block(reason);
    let dim = Style::new().fg(DIM);

    // The header already brands the screen; this red panel carries the diagnostic.
    let mut lines = vec![
        Line::raw(""),
        Line::from(Span::styled(
            format!("✗  {title}"),
            Style::new().fg(BAD).add_modifier(Modifier::BOLD),
        )),
        Line::raw(""),
        Line::from(Span::styled(detail, Style::new().fg(theme::TEXT))),
        Line::raw(""),
    ];
    lines.push(Line::from(Span::styled(
        "Refusing to operate — restore the vault from a good source.",
        dim,
    )));
    lines.push(Line::raw(""));
    lines.push(Line::from(vec![
        Span::styled("[q]", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("  quit", dim),
    ]));

    let panel = centered(area, 70, lines.len() as u16 + 2);
    frame.render_widget(Clear, panel);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(BAD))
                    .title(Span::styled(" blocked ", Style::new().fg(BAD)))
                    .padding(GUTTER),
            )
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: false }),
        panel,
    );
}

fn describe_block(reason: &BlockReason) -> (String, String) {
    match reason {
        BlockReason::BadSignature(_) => (
            "Invalid signature".to_string(),
            "A record's signature did not verify — the vault may be tampered.".to_string(),
        ),
        BlockReason::RootNotTrusted => (
            "Root not trusted".to_string(),
            "This vault's root does not match your local trust anchor.".to_string(),
        ),
        BlockReason::AmbiguousRoot => (
            "Ambiguous root".to_string(),
            "More than one root candidate was found; cannot pick a trust anchor.".to_string(),
        ),
        BlockReason::AuthorityDidNotConverge => (
            "Authority did not converge".to_string(),
            "The grant/membership graph could not be resolved safely.".to_string(),
        ),
        BlockReason::UnknownSignerKey => (
            "Unknown signer key".to_string(),
            "A record is signed with a key no introduced identity holds — the vault may be tampered.".to_string(),
        ),
        BlockReason::FormatVersionRegression { remembered, current } => (
            "Vault format downgraded".to_string(),
            format!(
                "The vault uses format version {current}, but this machine already verified \
                 version {remembered} for this root — a newer vault re-wrapped in an older \
                 envelope is a downgrade, not an honest state."
            ),
        ),
        BlockReason::Structure(msg) => ("Malformed vault".to_string(), msg.clone()),
    }
}

pub(super) fn render_message_screen(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    body: &[String],
    color: Color,
) {
    let mut lines = vec![Line::from(Span::styled(
        title.to_string(),
        Style::new().fg(color).add_modifier(Modifier::BOLD),
    ))];
    lines.push(Line::raw(""));
    for line in body {
        lines.push(Line::from(slashed(line, Style::default())));
    }
    // Use the full terminal height so long body lines that wrap within the panel
    // width don't get clipped. centered() clamps to area.height - 2 internally.
    let inner = centered(area, 70, area.height);
    frame.render_widget(Clear, inner);
    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(theme::STRUCT))
                    .padding(GUTTER),
            )
            .wrap(Wrap { trim: false }),
        inner,
    );
}

/// The passphrase entry row shared by the unlock and init gates. While the entry is no longer than
/// the label it keeps a two-column gutter look (label right-aligned to the centre, dots left-aligned
/// just past it); once it grows longer than "PASSPHRASE" it becomes one centred unit that expands
/// symmetrically instead of overflowing, with the dots capped to the row so they never spill.
fn render_passphrase_row(frame: &mut Frame, area: Rect, count: usize, accent: Color) {
    const LABEL: &str = "PASSPHRASE";
    let label_style = Style::new().fg(theme::STRUCT);
    let dot_style = Style::new().fg(accent);
    let cursor = Span::styled("▏", Style::new().fg(accent).add_modifier(Modifier::BOLD));
    if count <= LABEL.chars().count() {
        let cols = Layout::horizontal([
            Constraint::Min(0),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);
        frame.render_widget(
            Paragraph::new(Span::styled(LABEL, label_style)).alignment(Alignment::Right),
            cols[0],
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("•".repeat(count), dot_style),
                cursor,
            ]))
            .alignment(Alignment::Left),
            cols[2],
        );
    } else {
        let avail = (area.width as usize).saturating_sub(LABEL.len() + 5);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(LABEL, label_style),
                Span::raw("  "),
                Span::styled("•".repeat(count.min(avail)), dot_style),
                cursor,
            ]))
            .alignment(Alignment::Center),
            area,
        );
    }
}

/// Full-screen unlock gate for a usable workspace whose session is locked. Accepts only the
/// passphrase (or Ctrl-C). While the synchronous KDF runs, the loop paints once with
/// [`Model::deriving`] set.
pub(super) fn render_unlock_gate(model: &Model, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let deriving = model.deriving;
    let identity = model
        .acting_label
        .clone()
        .map(|l| format!("@{l}"))
        .unwrap_or_else(|| "identity".to_string());
    let root_hex = model
        .effective()
        .and_then(|s| s.root_signing_public_key_hash.as_ref())
        .map(thorax_frontend::short_hash)
        .unwrap_or_else(|| "—".to_string());
    let user_hex = model.acting.as_ref().map(thorax_frontend::short_user_hex);

    const PANEL_W: usize = 54;
    let dim = Style::new().fg(DIM);
    let has_err = !deriving && model.unlock_error.is_some();

    // Rows inside the panel (blank rows are simply left unrendered):
    //   0 brand ╱ 1 repo ╱ 2 _ ╱ 3 main ╱ 4 _ ╱ 5 (err|hint) ╱ 6 _ ╱ 7 hint
    let n_rows: u16 = if deriving || !has_err { 6 } else { 8 };
    let panel = centered(area, PANEL_W as u16, n_rows + 2);
    let border = if deriving { ACCENT } else { theme::STRUCT };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(border))
        .title(Span::styled(" unlock ", Style::new().fg(theme::STRUCT)));
    let inner = block.inner(panel);
    frame.render_widget(block, panel);
    let row = |i: u16| Rect {
        x: inner.x,
        y: inner.y + i,
        width: inner.width,
        height: 1,
    };
    let center = |frame: &mut Frame, i: u16, line: Line| {
        frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), row(i));
    };

    // Row 0 — the brand, stacked over the repo line. THORAX carries the verdict via colour
    // (amber verified, warn on issues); SECRET VAULT stays grey.
    let verdict = if model.verified() { ACCENT } else { WARN };
    center(
        frame,
        0,
        Line::from(vec![
            Span::styled(
                "THORAX",
                Style::new().fg(verdict).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" SECRET VAULT", Style::new().fg(theme::STRUCT)),
        ]),
    );

    // Row 1 — the repo + user readout, exactly like the header.
    let mut repo = vec![
        Span::styled(model.vault_name.clone(), Style::new().fg(theme::TEXT)),
        Span::styled(format!(" {root_hex}"), dim),
        Span::styled("  ╱  ", Style::new().fg(theme::STRUCT_DIM)),
        Span::styled(identity, Style::new().fg(theme::TEXT)),
    ];
    if let Some(hex) = &user_hex {
        repo.push(Span::styled(format!(" {hex}"), dim));
    }
    center(frame, 1, Line::from(repo));

    if deriving {
        center(
            frame,
            3,
            Line::from(slashed(
                "DERIVING KEY ╱ ARGON2ID",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
        );
        center(
            frame,
            5,
            Line::from(Span::styled(
                "ASSUMING IDENTITY …",
                Style::new().fg(theme::STRUCT),
            )),
        );
        return;
    }

    // Row 3 — passphrase entry (shared with the init gate).
    render_passphrase_row(frame, row(3), model.unlock_input.chars().count(), ACCENT);

    let hint_row = if let Some(err) = &model.unlock_error {
        center(
            frame,
            5,
            Line::from(Span::styled(format!("✗ {err}"), Style::new().fg(BAD))),
        );
        7
    } else {
        5
    };
    center(
        frame,
        hint_row,
        Line::from(vec![
            Span::styled(
                "ENTER",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  assume identity      ", dim),
            Span::styled("^C", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  abort", dim),
        ]),
    );
}

/// The init gate, shown when no vault exists here or in any parent. Mirrors the unlock gate: you
/// are about to *create* a new encrypted vault, so it asks for a passphrase inline (no two-step
/// dialog) and creates the vault on Enter. Ctrl-C backs out.
pub(super) fn render_init_gate(model: &Model, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let deriving = model.deriving;
    let path = model.paths.root.display().to_string();

    const PANEL_W: usize = 54;
    let dim = Style::new().fg(DIM);
    let has_err = !deriving && model.unlock_error.is_some();

    let n_rows: u16 = if deriving || !has_err { 6 } else { 8 };
    let panel = centered(area, PANEL_W as u16, n_rows + 2);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(" initialize ", Style::new().fg(ACCENT)));
    let inner = block.inner(panel);
    frame.render_widget(block, panel);
    let row = |i: u16| Rect {
        x: inner.x,
        y: inner.y + i,
        width: inner.width,
        height: 1,
    };
    let center = |frame: &mut Frame, i: u16, line: Line| {
        frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), row(i));
    };

    // Row 0 — brand: this vault does not exist yet, you are about to create it.
    center(
        frame,
        0,
        Line::from(vec![
            Span::styled(
                "THORAX",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" NEW VAULT", Style::new().fg(theme::STRUCT)),
        ]),
    );

    // Row 1 — where it will be created.
    center(
        frame,
        1,
        Line::from(vec![
            Span::styled("create at  ", Style::new().fg(theme::STRUCT)),
            Span::styled(
                truncate(&path, (inner.width as usize).saturating_sub(12)),
                Style::new().fg(theme::TEXT),
            ),
        ]),
    );

    if deriving {
        center(
            frame,
            3,
            Line::from(slashed(
                "CREATING VAULT ╱ ARGON2ID",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            )),
        );
        center(
            frame,
            5,
            Line::from(Span::styled(
                "FORGING ROOT IDENTITY …",
                Style::new().fg(theme::STRUCT),
            )),
        );
        return;
    }

    // Row 3 — passphrase entry (shared with the unlock gate).
    render_passphrase_row(frame, row(3), model.unlock_input.chars().count(), ACCENT);

    let hint_row = if let Some(err) = &model.unlock_error {
        center(
            frame,
            5,
            Line::from(Span::styled(format!("✗ {err}"), Style::new().fg(BAD))),
        );
        7
    } else {
        5
    };
    center(
        frame,
        hint_row,
        Line::from(vec![
            Span::styled(
                "ENTER",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  create vault      ", dim),
            Span::styled("^C", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  cancel", dim),
        ]),
    );
}

/// The startup join screen: a vault exists but this machine has no identity for it. Offers to
/// claim an invite (which establishes your identity), rather than borrowing a default.
pub(super) fn render_join(model: &Model, frame: &mut Frame, area: Rect) {
    frame.render_widget(Clear, area);
    let root_hex = model
        .effective()
        .and_then(|s| s.root_signing_public_key_hash.as_ref())
        .map(thorax_frontend::short_hash)
        .unwrap_or_else(|| "—".to_string());
    let dim = Style::new().fg(DIM);

    const PANEL_W: usize = 60;
    let n_rows: u16 = 6;
    let panel = centered(area, PANEL_W as u16, n_rows + 2);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(" join ", Style::new().fg(theme::STRUCT)));
    let inner = block.inner(panel);
    frame.render_widget(block, panel);
    let row = |i: u16| Rect {
        x: inner.x,
        y: inner.y + i,
        width: inner.width,
        height: 1,
    };
    let center = |frame: &mut Frame, i: u16, line: Line| {
        frame.render_widget(Paragraph::new(line).alignment(Alignment::Center), row(i));
    };

    // Brand stacked over the vault readout, as on the unlock gate.
    center(
        frame,
        0,
        Line::from(vec![
            Span::styled(
                "THORAX",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled(" JOIN VAULT", Style::new().fg(theme::STRUCT)),
        ]),
    );
    center(
        frame,
        1,
        Line::from(vec![
            Span::styled(model.vault_name.clone(), Style::new().fg(theme::TEXT)),
            Span::styled(format!(" {root_hex}"), dim),
        ]),
    );
    center(
        frame,
        3,
        Line::from(Span::styled(
            "no identity on this machine — claim an invite to join",
            Style::new().fg(theme::STRUCT),
        )),
    );
    center(
        frame,
        5,
        Line::from(vec![
            Span::styled(
                "ENTER",
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("  paste invite      ", dim),
            Span::styled("[q]", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled("  quit", dim),
        ]),
    );
}

pub(super) fn render_help(frame: &mut Frame, area: Rect) {
    let body: Vec<String> = vec![
        "Move      ↑ ↓  (or [j]/[k]) ╱ PgUp/PgDn ╱ Home/End jump".to_string(),
        "Open      → or Enter expands a folder ╱ ← collapses it".to_string(),
        "Views     [1] Secrets ╱ [2] Users ╱ [3] Groups ╱ [4] Conflicts (while conflicted)"
            .to_string(),
        "Secrets   [r] reveal ╱ [y] copy ╱ [n] new ╱ [e] edit ╱ [d] delete ╱ [f] filter ╱ [/] search"
            .to_string(),
        "Search    [/] fuzzy-filter keys ╱ ↑↓ pick a hit ╱ Enter act on it ╱ Esc clear".to_string(),
        "Access    [n] invite/new group ╱ [V] delete user ╱ [d] delete grant/group".to_string(),
        "Conflicts Enter resolve candidate ╱ [r] reveal ╱ [a] accept rollback ╱ [s] set a fresh value"
            .to_string(),
        "Editor    Ctrl-S save ╱ Esc discard (edits stay in memory, never on disk)".to_string(),
        "Status    [H] health/diagnostics ╱ [L] lock now ╱ [q] quit".to_string(),
        "Safety    masked by default; reveals auto-hide after 30s; relocks after 30m idle"
            .to_string(),
        "Close     Esc (or press [?] again)".to_string(),
    ];
    render_message_screen(frame, area, "Keys", &body, ACCENT);
}
