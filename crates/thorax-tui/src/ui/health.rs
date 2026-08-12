use ratatui::{
    layout::Rect,
    style::Style,
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
    Frame,
};

use crate::app::Model;
use crate::project;

use super::{centered, panel, section, slashed, BAD, DIM, OK, WARN};

// ── health view ──────────────────────────────────────────────────────────────

pub(super) fn render_health(model: &Model, frame: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(section("Verification"));
    if model.health.issues.is_empty() {
        lines.push(Line::from(Span::styled(
            "  ✓ clean — signatures and trust verified",
            Style::new().fg(OK),
        )));
    } else {
        for issue in &model.health.issues {
            lines.push(Line::from(Span::styled(
                format!("  ✗ {issue}"),
                Style::new().fg(BAD),
            )));
        }
    }
    // Warnings are advisory, never blocking — the clean line above stands; they render in the
    // attention amber, not the breach red (red is reserved for the danger axis).
    for warning in &model.health.warnings {
        lines.push(Line::from(Span::styled(
            format!("  ! {warning}"),
            Style::new().fg(WARN),
        )));
    }
    lines.push(Line::raw(""));
    lines.push(section("Inventory"));
    lines.push(Line::from(slashed(
        &format!(
            "  {} secrets ╱ {} users",
            model.health.secret_count, model.health.user_count
        ),
        Style::default(),
    )));
    lines.push(Line::raw(""));
    lines.push(section("Stale secrets (a current reader lacks a slot)"));
    if model.health.stale.is_empty() {
        lines.push(Line::from(Span::styled("  none", Style::new().fg(DIM))));
    } else {
        for selector in &model.health.stale {
            lines.push(Line::from(Span::styled(
                format!("  ! {}", project::selector_display(selector)),
                Style::new().fg(WARN),
            )));
        }
    }
    lines.push(Line::raw(""));
    lines.push(section("Trust"));
    let watermarks = match model.health.watermark_count {
        1 => "1 remembered watermark (rollback ratchet)".to_string(),
        n => format!("{n} remembered watermarks (rollback ratchet)"),
    };
    lines.push(Line::from(slashed(
        &format!("  root {} ╱ {}", model.health.trusted_root, watermarks),
        Style::default(),
    )));
    if model.health.format_version > 0 {
        lines.push(Line::raw(format!(
            "  remembered format version {}",
            model.health.format_version
        )));
    }
    lines.push(Line::raw(""));
    lines.push(section("Identity"));
    // The acting identity: handle when known, with the faint fingerprint the header also shows.
    let mut acting = vec![Span::raw("  acting as ")];
    match (&model.acting_label, &model.acting) {
        (Some(label), user) => {
            acting.push(Span::raw(format!("@{label}")));
            if let Some(user) = user {
                acting.push(Span::styled(
                    format!(" {}", thorax_frontend::short_user_hex(user)),
                    Style::new().fg(DIM),
                ));
            }
        }
        (None, Some(user)) => acting.push(Span::raw(thorax_frontend::short_user_hex(user))),
        (None, None) => acting.push(Span::styled("no local identity", Style::new().fg(DIM))),
    }
    lines.push(Line::from(acting));
    let session = if model.unlock_session.is_locked() {
        "  locked — actions will prompt for your passphrase".to_string()
    } else {
        "  unlocked for this session (press L to lock now)".to_string()
    };
    lines.push(Line::raw(session));

    let rect = centered(area, 72, lines.len() as u16 + 2);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel("health").title_bottom(" Esc to close "))
            .wrap(Wrap { trim: false }),
        rect,
    );
}
