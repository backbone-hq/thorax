use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
    Frame,
};

use crate::app::{Modal, Model};
use crate::theme;

use super::gates::{render_help, render_message_screen};
use super::health::render_health;
use super::{centered, slashed, truncate, ACCENT, BAD, DIM, GUTTER, WARN};

// ── modals ───────────────────────────────────────────────────────────────────

pub(super) fn render_modal(model: &Model, modal: &Modal, frame: &mut Frame, area: Rect) {
    match modal {
        Modal::Help => render_help(frame, area),
        Modal::Health => render_health(model, frame, area),
        Modal::Editor {
            title, textarea, ..
        } => {
            let rect = centered(area, 80, 18);
            frame.render_widget(Clear, rect);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::new().fg(theme::STRUCT))
                .title(format!(" {title} "))
                .title_bottom(Line::from(slashed(
                    " Ctrl-S save ╱ Esc discard ╱ edits stay in memory ",
                    Style::default(),
                )))
                .padding(GUTTER);
            let inner = block.inner(rect);
            frame.render_widget(block, rect);
            frame.render_widget(&**textarea, inner);
        }
        Modal::Form(form) => render_form(form, frame, area),
        Modal::InviteBundle { encoded } => render_invite_bundle(encoded, frame, area),
        Modal::Confirm { title, lines, .. } => {
            let mut body = lines.clone();
            body.push(String::new());
            body.push("[y] confirm    [n] cancel".to_string());
            render_message_screen(frame, area, title, &body, WARN);
        }
        Modal::Grant(form) => render_grant_form(form, frame, area),
        Modal::Member(form) => render_member_form(form, frame, area),
        Modal::Facet { focus } => render_facet_form(model, *focus, frame, area),
    }
}

fn render_invite_bundle(encoded: &str, frame: &mut Frame, area: Rect) {
    const PANEL_W: u16 = 76;
    const WARNING: &str = "Share this ONLY over a secure out-of-band channel.";
    const SEED_NOTE: &str = "It is the new user's private key seed.";
    const BASELINE_NOTE: &str = "Compact invite: rollback protection begins after claim.";
    const CLAIM_NOTE: &str = "The recipient runs: thorax claim <invite>  (or pastes it in Claim).";
    let panel_w = PANEL_W.min(area.width.saturating_sub(2)).max(10);
    let content_w = panel_w.saturating_sub(4).max(1) as usize;
    let wrapped_rows =
        |text: &str| text.chars().count().max(1).saturating_add(content_w - 1) / content_w;
    let body_rows = wrapped_rows(WARNING)
        + wrapped_rows(SEED_NOTE)
        + wrapped_rows(BASELINE_NOTE)
        + 1
        + wrapped_rows(encoded)
        + 1
        + wrapped_rows(CLAIM_NOTE);
    let height = (body_rows as u16).saturating_add(2);
    let rect = centered(area, panel_w, height);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme::STRUCT))
        .title(" Invite bundle — secret material ")
        .title_bottom(Line::from(slashed(
            " [y] copy ╱ Esc close ",
            Style::default(),
        )))
        .padding(GUTTER);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let lines = vec![
        Line::from(slashed(WARNING, Style::default())),
        Line::from(slashed(SEED_NOTE, Style::default())),
        Line::from(slashed(BASELINE_NOTE, Style::default())),
        Line::raw(""),
        Line::raw(encoded.to_string()),
        Line::raw(""),
        Line::from(slashed(CLAIM_NOTE, Style::default())),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
}

/// The label filter picker: one row per label key, `←→` chooses a value (or "any"). Applies live.
fn render_facet_form(model: &Model, focus: usize, frame: &mut Frame, area: Rect) {
    let keys = &model.facets.keys;
    let rect = centered(area, 56, (keys.len() as u16).min(14) + 2);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme::STRUCT))
        .title(" filter ")
        .title_bottom(Line::from(slashed(
            " ↑↓ key ╱ ←→ value ╱ [c] clear ╱ Enter done ",
            Style::default(),
        )))
        .padding(GUTTER);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let label_w = keys
        .iter()
        .map(|k| k.chars().count())
        .max()
        .unwrap_or(6)
        .max(6)
        + 2;
    let lines: Vec<Line> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let focused = i == focus;
            let set = model.facet_filter.constraints.get(key);
            let value = set.cloned().unwrap_or_else(|| "any".to_string());
            let key_style = if focused {
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(DIM)
            };
            // The focused row gets the ‹ › chooser; a set value reads as live text, "any" stays dim.
            let value_span = if focused {
                Span::styled(
                    format!("‹ {value} ›"),
                    Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
                )
            } else if set.is_some() {
                Span::styled(value, Style::new().fg(theme::TEXT))
            } else {
                Span::styled(value, Style::new().fg(DIM))
            };
            Line::from(vec![
                Span::styled(format!("{key:<label_w$}"), key_style),
                value_span,
            ])
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The add-member-to-group picker: choose a principal to add to the selected group.
fn render_member_form(form: &crate::app::MemberForm, frame: &mut Frame, area: Rect) {
    let rect = centered(area, 60, 9);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme::STRUCT))
        .title(format!(" add member to {} ", form.group_label))
        .title_bottom(Line::from(slashed(
            " ←→ choose ╱ Enter add ╱ Esc cancel ",
            Style::default(),
        )))
        .padding(GUTTER);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let mut lines = Vec::new();
    if form.candidates.is_empty() {
        lines.push(Line::from(Span::styled(
            "No principals available to add.",
            Style::new().fg(DIM),
        )));
    } else {
        let label = form
            .candidates
            .get(form.idx)
            .map(|c| c.label.clone())
            .unwrap_or_else(|| "—".to_string());
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("‹ {label} ›"),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("{} of {}", form.idx + 1, form.candidates.len()),
            Style::new().fg(DIM),
        )));
    }
    if let Some(err) = &form.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("✗ {err}"),
            Style::new().fg(BAD),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The last `max` characters of `s`, prefixed with `…` when truncated — a tail window so an
/// append-only field keeps its end (where the cursor sits) in view rather than its start.
fn tail_window(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        format!("…{tail}")
    }
}

/// A guided multi-field form (new secret, move, claim, invite, group, init), structured like
/// the grant form: one labeled field per row, the focused one accented with a cursor.
fn render_form(form: &crate::app::Form, frame: &mut Frame, area: Rect) {
    let label_w = form
        .fields
        .iter()
        .map(|f| f.label.chars().count())
        .max()
        .unwrap_or(6)
        .max(6)
        + 2;

    let extra = form.error.is_some() as u16 + form.note.is_some() as u16;
    let height = form.fields.len() as u16 + extra + 4;
    let rect = centered(area, 70, height);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme::STRUCT))
        .title(format!(" {} ", form.title))
        .title_bottom(Line::from(slashed(
            &format!(
                " ↑↓ field ╱ type ╱ Enter {} ╱ Esc cancel ",
                form.submit_verb
            ),
            Style::default(),
        )))
        .padding(GUTTER);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    // The value column is whatever's left after the label; a value longer than that scrolls so the
    // cursor (always at the end — the field has no caret movement) stays visible, instead of running
    // off the box edge where you can't see what you're typing.
    let value_w = (inner.width as usize).saturating_sub(label_w);
    let mut lines: Vec<Line> = Vec::new();
    for (i, field) in form.fields.iter().enumerate() {
        let focused = form.focus == i;
        let key_style = if focused {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(DIM)
        };
        let shown = if field.masked {
            "•".repeat(field.value.chars().count())
        } else {
            field.value.clone()
        };
        // Placeholder (dim) when empty; otherwise the value, with a cursor on the focused field.
        let value_span = if field.value.is_empty() && !focused {
            Span::styled(truncate(&field.placeholder, value_w), Style::new().fg(DIM))
        } else if field.value.is_empty() && focused {
            Span::styled(
                format!(
                    "▏{}",
                    truncate(&field.placeholder, value_w.saturating_sub(1))
                ),
                Style::new().fg(DIM).add_modifier(Modifier::BOLD),
            )
        } else if focused {
            Span::styled(
                format!("{}▏", tail_window(&shown, value_w.saturating_sub(1))),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw(truncate(&shown, value_w))
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{:<width$}", field.label, width = label_w),
                key_style,
            ),
            value_span,
        ]));
    }
    if let Some(note) = &form.note {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("! {note}"),
            Style::new().fg(WARN),
        )));
    }
    if let Some(err) = &form.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("✗ {err}"),
            Style::new().fg(BAD),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The guided grant-creation form: pick a subject, an access level, and a keyspace.
fn render_grant_form(form: &crate::app::GrantForm, frame: &mut Frame, area: Rect) {
    use crate::app::GRANT_CLASSES;
    let rect = centered(area, 66, 12);
    frame.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(theme::STRUCT))
        .title(" grant access ")
        .title_bottom(Line::from(slashed(
            if form.is_admin() {
                " ↑↓ field ╱ ←→ choose ╱ Enter grant ╱ Esc cancel "
            } else {
                " ↑↓ field ╱ ←→ choose ╱ type keyspace ╱ Enter grant ╱ Esc cancel "
            },
            Style::default(),
        )))
        .padding(GUTTER);
    let inner = block.inner(rect);
    frame.render_widget(block, rect);

    let subject = form
        .subjects
        .get(form.subject_idx)
        .map(|s| s.label.clone())
        .unwrap_or_else(|| "—".to_string());
    let access = GRANT_CLASSES[form.class_idx];
    let keyspace = if form.is_admin() {
        "entire vault".to_string()
    } else if form.keyspace.is_empty() {
        "—".to_string()
    } else {
        form.keyspace.clone()
    };

    // One field per line; the focused field gets the ‹ › chooser markers and accent. The keyspace
    // is free text, so it scrolls (tail window) when longer than the column.
    let value_w = (inner.width as usize).saturating_sub(10);
    let field_line = |idx: usize, label: &str, value: &str, choose: bool| -> Line<'static> {
        let focused = form.field == idx;
        let value_span = if focused && choose {
            Span::styled(
                format!("‹ {value} ›"),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            )
        } else if focused {
            Span::styled(
                format!("{}▏", tail_window(value, value_w.saturating_sub(1))),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            )
        } else {
            Span::raw(truncate(value, value_w))
        };
        let key_style = if focused {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(DIM)
        };
        Line::from(vec![
            Span::styled(format!("{label:<10}"), key_style),
            value_span,
        ])
    };

    let mut lines = vec![
        field_line(0, "Subject", &subject, true),
        field_line(1, "Access", access, true),
        field_line(
            2,
            if form.is_admin() { "Scope" } else { "Keyspace" },
            &keyspace,
            false,
        ),
    ];
    if let Some(err) = &form.error {
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            format!("✗ {err}"),
            Style::new().fg(BAD),
        )));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::tail_window;

    #[test]
    fn tail_window_passes_short_values_through() {
        assert_eq!(tail_window("app/db", 10), "app/db");
        assert_eq!(tail_window("exact", 5), "exact");
    }

    #[test]
    fn tail_window_keeps_the_end_in_view() {
        // A value longer than the column shows its tail (where the cursor is) with a leading ellipsis.
        let got = tail_window("app/prod/region/database-url", 10);
        assert_eq!(got.chars().count(), 10);
        assert!(got.starts_with('…'));
        assert!(got.ends_with("base-url"));
    }

    #[test]
    fn tail_window_handles_zero_width() {
        assert_eq!(tail_window("anything", 0), "");
    }
}
