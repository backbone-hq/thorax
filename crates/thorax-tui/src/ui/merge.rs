use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::{ListKind, ListRegion, Model};
use crate::theme;

use super::secrets::access_table_lines;
use super::{hex, kv, panel, slashed, value_title, ACCENT, BAD, DIM, GUTTER, OK, WARN};

// ── merge view ───────────────────────────────────────────────────────────────

/// Merge-conflict resolution: a conflict→candidate tree on the left, with full details for
/// the selected candidate on the right.
pub(super) fn render_merge(model: &mut Model, frame: &mut Frame, area: Rect) {
    let cols = Layout::horizontal([Constraint::Percentage(40), Constraint::Min(0)]).split(area);
    let (list_area, detail_area) = (cols[0], cols[1]);

    // Left: the tree. Conflicts are always expanded — the candidates are the decision.
    let rows = model.merge_rows();
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::new().fg(BAD))
        .title(Span::styled(
            format!(
                " {} ",
                thorax_frontend::count_noun(model.merge.len(), "unresolved conflict")
            ),
            Style::new().fg(BAD).add_modifier(Modifier::BOLD),
        ))
        .padding(GUTTER);
    let inner = block.inner(list_area);
    let items: Vec<ListItem> = rows.iter().map(|row| merge_line(model, row)).collect();
    let list = List::new(items).block(block).highlight_style(
        Style::new()
            .bg(theme::STRUCT_DIM)
            .add_modifier(Modifier::BOLD),
    );
    let mut state = ListState::default()
        .with_selected(Some(model.merge_selected.min(rows.len().saturating_sub(1))));
    frame.render_stateful_widget(list, list_area, &mut state);
    model.list_region = Some(ListRegion {
        kind: ListKind::Merge,
        rect: inner,
        offset: state.offset(),
    });

    // Right: details for the selection.
    match model.selected_merge_row() {
        Some(crate::app::MergeRow::Candidate { .. }) => {
            render_merge_candidate_detail(model, frame, detail_area)
        }
        _ => render_merge_conflict_detail(model, frame, detail_area),
    }
}

fn merge_line(model: &Model, row: &crate::app::MergeRow) -> ListItem<'static> {
    use crate::app::MergeRow;
    match row {
        MergeRow::Conflict { conflict } => {
            let Some(view) = model.merge.get(*conflict) else {
                return ListItem::new(Line::raw(""));
            };
            ListItem::new(Line::from(vec![
                Span::styled("▾ ", Style::new().fg(BAD)),
                Span::styled(
                    view.label.clone(),
                    Style::new().fg(theme::TEXT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("  {}", view.kind), Style::new().fg(WARN)),
                Span::styled(" ╱ ", Style::new().fg(theme::STRUCT_DIM)),
                Span::styled(view.conflict_kind, Style::new().fg(BAD)),
            ]))
        }
        MergeRow::Candidate {
            conflict,
            candidate,
        } => {
            let Some(view) = model.merge.get(*conflict) else {
                return ListItem::new(Line::raw(""));
            };
            let Some(entry) = view.candidates.get(*candidate) else {
                return ListItem::new(Line::raw(""));
            };
            // The conflict header above already names the object; dropping it from each
            // candidate row keeps the lines short ("set (23 bytes)", not the full selector).
            let compact = entry.summary.replace(&format!(" {}", view.label), "");
            ListItem::new(Line::from(vec![
                Span::raw("    "),
                Span::styled("● ", Style::new().fg(BAD)),
                Span::raw(compact),
            ]))
        }
    }
}

/// Right pane when a conflict header (or nothing) is selected: what this conflict is, and
/// how to proceed. Same bordered-section idiom as the other detail panes.
fn render_merge_conflict_detail(model: &Model, frame: &mut Frame, area: Rect) {
    let Some(crate::app::MergeRow::Conflict { conflict }) = model.selected_merge_row() else {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Use ↑/↓ to pick a conflict or candidate.",
                    Style::new().fg(DIM),
                )),
            ])
            .block(panel("conflict")),
            area,
        );
        return;
    };
    let Some(view) = model.merge.get(conflict) else {
        return;
    };
    let mut meta = vec![
        kv("conflict", &format!("{} {}", view.kind, view.label)),
        kv("kind", view.conflict_kind),
        kv("counter", &view.counter.to_string()),
        kv("options", &view.candidates.len().to_string()),
    ];
    if let Some(reason) = &view.blocked {
        meta.push(Line::from(slashed(
            &format!("! {reason}"),
            Style::new().fg(WARN),
        )));
    }
    let rows = Layout::vertical([
        Constraint::Length(meta.len() as u16 + 2),
        Constraint::Min(0),
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(meta)
            .block(panel("conflict"))
            .wrap(Wrap { trim: false }),
        rows[0],
    );
    let mut body = vec![
        Line::from(""),
        Line::from(Span::styled(
            view.summary.clone(),
            Style::new().fg(theme::TEXT),
        )),
        Line::from(""),
    ];
    if !view.candidates.is_empty() {
        // Ratifying a survivor stays the primary out of a rollback; accepting is the
        // fail-open alternative (this machine adapts its memory instead).
        body.push(Line::from(slashed(
            if view.acceptable {
                "↓ onto a candidate for its full details, Enter there to ratify it ╱ [a] accepts the rollback instead."
            } else {
                "↓ onto a candidate for its full details, Enter there to resolve."
            },
            Style::new().fg(DIM),
        )));
    }
    body.push(Line::from(Span::styled(
        "Until resolved, this key has no effective value — reads of it fail.",
        Style::new().fg(DIM),
    )));
    frame.render_widget(
        Paragraph::new(body)
            .block(panel("resolution"))
            .wrap(Wrap { trim: false }),
        rows[1],
    );
}

/// Right pane for a selected candidate: metadata, access (for secret candidates — the same
/// principal table as the Secrets view), and the value section with the gated reveal.
fn render_merge_candidate_detail(model: &Model, frame: &mut Frame, area: Rect) {
    let Some((conflict, candidate)) = model.selected_merge_candidate() else {
        return;
    };

    let mut meta: Vec<Line> = candidate
        .details
        .iter()
        .map(|(label, value)| kv(label, value))
        .collect();
    if let Some(reason) = &conflict.blocked {
        meta.push(Line::from(Span::styled(
            format!("! not resolvable by you: {reason}"),
            Style::new().fg(WARN),
        )));
    }
    let meta_h = meta.len() as u16 + 2;

    // Secret candidates get the access table + value sections, like the Secrets detail.
    let Some(selector) = &candidate.selector else {
        let rows = Layout::vertical([Constraint::Length(meta_h), Constraint::Min(0)]).split(area);
        frame.render_widget(
            Paragraph::new(meta)
                .block(panel("candidate"))
                .wrap(Wrap { trim: false }),
            rows[0],
        );
        frame.render_widget(
            Paragraph::new(Line::from(slashed(
                if conflict.blocked.is_some() {
                    "an authorized user must resolve this conflict"
                } else {
                    "Enter makes this candidate the winner ╱ all other candidates lose"
                },
                Style::new().fg(DIM),
            )))
            .block(panel("resolution")),
            rows[1],
        );
        return;
    };

    let access = access_table_lines(model, selector, area.width.saturating_sub(4));
    let access_h = (access.len() as u16 + 2).min(12);
    // Revealing any candidate revealed the whole conflict; look this candidate's value up
    // in the shared batch (one countdown for all of them).
    let revealed = model
        .merge_reveal
        .as_ref()
        .and_then(|reveal| Some((reveal.expires_at, reveal.value_for(&candidate.pick)?)));
    let (value_h, value_body, value_title, value_border) =
        if let Some((expires_at, value)) = revealed {
            let remaining = expires_at.saturating_duration_since(model.now).as_secs();
            let shown = if value.is_utf8 {
                String::from_utf8_lossy(&value.plaintext).to_string()
            } else {
                hex(&value.plaintext)
            };
            let kind = value_title(value.is_utf8);
            (
                Constraint::Min(5),
                Line::from(Span::styled(shown, Style::new().fg(OK))),
                format!(" {kind} ╱ drag to select ╱ hides in {remaining}s "),
                WARN,
            )
        } else if candidate.decryptable {
            (
                Constraint::Length(5),
                Line::from(slashed(
                    "press [r] to reveal this conflict's values (all candidates, one countdown)",
                    Style::new().fg(DIM),
                )),
                " value ".to_string(),
                ACCENT,
            )
        } else {
            (
                Constraint::Length(5),
                Line::from(Span::styled(
                    "not decryptable by you (no recipient slot on this candidate)",
                    Style::new().fg(DIM),
                )),
                " value ".to_string(),
                DIM,
            )
        };

    let rows = Layout::vertical([
        Constraint::Length(meta_h),
        Constraint::Length(access_h),
        value_h,
    ])
    .split(area);
    frame.render_widget(
        Paragraph::new(meta)
            .block(panel("candidate"))
            .wrap(Wrap { trim: false }),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(access)
            .block(panel("access"))
            .wrap(Wrap { trim: false }),
        rows[1],
    );
    frame.render_widget(
        Paragraph::new(value_body)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(value_border))
                    .title(Line::from(slashed(&value_title, Style::default())))
                    .padding(GUTTER),
            )
            .wrap(Wrap { trim: false }),
        rows[2],
    );
}
