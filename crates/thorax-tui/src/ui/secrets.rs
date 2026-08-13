use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::{ListKind, ListRegion, Model, Row};
use crate::project;
use crate::theme;
use thorax_ops::SecretSelectorV1;

use super::{hex, kv, panel, slashed, truncate, value_title, ACCENT, BAD, DIM, GUTTER, OK, WARN};

// ── secrets view ───────────────────────────────────────────────────────────

pub(super) fn render_secrets(model: &mut Model, frame: &mut Frame, area: Rect) {
    // Two optional one-line bars sit above the columns: the search bar (while the bar is open or a
    // query is applied) and the label-filter bar (while a label constraint is set). In the default
    // state neither shows — press `/` to search or `f` to filter by label.
    let show_search = model.searching || !model.search.is_empty();
    let show_facets = !model.facet_filter.constraints.is_empty();
    let main = if !show_search && !show_facets {
        area
    } else {
        let mut rows = Vec::new();
        if show_search {
            rows.push(Constraint::Length(1));
        }
        if show_facets {
            rows.push(Constraint::Length(1));
        }
        rows.push(Constraint::Min(0));
        let body = Layout::vertical(rows).split(area);
        let mut next = 0;
        if show_search {
            render_search(model, frame, body[next]);
            next += 1;
        }
        if show_facets {
            render_facets(model, frame, body[next]);
            next += 1;
        }
        body[next]
    };
    let cols =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(main);
    render_tree(model, frame, cols[0]);
    render_detail(model, frame, cols[1]);
}

/// The live fuzzy-search bar. While focused, every letter types into the query (so command keys
/// like `r`/`e`/`d` can't fire here — they're valid search text); ↑↓ pick a hit and Enter hands off
/// to the list (query still applied) where those shortcuts work. Once applied (bar closed, query
/// kept) it dims and offers `[/]` to edit or Esc to clear. Slash hints are bracketed so the `/` key
/// never abuts the `╱` separator (which would read as a double slash).
fn render_search(model: &Model, frame: &mut Frame, area: Rect) {
    let active = model.searching;
    let label_style = Style::new().fg(if active { ACCENT } else { DIM });
    let mut spans = vec![
        Span::styled("search ", label_style),
        Span::styled(
            model.search.clone(),
            Style::new().fg(theme::TEXT).add_modifier(Modifier::BOLD),
        ),
    ];
    if active {
        spans.push(Span::styled("▏", Style::new().fg(ACCENT)));
        spans.push(Span::styled(
            "    ↑↓ pick ╱ Enter to act ╱ Esc clear",
            Style::new().fg(DIM),
        ));
    } else {
        spans.push(Span::styled(
            "    [/] edit ╱ Esc clear",
            Style::new().fg(DIM),
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// The active-filter bar, shown only when at least one label constraint is set.
fn render_facets(model: &Model, frame: &mut Frame, area: Rect) {
    let mut spans = vec![Span::styled("filtered to ", Style::new().fg(DIM))];
    let mut first = true;
    for (key, value) in &model.facet_filter.constraints {
        if !first {
            spans.push(Span::styled(", ", Style::new().fg(DIM)));
        }
        first = false;
        spans.push(Span::styled(
            format!("{key}={value}"),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        "   ╱ [f] change or clear",
        Style::new().fg(DIM),
    ));
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn render_tree(model: &mut Model, frame: &mut Frame, area: Rect) {
    let rows = model.visible_rows();
    let block = panel("secrets");
    let inner = block.inner(area);
    let items: Vec<ListItem> = rows
        .iter()
        .map(|row| ListItem::new(tree_line(row, inner.width)))
        .collect();
    if items.is_empty() {
        let lines = if !model.search.is_empty() {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("No keys match “{}”.", model.search),
                    Style::new().fg(DIM),
                )),
                Line::from(Span::styled(
                    "Edit the query, or press  Esc  to clear it.",
                    Style::new().fg(DIM),
                )),
            ]
        } else if model.facet_filter.constraints.is_empty() {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "No secrets yet.",
                    Style::new().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Press [n] to create your first secret.",
                    Style::new().fg(ACCENT),
                )),
                Line::from(Span::styled(
                    "Press [?] for all keys.",
                    Style::new().fg(DIM),
                )),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "No secrets match this filter.",
                    Style::new().fg(DIM),
                )),
                Line::from(Span::styled(
                    "Press [f] to change it.",
                    Style::new().fg(DIM),
                )),
            ]
        };
        frame.render_widget(Paragraph::new(lines).block(block), area);
        return;
    }
    let list = List::new(items)
        .block(block)
        // Selected row: a subtle dark-slate bar + bold, not a bright reverse. Only `bg`/bold are
        // set so each row keeps its own glyph colours (amber active, red invalid, …).
        .highlight_style(
            Style::new()
                .bg(theme::STRUCT_DIM)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default()
        .with_selected(Some(model.selected_row.min(rows.len().saturating_sub(1))));
    frame.render_stateful_widget(list, area, &mut state);
    model.list_region = Some(ListRegion {
        kind: ListKind::Secrets,
        rect: inner,
        offset: state.offset(),
    });
}

fn tree_line(row: &Row, width: u16) -> Line<'static> {
    match row {
        Row::Branch {
            label,
            depth,
            expanded,
            has_children,
            ..
        } => {
            let indent = "  ".repeat(*depth);
            let marker = if !has_children {
                "  "
            } else if *expanded {
                "▾ "
            } else {
                "▸ "
            };
            // indent + 2-col marker consumed before the label.
            let avail = (width as usize).saturating_sub(indent.chars().count() + 2);
            Line::from(vec![
                Span::raw(format!("{indent}{marker}")),
                Span::styled(
                    truncate(label, avail.max(1)),
                    Style::new().add_modifier(Modifier::BOLD),
                ),
            ])
        }
        Row::Leaf { depth, name, leaf } => {
            let indent = "  ".repeat(*depth);
            let (glyph, color) = state_glyph(leaf);
            // indent + glyph + trailing space consumed before the name.
            let avail = (width as usize).saturating_sub(indent.chars().count() + 2);
            Line::from(vec![
                Span::raw(indent),
                Span::styled(format!("{glyph} "), Style::new().fg(color)),
                Span::raw(truncate(name, avail.max(1))),
            ])
        }
    }
}

fn state_glyph(leaf: &crate::project::SecretLeaf) -> (&'static str, Color) {
    use thorax_ops::SecretState::*;
    match leaf.state {
        ActiveDecryptable => ("●", OK),
        NotEncryptedForReader => ("!", WARN),
        // Routine for a low-privilege viewer — not the danger axis, so dim, not red.
        Unauthorized => ("✗", DIM),
        Missing => ("○", DIM),
        // The alert axis, like the Conflicts tab: this key has no effective value.
        Conflicted => ("≠", BAD),
        // Tamper/validation failure — the danger axis proper stays red.
        Invalid => ("✗", BAD),
    }
}

fn render_detail(model: &Model, frame: &mut Frame, area: Rect) {
    let Some(leaf) = model.selected_leaf() else {
        // A namespace (folder) is selected: metadata + access sections; else a hint.
        if let Some(prefix) = model.selected_branch_path() {
            render_namespace_detail(model, frame, area, &prefix);
        } else {
            let hint = Paragraph::new(vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Use ↑/↓ to pick a secret, → to open a folder.",
                    Style::new().fg(DIM),
                )),
                Line::from(slashed(
                    "Then [r] reveal ╱ [y] copy ╱ [e] edit.",
                    Style::new().fg(DIM),
                )),
            ]);
            frame.render_widget(hint.block(panel("metadata")), area);
        }
        return;
    };

    let labels = project::selector_labels(&leaf.selector);
    let revealed = model
        .reveal
        .as_ref()
        .filter(|r| r.selector == leaf.selector);

    let meta = vec![
        kv("selector", &project::selector_path(&leaf.selector)),
        kv("labels", if labels.is_empty() { "—" } else { &labels }),
        kv("state", &state_text(&leaf)),
    ];

    // Three sections, always: metadata, value, access — each in its own bordered block. The value
    // section is the dedicated home for the secret's contents: masked placeholder + reveal hint
    // when hidden, plaintext + auto-hide countdown when revealed.
    let access = access_table_lines(model, &leaf.selector, area.width.saturating_sub(4));
    let access_h = (access.len() as u16 + 2).min(12);
    let decryptable = leaf.state == thorax_ops::SecretState::ActiveDecryptable;

    let (value_h, value_body, value_title, value_border) = if let Some(reveal) = revealed {
        let remaining = reveal
            .expires_at
            .saturating_duration_since(model.now)
            .as_secs();
        let shown = if reveal.is_utf8 {
            String::from_utf8_lossy(&reveal.plaintext).to_string()
        } else {
            hex(&reveal.plaintext)
        };
        let kind = value_title(reveal.is_utf8);
        (
            Constraint::Percentage(40),
            Line::from(Span::styled(shown, Style::new().fg(OK))),
            format!(" {kind} ╱ drag to select ╱ hides in {remaining}s "),
            WARN,
        )
    } else if decryptable {
        (
            Constraint::Length(5),
            Line::from(slashed(
                "press [r] to reveal ╱ [y] to copy",
                Style::new().fg(DIM),
            )),
            " value ".to_string(),
            ACCENT,
        )
    } else if leaf.state == thorax_ops::SecretState::Conflicted {
        (
            Constraint::Length(5),
            Line::from(slashed(
                "conflicted — no effective value ╱ resolve in the Conflicts tab",
                Style::new().fg(DIM),
            )),
            " value ".to_string(),
            BAD,
        )
    } else {
        (
            Constraint::Length(5),
            Line::from(Span::styled("not decryptable by you", Style::new().fg(DIM))),
            " value ".to_string(),
            DIM,
        )
    };

    // The selected secret's additional fields, eagerly decrypted, shown in plaintext (no reveal
    // gate) below the value. Short single-line values share a compact "fields" box (one
    // `key: value` line each); long or multi-line values each get their own titled box so they
    // are readable rather than truncated. Only present when the secret has fields and we hold
    // their decrypted form for *this* selector.
    let inner_w = area.width.saturating_sub(4).max(1) as usize;
    let mut inline_lines: Vec<Line> = Vec::new();
    let mut block_fields: Vec<(String, Vec<Line>, u16)> = Vec::new();
    if let Some(loaded) = model
        .secret_fields
        .as_ref()
        .filter(|loaded| loaded.selector == leaf.selector)
    {
        for field in &loaded.fields {
            let shown = if field.is_utf8 {
                String::from_utf8_lossy(&field.value).to_string()
            } else {
                hex(&field.value)
            };
            let multiline = shown.contains('\n');
            let overflows = field.key.chars().count() + 2 + shown.chars().count() > inner_w;
            if multiline || overflows {
                let body: Vec<Line> = shown
                    .split('\n')
                    .map(|line| Line::from(Span::styled(line.to_string(), Style::new().fg(OK))))
                    .collect();
                // Height: each logical line wraps to inner width; clamp so one giant field can't
                // crowd out the rest.
                let wrapped: usize = shown
                    .split('\n')
                    .map(|line| line.chars().count() / inner_w + 1)
                    .sum();
                let height = (wrapped as u16 + 2).clamp(3, 14);
                block_fields.push((field.key.clone(), body, height));
            } else {
                inline_lines.push(Line::from(vec![
                    Span::styled(format!("{}: ", field.key), Style::new().fg(DIM)),
                    Span::styled(shown, Style::new().fg(OK)),
                ]));
            }
        }
    }
    let show_inline = !inline_lines.is_empty();

    // Order: metadata, access (who can see it), the value, the compact fields box, then one box
    // per long/multi-line field.
    let mut constraints = vec![Constraint::Length(5), Constraint::Length(access_h), value_h];
    if show_inline {
        constraints.push(Constraint::Length((inline_lines.len() as u16 + 2).min(12)));
    }
    for (_, _, height) in &block_fields {
        constraints.push(Constraint::Length(*height));
    }
    let rows = Layout::vertical(constraints).split(area);

    frame.render_widget(
        Paragraph::new(meta)
            .block(panel("metadata"))
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
    let mut next = 3;
    if show_inline {
        frame.render_widget(
            Paragraph::new(inline_lines)
                .block(panel("fields"))
                .wrap(Wrap { trim: false }),
            rows[next],
        );
        next += 1;
    }
    for (title, body, _) in block_fields {
        frame.render_widget(
            Paragraph::new(body)
                .block(panel(&title))
                .wrap(Wrap { trim: false }),
            rows[next],
        );
        next += 1;
    }
}

/// The principal × read/write/manage access table for a target (a secret selector, or a namespace
/// expressed as a selector). Used in both the secret detail and the namespace detail so they match.
pub(super) fn access_table_lines(
    model: &Model,
    selector: &SecretSelectorV1,
    width: u16,
) -> Vec<Line<'static>> {
    let rows = model.access_matrix(selector);
    // Two layouts so the table degrades instead of overflowing: wide panes get full column
    // headers; narrow panes use single-letter headers and thinner boolean columns. Either way the
    // principal name column absorbs the remaining width and every header is truncated to its
    // column, so `manage` never wraps onto a second line.
    let wide = width >= 40;
    let (heads, bw): ([&str; 3], usize) = if wide {
        (["read", "write", "manage"], 8)
    } else {
        (["r", "w", "m"], 4)
    };
    // No upper bound: a wide pane shows full principal names (full-details rule); the floor keeps
    // the header legible when the pane is squeezed.
    let pw = (width as usize).saturating_sub(bw * 3).max(6);
    let header = format!(
        "{:<pw$}{:<bw$}{:<bw$}{}",
        truncate("principal", pw),
        truncate(heads[0], bw),
        truncate(heads[1], bw),
        truncate(heads[2], bw),
    );
    let mut lines = vec![Line::from(Span::styled(header, Style::new().fg(DIM)))];
    if rows.is_empty() {
        lines.push(Line::from(Span::styled(
            "(no access granted)",
            Style::new().fg(DIM),
        )));
        return lines;
    }
    let cell = |b: bool| -> Span<'static> {
        if b {
            Span::styled(format!("{:<bw$}", "✓"), Style::new().fg(OK))
        } else {
            Span::styled(format!("{:<bw$}", "·"), Style::new().fg(DIM))
        }
    };
    for r in rows {
        lines.push(Line::from(vec![
            Span::raw(format!("{:<pw$}", truncate(&r.label, pw.saturating_sub(1)))),
            cell(r.read),
            cell(r.write),
            cell(r.manage),
        ]));
    }
    lines
}

/// Detail for a selected namespace (folder): a metadata section + an access section.
fn render_namespace_detail(model: &Model, frame: &mut Frame, area: Rect, prefix: &[String]) {
    let (count, _) = model.namespace_summary(prefix);
    let selector = SecretSelectorV1 {
        tuple: prefix.to_vec(),
        labels: Vec::new(),
    };
    let access = access_table_lines(model, &selector, area.width.saturating_sub(4));
    let access_h = (access.len() as u16 + 2).min(12);
    let rows = Layout::vertical([Constraint::Length(4), Constraint::Length(access_h)]).split(area);
    frame.render_widget(
        Paragraph::new(vec![
            kv("namespace", &prefix.join("/")),
            kv("secrets", &format!("{count} under this path")),
        ])
        .block(panel("metadata"))
        .wrap(Wrap { trim: false }),
        rows[0],
    );
    frame.render_widget(
        Paragraph::new(access)
            .block(panel("access"))
            .wrap(Wrap { trim: false }),
        rows[1],
    );
}

fn state_text(leaf: &crate::project::SecretLeaf) -> String {
    use thorax_ops::SecretState::*;
    match leaf.state {
        ActiveDecryptable => "active ╱ decryptable by you".to_string(),
        NotEncryptedForReader => "stale ╱ not encrypted to you".to_string(),
        Unauthorized => "not authorized".to_string(),
        Missing => "missing".to_string(),
        Conflicted => "conflict ╱ no effective value ╱ resolve in the Conflicts tab".to_string(),
        Invalid => "invalid".to_string(),
    }
}
