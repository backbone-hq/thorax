use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};

use crate::app::{AccessTab, ListKind, ListRegion, Model};
use crate::theme;

use super::{panel, slashed, truncate, ACCENT, DIM, OK};

// ── access view ──────────────────────────────────────────────────────────────

pub(super) fn render_access(model: &mut Model, frame: &mut Frame, area: Rect) {
    // Users and Groups are top-level tabs now (in the header), so the view is just the one list for
    // whichever section is active — no nested sub-tab bar.
    let title = match model.access_tab {
        AccessTab::Users => "users",
        AccessTab::Groups => "groups",
    };
    let rows = model.access_rows();
    let block = panel(title).title_bottom(Line::from(slashed(
        " Enter/→ expand ╱ ← collapse ╱ details appear below each principal ",
        Style::default(),
    )));
    let inner = block.inner(area);
    if rows.is_empty() {
        let bold = Style::new().add_modifier(Modifier::BOLD);
        let act = Style::new().fg(ACCENT);
        let hint = Style::new().fg(DIM);
        let lines = match model.access_tab {
            AccessTab::Users => vec![
                Line::raw(""),
                Line::from(Span::styled("No users yet.", bold)),
                Line::raw(""),
                Line::from(Span::styled("Press [n] to invite someone.", act)),
                Line::from(Span::styled(
                    "Invited users appear here after creation.",
                    hint,
                )),
            ],
            AccessTab::Groups => vec![
                Line::raw(""),
                Line::from(Span::styled("No groups yet.", bold)),
                Line::raw(""),
                Line::from(Span::styled("Press [n] to create your first group.", act)),
                Line::from(Span::styled(
                    "Groups bundle grants so you can hand out access in one step.",
                    hint,
                )),
            ],
        };
        // A plain titled box (no "grants shown below each" hint, since there's nothing below).
        frame.render_widget(
            Paragraph::new(lines)
                .block(panel(title))
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let items: Vec<ListItem> = rows
        .iter()
        .map(|r| access_line(model, r, inner.width))
        .collect();
    let list = List::new(items)
        .block(block)
        // Selected row: a subtle dark bar + bold, not a bright reverse. Only `bg`/bold are set so
        // each row keeps its own glyph colours (amber active, red invalid, …).
        .highlight_style(
            Style::new()
                .bg(theme::STRUCT_DIM)
                .add_modifier(Modifier::BOLD),
        );
    let mut state = ListState::default().with_selected(Some(
        model.access_selected.min(rows.len().saturating_sub(1)),
    ));
    frame.render_stateful_widget(list, area, &mut state);
    model.list_region = Some(ListRegion {
        kind: ListKind::Access,
        rect: inner,
        offset: state.offset(),
    });
}

fn counted(count: usize, singular: &str) -> String {
    thorax_frontend::count_noun(count, singular)
}

fn access_line(model: &Model, row: &crate::app::AccessRow, width: u16) -> ListItem<'static> {
    use crate::app::AccessRow;
    match row {
        AccessRow::User { idx, expanded } => {
            let Some(u) = model.access.users.get(*idx) else {
                return ListItem::new(Line::raw(""));
            };
            let marker = if *expanded { "▾ " } else { "▸ " };
            let mut tags = Vec::new();
            let direct_grants = u
                .grants
                .iter()
                .filter(|grant| grant.grant_id.is_some())
                .count();
            if u.is_root {
                tags.push("root".to_string());
                tags.push("full access".to_string());
            }
            if direct_grants > 0 || !u.is_root {
                tags.push(counted(direct_grants, "grant"));
            }
            if !u.group_memberships.is_empty() {
                tags.push(counted(u.group_memberships.len(), "group"));
            }
            let color = theme::TEXT;
            let mut line = vec![
                Span::raw(marker),
                Span::styled(
                    format!("{:<20}", truncate(&u.label(), 19)),
                    Style::new().fg(color).add_modifier(Modifier::BOLD),
                ),
            ];
            line.extend(slashed(&tags.join(" ╱ "), Style::new().fg(DIM)));
            ListItem::new(Line::from(line))
        }
        AccessRow::Group { idx, expanded } => {
            let Some(g) = model.access.groups.get(*idx) else {
                return ListItem::new(Line::raw(""));
            };
            let marker = if *expanded { "▾ " } else { "▸ " };
            let mut line = vec![
                Span::raw(marker),
                Span::styled(
                    format!("{:<20}", truncate(&format!("%{}", g.handle), 19)),
                    Style::new().fg(theme::TEXT).add_modifier(Modifier::BOLD),
                ),
            ];
            line.extend(slashed(
                &format!(
                    "{} ╱ {}",
                    counted(g.grants.len(), "grant"),
                    counted(g.members.len(), "member")
                ),
                Style::new().fg(DIM),
            ));
            ListItem::new(Line::from(line))
        }
        AccessRow::Grant {
            class, keyspace, ..
        } => {
            // Two columns: access class, then keyspace (like the keyspace display).
            // `administer` is ten characters, so the class column needs an explicit two-cell
            // gutter beyond that longest label; otherwise it runs into `entire vault`.
            let keyspace_width = (width as usize).saturating_sub(16).max(1);
            ListItem::new(Line::from(vec![
                Span::raw("    "),
                Span::styled(format!("{class:<12}"), Style::new().fg(OK)),
                Span::raw(truncate(keyspace, keyspace_width)),
            ]))
        }
        AccessRow::Member { label } => ListItem::new(Line::from(vec![
            Span::raw("    "),
            Span::styled(label.clone(), Style::new().fg(DIM)),
        ])),
        AccessRow::Note(text) => ListItem::new(Line::from(vec![
            Span::raw("    "),
            Span::styled(text.clone(), Style::new().fg(DIM)),
        ])),
    }
}
