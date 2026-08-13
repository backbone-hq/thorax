//! Headless renderer used by `tools/tui-screenshots/generate.sh`.
//!
//! This is compiled as a child of `thorax_tui::tests`, which gives the tool access to the private
//! model and renderer without turning screenshot-only hooks into public library API.

use std::fmt::Write as _;
use std::path::Path;

use ratatui::{
    backend::TestBackend,
    buffer::Buffer,
    style::{Color, Modifier},
    Terminal,
};

use super::{drain_with, unlock, update, Message, Model};

fn color(color: Color, default: &str) -> String {
    match color {
        Color::Reset => default.to_string(),
        Color::Black => "#000000".to_string(),
        Color::Red => "#cd3131".to_string(),
        Color::Green => "#0dbc79".to_string(),
        Color::Yellow => "#e5e510".to_string(),
        Color::Blue => "#2472c8".to_string(),
        Color::Magenta => "#bc3fbc".to_string(),
        Color::Cyan => "#11a8cd".to_string(),
        Color::Gray => "#e5e5e5".to_string(),
        Color::DarkGray => "#666666".to_string(),
        Color::LightRed => "#f14c4c".to_string(),
        Color::LightGreen => "#23d18b".to_string(),
        Color::LightYellow => "#f5f543".to_string(),
        Color::LightBlue => "#3b8eea".to_string(),
        Color::LightMagenta => "#d670d6".to_string(),
        Color::LightCyan => "#29b8db".to_string(),
        Color::White => "#ffffff".to_string(),
        Color::Rgb(r, g, b) => format!("#{r:02x}{g:02x}{b:02x}"),
        // The Thorax palette uses RGB colors. This keeps the renderer total if an indexed color is
        // introduced later; a screenshot review will make any palette mismatch obvious.
        Color::Indexed(i) => format!("hsl({}, 55%, 55%)", u16::from(i) * 360 / 256),
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn write_svg(buffer: &Buffer, path: &Path, replacements: &[(&str, &str)]) {
    const CELL_W: f32 = 8.45;
    const CELL_H: f32 = 18.0;
    const PAD: f32 = 16.0;
    const BACKGROUND: &str = "#111214";
    const FOREGROUND: &str = "#d4d4d4";

    let cols = buffer.area.width;
    let rows = buffer.area.height;
    let width = f32::from(cols) * CELL_W + PAD * 2.0;
    let height = f32::from(rows) * CELL_H + PAD * 2.0;
    let mut svg = format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
<rect width="100%" height="100%" rx="10" fill="{BACKGROUND}"/>
<style>text {{ font-family: "DejaVu Sans Mono", "Liberation Mono", monospace; font-size: 14px; font-variant-ligatures: none; }}</style>
"#
    );

    // Draw contiguous background runs first so reversed selections and focused tabs sit beneath
    // their glyphs without emitting a rectangle for every terminal cell.
    for y in 0..rows {
        let mut x = 0;
        while x < cols {
            let cell = &buffer[(x, y)];
            let reversed = cell.modifier.contains(Modifier::REVERSED);
            let background = if reversed { cell.fg } else { cell.bg };
            let mut end = x + 1;
            while end < cols {
                let next = &buffer[(end, y)];
                let next_background = if next.modifier.contains(Modifier::REVERSED) {
                    next.fg
                } else {
                    next.bg
                };
                if next_background != background {
                    break;
                }
                end += 1;
            }
            if background != Color::Reset {
                let fill = color(background, BACKGROUND);
                let rect_x = PAD + f32::from(x) * CELL_W;
                let rect_y = PAD + f32::from(y) * CELL_H;
                let rect_w = f32::from(end - x) * CELL_W;
                let _ = writeln!(
                    svg,
                    r#"<rect x="{rect_x}" y="{rect_y}" width="{rect_w}" height="{CELL_H}" fill="{fill}"/>"#
                );
            }
            x = end;
        }
    }

    // Group adjacent cells with the same foreground and weight. Position still comes from the
    // Ratatui cell index, so box drawing and column alignment match the terminal exactly.
    for y in 0..rows {
        let mut x = 0;
        while x < cols {
            let cell = &buffer[(x, y)];
            let reversed = cell.modifier.contains(Modifier::REVERSED);
            let foreground = if reversed { cell.bg } else { cell.fg };
            let bold = cell.modifier.contains(Modifier::BOLD);
            let mut text = cell.symbol().to_string();
            let mut end = x + 1;
            while end < cols {
                let next = &buffer[(end, y)];
                let next_reversed = next.modifier.contains(Modifier::REVERSED);
                let next_foreground = if next_reversed { next.bg } else { next.fg };
                let next_bold = next.modifier.contains(Modifier::BOLD);
                if next_foreground != foreground || next_bold != bold {
                    break;
                }
                text.push_str(next.symbol());
                end += 1;
            }
            if !text.trim().is_empty() {
                let fill = color(foreground, FOREGROUND);
                let text_x = PAD + f32::from(x) * CELL_W;
                let text_y = PAD + (f32::from(y) + 0.78) * CELL_H;
                let weight = if bold { "700" } else { "400" };
                let escaped = xml_escape(&text);
                let _ = writeln!(
                    svg,
                    r#"<text x="{text_x}" y="{text_y}" fill="{fill}" font-weight="{weight}" xml:space="preserve">{escaped}</text>"#
                );
            }
            x = end;
        }
    }

    svg.push_str("</svg>\n");
    for (generated, stable) in replacements {
        svg = svg.replace(generated, stable);
    }
    std::fs::write(path, svg).unwrap();
}

fn render(model: &mut Model, path: &Path) {
    let root = model
        .effective()
        .and_then(|state| state.root_signing_public_key_hash.as_ref())
        .map(thorax_frontend::short_hash)
        .unwrap_or_default();
    let user = model
        .acting
        .as_ref()
        .map(thorax_frontend::short_user_hex)
        .unwrap_or_default();
    let record = model
        .selected_merge_candidate()
        .map(|(_, candidate)| thorax_frontend::short_hash(&candidate.pick))
        .unwrap_or_default();
    let mut replacements = vec![(root.as_str(), "a71a5c0d"), (user.as_str(), "a7a00001")];
    if !record.is_empty() {
        replacements.push((record.as_str(), "c0ffee01"));
    }
    let backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| crate::ui::render(model, frame))
        .unwrap();
    write_svg(terminal.backend().buffer(), path, &replacements);
}

#[test]
#[ignore = "run tools/tui-screenshots/generate.sh"]
fn generate_readme_screenshots() {
    use crate::app::{AccessRow, AccessTab, Status, View};
    use thorax_ops::{
        decode_vault, encode_vault, merge_vaults, ratchet_path, GrantPermissionV1,
        KeyspaceSelectorV1, MergeOutcome, PrincipalRefV1, TupleMatcherV1,
    };

    let workspace = std::env::var_os("THORAX_SCREENSHOT_WORKSPACE")
        .expect("THORAX_SCREENSHOT_WORKSPACE must point to the demo vault");
    let output = std::path::PathBuf::from(
        std::env::var_os("THORAX_SCREENSHOT_OUTPUT")
            .expect("THORAX_SCREENSHOT_OUTPUT must point to the media directory"),
    );
    let passphrase = std::env::var("THORAX_SCREENSHOT_PASSPHRASE")
        .expect("THORAX_SCREENSHOT_PASSPHRASE must unlock the demo identity");

    let paths = thorax_ops::WorkspacePaths::from_root(workspace);
    let mut model = Model::load(paths.clone());
    unlock(&mut model, &passphrase);
    assert!(!model.is_unlock_gate(), "demo vault did not unlock");

    // Create invited principals directly through the shared operation layer. The screenshot does
    // not need to serialize their private invite material, and avoiding that output keeps the
    // fixture independent of transport-format size limits.
    let prefix = |parts: &[&str]| KeyspaceSelectorV1 {
        tuple: TupleMatcherV1::Prefix(parts.iter().map(|part| (*part).to_string()).collect()),
        labels: Vec::new(),
    };
    let developers = model
        .effective()
        .unwrap()
        .groups
        .iter()
        .find(|(_, group)| group.handle == "developers")
        .map(|(id, _)| id.clone())
        .expect("screenshot fixture should include %developers");
    let deployments = model
        .effective()
        .unwrap()
        .groups
        .iter()
        .find(|(_, group)| group.handle == "deployments")
        .map(|(id, _)| id.clone())
        .expect("screenshot fixture should include %deployments");
    let crypto = thorax_ops::Crypto;
    let maya = model
        .session
        .unlocked_mut()
        .unwrap()
        .invite_user(
            &crypto,
            Some("maya".to_string()),
            vec![
                GrantPermissionV1::ReadKeyspace(prefix(&["app", "production"])),
                GrantPermissionV1::WriteKeyspace(prefix(&["app", "staging"])),
            ],
        )
        .unwrap()
        .user_id;
    let release_bot = model
        .session
        .unlocked_mut()
        .unwrap()
        .invite_user(
            &crypto,
            Some("release-bot".to_string()),
            vec![GrantPermissionV1::ReadKeyspace(prefix(&[
                "services", "payments",
            ]))],
        )
        .unwrap()
        .user_id;
    model
        .session
        .unlocked_mut()
        .unwrap()
        .add_group_member(&crypto, developers, PrincipalRefV1::User(maya))
        .unwrap();
    model
        .session
        .unlocked_mut()
        .unwrap()
        .add_group_member(&crypto, deployments, PrincipalRefV1::User(release_bot))
        .unwrap();
    model.refresh_from_session();

    // The demo starts with top-level namespaces expanded. Select app/production/api to show the
    // tree, metadata, effective access, masked-value behavior, and context-aware action bar.
    update(&mut model, Message::MoveDown);
    update(&mut model, Message::Open);
    update(&mut model, Message::MoveDown);
    model.status = Status::default();
    render(&mut model, &output.join("tui-secrets.svg"));

    // Show the actual in-memory editor populated through the same gated read effect used by the
    // interactive application.
    drain_with(&mut model, Message::StartEdit);
    render(&mut model, &output.join("tui-editor.svg"));
    update(&mut model, Message::CloseModal);

    // Select and expand @maya so direct grants and inherited group membership are visible.
    update(&mut model, Message::SetAccessTab(AccessTab::Users));
    let maya = model
        .access
        .users
        .iter()
        .position(|user| user.handle.as_deref() == Some("maya"))
        .expect("screenshot fixture should include @maya");
    model.access_selected = model
        .access_rows()
        .iter()
        .position(|row| matches!(row, AccessRow::User { idx, .. } if *idx == maya))
        .expect("@maya should have an access row");
    update(&mut model, Message::Open);
    render(&mut model, &output.join("tui-users.svg"));

    // Likewise, expand the developers group to show both grants and memberships in one frame.
    update(&mut model, Message::SetAccessTab(AccessTab::Groups));
    let developers = model
        .access
        .groups
        .iter()
        .position(|group| group.handle == "developers")
        .expect("screenshot fixture should include %developers");
    model.access_selected = model
        .access_rows()
        .iter()
        .position(|row| matches!(row, AccessRow::Group { idx, .. } if *idx == developers))
        .expect("%developers should have an access row");
    update(&mut model, Message::Open);
    render(&mut model, &output.join("tui-groups.svg"));

    // Produce a genuine same-counter tie by making two writes from the same vault and ratchet
    // snapshot, then feeding the structural union back through the normal loader. Keeping the two
    // values the same length makes candidate ordering irrelevant to the masked screenshot.
    let root_hash = model
        .effective()
        .and_then(|state| state.root_signing_public_key_hash.clone())
        .expect("demo vault should have a trusted root");
    let trust_file = ratchet_path(&paths, &root_hash);
    let selector = crate::project::parse_selector("services/payments/webhook").unwrap();
    let base_bytes = std::fs::read(&paths.vault_path).unwrap();
    let trust_snapshot = std::fs::read(&trust_file).unwrap();
    model
        .session
        .unlocked_mut()
        .unwrap()
        .set_secret(&crypto, selector.clone(), b"whsec_candidate_east")
        .unwrap();
    let ours_bytes = std::fs::read(&paths.vault_path).unwrap();
    drop(model);

    std::fs::write(&paths.vault_path, &base_bytes).unwrap();
    std::fs::write(&trust_file, &trust_snapshot).unwrap();
    let mut other = Model::load(paths.clone());
    unlock(&mut other, &passphrase);
    other
        .session
        .unlocked_mut()
        .unwrap()
        .set_secret(&crypto, selector, b"whsec_candidate_west")
        .unwrap();
    let theirs_bytes = std::fs::read(&paths.vault_path).unwrap();
    drop(other);

    let MergeOutcome::Merged { merged } = merge_vaults(
        Some(&decode_vault(&base_bytes).unwrap()),
        &decode_vault(&ours_bytes).unwrap(),
        &decode_vault(&theirs_bytes).unwrap(),
    )
    .unwrap() else {
        panic!("screenshot fixture union must merge");
    };
    std::fs::write(&paths.vault_path, encode_vault(&merged).unwrap()).unwrap();

    let mut conflict = Model::load(paths);
    unlock(&mut conflict, &passphrase);
    assert_eq!(conflict.merge.len(), 1, "fixture should contain one tie");
    update(&mut conflict, Message::SwitchView(View::Merge));
    conflict.merge_selected = 1;
    conflict.status = Status::default();
    render(&mut conflict, &output.join("tui-conflicts.svg"));
}
