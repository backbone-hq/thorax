use std::{
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    process::ExitCode,
};

use serde_json::json;
use thorax_frontend::{
    confirm_destructive, conflict_kind_name, conflict_label, copy_to_clipboard, hash_hex,
    hex_bytes, map_secret_error, parse_secret_selector, remember_user_if_explicit,
    resolve_optional_cli_user_ref_with_report, selector_string, user_hex, FrontendError,
};
use thorax_ops::{
    read_file_bounded, write_private_output, ActiveSecretV1, Crypto, HashValue, KeyUsePurpose,
    OpsError, OutputSink, ResolvedUserRef, SecretPlaintext, SecretSelectorV1, SecretState,
};

const MAX_SECRET_INPUT_BYTES: usize = 16 * 1024 * 1024;

use crate::args::{
    FieldCommand, FieldDeleteArgs, FieldGetArgs, FieldListArgs, FieldSetArgs, ListArgs, MoveArgs,
    SecretDeleteArgs, SecretGetArgs, SecretSetArgs, SecretShowArgs,
};
use crate::output::handle_display;
use crate::CliContext;

pub(crate) fn cmd_list(cli: &CliContext, args: ListArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.read_session()?;
    let user = resolve_optional_cli_user_ref_with_report(
        session.paths(),
        session.report(),
        &crypto,
        args.user.as_deref(),
    )?;
    let mut rows = session.effective().secret_records();
    rows.sort_by(|left, right| {
        let (left, right) = (active_secret_selector(left), active_secret_selector(right));
        (&left.tuple, &left.labels).cmp(&(&right.tuple, &right.labels))
    });
    let mut conflicts = session.effective().secret_conflicts();
    conflicts.sort_by_key(|conflict| conflict_label(conflict));

    // Determine output format: --json flag or --format flag (format takes precedence)
    let format = args
        .format
        .as_deref()
        .unwrap_or(if cli.json { "json" } else { "table" });

    if format == "json" || cli.json {
        let mut rows = session.effective().secret_records();
        rows.sort_by(|left, right| {
            let (left, right) = (active_secret_selector(left), active_secret_selector(right));
            (&left.tuple, &left.labels).cmp(&(&right.tuple, &right.labels))
        });
        let mut conflicts = session.effective().secret_conflicts();
        conflicts.sort_by_key(|conflict| conflict_label(conflict));

        let mut secrets = rows
            .iter()
            .map(|record| {
                let selector = active_secret_selector(record);
                json!({
                    "selector": selector_string(selector),
                    "state": "active",
                    "access": user.as_ref().map(|user| secret_state_name(&session.effective().classify_secret_for_user(selector, &user.resolved.user_id, &crypto))),
                    "counter": active_secret_counter(record),
                })
            })
            .collect::<Vec<_>>();
        secrets.extend(conflicts.iter().map(|conflict| {
            json!({
                "selector": conflict_label(conflict),
                "state": "conflict",
                "conflict": conflict_kind_name(&conflict.kind),
                "counter": conflict.counter,
            })
        }));
        println!("{}", json!({ "trusted": true, "secrets": secrets }));
        return Ok(ExitCode::SUCCESS);
    }

    if format == "csv" {
        println!("selector,state,access,counter");
        for record in rows {
            let selector = active_secret_selector(&record);
            let access = user.as_ref().map(|user| {
                session.effective().classify_secret_for_user(
                    selector,
                    &user.resolved.user_id,
                    &crypto,
                )
            });
            let access_str = access
                .as_ref()
                .map(|s| secret_state_name(s))
                .unwrap_or("unknown");
            println!(
                "{},active,{},{}",
                selector_string(selector),
                access_str,
                active_secret_counter(&record)
            );
        }
        for conflict in &conflicts {
            println!(
                "{},conflict,{},{}",
                conflict_label(conflict),
                conflict_kind_name(&conflict.kind),
                conflict.counter
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    let mut not_encrypted = 0usize;
    for record in rows {
        let selector = active_secret_selector(&record);
        let access = user.as_ref().map(|user| {
            session
                .effective()
                .classify_secret_for_user(selector, &user.resolved.user_id, &crypto)
        });
        if matches!(&access, Some(SecretState::NotEncryptedForReader)) {
            not_encrypted += 1;
        }
        match access {
            Some(access) => println!(
                "{}\tactive\t{}",
                selector_string(selector),
                secret_state_name(&access)
            ),
            None => println!("{}\tactive", selector_string(selector)),
        }
    }
    for conflict in &conflicts {
        println!(
            "{}\tconflict\t{}",
            conflict_label(conflict),
            conflict_kind_name(&conflict.kind)
        );
    }
    // Hints go to stderr so stdout stays clean for piping/scripts.
    if not_encrypted > 0 {
        eprintln!(
            "note: {} you're authorized for aren't encrypted to you (unexpected — ask someone who can write them to set them again)",
            thorax_frontend::count_noun(not_encrypted, "secret")
        );
    }
    if !conflicts.is_empty() {
        let verb = if conflicts.len() == 1 { "is" } else { "are" };
        let possession = if conflicts.len() == 1 { "has" } else { "have" };
        eprintln!(
            "note: {} {verb} conflicted and {possession} no current value — see thorax conflicts",
            thorax_frontend::count_noun(conflicts.len(), "secret")
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_show(cli: &CliContext, args: SecretShowArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let session = cli.read_session()?;
    let selector = parse_secret_selector(&args.selector)?;
    if session
        .effective()
        .secret_conflict(&selector, &crypto)
        .map_err(OpsError::from)?
        .is_some()
    {
        return Err(FrontendError::SecretConflicted {
            selector: args.selector.clone(),
        });
    }
    let active = session
        .effective()
        .secret_record(&selector, &crypto)
        .map_err(OpsError::from)?
        .ok_or(OpsError::SecretMissing)?;
    let user = resolve_optional_cli_user_ref_with_report(
        session.paths(),
        session.report(),
        &crypto,
        args.user.as_deref(),
    )?;
    let access = user.as_ref().map(|user| {
        session
            .effective()
            .classify_secret_for_user(&selector, &user.resolved.user_id, &crypto)
    });
    let readers = session.effective().current_reader_entries(&selector);

    if cli.json {
        println!(
            "{}",
            json!({
                "selector": selector_string(&selector),
                "secret": hash_hex(active_secret_secret(&active)),
                "state": "active",
                "access": access.as_ref().map(|s| secret_state_name(s)),
                "counter": active_secret_counter(&active),
                "readers": readers.iter().map(user_hex).collect::<Vec<_>>(),
            })
        );
    } else {
        println!("secret: {}", selector_string(&selector));
        println!("state: active");
        println!("version: {}", active_secret_counter(&active));
        if let Some(access) = access {
            println!("access: {}", secret_state_name(&access));
        }
        println!("readers: {}", readers.len());
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_secret_set(
    cli: &CliContext,
    args: SecretSetArgs,
) -> Result<ExitCode, FrontendError> {
    let verb = if args.rotate { "rotated" } else { "set" };
    cmd_secret_write(cli, args, verb)
}

fn cmd_secret_write(
    cli: &CliContext,
    args: SecretSetArgs,
    verb: &'static str,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    let plaintext = read_secret_input(args.positional_value, args.file)?;
    let (mut unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignSecretWrite {
            selector: selector.clone(),
        },
    )?;
    // Updating the primary value must not silently discard a secret's additional fields. Read
    // the current value first and carry its fields across; a brand-new secret has none, and a
    // secret we cannot decrypt has its fields replaced (we can't read them to preserve them).
    let output = match unlocked.get_secret(&crypto, selector.clone()) {
        Ok(previous) => unlocked.set_secret_value(
            &crypto,
            selector.clone(),
            previous.to_value_with_primary(plaintext),
        )?,
        Err(OpsError::SecretMissing) => {
            unlocked.set_secret(&crypto, selector.clone(), &plaintext)?
        }
        Err(_) => {
            eprintln!(
                "note: could not read {}'s existing fields to preserve them — they are replaced",
                selector_string(&selector)
            );
            unlocked.set_secret(&crypto, selector.clone(), &plaintext)?
        }
    };
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "selector": selector_string(&output.selector),
                "secret": hash_hex(&output.secret_id.0),
                "user": user_hex(&user.resolved.user_id),
                "user_handle": user.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("{verb} {}", selector_string(&output.selector));
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_secret_move(cli: &CliContext, args: MoveArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let from = parse_secret_selector(&args.from)?;
    let to = parse_secret_selector(&args.to)?;
    let purpose = KeyUsePurpose::MoveSecret {
        from: from.clone(),
        to: to.clone(),
    };
    let (mut unlocked, user) = cli.unlock_for_action(args.user.as_deref(), purpose)?;

    if from != to
        && (unlocked
            .effective()
            .secret_conflict(&to, &crypto)
            .map_err(OpsError::from)?
            .is_some()
            || unlocked
                .effective()
                .secret_record(&to, &crypto)
                .map_err(OpsError::from)?
                .is_some())
    {
        return Err(FrontendError::SecretAlreadyExists {
            selector: selector_string(&to),
        });
    }

    let output = unlocked.relabel_secret(&crypto, from.clone(), to.clone())?;
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "moved": {
                    "from": selector_string(&output.from),
                    "to": selector_string(&output.to),
                },
                "user": user_hex(&user.resolved.user_id),
                "user_handle": user.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!(
            "moved {} -> {}",
            selector_string(&output.from),
            selector_string(&output.to)
        );
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_secret_get(
    cli: &CliContext,
    args: SecretGetArgs,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    let sink = if let Some(path) = &args.out {
        OutputSink::File(path.clone())
    } else if args.clipboard {
        OutputSink::Clipboard
    } else {
        OutputSink::Stdout
    };
    let (unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::DecryptSecret {
            selector: selector.clone(),
            sink,
        },
    )?;
    let opened = unlocked
        .get_secret(&crypto, selector)
        .map_err(|error| map_secret_error(error, &args.selector))?;
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if let Some(path) = &args.out {
        write_private_output(path, &opened.plaintext, args.overwrite)?;
        if cli.json {
            println!(
                "{}",
                json!({
                    "selector": selector_string(&opened.selector),
                    "out": path.display().to_string(),
                })
            );
        } else {
            eprintln!(
                "wrote {} to {}",
                selector_string(&opened.selector),
                path.display()
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    if args.clipboard {
        copy_to_clipboard(&opened.plaintext)?;
        if cli.json {
            println!(
                "{}",
                json!({
                    "selector": selector_string(&opened.selector),
                    "clipboard": true,
                })
            );
        } else {
            eprintln!("copied {} to clipboard", selector_string(&opened.selector));
        }
        return Ok(ExitCode::SUCCESS);
    }
    // Guard plaintext from landing in terminal scrollback by accident. Piped output is the
    // intended non-leaky path and is not gated; an interactive terminal is. The prompt is
    // written to stdout so it remains visible even when stderr is redirected to a file.
    if !cli.json && !args.force && io::stdout().is_terminal() {
        print!(
            "This prints the plaintext of {} to your terminal. Continue? [y/N] ",
            selector_string(&opened.selector)
        );
        io::stdout().flush().map_err(FrontendError::Stdio)?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(FrontendError::Stdio)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("aborted");
            return Ok(ExitCode::SUCCESS);
        }
    }
    write_plaintext(cli.json, opened, &user.resolved)?;
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_secret_delete(
    cli: &CliContext,
    args: SecretDeleteArgs,
) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    // Confirm intent before the unlock prompt: a declined confirmation should never have
    // cost a passphrase entry.
    if !confirm_destructive(
        &format!("delete secret {}", args.selector),
        args.yes,
        args.dry_run,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let (mut unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignSecretDelete {
            selector: selector.clone(),
        },
    )?;
    let output = unlocked.delete_secret(&crypto, selector)?;
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "selector": selector_string(&output.selector),
                "secret": hash_hex(&output.secret_id.0),
                "deleted": true,
                "user": user_hex(&user.resolved.user_id),
                "user_handle": user.resolved.handle.as_ref().map(|handle| handle_display(handle)),
            })
        );
    } else {
        println!("deleted {}", selector_string(&output.selector));
    }
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn cmd_field(
    cli: &CliContext,
    command: FieldCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        FieldCommand::List(args) => cmd_field_list(cli, args),
        FieldCommand::Get(args) => cmd_field_get(cli, args),
        FieldCommand::Set(args) => cmd_field_set(cli, args),
        FieldCommand::Delete(args) => cmd_field_delete(cli, args),
    }
}

/// Render a field value as text when UTF-8, else hex with a `0x` marker — for human listings.
fn field_display(value: &[u8]) -> String {
    if std::str::from_utf8(value).is_ok() {
        String::from_utf8_lossy(value).into_owned()
    } else {
        format!("0x{}", hex_bytes(value))
    }
}

fn cmd_field_list(cli: &CliContext, args: FieldListArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    let (unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::DecryptSecret {
            selector: selector.clone(),
            sink: OutputSink::Stdout,
        },
    )?;
    let opened = unlocked
        .get_secret(&crypto, selector)
        .map_err(|error| map_secret_error(error, &args.selector))?;
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if cli.json {
        let fields = opened
            .fields
            .iter()
            .map(|field| {
                if args.reveal {
                    json!({ "key": field.key, "value": field_display(&field.value) })
                } else {
                    json!({ "key": field.key })
                }
            })
            .collect::<Vec<_>>();
        println!(
            "{}",
            json!({
                "selector": selector_string(&opened.selector),
                "fields": fields,
            })
        );
    } else {
        for field in &opened.fields {
            if args.reveal {
                println!("{}\t{}", field.key, field_display(&field.value));
            } else {
                println!("{}", field.key);
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_field_get(cli: &CliContext, args: FieldGetArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    let sink = if let Some(path) = &args.out {
        OutputSink::File(path.clone())
    } else if args.clipboard {
        OutputSink::Clipboard
    } else {
        OutputSink::Stdout
    };
    let (unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::DecryptSecret {
            selector: selector.clone(),
            sink,
        },
    )?;
    let opened = unlocked
        .get_secret(&crypto, selector)
        .map_err(|error| map_secret_error(error, &args.selector))?;
    remember_user_if_explicit(unlocked.paths(), &user)?;
    let field = opened
        .field(&args.key)
        .ok_or_else(|| FrontendError::SecretFieldNotFound {
            selector: args.selector.clone(),
            key: args.key.clone(),
        })?;
    let value = field.value.as_slice();
    let label = format!(
        "field {} of {}",
        args.key,
        selector_string(&opened.selector)
    );

    if let Some(path) = &args.out {
        write_private_output(path, value, args.overwrite)?;
        if cli.json {
            println!(
                "{}",
                json!({ "selector": selector_string(&opened.selector), "key": args.key, "out": path.display().to_string() })
            );
        } else {
            eprintln!("wrote {label} to {}", path.display());
        }
        return Ok(ExitCode::SUCCESS);
    }
    if args.clipboard {
        copy_to_clipboard(value)?;
        if cli.json {
            println!(
                "{}",
                json!({ "selector": selector_string(&opened.selector), "key": args.key, "clipboard": true })
            );
        } else {
            eprintln!("copied {label} to clipboard");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if !cli.json && !args.force && io::stdout().is_terminal() {
        print!("This prints the plaintext of {label} to your terminal. Continue? [y/N] ");
        io::stdout().flush().map_err(FrontendError::Stdio)?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(FrontendError::Stdio)?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("aborted");
            return Ok(ExitCode::SUCCESS);
        }
    }
    let is_utf8 = field.is_utf8();
    if cli.json {
        let mut payload = json!({
            "selector": selector_string(&opened.selector),
            "key": args.key,
            "user": user_hex(&user.resolved.user_id),
        });
        let object = payload.as_object_mut().expect("payload is an object");
        if is_utf8 {
            object.insert("value".to_string(), json!(String::from_utf8_lossy(value)));
        } else {
            object.insert("value_hex".to_string(), json!(hex_bytes(value)));
        }
        println!("{payload}");
    } else {
        let needs_newline = is_utf8
            && !value.ends_with(b"\n")
            && (io::stdout().is_terminal() || io::stderr().is_terminal());
        let mut stdout = io::stdout();
        stdout.write_all(value).map_err(FrontendError::Stdio)?;
        stdout.flush().map_err(FrontendError::Stdio)?;
        if needs_newline {
            eprintln!();
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_field_set(cli: &CliContext, args: FieldSetArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    let value = read_secret_input(args.positional_value, args.file)?;
    let (mut unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignSecretWrite {
            selector: selector.clone(),
        },
    )?;
    // Read-modify-write: keep the primary value and the other fields, upserting this one.
    let previous = unlocked
        .get_secret(&crypto, selector.clone())
        .map_err(|error| map_secret_error(error, &args.selector))?;
    let output = unlocked.set_secret_value(
        &crypto,
        selector,
        previous.with_field(args.key.clone(), value),
    )?;
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "selector": selector_string(&output.selector),
                "field": args.key,
                "user": user_hex(&user.resolved.user_id),
            })
        );
    } else {
        println!(
            "set field {} on {}",
            args.key,
            selector_string(&output.selector)
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_field_delete(cli: &CliContext, args: FieldDeleteArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    let selector = parse_secret_selector(&args.selector)?;
    if !confirm_destructive(
        &format!("remove field {} from {}", args.key, args.selector),
        args.yes,
        false,
    )? {
        return Ok(ExitCode::SUCCESS);
    }
    let (mut unlocked, user) = cli.unlock_for_action(
        args.user.as_deref(),
        KeyUsePurpose::SignSecretWrite {
            selector: selector.clone(),
        },
    )?;
    let previous = unlocked
        .get_secret(&crypto, selector.clone())
        .map_err(|error| map_secret_error(error, &args.selector))?;
    if previous.field(&args.key).is_none() {
        return Err(FrontendError::SecretFieldNotFound {
            selector: args.selector.clone(),
            key: args.key.clone(),
        });
    }
    let output = unlocked.set_secret_value(&crypto, selector, previous.without_field(&args.key))?;
    remember_user_if_explicit(unlocked.paths(), &user)?;

    if cli.json {
        println!(
            "{}",
            json!({
                "selector": selector_string(&output.selector),
                "field": args.key,
                "removed": true,
                "user": user_hex(&user.resolved.user_id),
            })
        );
    } else {
        println!(
            "removed field {} from {}",
            args.key,
            selector_string(&output.selector)
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn read_secret_input(
    positional_value: Option<String>,
    file: Option<PathBuf>,
) -> Result<Vec<u8>, FrontendError> {
    let provided_count = positional_value.is_some() as usize + file.is_some() as usize;
    if provided_count > 1 {
        return Err(FrontendError::AmbiguousSecretInput);
    }

    match (positional_value, file) {
        (Some(value), None) => {
            let value = value.into_bytes();
            if value.len() > MAX_SECRET_INPUT_BYTES {
                return Err(FrontendError::SecretInputTooLarge {
                    max_bytes: MAX_SECRET_INPUT_BYTES,
                });
            }
            Ok(value)
        }
        (None, Some(path)) => read_file_bounded(&path, MAX_SECRET_INPUT_BYTES).map_err(|source| {
            if source.kind() == io::ErrorKind::InvalidData {
                FrontendError::SecretInputTooLarge {
                    max_bytes: MAX_SECRET_INPUT_BYTES,
                }
            } else {
                FrontendError::Io { path, source }
            }
        }),
        (None, None) => {
            let mut bytes = Vec::new();
            io::stdin()
                .take(MAX_SECRET_INPUT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(FrontendError::Stdio)?;
            if bytes.len() > MAX_SECRET_INPUT_BYTES {
                return Err(FrontendError::SecretInputTooLarge {
                    max_bytes: MAX_SECRET_INPUT_BYTES,
                });
            }
            Ok(bytes)
        }
        _ => unreachable!("ambiguous secret input checked above"),
    }
}

fn write_plaintext(
    json_output: bool,
    opened: SecretPlaintext,
    user: &ResolvedUserRef,
) -> Result<(), FrontendError> {
    // Bytes are opaque: render text when the value is valid UTF-8, else fall back to hex.
    // The key name (`plaintext` vs `plaintext_hex`) is what tells the caller which transform
    // was applied, so a hex blob is never mistaken for the literal value.
    let is_utf8 = opened.is_utf8();
    if json_output {
        // Top-level value key: `"secret"` is reserved for the secret-id hash (show/set/delete);
        // the plaintext rides at the top level.
        let mut payload = json!({
            "selector": selector_string(&opened.selector),
            "user": user_hex(&user.user_id),
            "user_handle": user.handle.as_ref().map(|handle| handle_display(handle)),
        });
        let object = payload.as_object_mut().expect("payload is an object");
        if is_utf8 {
            object.insert(
                "plaintext".to_string(),
                json!(String::from_utf8_lossy(&opened.plaintext)),
            );
        } else {
            object.insert(
                "plaintext_hex".to_string(),
                json!(hex_bytes(&opened.plaintext)),
            );
        }
        if !opened.fields.is_empty() {
            // Additional fields ride under a `fields` object, each value rendered text-or-hex
            // exactly like the primary: a binary field's key gets a `_hex` suffix so the caller
            // can tell which transform was applied.
            let mut fields = serde_json::Map::new();
            for field in &opened.fields {
                if field.is_utf8() {
                    fields.insert(
                        field.key.clone(),
                        json!(String::from_utf8_lossy(&field.value)),
                    );
                } else {
                    fields.insert(format!("{}_hex", field.key), json!(hex_bytes(&field.value)));
                }
            }
            object.insert("fields".to_string(), json!(fields));
        }
        println!("{payload}");
    } else {
        let needs_terminal_newline = is_utf8
            && !opened.plaintext.as_slice().ends_with(b"\n")
            && (io::stdout().is_terminal() || io::stderr().is_terminal());
        let mut stdout = io::stdout();
        stdout
            .write_all(&opened.plaintext)
            .map_err(FrontendError::Stdio)?;
        stdout.flush().map_err(FrontendError::Stdio)?;
        if needs_terminal_newline {
            eprintln!();
        }
    }
    Ok(())
}

pub(crate) fn active_secret_selector(record: &ActiveSecretV1) -> &SecretSelectorV1 {
    &record.value.selector
}

fn active_secret_secret(record: &ActiveSecretV1) -> &HashValue {
    &record.value.id.0
}

/// The record's Lamport ordering counter — a logical version, not a wall-clock time.
fn active_secret_counter(record: &ActiveSecretV1) -> u64 {
    record.value.counter
}

fn secret_state_name(state: &SecretState) -> &'static str {
    match state {
        SecretState::ActiveDecryptable => "decryptable",
        SecretState::NotEncryptedForReader => "not_encrypted_to_you",
        SecretState::Unauthorized => "unauthorized",
        SecretState::Missing => "missing",
        SecretState::Conflicted => "conflict",
        SecretState::Invalid => "invalid",
    }
}
