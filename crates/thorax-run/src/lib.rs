//! Environment injection: `thorax run` decrypts selected secrets and injects them into a child
//! process environment.
//!
//! Like every Thorax frontend it reaches plaintext through [`thorax_frontend`] / [`thorax_ops`]
//! so keychain release and verification behave identically to `get` — one keychain approval
//! scoped to the full expanded selector set *and* the child command. It injects only explicitly
//! selected secrets, refuses to overwrite pre-existing environment variables unless asked,
//! executes the command directly (no shell), and strips Thorax key material
//! (`THORAX_UNSAFE_KEYCHAIN_PASSPHRASE`, `THORAX_UNSAFE_INVITE`) from the child environment.
//!
//! Selection uses the same matcher as access grants ([`selector_matches`]): each positional
//! `[NAME=]SELECTOR` covers the secret at that path and everything under it, optionally filtered
//! by labels — `app/prod`, `app@env=prod&tier=web`, `@env=prod`, `*`. The expansion happens
//! against the verified vault state, and every matched secret must be decryptable or the run
//! fails closed before anything launches.

use std::collections::HashMap;
use std::process::ExitCode;

use clap::Args;
use thorax_frontend::{
    build_keychain, conflict_label, map_secret_error, maybe_bootstrap_ci_trust, open_valid_session,
    parse_secret_query, remember_user_if_explicit, resolve_cli_user_ref_with_report,
    selector_string, FrontendError, GlobalArgs, INVITE_ENV, UNSAFE_KEYCHAIN_PASSPHRASE_ENV,
};
use thorax_ops::{
    selector_matches, Crypto, KeyOrigin, KeyUsePurpose, RecordBodyV1, RunSecretsError,
    SecretSelectorV1, UnlockedSession,
};

/// Arguments for `thorax run`: which secrets to inject, and the child command to launch with them.
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Secrets to inject, each [NAME=]SELECTOR. A selector matches its path and everything
    /// under it (app/prod), filtered by labels after @, &-separated (@env=prod&tier=web; @env
    /// for present, @!env for absent); * selects the whole vault. Variables are named from the
    /// full path (app/prod/db -> APP__PROD__DB) unless NAME= is given, which requires the
    /// selector to match exactly one secret.
    #[arg(required = true, value_name = "[NAME=]SELECTOR")]
    pub selections: Vec<String>,
    /// Act as this Thorax user. Defaults to the vault's default user.
    #[arg(long)]
    pub user: Option<String>,
    /// Replace pre-existing environment variables that collide with injected names.
    #[arg(long)]
    pub overwrite: bool,
    /// Show the injection plan without executing the command.
    #[arg(long)]
    pub dry_run: bool,
    /// The command to run, with its arguments (everything after `--`).
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// One resolved injection: the environment variable name and the secret that fills it.
#[derive(Debug)]
struct Injection {
    name: String,
    display: String,
    selector: SecretSelectorV1,
}

/// A conflicted secret a selection must not silently skip. `claimed` is what its candidates
/// name; because the conflict origin remembers the whole selector (labels are identity),
/// label filters apply normally and can exonerate a secret the query doesn't ask for.
struct ConflictedSecret {
    label: String,
    claimed: Vec<SecretSelectorV1>,
}

impl ConflictedSecret {
    fn matches(&self, query: &thorax_ops::KeyspaceSelectorV1) -> bool {
        self.claimed
            .iter()
            .any(|selector| selector_matches(query, selector))
    }
}

/// Run a child command with the selected secrets injected into its environment. Receives the
/// global flags from the umbrella binary.
pub fn run_inject(global: GlobalArgs, args: RunArgs) -> Result<ExitCode, FrontendError> {
    let crypto = Crypto;
    // The umbrella dispatches here directly (not through `run_cli`), so establish CI trust from
    // an injected invite the same way every CLI command does.
    maybe_bootstrap_ci_trust(global.path.as_ref())?;
    let session = open_valid_session(global.path.as_ref())?;
    let user = resolve_cli_user_ref_with_report(
        session.paths(),
        session.report(),
        &crypto,
        args.user.as_deref(),
    )?;
    // Unlock FIRST: nothing derived from the vault — selector planning, availability,
    // even error messages about what matched — is computed or shown before the identity
    // anchors the session (possession-checked verifications + membership pin). The prompt
    // names exactly what the user asked for on the command line.
    let keychain = build_keychain()?;
    let unlocked = UnlockedSession::promote(
        session,
        &crypto,
        &*keychain,
        &user.resolved.user_id,
        KeyUsePurpose::RunWithSecrets {
            selections: args.selections.clone(),
            command: args.command.clone(),
        },
    )?;
    remember_user_if_explicit(unlocked.session().paths(), &user)?;

    let available = unlocked
        .effective()
        .secret_records()
        .into_iter()
        .map(|record| record.value.selector)
        .collect::<Vec<_>>();

    // Conflicted secrets fail the run closed, never silently shrink it. A conflict whose
    // records were dropped entirely is still named precisely by the origin remembered for the
    // key — the whole selector (labels are identity), so label filters apply normally. Only a
    // conflict with neither candidates nor a remembered origin refuses every run (pre-origin
    // state files).
    let mut conflicted_secrets = Vec::new();
    for conflict in unlocked.effective().secret_conflicts() {
        let claimed: Vec<SecretSelectorV1> = conflict
            .candidates
            .iter()
            .filter_map(|candidate| match candidate.body.known() {
                Some(RecordBodyV1::Secret(record)) => Some(record.selector.clone()),
                Some(RecordBodyV1::SecretDeleted(record)) => Some(record.selector.clone()),
                _ => None,
            })
            .collect();
        if claimed.is_empty() {
            match &conflict.origin {
                Some(KeyOrigin::Secret(selector)) => {
                    // The origin remembers the full selector (labels are identity), so even
                    // a rollback that erased every record still names the secret precisely —
                    // label filters can exonerate it.
                    conflicted_secrets.push(ConflictedSecret {
                        label: conflict_label(conflict),
                        claimed: vec![selector.clone()],
                    });
                }
                _ => {
                    return Err(FrontendError::SecretConflicted {
                        selector: conflict_label(conflict),
                    });
                }
            }
        } else {
            conflicted_secrets.push(ConflictedSecret {
                label: conflict_label(conflict),
                claimed,
            });
        }
    }

    let plan = plan_injections(&args.selections, &available, &conflicted_secrets)?;

    // Dry-run: show injection plan and exit without decrypting or executing.
    if args.dry_run {
        println!("Would inject:");
        for injection in &plan {
            println!(
                "  {}={}  ({})",
                injection.name,
                injection.display,
                selector_string(&injection.selector)
            );
            // Note: field variables (NAME__FIELDKEY) are only known after decryption;
            // they are not shown in dry-run.
        }
        println!("Command: {}", args.command.join(" "));
        return Ok(ExitCode::SUCCESS);
    }

    // Fail on collisions with the inherited environment before launching the child: the user
    // either renames the injection or explicitly opts into overwriting.
    if !args.overwrite {
        let colliding = plan
            .iter()
            .filter(|injection| std::env::var_os(&injection.name).is_some())
            .map(|injection| injection.name.clone())
            .collect::<Vec<_>>();
        if !colliding.is_empty() {
            return Err(FrontendError::EnvCollision { names: colliding });
        }
    }

    // Release under the already-anchored identity (no second prompt; the unlock above
    // described this exact run).
    let selectors: Vec<SecretSelectorV1> = plan
        .iter()
        .map(|injection| injection.selector.clone())
        .collect();
    let opened = unlocked
        .get_secrets_for_run(&crypto, selectors)
        .map_err(|error| match error {
            RunSecretsError::Secret { selector, source } => {
                map_secret_error(*source, &selector_string(&selector))
            }
            RunSecretsError::Ops(source) => FrontendError::Ops(source),
        })?;

    // Environment values are strings: require UTF-8 with no NUL, and fail closed before the
    // child is launched rather than inject something mangled. Each secret contributes its
    // primary value under the derived name, plus one variable per additional field named
    // `NAME__FIELDKEY` (the field key sanitized the same way path segments are).
    let mut env: Vec<(String, String)> = Vec::with_capacity(plan.len());
    let mut assigned: HashMap<String, SecretSelectorV1> = HashMap::new();
    for (injection, secret) in plan.iter().zip(&opened) {
        let value = env_value(&secret.plaintext, &injection.display)?;
        push_injection(
            &mut env,
            &mut assigned,
            injection.name.clone(),
            &injection.selector,
            value,
        )?;
        for field in &secret.fields {
            let name = format!("{}__{}", injection.name, sanitize_env_segment(&field.key));
            if let Err(reason) = validate_env_name(&name) {
                return Err(FrontendError::InvalidEnvName { name, reason });
            }
            let display = format!("{} field {}", injection.display, field.key);
            let value = env_value(&field.value, &display)?;
            push_injection(&mut env, &mut assigned, name, &injection.selector, value)?;
        }
    }

    // Field-derived names are only known after decryption, so the inherited-environment
    // collision guard above (over the planned primary names) cannot have covered them — check
    // the full assignment set here.
    if !args.overwrite {
        let colliding = env
            .iter()
            .filter(|(name, _)| std::env::var_os(name).is_some())
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        if !colliding.is_empty() {
            return Err(FrontendError::EnvCollision { names: colliding });
        }
    }

    let mut command = std::process::Command::new(&args.command[0]);
    command.args(&args.command[1..]);
    // Never hand Thorax private key material to the child. These two variables *are* material
    // (a keychain passphrase, an identity seed); the *_FILE pointer is a path the child
    // could read from disk anyway, and stay so nested CI invocations keep working.
    command.env_remove(UNSAFE_KEYCHAIN_PASSPHRASE_ENV);
    command.env_remove(INVITE_ENV);
    for (name, value) in &env {
        command.env(name, value);
    }
    exec_command(command, &args.command[0])
}

/// Expand each `[NAME=]SELECTOR` argument against the vault's active secrets into concrete
/// injections, deriving names where they were not given. A selector matching nothing is an error
/// (a typo must not silently launch the child with fewer variables than asked for); two distinct
/// secrets mapping to the same variable is an error; the same secret selected twice (overlapping
/// selectors) injects once. A selector touching a *conflicted* secret (matched against any
/// selector its candidates claim) fails the run closed — a conflicted secret has no value, and
/// skipping it would launch the child with fewer variables than asked for.
fn plan_injections(
    specs: &[String],
    available: &[SecretSelectorV1],
    conflicted: &[ConflictedSecret],
) -> Result<Vec<Injection>, FrontendError> {
    let mut named: HashMap<String, SecretSelectorV1> = HashMap::new();
    let mut plan = Vec::new();
    for spec in specs {
        // `NAME=` can only precede the path. The path itself may now contain `=` (in a quoted or
        // escaped segment or a label value), so the leading `=` introduces a name only when the
        // text before it is a bare env name — never containing a path/label/quoting character.
        let name_split = spec
            .find('=')
            .filter(|&eq| !spec[..eq].contains(['/', '@', '"', '\\']));
        let (explicit_name, query_source) = match name_split {
            Some(eq) => (Some(spec[..eq].to_string()), spec[eq + 1..].to_string()),
            None => (None, spec.clone()),
        };
        if let Some(name) = &explicit_name {
            if let Err(reason) = validate_env_name(name) {
                return Err(FrontendError::InvalidEnvName {
                    name: name.clone(),
                    reason,
                });
            }
        }
        let query = parse_secret_query(&query_source)?;
        if let Some(conflict) = conflicted.iter().find(|conflict| conflict.matches(&query)) {
            return Err(FrontendError::SecretConflicted {
                selector: conflict.label.clone(),
            });
        }
        let mut matched = available
            .iter()
            .filter(|selector| selector_matches(&query, selector))
            .cloned()
            .collect::<Vec<_>>();
        matched
            .sort_by(|left, right| (&left.tuple, &left.labels).cmp(&(&right.tuple, &right.labels)));
        matched.dedup();
        if matched.is_empty() {
            return Err(FrontendError::SecretNotFound {
                selector: spec.clone(),
            });
        }
        if let Some(name) = &explicit_name {
            if matched.len() > 1 {
                return Err(FrontendError::AmbiguousNamedSelector {
                    name: name.clone(),
                    selector: spec.clone(),
                    count: matched.len(),
                });
            }
        }
        for selector in matched {
            let name = match &explicit_name {
                Some(name) => name.clone(),
                None => derive_env_name(&selector),
            };
            match named.get(&name) {
                Some(existing) if *existing == selector => continue,
                Some(_) => return Err(FrontendError::DuplicateEnvName { name }),
                None => {}
            }
            named.insert(name.clone(), selector.clone());
            plan.push(Injection {
                name,
                display: selector_string(&selector),
                selector,
            });
        }
    }
    Ok(plan)
}

/// Default environment variable name for a secret: the full tuple, each segment uppercased with
/// anything outside `[A-Za-z0-9_]` mapped to `_`, joined by `__` (`app/prod/api-key` becomes
/// `APP__PROD__API_KEY`), and a leading underscore added if it would start with a digit. Labels
/// do not contribute to the name.
fn derive_env_name(selector: &SecretSelectorV1) -> String {
    let mut name = String::new();
    for (index, segment) in selector.tuple.iter().enumerate() {
        if index > 0 {
            name.push_str("__");
        }
        name.push_str(&sanitize_env_segment(segment));
    }
    if name
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_digit())
    {
        name.insert(0, '_');
    }
    name
}

/// Map one path segment or field key to env-name characters: ASCII alphanumerics uppercased,
/// everything else collapsed to `_`. Shared by the tuple name and the `NAME__FIELDKEY` suffix
/// so a field key maps exactly like a path segment does.
fn sanitize_env_segment(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for character in segment.chars() {
        if character.is_ascii_alphanumeric() {
            out.push(character.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    out
}

/// Validate a secret/field plaintext as an environment value: UTF-8, no NUL byte. `display`
/// names the source for the error message.
fn env_value(bytes: &[u8], display: &str) -> Result<String, FrontendError> {
    let value = std::str::from_utf8(bytes).map_err(|_| FrontendError::SecretNotInjectable {
        selector: display.to_string(),
        reason: "its value is not valid UTF-8",
    })?;
    if value.contains('\0') {
        return Err(FrontendError::SecretNotInjectable {
            selector: display.to_string(),
            reason: "its value contains a NUL byte",
        });
    }
    Ok(value.to_string())
}

/// Record one `name = value` assignment, rejecting a name already claimed by a *different*
/// secret (two injections fighting over one variable). The same secret reaching the same name
/// twice is idempotent.
fn push_injection(
    env: &mut Vec<(String, String)>,
    assigned: &mut HashMap<String, SecretSelectorV1>,
    name: String,
    selector: &SecretSelectorV1,
    value: String,
) -> Result<(), FrontendError> {
    match assigned.get(&name) {
        Some(existing) if existing == selector => return Ok(()),
        Some(_) => return Err(FrontendError::DuplicateEnvName { name }),
        None => {}
    }
    assigned.insert(name.clone(), selector.clone());
    env.push((name, value));
    Ok(())
}

fn validate_env_name(name: &str) -> Result<(), &'static str> {
    let Some(first) = name.chars().next() else {
        return Err("it is empty");
    };
    if first.is_ascii_digit() {
        return Err("it must not start with a digit");
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err("it may contain only letters, digits, and underscores");
    }
    Ok(())
}

/// Launch the child. On Unix this replaces the `thorax` process entirely (`execvp`), so signals
/// and the exit status reach the caller with no wrapper in between; it only returns on failure
/// to launch. Elsewhere it spawns, waits, and forwards the exit code.
#[cfg(unix)]
fn exec_command(
    mut command: std::process::Command,
    program: &str,
) -> Result<ExitCode, FrontendError> {
    use std::os::unix::process::CommandExt;
    let source = command.exec();
    Err(FrontendError::ExecFailed {
        command: program.to_string(),
        source,
    })
}

#[cfg(not(unix))]
fn exec_command(
    mut command: std::process::Command,
    program: &str,
) -> Result<ExitCode, FrontendError> {
    let status = command
        .status()
        .map_err(|source| FrontendError::ExecFailed {
            command: program.to_string(),
            source,
        })?;
    let code = status.code().unwrap_or(1).clamp(0, u8::MAX as i32) as u8;
    Ok(ExitCode::from(code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use thorax_frontend::parse_secret_selector;

    fn vault(selectors: &[&str]) -> Vec<SecretSelectorV1> {
        selectors
            .iter()
            .map(|selector| parse_secret_selector(selector).unwrap())
            .collect()
    }

    fn plan(
        specs: &[&str],
        available: &[SecretSelectorV1],
    ) -> Result<Vec<(String, String)>, FrontendError> {
        let specs = specs
            .iter()
            .map(|spec| spec.to_string())
            .collect::<Vec<_>>();
        Ok(plan_injections(&specs, available, &[])?
            .into_iter()
            .map(|injection| (injection.name, injection.display))
            .collect())
    }

    #[test]
    fn derives_names_from_the_full_tuple() {
        let available = vault(&["app/prod/db", "app/prod/api-key", "2fa/seed"]);
        assert_eq!(
            plan(&["app/prod/db", "app/prod/api-key", "2fa/seed"], &available).unwrap(),
            vec![
                ("APP__PROD__DB".into(), "app/prod/db".into()),
                ("APP__PROD__API_KEY".into(), "app/prod/api-key".into()),
                ("_2FA__SEED".into(), "2fa/seed".into()),
            ]
        );
    }

    #[test]
    fn a_selector_expands_to_everything_under_it() {
        let available = vault(&[
            "app/prod/db",
            "app/prod/api-key",
            "app/staging/db",
            "ops/pager",
        ]);
        assert_eq!(
            plan(&["app/prod"], &available).unwrap(),
            vec![
                ("APP__PROD__API_KEY".into(), "app/prod/api-key".into()),
                ("APP__PROD__DB".into(), "app/prod/db".into()),
            ]
        );
        assert_eq!(plan(&["*"], &available).unwrap().len(), 4);
    }

    #[test]
    fn labels_filter_the_selection() {
        // Labels are part of identity, so a tuple can carry several secrets distinguished by
        // their labels; a label query selects across them.
        let available = vault(&[
            "app/db@env=prod",
            "app/cache@env=staging",
            "app/token",
            "ops/key@env=prod",
        ]);
        assert_eq!(
            plan(&["@env=prod"], &available).unwrap(),
            vec![
                ("APP__DB".into(), "app/db@env=prod".into()),
                ("OPS__KEY".into(), "ops/key@env=prod".into()),
            ]
        );
        assert_eq!(
            plan(&["ops@env"], &available).unwrap(),
            vec![("OPS__KEY".into(), "ops/key@env=prod".into())]
        );
        assert_eq!(
            plan(&["app@!env"], &available).unwrap(),
            vec![("APP__TOKEN".into(), "app/token".into())]
        );
    }

    #[test]
    fn multiple_labels_on_one_selector_all_apply() {
        let available = vault(&[
            "app/db@env=prod&tier=web",
            "app/queue@env=prod&tier=worker",
            "app/cache@env=staging&tier=web",
        ]);
        assert_eq!(
            plan(&["app@env=prod&tier=web"], &available).unwrap(),
            vec![("APP__DB".into(), "app/db@env=prod&tier=web".into())]
        );
        assert_eq!(
            plan(&["X=app@env=staging&tier=web"], &available).unwrap(),
            vec![("X".into(), "app/cache@env=staging&tier=web".into())]
        );
    }

    #[test]
    fn a_selection_touching_a_conflicted_secret_fails_closed() {
        let available = vault(&["app/token"]);
        let conflicted = vec![ConflictedSecret {
            label: "app/db".to_string(),
            claimed: vault(&["app/db@env=prod", "app/db@env=staging"]),
        }];
        let specs = vec!["app".to_string()];
        // The query covers the conflicted tuple (whichever labels its candidates claim):
        // the run must refuse rather than silently inject fewer variables than selected.
        let error = plan_injections(&specs, &available, &conflicted).unwrap_err();
        assert!(
            matches!(&error, FrontendError::SecretConflicted { selector } if selector == "app/db")
        );
        // A selection that cannot touch the conflicted tuple still runs.
        let specs = vec!["app/token".to_string()];
        assert_eq!(
            plan_injections(&specs, &available, &conflicted)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn an_erased_conflicted_secret_is_matched_by_its_remembered_selector() {
        // A rollback erased the records, but the origin remembers the whole selector
        // (`app/db@env=prod`). Label filters apply normally: a query whose labels the
        // remembered selector carries refuses, while a disjoint label exonerates it.
        let available = vault(&["ops/pager@env=staging"]);
        let conflicted = vec![ConflictedSecret {
            label: "app/db".to_string(),
            claimed: vault(&["app/db@env=prod"]),
        }];
        // `@env=prod` matches the remembered selector: refuse.
        let error =
            plan_injections(&["@env=prod".to_string()], &available, &conflicted).unwrap_err();
        assert!(matches!(&error, FrontendError::SecretConflicted { .. }));
        // The tuple prefix covers it regardless of labels: refuse.
        let error = plan_injections(&["app".to_string()], &available, &conflicted).unwrap_err();
        assert!(matches!(&error, FrontendError::SecretConflicted { .. }));
        // `@env=staging` is a label the remembered selector does not carry: the conflict is
        // exonerated and the run proceeds, injecting the matching available secret.
        assert_eq!(
            plan_injections(&["@env=staging".to_string()], &available, &conflicted)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn named_selectors_must_match_exactly_one_secret() {
        let available = vault(&["app/prod/db", "app/prod/api-key"]);
        let error = plan(&["X=app/prod"], &available).unwrap_err();
        assert!(matches!(
            error,
            FrontendError::AmbiguousNamedSelector { count: 2, .. }
        ));
    }

    #[test]
    fn overlapping_selectors_inject_a_secret_once() {
        let available = vault(&["app/prod/db", "app/prod/api-key"]);
        assert_eq!(plan(&["app", "app/prod/db"], &available).unwrap().len(), 2);
    }

    #[test]
    fn unmatched_selectors_fail_closed() {
        let available = vault(&["app/prod/db"]);
        let error = plan(&["app/nope"], &available).unwrap_err();
        assert!(
            matches!(error, FrontendError::SecretNotFound { selector } if selector == "app/nope")
        );
        let error = plan(&["app@env=prod"], &available).unwrap_err();
        assert!(matches!(error, FrontendError::SecretNotFound { .. }));
    }

    #[test]
    fn invalid_explicit_names_are_refused() {
        let available = vault(&["app/db"]);
        for spec in ["=app/db", "9X=app/db", "A B=app/db"] {
            let error = plan(&[spec], &available).unwrap_err();
            assert!(
                matches!(error, FrontendError::InvalidEnvName { .. }),
                "expected InvalidEnvName for {spec:?}"
            );
        }
    }

    #[test]
    fn selector_grammar_is_still_enforced() {
        let available = vault(&["app/db"]);
        let error = plan(&["X=app//db"], &available).unwrap_err();
        assert!(matches!(error, FrontendError::InvalidSelector { .. }));
        let error = plan(&[""], &available).unwrap_err();
        assert!(matches!(error, FrontendError::InvalidSelector { .. }));
    }
}
