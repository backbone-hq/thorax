use std::fs;

use assert_cmd::Command;
use serde_json::Value;

const UNSAFE_KEYCHAIN_PASSPHRASE_ENV: &str = "THORAX_UNSAFE_KEYCHAIN_PASSPHRASE";

#[test]
fn init_status_validate_and_secret_flow_work() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    let state = temp.path().join("state");
    fs::create_dir_all(&repo).unwrap();

    let init_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("init")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let init: Value = serde_json::from_slice(&init_output).unwrap();
    let root_user = init
        .get("root_user")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let trusted_root = init
        .get("trusted_root")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    assert_eq!(init.get("handle").and_then(Value::as_str), Some("root"));
    assert_eq!(init.get("vault_name").and_then(Value::as_str), Some("repo"));
    assert_eq!(
        init.get("default_user").and_then(Value::as_str),
        Some("root")
    );
    let current_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["user", "current"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let current: Value = serde_json::from_slice(&current_output).unwrap();
    assert_eq!(current["default_user"].as_str(), Some("root"));
    assert!(state.join(&trusted_root).join("ratchet.cord").exists());
    assert!(!repo
        .join(".thorax")
        .join(&trusted_root)
        .join("ratchet.cord")
        .exists());
    assert!(!repo.join(".thorax").join("config.toml").exists());
    assert!(!repo.join(".thorax").join("state").exists());

    // Default reads are trust-anchored: the identity unlocks (passphrase from the env),
    // possession-checks the verification cache, and pins membership.
    let status_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status_output).unwrap();
    assert_eq!(status["trusted"].as_bool(), Some(true));
    // Authentication is mandatory for reads: there is no `--untrusted` escape hatch.
    thorax(&repo, &keychain)
        .args(["--untrusted", "--json", "status"])
        .assert()
        .failure();
    thorax(&repo, &keychain).arg("validate").assert().success();

    let vault_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["vault", "show"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let vault: Value = serde_json::from_slice(&vault_output).unwrap();
    assert_eq!(vault["names"][0]["name"].as_str(), Some("repo"));

    thorax(&repo, &keychain)
        .args(["vault", "name", "set", "project"])
        .assert()
        .success();

    let users_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["user", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let users: Value = serde_json::from_slice(&users_output).unwrap();
    assert_eq!(
        users["users"][0]["handles"][0]["handle"].as_str(),
        Some("root")
    );
    let shown_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["user", "show", "root"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let shown: Value = serde_json::from_slice(&shown_output).unwrap();
    assert_eq!(shown["user"].as_str(), Some(root_user.as_str()));
    assert_eq!(shown["resolved_handle"].as_str(), Some("root"));

    thorax(&repo, &keychain)
        .args(["user", "handle", "set", "admin", "--target", "root"])
        .assert()
        .success();

    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "postgres://example"])
        .assert()
        .success();

    thorax(&repo, &keychain)
        .args(["get", "app/prod/db"])
        .assert()
        .success()
        .stdout("postgres://example");

    // `get --json` carries the value at the top level; `"secret"` stays reserved for the
    // secret-id hash (show/set/delete).
    let get_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["get", "app/prod/db"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let got: Value = serde_json::from_slice(&get_output).unwrap();
    assert_eq!(got["selector"].as_str(), Some("app/prod/db"));
    assert_eq!(got["plaintext"].as_str(), Some("postgres://example"));
    assert!(got.get("secret").is_none());

    let file_secret = temp.path().join("secret.txt");
    fs::write(&file_secret, b"from file").unwrap();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/file", "--user", "admin"])
        .arg("--file")
        .arg(&file_secret)
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["user", "use", "root"])
        .assert()
        .success();
    let current_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["user", "current"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let current: Value = serde_json::from_slice(&current_output).unwrap();
    assert_eq!(current["default_user"].as_str(), Some("root"));
    thorax(&repo, &keychain)
        .args(["user", "use", "admin"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["get", "app/prod/file", "--user", "admin"])
        .assert()
        .success()
        .stdout("from file");
    let status_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status_output).unwrap();
    assert_eq!(status["default_user"].as_str(), Some("admin"));

    let mut set_stdin = thorax(&repo, &keychain);
    set_stdin.args(["set", "app/prod/stdin"]);
    set_stdin.write_stdin("from stdin").assert().success();
    thorax(&repo, &keychain)
        .args(["get", "app/prod/stdin"])
        .assert()
        .success()
        .stdout("from stdin");

    let list_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: Value = serde_json::from_slice(&list_output).unwrap();
    assert_eq!(listed["secrets"].as_array().unwrap().len(), 3);

    let show_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["show", "app/prod/stdin"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let shown_secret: Value = serde_json::from_slice(&show_output).unwrap();
    assert_eq!(shown_secret["state"].as_str(), Some("active"));
    assert_eq!(shown_secret["access"].as_str(), Some("decryptable"));

    thorax(&repo, &keychain)
        .args([
            "set",
            "app/prod/stdin",
            "--value-unsafe",
            "rotated",
            "--rotate",
        ])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["get", "app/prod/stdin"])
        .assert()
        .success()
        .stdout("rotated");

    thorax(&repo, &keychain)
        .args(["delete", "app/prod/db", "--user", "root", "--yes"])
        .assert()
        .success();
    // `list` shows active secrets only; the deleted secret must disappear from it.
    let list_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: Value = serde_json::from_slice(&list_output).unwrap();
    assert!(!listed["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .any(|secret| secret["selector"].as_str() == Some("app/prod/db")));
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--user", "root"])
        .assert()
        .failure();
}

#[test]
fn invite_grant_group_and_delete_flow_work() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain)
        .args(["init", "--name", "project"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "secret"])
        .assert()
        .success();

    let alice_invite_output = thorax(&repo, &keychain)
        .arg("--json")
        .args([
            "user",
            "invite",
            "alice",
            "--read",
            "app/prod",
            "--print-unsafe",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let alice_invite: Value = serde_json::from_slice(&alice_invite_output).unwrap();
    let alice_bundle = alice_invite["invite"].as_str().unwrap();
    assert!(
        alice_bundle.starts_with("thrx1"),
        "invite should be bech32: {alice_bundle}"
    );
    thorax(&repo, &keychain)
        .args(["claim", "--invite", alice_bundle])
        .assert()
        .success();
    // Inviting alice with read access automatically encrypted existing matching secrets, so
    // she can read them immediately — no manual encrypt step.
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--user", "alice"])
        .assert()
        .success()
        .stdout("secret");

    let bob_invite_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["user", "invite", "bob", "--user", "root", "--invite-file"])
        .arg(temp.path().join("bob.identity.cord"))
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let bob_invite: Value = serde_json::from_slice(&bob_invite_output).unwrap();
    assert!(
        bob_invite.get("invite").is_none(),
        "JSON must not include invitation seed material without --print-unsafe"
    );
    let bob_bundle_file = bob_invite["invite_file"].as_str().unwrap();
    thorax(&repo, &keychain)
        .args(["claim", bob_bundle_file])
        .assert()
        .success();

    thorax(&repo, &keychain)
        .args(["group", "create", "devs", "--user", "root"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["group", "add", "devs", "bob", "--user", "root"])
        .assert()
        .success();
    let grant_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["grant", "read", "%devs", "app/prod", "--user", "root"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let grant: Value = serde_json::from_slice(&grant_output).unwrap();
    let grant_id = grant["grant"].as_str().unwrap();
    // Granting read to the group auto-encrypts existing secrets to bob (via membership), so he
    // can read immediately — no manual step.
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--user", "bob"])
        .assert()
        .success()
        .stdout("secret");

    let grant_list_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["grant", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let grant_list: Value = serde_json::from_slice(&grant_list_output).unwrap();
    assert!(grant_list["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|grant| grant["grant"].as_str() == Some(grant_id)));
    let group_list_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["group", "list"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let group_list: Value = serde_json::from_slice(&group_list_output).unwrap();
    assert_eq!(
        group_list["groups"][0]["members"][0]["member"]["handle"].as_str(),
        Some("bob")
    );

    thorax(&repo, &keychain)
        .args(["grant", "delete", grant_id, "--user", "root", "--yes"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--user", "bob"])
        .assert()
        .failure();

    thorax(&repo, &keychain)
        .args(["group", "remove", "devs", "bob", "--user", "root"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["user", "delete", "alice", "--user", "root", "--yes"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--user", "alice"])
        .assert()
        .failure();
}

#[test]
fn unusable_invite_destination_does_not_create_a_member() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    let destination = temp.path().join("already-a-directory");
    fs::create_dir_all(&repo).unwrap();
    fs::create_dir_all(&destination).unwrap();
    thorax(&repo, &keychain).arg("init").assert().success();

    thorax(&repo, &keychain)
        .args(["user", "invite", "alice", "--invite-file"])
        .arg(&destination)
        .assert()
        .failure();

    thorax(&repo, &keychain)
        .args(["user", "show", "alice"])
        .assert()
        .failure();
}

#[test]
fn invalid_selector_fails_before_keychain_prompt() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    fs::create_dir_all(repo.join(".thorax")).unwrap();

    thorax_without_keychain_env(&repo)
        .args([
            "get",
            "/app//db",
            "--user",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ])
        .assert()
        .failure();
}

#[test]
fn invite_refuses_terminal_and_claim_onboards_fresh_machine() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let root_keychain = temp.path().join("root").join("keychain");
    let alice_keychain = temp.path().join("alice").join("keychain");
    let bundle = temp.path().join("alice.bundle");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &root_keychain).arg("init").assert().success();
    thorax(&repo, &root_keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "topsecret"])
        .assert()
        .success();

    // Inviting without a destination must refuse rather than print private keys.
    thorax(&repo, &root_keychain)
        .args(["user", "invite", "alice", "--read", "app"])
        .assert()
        .failure();

    // Inviting to a file succeeds and writes the bundle.
    thorax(&repo, &root_keychain)
        .args(["user", "invite", "alice", "--read", "app", "--invite-file"])
        .arg(&bundle)
        .assert()
        .success();
    assert!(bundle.exists());

    // Inviting alice with read access auto-encrypts the pre-existing secret to her, so she can
    // read it immediately on claim — no manual step.

    // Alice on a fresh machine (separate keychain + empty state) claims and reads.
    thorax(&repo, &alice_keychain)
        .arg("claim")
        .arg(&bundle)
        .assert()
        .success();
    thorax(&repo, &alice_keychain)
        .args(["get", "app/prod/db"])
        .assert()
        .success()
        .stdout("topsecret");
}

// A read must not require the workspace lock: `thorax get` only loads and validates the vault
// snapshot — nothing it does writes the vault — so a lock held by another process (or left behind
// by a crash) cannot block it. This is an intentional behavior improvement over the old
// load-path, which failed closed on a held lock even for pure reads.
#[test]
fn get_succeeds_while_lock_is_held() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "postgres://example"])
        .assert()
        .success();

    // Simulate another holder: the lock file's presence is the lock.
    let lock_path = repo.join(".thorax").join("vault.cord.lock");
    fs::write(&lock_path, b"held-by-another-process").unwrap();

    thorax(&repo, &keychain)
        .args(["get", "app/prod/db"])
        .assert()
        .success()
        .stdout("postgres://example");
    assert!(
        lock_path.exists(),
        "the read must not steal or remove the lock"
    );
}

fn thorax(repo: &std::path::Path, keychain: &std::path::Path) -> Command {
    let mut command = thorax_without_keychain_env(repo);
    command
        .env("THORAX_KEYCHAIN_DIR", keychain)
        .env("THORAX_STATE_DIR", keychain.parent().unwrap().join("state"))
        .env(UNSAFE_KEYCHAIN_PASSPHRASE_ENV, "test passphrase");
    command
}

// A `manage` (or `write`) grant confers read via the capability hierarchy, so granting it must
// auto-encrypt pre-existing secrets to the new holder — exactly like a `read` grant. Regression
// guard: the grant-time reconcile must fire for every read-conferring grant kind, not just read.
#[test]
fn granting_manage_auto_encrypts_to_the_new_manager() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let root_keychain = temp.path().join("root").join("keychain");
    let bob_keychain = temp.path().join("bob").join("keychain");
    let bundle = temp.path().join("bob.bundle");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &root_keychain).arg("init").assert().success();
    thorax(&repo, &root_keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "topsecret"])
        .assert()
        .success();
    // Invite bob with no keyspace access at all.
    thorax(&repo, &root_keychain)
        .args(["user", "invite", "bob", "--invite-file"])
        .arg(&bundle)
        .assert()
        .success();
    // Grant bob manage on app. manage ⊃ read, so the pre-existing secret must be encrypted to him.
    thorax(&repo, &root_keychain)
        .args(["grant", "manage", "bob", "app"])
        .assert()
        .success();
    // Bob claims on a fresh machine and reads immediately — no manual step.
    thorax(&repo, &bob_keychain)
        .arg("claim")
        .arg(&bundle)
        .assert()
        .success();
    thorax(&repo, &bob_keychain)
        .args(["get", "app/prod/db", "--force"])
        .assert()
        .success()
        .stdout("topsecret");
}

// An `administer` grant sits above manage/write/read, so it must also be treated as a
// read-conferring access addition and rewrap existing secrets to the new administrator.
#[test]
fn granting_admin_auto_encrypts_to_the_new_admin() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let root_keychain = temp.path().join("root").join("keychain");
    let bob_keychain = temp.path().join("bob").join("keychain");
    let bundle = temp.path().join("bob.bundle");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &root_keychain).arg("init").assert().success();
    thorax(&repo, &root_keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "topsecret"])
        .assert()
        .success();
    thorax(&repo, &root_keychain)
        .args(["user", "invite", "bob", "--invite-file"])
        .arg(&bundle)
        .assert()
        .success();
    thorax(&repo, &root_keychain)
        .args(["grant", "admin", "bob"])
        .assert()
        .success();
    thorax(&repo, &bob_keychain)
        .arg("claim")
        .arg(&bundle)
        .assert()
        .success();
    thorax(&repo, &bob_keychain)
        .args(["get", "app/prod/db", "--force"])
        .assert()
        .success()
        .stdout("topsecret");
}

// CI access: an identity injected via THORAX_UNSAFE_INVITE_FILE must let the CLI read the
// vault on a fresh checkout — no keychain dir, no passphrase, no explicit `claim`. The first
// command bootstraps local trust from the bundle and the injected identity becomes the actor.
#[test]
fn ci_identity_via_env_bundle_reads_without_keychain_or_claim() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let admin_keychain = temp.path().join("admin").join("keychain");
    let bundle = temp.path().join("ci.bundle");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &admin_keychain)
        .arg("init")
        .assert()
        .success();
    thorax(&repo, &admin_keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "topsecret"])
        .assert()
        .success();
    thorax(&repo, &admin_keychain)
        .args(["user", "invite", "ci", "--read", "app", "--invite-file"])
        .arg(&bundle)
        .assert()
        .success();

    // Fresh "CI checkout": only the bundle file + an ephemeral trust dir. No keychain, no --user.
    let ci_state = temp.path().join("ci-state");
    thorax_without_keychain_env(&repo)
        .env("THORAX_UNSAFE_INVITE_FILE", &bundle)
        .env("THORAX_STATE_DIR", &ci_state)
        .args(["get", "app/prod/db", "--force"])
        .assert()
        .success()
        .stdout("topsecret");

    // A bundle for a different vault must be rejected (membership/rollback safety still applies).
    let other_repo = temp.path().join("other");
    fs::create_dir_all(&other_repo).unwrap();
    thorax(&other_repo, &temp.path().join("other").join("keychain"))
        .arg("init")
        .assert()
        .success();
    thorax_without_keychain_env(&other_repo)
        .env("THORAX_UNSAFE_INVITE_FILE", &bundle)
        .env("THORAX_STATE_DIR", temp.path().join("ci-state-2"))
        .args(["get", "app/prod/db", "--force"])
        .assert()
        .failure();
}

fn thorax_without_keychain_env(repo: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("thorax").unwrap();
    command.arg("--path").arg(repo);
    command
}

// `thorax run` expands each positional selector against the vault (the path itself and
// everything under it), injects with full-path derived names or explicit NAME= overrides,
// executes the command directly, and forwards the child's exit status because the process is
// exec-replaced on Unix.
#[test]
fn run_injects_selected_secrets_and_forwards_exit_code() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "postgres://example"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/api-key", "--value-unsafe", "k-123"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["set", "ops/pager", "--value-unsafe", "p-1"])
        .assert()
        .success();

    // One prefix selector covers both app/prod secrets; ops/pager is not selected.
    thorax(&repo, &keychain)
        .args([
            "run",
            "app/prod",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s' \"$APP__PROD__DB\" \"$APP__PROD__API_KEY\" \"${OPS__PAGER:-unset}\"",
        ])
        .assert()
        .success()
        .stdout("postgres://example|k-123|unset");

    // An explicit NAME= renames a single match.
    thorax(&repo, &keychain)
        .args([
            "run",
            "TOKEN=app/prod/api-key",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$TOKEN\"",
        ])
        .assert()
        .success()
        .stdout("k-123");

    let exit = thorax(&repo, &keychain)
        .args(["run", "app/prod/db", "--", "sh", "-c", "exit 7"])
        .assert()
        .failure();
    assert_eq!(exit.get_output().status.code(), Some(7));
}

// Selection by label: a query like @env=prod picks the labeled secrets the same way a
// label-scoped grant would, and NAME= demands an unambiguous match. A secret's identity is
// its whole selector — labels are scope axes, not metadata — so re-setting a tuple with a
// different label creates a *second* secret rather than moving the first.
#[test]
fn run_selects_by_label() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/db@env=prod", "--value-unsafe", "prod-db"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args([
            "set",
            "app/cache@env=staging",
            "--value-unsafe",
            "staging-cache",
        ])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["set", "app/token", "--value-unsafe", "t-1"])
        .assert()
        .success();

    // Label-only query: everything labeled env=prod, regardless of path.
    thorax(&repo, &keychain)
        .args([
            "run",
            "@env=prod",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$APP__DB\"",
        ])
        .assert()
        .success()
        .stdout("prod-db");

    // Tuple + absence matcher: secrets under app/ with no env label at all.
    thorax(&repo, &keychain)
        .args([
            "run",
            "app@!env",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$APP__TOKEN\"",
        ])
        .assert()
        .success()
        .stdout("t-1");

    // Label queries narrow to the matching secrets; explicit names rename single matches.
    thorax(&repo, &keychain)
        .args([
            "run",
            "PROD=app@env=prod",
            "STAGING=app@env=staging",
            "--",
            "sh",
            "-c",
            "printf '%s|%s' \"$PROD\" \"$STAGING\"",
        ])
        .assert()
        .success()
        .stdout("prod-db|staging-cache");

    // NAME= over a selector matching two secrets is refused as ambiguous (taxonomy's
    // AMBIGUOUS code, 10: the reference matched more than one thing).
    let ambiguous = thorax(&repo, &keychain)
        .args(["run", "X=app@env", "--", "true"])
        .assert()
        .failure();
    assert_eq!(ambiguous.get_output().status.code(), Some(10));

    // Whole-selector identity: setting app/db with a *different* label adds a second secret
    // alongside the prod one — it does not move it away.
    thorax(&repo, &keychain)
        .args(["set", "app/db@env=staging", "--value-unsafe", "staging-db"])
        .assert()
        .success();
    // The prod variant still resolves — the staging write left it untouched.
    thorax(&repo, &keychain)
        .args([
            "run",
            "@env=prod",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$APP__DB\"",
        ])
        .assert()
        .success()
        .stdout("prod-db");
    // Each labeled selector reads its own value; the two coexist at the same tuple.
    for (selector, expected) in [
        ("app/db@env=prod", "prod-db"),
        ("app/db@env=staging", "staging-db"),
    ] {
        let value = thorax(&repo, &keychain)
            .args(["get", selector, "--force"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone();
        assert_eq!(String::from_utf8(value).unwrap(), expected);
    }
}

// Pre-existing environment variables are never overwritten silently: the run is refused unless
// the user opts in with --overwrite.
#[test]
fn run_refuses_env_collisions_unless_overwrite() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "injected"])
        .assert()
        .success();

    let refused = thorax(&repo, &keychain)
        .env("APP__PROD__DB", "preexisting")
        .args(["run", "app/prod/db", "--", "true"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(String::from_utf8_lossy(&refused).contains("APP__PROD__DB"));

    thorax(&repo, &keychain)
        .env("APP__PROD__DB", "preexisting")
        .args([
            "run",
            "--overwrite",
            "app/prod/db",
            "--",
            "sh",
            "-c",
            "printf '%s' \"$APP__PROD__DB\"",
        ])
        .assert()
        .success()
        .stdout("injected");
}

// Two distinct secrets that map to the same variable name are ambiguous and refused up front.
#[test]
fn run_refuses_duplicate_env_names() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "a"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["set", "app/staging/db", "--value-unsafe", "b"])
        .assert()
        .success();

    let stderr = thorax(&repo, &keychain)
        .args(["run", "X=app/prod/db", "X=app/staging/db", "--", "true"])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    assert!(String::from_utf8_lossy(&stderr).contains("NAME=selector"));
}

// Thorax key material must never reach the child environment: the keychain passphrase and any
// inline invite are stripped even though thorax itself was invoked with them.
#[test]
fn run_strips_thorax_key_material_from_child_env() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "v"])
        .assert()
        .success();

    thorax(&repo, &keychain)
        .args([
            "run",
            "app/prod/db",
            "--",
            "sh",
            "-c",
            "printf '%s' \"${THORAX_UNSAFE_KEYCHAIN_PASSPHRASE:-scrubbed}\"",
        ])
        .assert()
        .success()
        .stdout("scrubbed");
}

// A selector matching nothing fails closed, naming the selector, before anything is launched;
// an unknown command fails with the shell convention exit code 127.
#[test]
fn run_fails_closed_on_missing_secret_and_missing_command() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "v"])
        .assert()
        .success();

    let missing = thorax(&repo, &keychain)
        .args(["run", "app/prod/nope", "--", "true"])
        .assert()
        .failure();
    let stderr = String::from_utf8_lossy(&missing.get_output().stderr).to_string();
    assert!(stderr.contains("app/prod/nope"));
    assert_eq!(missing.get_output().status.code(), Some(3));

    let unknown = thorax(&repo, &keychain)
        .args([
            "run",
            "app/prod/db",
            "--",
            "definitely-not-a-real-command-xyz",
        ])
        .assert()
        .failure();
    assert_eq!(unknown.get_output().status.code(), Some(127));
}

// End-to-end merge flow: two "clones" (same identity, separate local-trust state) write the
// same secret concurrently from the same base, producing a same-counter tie. The driver
// writes the union and exits non-zero; `thorax conflicts` lists the tie; `conflicts resolve`
// re-signs the chosen candidate at a fresh counter and clears it. A concurrent write at a
// different key merges cleanly with exit 0.
#[test]
fn merge_driver_unions_ties_and_resolve_clears_them() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    let state = temp.path().join("state");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "base-value"])
        .assert()
        .success();

    let vault_path = repo.join(".thorax").join("vault.cord");
    let base_bytes = fs::read(&vault_path).unwrap();
    let state_snapshot: Vec<(std::path::PathBuf, Vec<u8>)> = walk_files(&state);

    // Clone A writes the secret...
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "value-a"])
        .assert()
        .success();
    let ours_bytes = fs::read(&vault_path).unwrap();

    // ...and clone B writes the same secret from the same base (vault and local trust
    // restored), so both writes carry the same Lamport counter.
    fs::write(&vault_path, &base_bytes).unwrap();
    for (path, bytes) in &state_snapshot {
        fs::write(path, bytes).unwrap();
    }
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "value-b"])
        .assert()
        .success();
    let theirs_bytes = fs::read(&vault_path).unwrap();

    // Git hands the driver three temp files and expects the result in "ours".
    let base_file = temp.path().join("base.cord");
    let ours_file = temp.path().join("ours.cord");
    let theirs_file = temp.path().join("theirs.cord");
    fs::write(&base_file, &base_bytes).unwrap();
    fs::write(&ours_file, &ours_bytes).unwrap();
    fs::write(&theirs_file, &theirs_bytes).unwrap();

    let driver = thorax(&repo, &keychain)
        .arg("merge-driver")
        .arg(&base_file)
        .arg(&ours_file)
        .arg(&theirs_file)
        .assert()
        .failure();
    let stderr = String::from_utf8(driver.get_output().stderr.clone()).unwrap();
    assert!(
        stderr.contains("tie"),
        "driver stderr should mention the tie: {stderr}"
    );

    // The union landed in "ours" (it grew), and is what the working tree now holds.
    let union_bytes = fs::read(&ours_file).unwrap();
    assert!(union_bytes.len() > ours_bytes.len());
    fs::write(&vault_path, &union_bytes).unwrap();

    // The conflicted union still validates: both candidates coexist; the tied key is
    // simply conflicted (no effective value) until an explicit resolution.
    thorax(&repo, &keychain).arg("validate").assert().success();

    // A conflicted secret has no current value: reads fail closed, and the listing flags it.
    let conflicted_get = thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--force"])
        .assert()
        .failure();
    let conflicted_stderr = String::from_utf8(conflicted_get.get_output().stderr.clone()).unwrap();
    assert!(
        conflicted_stderr.contains("conflicted"),
        "get of a conflicted secret should say so: {conflicted_stderr}"
    );
    let list = thorax(&repo, &keychain)
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let list = String::from_utf8(list).unwrap();
    assert!(
        list.lines()
            .any(|line| line.starts_with("app/prod/db") && line.contains("conflict")),
        "listing should flag the conflicted secret: {list}"
    );

    // Unresolved conflicts exit with the taxonomy's CONFLICT code (9), not the catch-all.
    let status = thorax(&repo, &keychain)
        .arg("--json")
        .args(["conflicts"])
        .assert()
        .code(9)
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status).unwrap();
    let conflicts = status["conflicts"].as_array().unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["kind"].as_str(), Some("secret"));
    assert_eq!(conflicts[0]["conflict"].as_str(), Some("tie"));
    assert_eq!(conflicts[0]["label"].as_str(), Some("app/prod/db"));
    assert_eq!(
        conflicts[0]["resolvable_by_default_user"].as_bool(),
        Some(true)
    );
    let candidates = conflicts[0]["candidates"].as_array().unwrap();
    assert_eq!(candidates.len(), 2);

    // The explicit pick — and nothing else — decides the winner.
    let pick = candidates[0]["record_hash"].as_str().unwrap();
    let resolve = thorax(&repo, &keychain)
        .arg("--json")
        .args(["conflicts", "resolve", pick, "--yes"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let resolve: Value = serde_json::from_slice(&resolve).unwrap();
    assert_eq!(resolve["remaining_conflicts"].as_u64(), Some(0));

    thorax(&repo, &keychain)
        .args(["conflicts"])
        .assert()
        .success();
    let value = thorax(&repo, &keychain)
        .args(["get", "app/prod/db", "--force"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let value = String::from_utf8(value).unwrap();
    assert!(
        value == "value-a" || value == "value-b",
        "resolved value should be one of the candidates: {value:?}"
    );

    // Concurrent writes at *different* keys merge cleanly: union written, exit 0.
    fs::write(&vault_path, &base_bytes).unwrap();
    for (path, bytes) in &state_snapshot {
        fs::write(path, bytes).unwrap();
    }
    thorax(&repo, &keychain)
        .args(["set", "app/prod/other", "--value-unsafe", "other-value"])
        .assert()
        .success();
    let disjoint_bytes = fs::read(&vault_path).unwrap();
    fs::write(&ours_file, &ours_bytes).unwrap();
    fs::write(&theirs_file, &disjoint_bytes).unwrap();
    thorax(&repo, &keychain)
        .arg("merge-driver")
        .arg(&base_file)
        .arg(&ours_file)
        .arg(&theirs_file)
        .assert()
        .success();
    assert!(fs::read(&ours_file).unwrap().len() > ours_bytes.len());
}

// Registration: `thorax git install` writes the committed .gitattributes entry and the
// per-clone [merge "thorax"] config; `status` reports the unregistered state as a hint.
#[test]
fn merge_install_registers_gitattributes_and_config() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .output()
            .expect("git must be runnable in tests")
    };
    assert!(git(&["init", "--quiet"]).status.success());

    thorax(&repo, &keychain).arg("init").assert().success();
    // init inside a git repo registers automatically; install is then a no-op…
    let status_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("status")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let status: Value = serde_json::from_slice(&status_output).unwrap();
    assert_eq!(status["merge_driver"].as_str(), Some("registered"));
    assert_eq!(status["conflicts"].as_u64(), Some(0));

    let attributes = fs::read_to_string(repo.join(".gitattributes")).unwrap();
    assert!(attributes.contains(".thorax/vault.cord merge=thorax-merge"));
    let config = git(&["config", "--get", "merge.thorax-merge.driver"]);
    assert!(config.status.success());
    assert_eq!(
        String::from_utf8(config.stdout).unwrap().trim(),
        "thorax merge-driver %O %A %B"
    );

    // …and remains idempotent when run again explicitly.
    thorax(&repo, &keychain)
        .args(["git", "install"])
        .assert()
        .success();
    let attributes_again = fs::read_to_string(repo.join(".gitattributes")).unwrap();
    assert_eq!(attributes, attributes_again);
}

#[test]
fn move_rekeys_a_secret_preserving_value() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/staging/db", "--value-unsafe", "staging-url"])
        .assert()
        .success();

    // Move from staging to prod.
    let move_output = thorax(&repo, &keychain)
        .arg("--json")
        .args(["move", "app/staging/db", "app/prod/db"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let moved: Value = serde_json::from_slice(&move_output).unwrap();
    assert_eq!(moved["moved"]["from"].as_str(), Some("app/staging/db"));
    assert_eq!(moved["moved"]["to"].as_str(), Some("app/prod/db"));
    assert!(moved["user"].as_str().unwrap().len() >= 8);

    // Value is readable at the new location.
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db"])
        .assert()
        .success()
        .stdout("staging-url");

    // Old location is gone.
    thorax(&repo, &keychain)
        .args(["get", "app/staging/db", "--user", "root"])
        .assert()
        .failure();

    // Only one secret listed (the tombstone is hidden from `list`).
    let list_output = thorax(&repo, &keychain)
        .arg("--json")
        .arg("list")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let listed: Value = serde_json::from_slice(&list_output).unwrap();
    assert_eq!(listed["secrets"].as_array().unwrap().len(), 1);
    assert_eq!(
        listed["secrets"][0]["selector"].as_str(),
        Some("app/prod/db")
    );
}

#[test]
fn move_from_nonexistent_source_fails() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();

    // Move from a non-existent source must fail closed. Use the short alias here.
    thorax(&repo, &keychain)
        .args(["mv", "app/nope", "app/anywhere"])
        .assert()
        .failure();
}

#[test]
fn move_refuses_to_overwrite_existing_destination() {
    let temp = tempfile::tempdir().unwrap();
    let repo = temp.path().join("repo");
    let keychain = temp.path().join("keychain");
    fs::create_dir_all(&repo).unwrap();

    thorax(&repo, &keychain).arg("init").assert().success();
    thorax(&repo, &keychain)
        .args(["set", "app/staging/db", "--value-unsafe", "staging-url"])
        .assert()
        .success();
    thorax(&repo, &keychain)
        .args(["set", "app/prod/db", "--value-unsafe", "prod-url"])
        .assert()
        .success();

    thorax(&repo, &keychain)
        .args(["move", "app/staging/db", "app/prod/db"])
        .assert()
        .failure();

    thorax(&repo, &keychain)
        .args(["get", "app/staging/db"])
        .assert()
        .success()
        .stdout("staging-url");
    thorax(&repo, &keychain)
        .args(["get", "app/prod/db"])
        .assert()
        .success()
        .stdout("prod-url");
}

fn walk_files(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                let bytes = fs::read(&path).unwrap();
                files.push((path, bytes));
            }
        }
    }
    files
}
