use super::*;
use crate::crypto::{derive_seeded_hash, derive_user_id, key_hash, DeterministicCrypto};
use crate::ratchet::KeyOrigin;
use crate::test_support::*;

#[test]
fn valid_grant_chain_allows_active_secret_only_for_readers() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob");
    let selector = secret_selector(&["app", "prod"]);

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            5,
        ),
        secret_record(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            6,
        ),
    ];

    let report = fixture.validate(records);
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &alice.id, &fixture.crypto),
        SecretState::ActiveDecryptable
    );
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &bob.id, &fixture.crypto),
        SecretState::Unauthorized
    );
}

#[test]
fn deleting_a_writer_drops_their_lww_winning_record() {
    // A Byzantine (or NTP-poisoned) writer can stamp an arbitrarily high Lamport counter
    // and so win LWW for a key. The Lamport clock does not defend against this — the remedy
    // is authority, not ordering: once the writer is deleted, `authority_for_user` empties
    // and their record drops from LWW candidacy, so the next-highest record from a
    // still-authorized writer wins. This pins that remedy.
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let selector = secret_selector(&["app", "prod"]);
    let readers = [&fixture.root, &alice];

    let base = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        // Root's honest value (low counter) vs. alice's forward-dated poison (huge counter).
        secret_record(&fixture.crypto, &fixture.root, &selector, &readers, 5),
        secret_record(&fixture.crypto, &alice, &selector, &readers, 1_000_000),
    ];

    let signer_of_active = |report: &ValidationReport| {
        report
            .effective
            .secret_record(&selector, &fixture.crypto)
            .unwrap()
            .expect("an active secret value")
            .signed
            .signing_public_key
    };

    // While alice is authorized, her forward-dated counter dominates.
    let report = fixture.validate(base.clone());
    assert_eq!(signer_of_active(&report), alice.signing_public_key);

    // Deleting alice drops her record from candidacy; root's lower-counter value now wins.
    let mut deleted = base;
    deleted.push(user_deleted_record(
        &fixture.crypto,
        &fixture.root,
        alice.id.clone(),
        4,
    ));
    let report = fixture.validate(deleted);
    assert!(report.effective.deleted_users.contains(&alice.id));
    assert_eq!(signer_of_active(&report), fixture.root.signing_public_key);
}

#[test]
fn unattested_pairing_claim_is_ignored_not_collided() {
    // A signature attests only to a signing key, but a UserId commits to *both* keys. The
    // hazard: a member appends a `User` record pairing a victim's real signing key with a
    // different HPKE key, minting a second UserId over that key. Resolution only counts a
    // pairing once it is *attested* by a self-signed entry point under that key — which
    // only the key's holder can produce. Here the twin pairing has no entry point, so it is
    // ignored: alice resolves cleanly and her signed secret stays active, no collision, no
    // block. (The production end-to-end attack — where the attacker genuinely cannot sign
    // the victim's entry point — is pinned in thorax-ops.)
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    // A second identity reusing alice's signing key but a different HPKE key, with no
    // self-signed entry point of its own (so it cannot attest alice's key).
    let twin = TestUser {
        id: derive_user_id(&fixture.crypto, &alice.signing_public_key, b"twin:hpke").unwrap(),
        signing_public_key: alice.signing_public_key.clone(),
        hpke_public_key: b"twin:hpke".to_vec(),
    };
    assert_ne!(alice.id, twin.id);

    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        // The unattested impostor pairing on alice's signing key.
        user_record(&fixture, &twin, 3),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
        secret_record(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            5,
        ),
    ];

    let report = fixture.validate(records);
    // The forged pairing neither collides nor blocks: it names an identity no entry point
    // attests, so it is simply ignored.
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(
        !report
            .warnings
            .iter()
            .any(|warning| matches!(warning, ValidationWarning::AmbiguousSigningKey(_))),
        "{:?}",
        report.warnings
    );
    // Alice's key resolves to alice, so her signed secret is active.
    assert!(report
        .effective
        .secret_record(&selector, &fixture.crypto)
        .unwrap()
        .is_some());
}

#[test]
fn self_collision_localizes_to_the_contested_key() {
    // The only way two *attested* identities share a signing key is for the key's own
    // holder to self-sign two entry points declaring different pairings — corruption, not
    // an attack on anyone else. When it happens the blast radius is contained: records
    // signed under the contested key are inert (a localized warning names it), while the
    // rest of the vault validates. A self-collision can therefore only deny the colliding
    // party their own records, never brick the vault for everyone.
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let twin = TestUser {
        id: derive_user_id(&fixture.crypto, &alice.signing_public_key, b"twin:hpke").unwrap(),
        signing_public_key: alice.signing_public_key.clone(),
        hpke_public_key: b"twin:hpke".to_vec(),
    };
    let bob = test_user(&fixture.crypto, "bob");

    let alice_selector = secret_selector(&["app", "alice"]);
    let bob_selector = secret_selector(&["app", "bob"]);
    let records = vec![
        vault_root_record(&fixture),
        // Alice and her twin each post a self-signed entry point under the shared key: two
        // attested pairings on one key — the self-collision.
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &twin, 3),
        trust_root(&fixture.crypto, &twin, &fixture, 3),
        // Bob is an independent, uncontested member.
        user_record(&fixture, &bob, 4),
        trust_root(&fixture.crypto, &bob, &fixture, 4),
        grant_record(
            &fixture.crypto,
            "bob-write",
            &fixture.root,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            5,
        ),
        // A secret signed under the contested key, and one under bob's clean key.
        secret_record(
            &fixture.crypto,
            &alice,
            &alice_selector,
            &[&fixture.root],
            6,
        ),
        secret_record(
            &fixture.crypto,
            &bob,
            &bob_selector,
            &[&fixture.root, &bob],
            7,
        ),
    ];

    let report = fixture.validate(records);
    // Localized, not global: no blocking issues, just a warning naming the contested key.
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| matches!(warning, ValidationWarning::AmbiguousSigningKey(_))),
        "{:?}",
        report.warnings
    );
    // The contested key's record is inert...
    assert!(report
        .effective
        .secret_record(&alice_selector, &fixture.crypto)
        .unwrap()
        .is_none());
    // ...but the rest of the vault is unaffected: bob's secret is active.
    assert!(report
        .effective
        .secret_record(&bob_selector, &fixture.crypto)
        .unwrap()
        .is_some());
}

#[test]
fn counters_above_the_ceiling_are_rejected_as_corrupt() {
    // A near-u64::MAX counter would tie with every later write forever — a permanent
    // wedge no well-behaved client (one increment per write) can produce. Such a record
    // is structurally invalid and blocks the vault; writers refuse to mint past the
    // ceiling (see thorax-ops).
    let fixture = Fixture::new();
    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            crate::validate::MAX_LWW_COUNTER + 1,
        ),
    ];

    let report = fixture.validate(records);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| matches!(issue, ValidationIssue::InvalidStructure(_))),
        "{:?}",
        report.issues
    );

    // At or below the ceiling is still an ordinary record.
    let records = vec![
        vault_root_record(&fixture),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            crate::validate::MAX_LWW_COUNTER,
        ),
    ];
    assert!(fixture.validate(records).issues.is_empty());
}

#[test]
fn an_extra_recipient_slot_does_not_block_a_readers_read() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob"); // bob has no read grant
    let selector = secret_selector(&["app", "prod"]);

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            5,
        ),
        // The value carries a slot for bob, who is not a current reader (a former
        // reader's leftover). It must not block alice's read.
        secret_record(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice, &bob],
            6,
        ),
    ];

    let report = fixture.validate(records);
    // alice holds a valid slot, so she reads regardless of bob's extra slot.
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &alice.id, &fixture.crypto),
        SecretState::ActiveDecryptable
    );
    // bob has no read authority, so Thorax will not serve him (his leftover slot only
    // lets him decrypt the raw record out-of-band — the accepted historical limitation).
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &bob.id, &fixture.crypto),
        SecretState::Unauthorized
    );
}

#[test]
fn weaker_manager_cannot_delete_stronger_active_grant() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob");
    let target_grant = grant_id(&fixture.crypto, "bob-write");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "alice-manage-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: KeyspaceSelectorV1::all(),
                grantable: vec![KeyspaceGrantClassV1::Read],
            }),
            4,
        ),
        grant_record_with_id(
            &fixture.crypto,
            "bob-write",
            &fixture.root,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            5,
        ),
        grant_deleted_record(
            &fixture.crypto,
            &alice,
            target_grant.clone(),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            6,
        ),
    ];

    let report = fixture.validate(records);
    assert!(!report.effective.deleted_grants.contains(&target_grant));
    assert!(report
        .effective
        .authority_for_user(&bob.id)
        .can_write(&secret_selector(&["any"])));
}

#[test]
fn unauthorized_same_key_update_does_not_shadow_valid_grant() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record_with_id(
            &fixture.crypto,
            "shared-grant",
            &fixture.root,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
        grant_record_with_id(
            &fixture.crypto,
            "shared-grant",
            &alice,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::Administer,
            5,
        ),
    ];

    let report = fixture.validate(records);
    assert!(report
        .effective
        .authority_for_user(&bob.id)
        .can_read(&secret_selector(&["app"])));
    assert!(!report.effective.authority_for_user(&alice.id).administer);
}

#[test]
fn read_only_members_cannot_poison_watermarks_or_the_next_counter() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root, &alice],
            4,
        ),
        // Signature-valid, structurally-valid, but authority-inert.
        secret_record(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            MAX_LWW_COUNTER,
        ),
    ];

    let report = fixture.validate(records);
    assert!(report.issues.is_empty());
    assert_eq!(next_counter(&report.effective), 5);
    assert!(report
        .ratchet_update
        .raised_watermarks
        .values()
        .all(|counter| *counter < MAX_LWW_COUNTER));
}

#[test]
fn manage_keyspace_delegates_only_to_selector_and_below() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "alice-manage-app",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: keyspace_prefix(&["app"]),
                grantable: vec![KeyspaceGrantClassV1::Read],
            }),
            4,
        ),
        // Alice must also hold read on app to be able to hand it out (manage alone is not
        // enough — you can only grant a use-permission you have).
        grant_record(
            &fixture.crypto,
            "alice-read-app",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(keyspace_prefix(&["app"])),
            5,
        ),
        grant_record(
            &fixture.crypto,
            "bob-read-app-prod",
            &alice,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ReadKeyspace(keyspace_prefix(&["app", "prod"])),
            6,
        ),
        grant_record(
            &fixture.crypto,
            "bob-read-other",
            &alice,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ReadKeyspace(keyspace_prefix(&["other"])),
            7,
        ),
    ];

    let report = fixture.validate(records);
    let bob_auth = report.effective.authority_for_user(&bob.id);
    assert!(bob_auth.can_read(&secret_selector(&["app", "prod", "db"])));
    // Alice neither manages nor reads `other`, so that grant is ineffective.
    assert!(!bob_auth.can_read(&secret_selector(&["other", "db"])));
}

#[test]
fn read_grant_requires_read_in_manage_grantable() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob");

    // Alice manages app with Read in her grantable set. Under the capability hierarchy this
    // both lets her read app herself and lets her delegate read — so bob's grant is effective.
    let with_read_grantable = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "alice-manage-app",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: keyspace_prefix(&["app"]),
                grantable: vec![KeyspaceGrantClassV1::Read],
            }),
            4,
        ),
        grant_record(
            &fixture.crypto,
            "bob-read-app",
            &alice,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ReadKeyspace(keyspace_prefix(&["app"])),
            5,
        ),
    ];
    let report = fixture.validate(with_read_grantable);
    assert!(
        report
            .effective
            .authority_for_user(&bob.id)
            .can_read(&secret_selector(&["app", "db"])),
        "a manager with Read in grantable can read and can delegate read"
    );

    // Alice manages app but only with Write in her grantable set. The hierarchy still lets her
    // read app, but she cannot *delegate* read — so bob's read grant is ineffective.
    let without_read_grantable = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "alice-manage-app",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: keyspace_prefix(&["app"]),
                grantable: vec![KeyspaceGrantClassV1::Write],
            }),
            4,
        ),
        grant_record(
            &fixture.crypto,
            "bob-read-app",
            &alice,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ReadKeyspace(keyspace_prefix(&["app"])),
            5,
        ),
    ];
    let report = fixture.validate(without_read_grantable);
    assert!(
        !report
            .effective
            .authority_for_user(&bob.id)
            .can_read(&secret_selector(&["app", "db"])),
        "without Read in grantable a manager cannot delegate read"
    );
}

#[test]
fn group_cycle_without_group_grant_does_not_create_authority() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let group_a = group_id(&fixture.crypto, "group-a");
    let group_b = group_id(&fixture.crypto, "group-b");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        group_record(&fixture.crypto, &fixture.root, "group-a", "a", 3),
        group_record(&fixture.crypto, &fixture.root, "group-b", "b", 4),
        group_member_record(
            &fixture.crypto,
            &fixture.root,
            group_a.clone(),
            PrincipalRefV1::Group(group_b.clone()),
            5,
        ),
        group_member_record(
            &fixture.crypto,
            &fixture.root,
            group_b,
            PrincipalRefV1::Group(group_a.clone()),
            6,
        ),
        group_member_record(
            &fixture.crypto,
            &fixture.root,
            group_a,
            PrincipalRefV1::User(alice.id.clone()),
            7,
        ),
    ];

    let report = fixture.validate(records);
    assert!(!report
        .effective
        .authority_for_user(&alice.id)
        .can_read(&secret_selector(&["app"])));
}

#[test]
fn administer_confers_full_keyspace_authority_after_validation() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let devs = group_id(&fixture.crypto, "devs");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-administer",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::Administer,
            3,
        ),
        // The devs group grants read on app.
        group_record(&fixture.crypto, &fixture.root, "devs", "devs", 4),
        grant_record(
            &fixture.crypto,
            "devs-read-app",
            &fixture.root,
            PrincipalRefV1::Group(devs.clone()),
            GrantPermissionV1::ReadKeyspace(keyspace_prefix(&["app"])),
            5,
        ),
    ];

    let report = fixture.validate(records);
    let group_perms = report
        .effective
        .authority_for_group(&devs)
        .as_grant_permissions();
    assert!(group_perms
        .iter()
        .any(|p| matches!(p, GrantPermissionV1::ReadKeyspace(_))));

    let alice_auth = report.effective.authority_for_user(&alice.id);
    assert!(alice_auth.administer);
    assert!(alice_auth.can_read(&secret_selector(&["app", "prod"])));
    assert!(alice_auth.can_write(&secret_selector(&["app", "prod"])));
    assert!(alice_auth.can_manage(&secret_selector(&["app", "prod"])));
    assert!(group_perms
        .iter()
        .all(|p| alice_auth.can_create_permission(p)));

    // Root has the same effective top-level authority.
    let root_auth = report.effective.authority_for_user(&fixture.root.id);
    assert!(group_perms
        .iter()
        .all(|p| root_auth.can_create_permission(p)));
}

#[test]
fn root_deletion_is_rejected() {
    let fixture = Fixture::new();
    let records = vec![
        vault_root_record(&fixture),
        user_deleted_record(&fixture.crypto, &fixture.root, fixture.root.id.clone(), 2),
    ];

    let report = fixture.validate(records);
    assert!(report
        .issues
        .iter()
        .any(|issue| matches!(issue, ValidationIssue::InvalidStructure(_))));
    assert!(!report.effective.deleted_users.contains(&fixture.root.id));
    assert!(
        report
            .effective
            .authority_for_user(&fixture.root.id)
            .administer
    );
}

#[test]
fn grant_deletion_resolves_by_lww_and_restore_out_votes_it() {
    let fixture = Fixture::new();
    let bob = test_user(&fixture.crypto, "bob");
    let target_grant = grant_id(&fixture.crypto, "bob-access");

    let base = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &bob, 2),
        trust_root(&fixture.crypto, &bob, &fixture, 2),
        grant_record_with_id(
            &fixture.crypto,
            "bob-access",
            &fixture.root,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        grant_deleted_record(
            &fixture.crypto,
            &fixture.root,
            target_grant.clone(),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
    ];

    // The deletion is the latest authorized record at the key: the grant is gone.
    let report = fixture.validate(base.clone());
    assert!(report.effective.deleted_grants.contains(&target_grant));
    assert!(!report
        .effective
        .authority_for_user(&bob.id)
        .can_read(&secret_selector(&["app"])));

    // A later authorized re-grant at the same key out-votes the deletion — that is the
    // restore path, not a resurrection bug.
    let mut restored = base;
    restored.push(grant_record_with_id(
        &fixture.crypto,
        "bob-access",
        &fixture.root,
        PrincipalRefV1::User(bob.id.clone()),
        GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
        5,
    ));
    let report = fixture.validate(restored);
    assert!(!report.effective.deleted_grants.contains(&target_grant));
    assert!(report
        .effective
        .authority_for_user(&bob.id)
        .can_write(&secret_selector(&["app"])));
}

#[test]
fn manage_confers_use_but_delegation_still_needs_grantable() {
    let fixture = Fixture::new();
    let bob = test_user(&fixture.crypto, "bob");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &bob, 2),
        trust_root(&fixture.crypto, &bob, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "bob-manage",
            &fixture.root,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: KeyspaceSelectorV1::all(),
                grantable: vec![KeyspaceGrantClassV1::Read],
            }),
            3,
        ),
    ];

    let report = fixture.validate(records);
    let bob_auth = report.effective.authority_for_user(&bob.id);
    // Capability hierarchy: holding manage confers read and write on the keyspace, so a
    // manager can always decrypt and re-encrypt what they administer.
    assert!(bob_auth.can_read(&secret_selector(&["app"])));
    assert!(bob_auth.can_write(&secret_selector(&["app"])));
    // Delegation, however, is still bounded by `grantable`: bob can hand out read but not
    // write, even though he can write himself.
    assert!(
        bob_auth.can_create_permission(&GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()))
    );
    assert!(!bob_auth
        .can_create_permission(&GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all())));
}

#[test]
fn omitting_a_remembered_user_deletion_is_suspected_rollback() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let alice_key = RecordKey::User {
        user_id: alice.id.clone(),
    };

    let alice_deletion = user_deleted_record(&fixture.crypto, &fixture.root, alice.id.clone(), 3);
    let full = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        alice_deletion.clone(),
    ];

    // First sync (empty ratchet): alice is deleted and the deletion raised her key's
    // watermark to the deletion's counter.
    let report = fixture.validate(full.clone());
    assert!(report.effective.deleted_users.contains(&alice.id));
    assert_eq!(
        report.ratchet_update.raised_watermarks.get(&alice_key),
        Some(&3)
    );

    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    ratchet
        .watermarks
        .extend(report.ratchet_update.raised_watermarks.clone());

    // Honest vault (deletion still present) validates cleanly.
    let report = fixture.validate_with_ratchet(full, &ratchet);
    assert!(report.issues.is_empty(), "{:?}", report.issues);

    // A rolled-back vault that drops the deletion shows a lower counter at alice's key.
    // The key becomes a rollback *conflict*, not a fatal issue: the vault still loads,
    // but everything at the key is inert — alice is neither live nor deleted (fail
    // closed) until an authorized resolver re-signs a winner above the remembered counter.
    let rolled_back = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
    ];
    let report = fixture.validate_with_ratchet(rolled_back, &ratchet);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    let conflict = report
        .effective
        .conflicted
        .get(&alice_key)
        .expect("alice's key is a rollback conflict");
    assert_eq!(
        conflict.kind,
        ConflictKind::Rollback {
            remembered_counter: 3
        }
    );
    assert_eq!(conflict.counter, 2);
    assert!(!conflict.candidates.is_empty());
    assert!(!report.effective.users.contains_key(&alice.id));
    assert!(!report.effective.deleted_users.contains(&alice.id));
}

#[test]
fn re_adding_a_deleted_user_restores_them_without_rollback_alarm() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");

    let full = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_deleted_record(&fixture.crypto, &fixture.root, alice.id.clone(), 3),
    ];
    let report = fixture.validate(full.clone());
    assert!(report.effective.deleted_users.contains(&alice.id));
    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    ratchet
        .watermarks
        .extend(report.ratchet_update.raised_watermarks.clone());

    // An admin-signed re-add at a higher counter out-votes the deletion: alice is back,
    // and because the counter moved forward this is not a rollback.
    let mut restored = full;
    restored.push(user_record(&fixture, &alice, 4));
    let report = fixture.validate_with_ratchet(restored, &ratchet);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(report.effective.users.contains_key(&alice.id));
    assert!(!report.effective.deleted_users.contains(&alice.id));
}

#[test]
fn a_deleted_user_cannot_resurrect_themselves() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");

    let mut records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        // Alice is even an admin — and still must not be able to undo her own deletion.
        grant_record(
            &fixture.crypto,
            "alice-admin",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::Administer,
            3,
        ),
        user_deleted_record(&fixture.crypto, &fixture.root, alice.id.clone(), 4),
    ];
    // Alice self-signs a re-add at a higher counter. Her record is unauthorized — she is
    // deleted, so she holds no administer — and must not enter the LWW competition.
    records.push(user_record_signed_by(&fixture, &alice, &alice, 5));

    let report = fixture.validate(records);
    assert!(!report.effective.users.contains_key(&alice.id));
    assert!(report.effective.deleted_users.contains(&alice.id));
}

#[test]
fn concurrent_mutual_admin_deletions_resolve_to_the_earlier_deletion() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let bob = test_user(&fixture.crypto, "bob");

    let admin_grant = |seed: &str, user: &TestUser, counter| {
        grant_record(
            &fixture.crypto,
            seed,
            &fixture.root,
            PrincipalRefV1::User(user.id.clone()),
            GrantPermissionV1::Administer,
            counter,
        )
    };
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        admin_grant("alice-admin", &alice, 4),
        admin_grant("bob-admin", &bob, 5),
        // Two admins delete each other concurrently. Deletions are admitted in Lamport
        // order: alice's (counter 10) lands first, after which bob is no longer an
        // admin and his deletion of alice (counter 11) is unauthorized.
        user_deleted_record(&fixture.crypto, &alice, bob.id.clone(), 10),
        user_deleted_record(&fixture.crypto, &bob, alice.id.clone(), 11),
    ];

    let report = fixture.validate(records);
    assert!(report.effective.deleted_users.contains(&bob.id));
    assert!(report.effective.users.contains_key(&alice.id));
    assert!(!report.effective.deleted_users.contains(&alice.id));
}

#[test]
fn omitting_a_remembered_grant_deletion_is_suspected_rollback() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let grant_seed = seed_from("alice-read");
    let grant =
        GrantId(derive_seeded_hash(&fixture.crypto, "thorax.grant.v1", &grant_seed).unwrap());
    let grant_key = RecordKey::Grant {
        grant_id: grant.clone(),
    };
    let permission = GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all());

    let full = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            permission.clone(),
            3,
        ),
        grant_deleted_record(
            &fixture.crypto,
            &fixture.root,
            grant.clone(),
            permission.clone(),
            4,
        ),
    ];

    let report = fixture.validate(full.clone());
    assert_eq!(
        report.ratchet_update.raised_watermarks.get(&grant_key),
        Some(&4)
    );

    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    ratchet
        .watermarks
        .extend(report.ratchet_update.raised_watermarks.clone());

    // Honest vault validates cleanly.
    assert!(fixture
        .validate_with_ratchet(full, &ratchet)
        .issues
        .is_empty());

    // Dropping the deletion record (resurrecting the grant) lowers the counter at the
    // grant's key: a rollback conflict. The resurrected grant must NOT become effective —
    // the key is inert (fail closed), so alice does not regain read authority.
    let rolled_back = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
    ];
    let report = fixture.validate_with_ratchet(rolled_back, &ratchet);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    let conflict = report
        .effective
        .conflicted
        .get(&grant_key)
        .expect("the grant's key is a rollback conflict");
    assert_eq!(
        conflict.kind,
        ConflictKind::Rollback {
            remembered_counter: 4
        }
    );
    assert!(!report.effective.grants.contains_key(&grant));
    assert!(!report
        .effective
        .authority_for_user(&alice.id)
        .can_read(&secret_selector(&["anything"])));
}

#[test]
fn deleting_an_admin_keeps_their_past_deletions_effective() {
    let fixture = Fixture::new();
    let admin = test_user(&fixture.crypto, "admin");
    let bob = test_user(&fixture.crypto, "bob");

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &admin, 2),
        trust_root(&fixture.crypto, &admin, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(&fixture.crypto, &bob, &fixture, 3),
        grant_record(
            &fixture.crypto,
            "admin-users",
            &fixture.root,
            PrincipalRefV1::User(admin.id.clone()),
            GrantPermissionV1::Administer,
            4,
        ),
        user_deleted_record(&fixture.crypto, &admin, bob.id.clone(), 5),
        user_deleted_record(&fixture.crypto, &fixture.root, admin.id.clone(), 6),
    ];

    // Deletion admission is monotone: bob's deletion was authorized when admitted (the
    // admin was still an admin at counter 5), so it stays effective even though the
    // admin was deleted right after.
    let report = fixture.validate(records);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(report.effective.deleted_users.contains(&bob.id));
    assert!(report.effective.deleted_users.contains(&admin.id));
}

#[test]
fn user_without_trust_root_record_is_not_effective() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");

    // alice has a user record and even a grant, but never vouches for the root.
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
    ];

    let report = fixture.validate(records);
    assert!(
        !report.effective.users.contains_key(&alice.id),
        "a user without a entry-point record must not be effective"
    );
    assert!(
        !report
            .effective
            .authority_for_user(&alice.id)
            .can_read(&secret_selector(&["app"])),
        "an ineffective user's grants confer nothing"
    );

    // Adding her entry-point record makes her effective.
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
    ];
    let report = fixture.validate(records);
    assert!(report.effective.users.contains_key(&alice.id));
    assert!(report
        .effective
        .authority_for_user(&alice.id)
        .can_read(&secret_selector(&["app"])));
}

#[test]
fn secrets_with_the_same_tuple_but_different_labels_are_distinct() {
    // Identity is the WHOLE selector (tuple + labels). Two records naming the same tuple
    // with different labels are two different keys, so both stay live — a label is a scope
    // axis, not LWW metadata painted on a single per-tuple secret.
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let prod = SecretSelectorV1 {
        tuple: vec!["app".into(), "db".into()],
        labels: vec![SecretLabelV1 {
            key: "env".into(),
            value: "prod".into(),
        }],
    };
    let staging = SecretSelectorV1 {
        tuple: prod.tuple.clone(),
        labels: vec![SecretLabelV1 {
            key: "env".into(),
            value: "staging".into(),
        }],
    };

    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        secret_record(&fixture.crypto, &fixture.root, &prod, &[&fixture.root], 3),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &staging,
            &[&fixture.root],
            4,
        ),
    ];
    let report = fixture.validate(records);

    // Both secrets are live — distinct keys, not competitors.
    let mut live: Vec<_> = report
        .effective
        .secret_records()
        .into_iter()
        .map(|r| r.value.selector.clone())
        .collect();
    live.sort();
    assert_eq!(live, vec![prod.clone(), staging.clone()]);

    // Each labeled selector addresses its own secret; the bare tuple (empty labels) is yet
    // another key, with no record, so it resolves to nothing.
    let bare = SecretSelectorV1::tuple(["app", "db"]);
    assert!(report
        .effective
        .secret_record(&prod, &fixture.crypto)
        .unwrap()
        .is_some());
    assert!(report
        .effective
        .secret_record(&staging, &fixture.crypto)
        .unwrap()
        .is_some());
    assert!(report
        .effective
        .secret_record(&bare, &fixture.crypto)
        .unwrap()
        .is_none());
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&bare, &fixture.root.id, &fixture.crypto),
        SecretState::Missing
    );
}

#[test]
fn same_counter_diverging_secret_writes_are_a_conflict_not_a_tiebreak() {
    let fixture = Fixture::new();
    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"ours-ciphertext",
            2,
        ),
        secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"theirs-ciphertext",
            2,
        ),
    ];
    let report = fixture.validate(records);

    // No winner is picked: the key is conflicted, reads classify as such, the value is
    // absent from the live views, and the conflict is listed for resolution.
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &fixture.root.id, &fixture.crypto),
        SecretState::Conflicted
    );
    assert!(report
        .effective
        .secret_record(&selector, &fixture.crypto)
        .unwrap()
        .is_none());
    assert!(report.effective.secret_records().is_empty());
    let conflicts = report.effective.secret_conflicts();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0].kind, ConflictKind::Tie);
    assert_eq!(conflicts[0].counter, 2);
    assert_eq!(conflicts[0].candidates.len(), 2);

    // A later write at a higher counter settles the key like any LWW update.
    let mut resolved_records = vec![
        vault_root_record(&fixture),
        secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"ours-ciphertext",
            2,
        ),
        secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"theirs-ciphertext",
            2,
        ),
    ];
    resolved_records.push(secret_record_with_payload(
        &fixture.crypto,
        &fixture.root,
        &selector,
        &[&fixture.root],
        b"resolved-ciphertext",
        3,
    ));
    let report = fixture.validate(resolved_records);
    assert!(report.effective.conflicted.is_empty());
    assert_eq!(report.effective.secret_records().len(), 1);
}

#[test]
fn tied_authority_records_are_fail_closed_until_resolved() {
    // Two diverging Grant bodies at the same key and counter (same seed, different
    // permissions): neither becomes effective — no silent tie-break may hand out
    // authority no one ordered — and the dispute is reported for resolution.
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-grant",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        grant_record(
            &fixture.crypto,
            "alice-grant",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
    ];
    let report = fixture.validate(records);

    let alice_auth = report.effective.authority_for_user(&alice.id);
    assert!(!alice_auth.can_read(&secret_selector(&["app"])));
    assert!(!alice_auth.can_write(&secret_selector(&["app"])));
    assert_eq!(report.effective.conflicted.len(), 1);
    let conflict = report.effective.conflicted.values().next().unwrap();
    assert_eq!(conflict.kind, ConflictKind::Tie);
    assert!(matches!(conflict.key, RecordKey::Grant { .. }));
    assert_eq!(conflict.candidates.len(), 2);
}

#[test]
fn a_tie_between_a_deleted_writers_records_is_not_a_conflict() {
    // Alice writes the same secret on two branches (a genuine same-counter divergence),
    // then is deleted. Authority-aware resolution excludes her records entirely, so the
    // key holds no authorized candidates: there is nothing an authorized user could even
    // resolve to, and reporting a conflict would make the merge surface demand a
    // resolution `thorax conflicts` cannot offer. The secret is simply gone, exactly as
    // the deletion cascade intends.
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        secret_record_with_payload(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            b"branch-a",
            4,
        ),
        secret_record_with_payload(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            b"branch-b",
            4,
        ),
        user_deleted_record(&fixture.crypto, &fixture.root, alice.id.clone(), 5),
    ];

    let report = fixture.validate(records);
    assert!(report.issues.is_empty(), "{:?}", report.issues);
    assert!(
        report.effective.conflicted.is_empty(),
        "an unauthorized-only tie is not a real ambiguity: {:?}",
        report.effective.conflicted
    );
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &fixture.root.id, &fixture.crypto),
        SecretState::Missing
    );

    // The same divergence while alice is still authorized IS a conflict — authority is
    // the only thing separating the two cases.
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        secret_record_with_payload(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            b"branch-a",
            4,
        ),
        secret_record_with_payload(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            b"branch-b",
            4,
        ),
    ];
    let report = fixture.validate(records);
    assert_eq!(report.effective.secret_conflicts().len(), 1);
}

#[test]
fn an_erased_keys_rollback_conflict_is_named_by_its_remembered_origin() {
    // The watermark remembers the id preimage alongside the counter, so a rollback that
    // erased a key's records entirely can still tell the user *what* is missing — the
    // secret's tuple — instead of an uninvertible hash.
    let fixture = Fixture::new();
    let selector = secret_selector(&["app", "prod", "db"]);
    let secret_key = RecordKey::Secret {
        secret_id: crate::ids::derive_secret_id(&fixture.crypto, &selector).unwrap(),
    };
    let full = vec![
        vault_root_record(&fixture),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            1,
        ),
    ];
    let report = fixture.validate(full);
    assert_eq!(
        report.ratchet_update.origins.get(&secret_key),
        Some(&KeyOrigin::Secret(SecretSelectorV1::tuple([
            "app", "prod", "db"
        ])))
    );
    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    ratchet.apply_update(&report.ratchet_update);

    // A checkout from before the secret existed: zero records at the key.
    let erased = vec![vault_root_record(&fixture)];
    let report = fixture.validate_with_ratchet(erased, &ratchet);
    let conflict = report
        .effective
        .conflicted
        .get(&secret_key)
        .expect("the erased key is a rollback conflict");
    assert!(conflict.candidates.is_empty());
    assert_eq!(
        conflict.origin,
        Some(KeyOrigin::Secret(SecretSelectorV1::tuple([
            "app", "prod", "db"
        ])))
    );
}

#[test]
fn byte_identical_duplicate_records_collapse_before_validation() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let selector = secret_selector(&["app", "prod"]);

    let originals = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
        secret_record(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            5,
        ),
    ];
    // Replay every record once, root included: an attacker with git write can duplicate
    // any validly-signed bytes, and the copies must change nothing — in particular the
    // duplicated root must not manufacture an `AmbiguousRoot`.
    let mut records = originals.clone();
    records.extend(originals);

    let report = fixture.validate(records);
    assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &alice.id, &fixture.crypto),
        SecretState::ActiveDecryptable
    );
}

#[test]
fn decode_rejects_vaults_beyond_the_supported_ceilings() {
    let fixture = Fixture::new();
    let vault = vault_from_records(vec![vault_root_record(&fixture)]);
    let bytes = encode_vault(&vault).unwrap();

    assert!(decode_vault_with_limits(&bytes, bytes.len(), MAX_VAULT_RECORDS).is_ok());
    assert!(decode_vault_with_limits(&bytes, bytes.len() - 1, MAX_VAULT_RECORDS).is_err());
    assert!(decode_vault_with_limits(&bytes, MAX_VAULT_BYTES, 1).is_ok());
    assert!(decode_vault_with_limits(&bytes, MAX_VAULT_BYTES, 0).is_err());

    // The file self-identifies: encode leads with the magic, decode requires it.
    assert!(bytes.starts_with(VAULT_MAGIC));
    assert!(decode_vault(&bytes[VAULT_MAGIC.len()..]).is_err());
}

/// The advisory contract: a record kind this build cannot read warns and stays inert, but
/// never blocks reads or fails the vault closed.
#[test]
fn unknown_records_warn_without_blocking_reads() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let selector = secret_selector(&["app", "prod"]);

    let mut records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            4,
        ),
        secret_record(
            &fixture.crypto,
            &alice,
            &selector,
            &[&fixture.root, &alice],
            5,
        ),
    ];
    // Two distinct record kinds from a newer thorax.
    records.push(future_record_kind(7));
    records.push(future_record_kind(8));

    let ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    let report = fixture.validate_with_ratchet(records, &ratchet);

    assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    assert_eq!(
        report.warnings,
        vec![ValidationWarning::UnknownRecords { count: 2 }]
    );
    assert!(!report.effective.authority_unresolved);
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &alice.id, &fixture.crypto),
        SecretState::ActiveDecryptable
    );
}

/// An unknown record kind round-trips byte-for-byte through decode and re-encode — the
/// pass-through half of the advisory contract.
#[test]
fn unknown_record_kinds_survive_a_rewrite_byte_for_byte() {
    let fixture = Fixture::new();
    let vault = vault_from_records(vec![vault_root_record(&fixture), future_record_kind(9)]);
    let bytes = encode_vault(&vault).unwrap();
    let reloaded = decode_vault(&bytes).unwrap();
    assert_eq!(vault, reloaded);
    assert_eq!(encode_vault(&reloaded).unwrap(), bytes);
}

/// The envelope's own ratchet: a vault whose format version is below the remembered one
/// is a downgrade, not an honest state — everything fails closed.
#[test]
fn format_version_regression_fails_closed() {
    let fixture = Fixture::new();
    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            2,
        ),
    ];

    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    ratchet.format_version = 2;
    let report = fixture.validate_with_ratchet(records, &ratchet);

    assert_eq!(
        report.issues,
        vec![ValidationIssue::FormatVersionRegression {
            remembered: 2,
            current: 1,
        }]
    );
    assert!(report.effective.authority_unresolved);
    assert_eq!(
        report
            .effective
            .classify_secret_for_user(&selector, &fixture.root.id, &fixture.crypto),
        SecretState::Invalid
    );
}

/// A clean validation raises the format-version ratchet to the vault's version, exactly
/// like a counter watermark.
#[test]
fn clean_validation_raises_the_format_version_ratchet() {
    let fixture = Fixture::new();
    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    assert_eq!(ratchet.format_version, 0);

    let report = fixture.validate_with_ratchet(vec![vault_root_record(&fixture)], &ratchet);
    assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
    assert_eq!(report.ratchet_update.raised_format_version, Some(1));

    ratchet.apply_update(&report.ratchet_update);
    assert_eq!(ratchet.format_version, 1);
    // Re-validating at the remembered version is clean and raises nothing further.
    let again = fixture.validate_with_ratchet(vec![vault_root_record(&fixture)], &ratchet);
    assert!(again.issues.is_empty());
    assert_eq!(again.ratchet_update.raised_format_version, None);
}

// --- Secret-index differential oracle ---------------------------------------------------
//
// `secret_records` / `secret_record` / `secret_record_is_current` resolve through the
// per-secret winner index built by `attach_verified_records`. The functions below are the
// pre-index linear scans those queries replaced, kept verbatim as the behavioral oracle:
// the indexed answer must be byte-identical to the scan's — same authority gate (against
// each record's own claimed selector), same conflict exclusion, same LWW resolution, and
// for listings the same first-appearance order.

fn reference_secret_identity(body: &RecordBodyV1) -> Option<(&SecretId, &SecretSelectorV1)> {
    match body {
        RecordBodyV1::Secret(value) => Some((&value.id, &value.selector)),
        RecordBodyV1::SecretDeleted(deleted) => Some((&deleted.id, &deleted.selector)),
        _ => None,
    }
}

fn reference_secret_records(state: &EffectiveState) -> Vec<ActiveSecretV1> {
    use super::effective::compare_lww;
    let mut latest = Vec::<(SecretId, &VerifiedRecord)>::new();
    for record in &state.verified_records {
        let Some((secret, selector)) = reference_secret_identity(&record.body) else {
            continue;
        };
        if state.conflicted.contains_key(&RecordKey::Secret {
            secret_id: secret.clone(),
        }) {
            continue;
        }
        if !state.authority_for_user(&record.signer).can_write(selector) {
            continue;
        }
        match latest
            .iter_mut()
            .find(|(existing_secret, _)| existing_secret == secret)
        {
            Some((_, existing_record)) => {
                if compare_lww(record, existing_record).is_gt() {
                    *existing_record = record;
                }
            }
            None => latest.push((secret.clone(), record)),
        }
    }
    latest
        .into_iter()
        .filter_map(|(_, record)| match &record.body {
            RecordBodyV1::Secret(value) => Some(ActiveSecretV1 {
                signed: record.signed.clone(),
                value: value.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn reference_latest_authorized(state: &EffectiveState, secret: &SecretId) -> Option<HashValue> {
    use super::effective::compare_lww;
    state
        .verified_records
        .iter()
        .filter(|record| match reference_secret_identity(&record.body) {
            Some((id, _)) => id == secret,
            None => false,
        })
        .filter(|record| {
            let Some((_, selector)) = reference_secret_identity(&record.body) else {
                return false;
            };
            state.authority_for_user(&record.signer).can_write(selector)
        })
        .max_by(|a, b| compare_lww(a, b))
        .map(|record| record.record_hash.clone())
}

fn reference_secret_record(
    state: &EffectiveState,
    selector: &SecretSelectorV1,
    crypto: &DeterministicCrypto,
) -> Option<ActiveSecretV1> {
    let secret = crate::ids::derive_secret_id(crypto, selector).unwrap();
    if state.conflicted.contains_key(&RecordKey::Secret {
        secret_id: secret.clone(),
    }) {
        return None;
    }
    let winner_hash = reference_latest_authorized(state, &secret)?;
    let record = state
        .verified_records
        .iter()
        .find(|record| record.record_hash == winner_hash)
        .unwrap();
    match &record.body {
        RecordBodyV1::Secret(value)
            if selector
                .labels
                .iter()
                .all(|label| value.selector.labels.contains(label)) =>
        {
            Some(ActiveSecretV1 {
                signed: record.signed.clone(),
                value: value.clone(),
            })
        }
        _ => None,
    }
}

fn reference_secret_record_is_current(state: &EffectiveState, hash: &HashValue) -> bool {
    let Some(target) = state
        .verified_records
        .iter()
        .find(|record| &record.record_hash == hash)
    else {
        return false;
    };
    let Some((secret, _)) = reference_secret_identity(&target.body) else {
        return false;
    };
    if state.conflicted.contains_key(&RecordKey::Secret {
        secret_id: secret.clone(),
    }) {
        return false;
    }
    reference_latest_authorized(state, secret) == Some(hash.clone())
}

fn assert_secret_queries_match_reference(
    state: &EffectiveState,
    crypto: &DeterministicCrypto,
    selectors: &[SecretSelectorV1],
    record_hashes: &[HashValue],
) {
    assert_eq!(state.secret_records(), reference_secret_records(state));
    for selector in selectors {
        assert_eq!(
            state.secret_record(selector, crypto).unwrap(),
            reference_secret_record(state, selector, crypto),
            "secret_record diverged from the scan at {selector:?}"
        );
    }
    for hash in record_hashes {
        assert_eq!(
            state.secret_record_is_current(hash),
            reference_secret_record_is_current(state, hash),
            "secret_record_is_current diverged from the scan at {hash:?}"
        );
    }
}

/// Deterministic Fisher-Yates over a fixed LCG, so the differential runs cover several
/// record orders (the index must reproduce the scan's first-appearance listing order for
/// every one) without a randomness dependency.
fn shuffle_records(records: &mut [VaultRecordV1], seed: u64) {
    let mut s = seed;
    for i in (1..records.len()).rev() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = ((s >> 33) as usize) % (i + 1);
        records.swap(i, j);
    }
}

#[test]
fn secret_index_matches_the_reference_scans() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice"); // write everywhere
    let bob = test_user(&fixture.crypto, "bob"); // write under app/* only
    let carol = test_user(&fixture.crypto, "carol"); // read-only: her writes never count
    let eve = test_user(&fixture.crypto, "eve"); // writer, later deleted

    let s1 = secret_selector(&["app", "db"]);
    let s1_prod = SecretSelectorV1 {
        tuple: s1.tuple.clone(),
        labels: vec![SecretLabelV1 {
            key: "env".into(),
            value: "prod".into(),
        }],
    };
    let s2 = secret_selector(&["app", "cache"]); // deletion wins
    let s3 = secret_selector(&["svc", "token"]); // unauthorized writes interleaved
    let s4 = secret_selector(&["app", "poison"]); // deleted writer's high counter drops
    let s5 = secret_selector(&["tie", "key"]); // same-counter diverging tie
    let s6 = secret_selector(&["app", "restore"]); // delete then re-add
    let s7 = secret_selector(&["ghost", "key"]); // deletion-only key, no prior value
    let unused = secret_selector(&["never", "written"]);

    let secret_deleted = |signer: &TestUser, selector: &SecretSelectorV1, counter: u64| {
        let id = crate::ids::derive_secret_id(&fixture.crypto, selector).unwrap();
        signed_record(
            &fixture.crypto,
            signer,
            RecordBodyV1::SecretDeleted(SecretDeletedRecordV1 {
                id,
                selector: selector.clone(),
                counter,
            }),
        )
    };

    let root = &fixture.root;
    let crypto = &fixture.crypto;
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(crypto, &alice, &fixture, 2),
        user_record(&fixture, &bob, 3),
        trust_root(crypto, &bob, &fixture, 3),
        user_record(&fixture, &carol, 4),
        trust_root(crypto, &carol, &fixture, 4),
        user_record(&fixture, &eve, 5),
        trust_root(crypto, &eve, &fixture, 5),
        grant_record(
            crypto,
            "alice-write",
            root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            6,
        ),
        grant_record(
            crypto,
            "bob-write-app",
            root,
            PrincipalRefV1::User(bob.id.clone()),
            GrantPermissionV1::WriteKeyspace(keyspace_prefix(&["app"])),
            7,
        ),
        grant_record(
            crypto,
            "carol-read",
            root,
            PrincipalRefV1::User(carol.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            8,
        ),
        grant_record(
            crypto,
            "eve-write",
            root,
            PrincipalRefV1::User(eve.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            9,
        ),
        secret_record(crypto, root, &s1, &[root], 10),
        secret_record(crypto, &bob, &s2, &[root, &bob], 11),
        secret_record(crypto, &alice, &s1, &[root, &alice], 12),
        // Same tuple as s1 but a different label: identity is the whole selector, so this is
        // a distinct key and a distinct live secret — not a competitor at s1's key.
        secret_record(crypto, &alice, &s1_prod, &[root, &alice], 25),
        secret_deleted(&bob, &s2, 13),
        secret_record(crypto, &alice, &s3, &[root, &alice], 15),
        // Outside bob's app/* keyspace and carol holds no write at all: neither competes,
        // despite carrying the highest counters at the key.
        secret_record(crypto, &bob, &s3, &[root, &bob], 16),
        secret_record(crypto, &carol, &s3, &[root, &carol], 17),
        // Eve's forward-dated counter would win — until her deletion empties her authority.
        secret_record(crypto, &eve, &s4, &[root, &eve], 1000),
        secret_record(crypto, root, &s4, &[root], 18),
        user_deleted_record(crypto, root, eve.id.clone(), 19),
        // Same counter, diverging bodies: a tie conflict; the key lists nothing.
        secret_record_with_payload(crypto, root, &s5, &[root], b"payload-a", 20),
        secret_record_with_payload(crypto, &alice, &s5, &[root, &alice], b"payload-b", 20),
        secret_record(crypto, root, &s6, &[root], 21),
        secret_deleted(root, &s6, 22),
        secret_record(crypto, &alice, &s6, &[root, &alice], 23),
        secret_deleted(root, &s7, 24),
        future_record_kind(9),
        // S1's LWW winner — kept last so the rollback phase below can drop it, regressing
        // s1's key from counter 14 to its surviving 10/12 records.
        secret_record(crypto, &alice, &s1, &[root, &alice], 14),
    ];

    let selectors = [
        s1.clone(),
        s1_prod.clone(),
        s2,
        s3.clone(),
        s4.clone(),
        s5,
        s6.clone(),
        s7,
        unused,
    ];
    let record_hashes: Vec<HashValue> = records
        .iter()
        .map(|signed| record_hash(crypto, signed).unwrap())
        .collect();

    for seed in [0u64, 1, 2, 3, 4] {
        let mut shuffled = records.clone();
        shuffle_records(&mut shuffled, seed);
        let report = fixture.validate(shuffled);
        assert!(report.issues.is_empty(), "issues: {:?}", report.issues);
        assert_secret_queries_match_reference(
            &report.effective,
            crypto,
            &selectors,
            &record_hashes,
        );

        // Pin the expected live set independently of the oracle, so a bug shared by both
        // implementations cannot hide: S2 deleted, S5 conflicted, S7 deletion-only.
        let live: Vec<SecretSelectorV1> = report
            .effective
            .secret_records()
            .into_iter()
            .map(|record| record.value.selector)
            .collect();
        assert_eq!(live.len(), 5);
        assert!(
            live.contains(&s1) && live.contains(&s1_prod),
            "s1 and its same-tuple labeled sibling are distinct live secrets"
        );
        assert!(live.contains(&s3) && live.contains(&s4) && live.contains(&s6));
    }

    // Rollback phase: remember the full vault's watermarks, then drop S1's winning record.
    // S1's key becomes a rollback conflict and both implementations must exclude it.
    let report = fixture.validate(records.clone());
    let mut ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    ratchet
        .watermarks
        .extend(report.ratchet_update.raised_watermarks.clone());
    let rolled_back = records[..records.len() - 1].to_vec();
    let report = fixture.validate_with_ratchet(rolled_back, &ratchet);
    let s1_key = RecordKey::Secret {
        secret_id: crate::ids::derive_secret_id(crypto, &s1).unwrap(),
    };
    assert!(matches!(
        report.effective.conflicted.get(&s1_key),
        Some(conflict) if matches!(conflict.kind, ConflictKind::Rollback { .. })
    ));
    assert_secret_queries_match_reference(&report.effective, crypto, &selectors, &record_hashes);
    assert!(report
        .effective
        .secret_record(&s1, crypto)
        .unwrap()
        .is_none());
    // The same-tuple sibling lives on a different key, untouched by s1's rollback.
    assert!(report
        .effective
        .secret_record(&s1_prod, crypto)
        .unwrap()
        .is_some());
}

// --- Pre-verified hash set (the verification cache's core contract) ---------------------

#[test]
fn pre_verified_hashes_skip_signature_checks_and_change_nothing() {
    let fixture = Fixture::new();
    let alice = test_user(&fixture.crypto, "alice");
    let selector = secret_selector(&["app", "prod"]);
    let records = vec![
        vault_root_record(&fixture),
        user_record(&fixture, &alice, 2),
        trust_root(&fixture.crypto, &alice, &fixture, 2),
        grant_record(
            &fixture.crypto,
            "alice-write",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all()),
            3,
        ),
        secret_record(&fixture.crypto, &alice, &selector, &[&fixture.root], 4),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            5,
        ),
    ];
    let vault = vault_from_records(records);
    let counting = CountingCrypto::default();
    let ratchet = Ratchet::new(key_hash(&counting, &fixture.root.signing_public_key).unwrap());

    let full = validate_vault(&vault, &ratchet, &counting).unwrap();
    assert!(full.issues.is_empty(), "{:?}", full.issues);
    let full_verifications = counting.verifications.get();
    assert!(full_verifications > 0);
    let verified = full.effective.verified_record_hashes();

    // Passing every verified hash back: zero signature verifications, identical outcome.
    let counting = CountingCrypto::default();
    let cached = validate_vault_with_verified(&vault, &ratchet, &counting, &verified).unwrap();
    assert_eq!(counting.verifications.get(), 0);
    assert!(cached.issues.is_empty(), "{:?}", cached.issues);
    assert_eq!(
        cached.effective.secret_records(),
        full.effective.secret_records()
    );
    assert_eq!(
        cached.effective.users.keys().collect::<Vec<_>>(),
        full.effective.users.keys().collect::<Vec<_>>()
    );
    assert_eq!(cached.effective.verified_record_hashes(), verified);

    // A partial set verifies exactly the uncovered remainder.
    let mut partial = verified.clone();
    let dropped = partial.pop_last().unwrap();
    let counting = CountingCrypto::default();
    let report = validate_vault_with_verified(&vault, &ratchet, &counting, &partial).unwrap();
    assert!(report.issues.is_empty());
    assert!(report.effective.verified_record_hashes().contains(&dropped));
    assert!(counting.verifications.get() >= 1);
    assert!(counting.verifications.get() < full_verifications);
}

#[test]
fn a_forged_record_outside_the_verified_set_is_still_caught() {
    let fixture = Fixture::new();
    let selector = secret_selector(&["app", "prod"]);
    let good = vec![
        vault_root_record(&fixture),
        secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            2,
        ),
    ];
    let ratchet = Ratchet::new(fixture.root_signing_public_key_hash());
    let verified = validate_vault(&vault_from_records(good.clone()), &ratchet, &fixture.crypto)
        .unwrap()
        .effective
        .verified_record_hashes();

    // Forge: byte-identical body re-wrapped with a corrupted signature. Its hash differs
    // (the record hash commits to body, key, AND signature), so the verified set cannot
    // cover it and the signature check runs — and fails.
    let mut forged = good.clone();
    let mut bad = good[1].clone();
    bad.signature[0] ^= 1;
    forged.push(bad.clone());
    let report = validate_vault_with_verified(
        &vault_from_records(forged.clone()),
        &ratchet,
        &fixture.crypto,
        &verified,
    )
    .unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| matches!(issue, ValidationIssue::InvalidSignature(_))));

    // The ratchet contract, pinned: if a caller DOES vouch for the forged hash, the check is
    // skipped — which is exactly why ops only accepts possession-checked caches on
    // unlock-gated paths. This documents the boundary, not a desired behavior.
    let mut poisoned = verified.clone();
    poisoned.insert(record_hash(&fixture.crypto, &bad).unwrap());
    let report = validate_vault_with_verified(
        &vault_from_records(forged),
        &ratchet,
        &fixture.crypto,
        &poisoned,
    )
    .unwrap();
    assert!(report.issues.is_empty());
}
