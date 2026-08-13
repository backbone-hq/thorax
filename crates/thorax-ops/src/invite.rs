use thorax_core::{
    validate_vault, HashValue, InvitationMaterial, PrincipalRefV1, Ratchet, RatchetBaselineV1,
    RatchetRecordV1,
};
use thorax_crypto::{Crypto, Identity};
use thorax_keychain::{IdentityKeychain, KeyUsePurpose, KeychainIdentityRef, KeychainRequest};
use thorax_store::{
    acquire_root_state_lock, read_ratchet_for_root, read_vault, write_ratchet_atomic,
    WorkspacePaths,
};

use thorax_core::GrantPermissionV1;

use crate::principals::{ensure_administer, ensure_can_create_permission, normalize_user_handle};
use crate::trust::has_suspected_rollback;
use crate::{
    ensure_no_issues, trusted_root_candidate, ClaimInviteOutput, InviteUserOutput, OpsError,
    ReconcileOutput, Result, UnlockedSession,
};

pub struct PreparedInviteUser {
    projected: crate::LockedSession,
    expected_vault_bytes: Vec<u8>,
    expected_ratchet_bytes: Vec<u8>,
    output: InviteUserOutput,
}

impl PreparedInviteUser {
    pub fn invite(&self) -> &InvitationMaterial {
        &self.output.invite
    }
}

/// Stores an identity in the configured local keychain.
///
/// This is the production-facing identity persistence path for consumers that
/// should not place human private keys under the repo-local `.thorax` directory.
pub fn save_identity_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    trusted_root: &HashValue,
    identity: &Identity,
) -> Result<KeychainIdentityRef> {
    save_identity_with_keychain_labeled(paths, crypto, keychain, trusted_root, identity, None, None)
}

pub fn save_identity_with_keychain_labeled(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    trusted_root: &HashValue,
    identity: &Identity,
    vault_label: Option<String>,
    user_label: Option<String>,
) -> Result<KeychainIdentityRef> {
    let request = KeychainRequest::new(
        paths,
        trusted_root.clone(),
        identity.user_id().clone(),
        KeyUsePurpose::StoreIdentity,
    )
    .with_labels(vault_label, user_label);
    Ok(keychain.store_identity(crypto, &request, identity)?)
}

/// The invite family of operations, acting as the session's unlocked identity. Claiming
/// stays a free function: it establishes local trust on a machine that may have none yet,
/// which is exactly the precondition a session load requires.
impl UnlockedSession {
    pub fn prepare_invite_user(
        &mut self,
        crypto: &Crypto,
        handle: Option<String>,
        grant_permissions: Vec<GrantPermissionV1>,
    ) -> Result<PreparedInviteUser> {
        ensure_administer(self.effective(), self.user_id())?;
        for permission in &grant_permissions {
            ensure_can_create_permission(self.effective(), self.user_id(), permission)?;
        }
        let handle = handle.map(normalize_user_handle).transpose()?;
        let (session, admin_identity) = self.parts();
        let expected_vault_bytes = session.vault_bytes().to_vec();
        let expected_ratchet_bytes = thorax_store::encode_ratchet(session.ratchet())?;

        // The invitation carries the seed, trusted root, and a snapshot of the issuer's
        // watermark ratchet so `claim` can reject root substitution and rollback. We snapshot
        // the *pre-invite* ratchet: the new user and grants
        // written below are additions, not removals, so they belong to the recipient's own
        // first-sync observations, not the baseline.
        // The baseline travels without the trusted-root scope record (the recipient's own
        // ratchet file names the root); everything else — the watermarks and the
        // format-version downgrade guard — carries, so the recipient's first sync rejects a
        // vault rolled back or downgraded past the issuer's view.
        let baseline_records: Vec<RatchetRecordV1> = session
            .ratchet()
            .to_records()
            .into_iter()
            .filter(|record| !matches!(record, RatchetRecordV1::TrustedRoot(_)))
            .collect();
        let rollback_baseline = RatchetBaselineV1 {
            records: baseline_records,
        };

        let invited = Identity::generate(crypto)?;
        let mut projected = session.prepared_clone();
        projected.add_user(crypto, admin_identity, &invited)?;
        let handle_id = if let Some(handle) = handle {
            Some(projected.set_user_handle(
                crypto,
                admin_identity,
                handle,
                invited.user_id().clone(),
            )?)
        } else {
            None
        };
        let mut grants = Vec::new();
        // Each grant is its own commit; the Lamport counter is derived per commit from the
        // vault, so successive grants are strictly ordered without any explicit offset
        // bookkeeping.
        for permission in grant_permissions.into_iter() {
            grants.push(projected.grant_permission(
                crypto,
                admin_identity,
                PrincipalRefV1::User(invited.user_id().clone()),
                permission,
                thorax_crypto::random_seed(),
            )?);
        }

        // The grants just written make the new user a reader of existing secrets — converge
        // them with the admin identity this session holds, exactly as a standalone grant
        // would. Without this, an invite-with-grants would authorize access the new user
        // cannot yet exercise until someone remembered to reconcile separately (the bug
        // this whole shape exists to prevent). No grants means nothing to converge.
        let reconcile = if grants.is_empty() {
            ReconcileOutput::default()
        } else {
            projected.converge_readers(crypto, admin_identity)?
        };

        let invite = InvitationMaterial {
            master_seed: invited.master_seed().to_vec(),
            trusted_root: session.ratchet().trusted_root.clone(),
            rollback_baseline: Some(rollback_baseline),
        };

        Ok(PreparedInviteUser {
            projected,
            expected_vault_bytes,
            expected_ratchet_bytes,
            output: InviteUserOutput {
                user_id: invited.user_id().clone(),
                invite,
                handle: handle_id,
                grants,
                reconcile,
            },
        })
    }

    pub fn commit_invite_user(
        &mut self,
        crypto: &Crypto,
        prepared: PreparedInviteUser,
    ) -> Result<InviteUserOutput> {
        let (session, _) = self.parts();
        session.commit_prepared(
            crypto,
            prepared.projected,
            "invite user",
            &prepared.expected_vault_bytes,
            &prepared.expected_ratchet_bytes,
        )?;
        Ok(prepared.output)
    }

    pub fn invite_user(
        &mut self,
        crypto: &Crypto,
        handle: Option<String>,
        grant_permissions: Vec<GrantPermissionV1>,
    ) -> Result<InviteUserOutput> {
        let prepared = self.prepare_invite_user(crypto, handle, grant_permissions)?;
        self.commit_invite_user(crypto, prepared)
    }
}

/// Claim an invitation on this machine: derive the recipient identity, require the embedded
/// trusted root, enforce the embedded first-sync rollback baseline, confirm current membership,
/// and store the identity in the keychain.
pub fn claim_invite_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    invitation: &InvitationMaterial,
) -> Result<ClaimInviteOutput> {
    let identity = Identity::from_master_seed(crypto, &invitation.master_seed)?;
    let vault = read_vault(paths)?;
    let trusted_root = trusted_root_candidate(&vault, crypto)?;
    if invitation.trusted_root != trusted_root {
        return Err(OpsError::InviteRootMismatch);
    }
    let _root_lock = acquire_root_state_lock(paths, &trusted_root)?;
    crate::transaction::ensure_no_pending_transaction_locked(paths, &trusted_root, crypto)?;

    // Validate against existing local trust if we have it (a returning user's remembered
    // ratchet is stronger); otherwise seed a fresh ratchet from the baseline. A vault rolled
    // back past that seed surfaces as rollback conflicts from the standard checks — and a
    // claim must not proceed into a conflicted vault at all, so it fails closed here.
    let existing_ratchet = read_ratchet_for_root(paths, &trusted_root)?;
    let rollback_protected = existing_ratchet.is_some() || invitation.has_rollback_baseline();
    let mut ratchet = match existing_ratchet {
        Some(existing) => existing,
        None => seed_ratchet_from_optional_baseline(
            &trusted_root,
            invitation.rollback_baseline.as_ref(),
        ),
    };
    let report = validate_vault(&vault, &ratchet, crypto)?;
    if has_suspected_rollback(&report) {
        return Err(OpsError::ClaimRolledBack);
    }
    ensure_no_issues(&report)?;

    // Membership now subsumes the trust-chain check: the validator only treats a user as
    // effective if their own key vouches for this root via an EntryPointRecord, so a member
    // here has, by construction, a valid entry-point record pinning this root.
    if !report.effective.users.contains_key(identity.user_id()) {
        return Err(OpsError::ClaimNotAMember(identity.user_id().clone()));
    }

    // Remember the current validated ratchet so the user's later syncs stay protected.
    ratchet.apply_update(&report.ratchet_update);
    write_ratchet_atomic(paths, &ratchet)?;

    let stored = save_identity_with_keychain(paths, crypto, keychain, &trusted_root, &identity)?;
    Ok(ClaimInviteOutput {
        user_id: identity.user_id().clone(),
        trusted_root,
        stored,
        report,
        rollback_protected,
    })
}

/// Seed a fresh local ratchet from the invitation's embedded issuer snapshot.
fn seed_ratchet_from_baseline(trusted_root: &HashValue, baseline: &RatchetBaselineV1) -> Ratchet {
    let mut ratchet = Ratchet::new(trusted_root.clone());
    for record in &baseline.records {
        ratchet.absorb_record(record);
    }
    ratchet
}

fn seed_ratchet_from_optional_baseline(
    trusted_root: &HashValue,
    baseline: Option<&RatchetBaselineV1>,
) -> Ratchet {
    match baseline {
        Some(baseline) => seed_ratchet_from_baseline(trusted_root, baseline),
        None => Ratchet::new(trusted_root.clone()),
    }
}

/// Establish local trust for the vault from an invite *without* storing the identity in a
/// keychain — the trust half of [`claim_invite_with_keychain`]. Used for non-interactive access (CI),
/// where the identity is injected directly and the only thing missing on a fresh checkout is the
/// rollback baseline. Idempotent: a no-op if local trust for this root already exists (the normal
/// load path then applies ongoing rollback protection against it).
///
/// The invitation's root and rollback baseline are enforced exactly as in
/// [`claim_invite_with_keychain`].
pub fn ensure_ratchet_from_invite(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    invitation: &InvitationMaterial,
) -> Result<()> {
    let identity = Identity::from_master_seed(crypto, &invitation.master_seed)?;
    let vault = read_vault(paths)?;
    let trusted_root = trusted_root_candidate(&vault, crypto)?;
    if invitation.trusted_root != trusted_root {
        return Err(OpsError::InviteRootMismatch);
    }
    let _root_lock = acquire_root_state_lock(paths, &trusted_root)?;
    crate::transaction::ensure_no_pending_transaction_locked(paths, &trusted_root, crypto)?;
    if read_ratchet_for_root(paths, &trusted_root)?.is_some() {
        return Ok(());
    }

    let Some(baseline) = invitation.rollback_baseline.as_ref() else {
        return Err(OpsError::InviteRollbackBaselineRequired);
    };
    let mut ratchet = seed_ratchet_from_baseline(&trusted_root, baseline);
    let report = validate_vault(&vault, &ratchet, crypto)?;
    if has_suspected_rollback(&report) {
        return Err(OpsError::ClaimRolledBack);
    }
    ensure_no_issues(&report)?;
    if !report.effective.users.contains_key(identity.user_id()) {
        return Err(OpsError::ClaimNotAMember(identity.user_id().clone()));
    }
    ratchet.apply_update(&report.ratchet_update);
    write_ratchet_atomic(paths, &ratchet)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::*;

    fn root_keychain(
        fixture: &ProductionFixture,
    ) -> PassphraseKeychain<thorax_keychain::StaticPassphraseProvider> {
        let keychain = PassphraseKeychain::new(
            fixture._temp.path.join("keychain"),
            thorax_keychain::StaticPassphraseProvider::new("root keychain passphrase"),
        );
        let root_hash = key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        save_identity_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            &root_hash,
            &fixture.root,
        )
        .unwrap();
        keychain
    }

    #[test]
    fn invitation_prepare_is_in_memory_and_stale_commit_is_rejected() {
        let fixture = ProductionFixture::initialized();
        let keychain = root_keychain(&fixture);
        let before_vault = thorax_store::read_vault_bytes(&fixture.paths).unwrap();
        let root_hash = key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        let before_ratchet = thorax_store::read_ratchet_bytes_for_root(&fixture.paths, &root_hash)
            .unwrap()
            .unwrap();
        let mut session = UnlockedSession::open(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            KeyUsePurpose::SignAdminChange {
                summary: "prepare invite".into(),
            },
        )
        .unwrap();
        let prepared = session
            .prepare_invite_user(&fixture.crypto, Some("alice".into()), vec![])
            .unwrap();
        assert_eq!(
            thorax_store::read_vault_bytes(&fixture.paths).unwrap(),
            before_vault
        );
        assert_eq!(
            thorax_store::read_ratchet_bytes_for_root(&fixture.paths, &root_hash)
                .unwrap()
                .unwrap(),
            before_ratchet
        );

        set_vault_handle_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            "changed",
        )
        .unwrap();
        let error = session
            .commit_invite_user(&fixture.crypto, prepared)
            .unwrap_err();
        assert!(matches!(
            error,
            OpsError::TransactionPreconditionChanged("vault")
        ));
    }

    #[test]
    fn invitation_commit_applies_the_whole_prepared_result() {
        let fixture = ProductionFixture::initialized();
        let keychain = root_keychain(&fixture);
        let mut session = UnlockedSession::open(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            KeyUsePurpose::SignAdminChange {
                summary: "invite alice".into(),
            },
        )
        .unwrap();
        let prepared = session
            .prepare_invite_user(&fixture.crypto, Some("alice".into()), vec![])
            .unwrap();
        let invite_root = prepared.invite().trusted_root.clone();
        let output = session
            .commit_invite_user(&fixture.crypto, prepared)
            .unwrap();
        assert_eq!(invite_root, session.session().ratchet().trusted_root);
        assert!(session.effective().users.contains_key(&output.user_id));
        assert!(output.handle.is_some());
        assert!(thorax_store::read_transaction(&fixture.paths, &invite_root)
            .unwrap()
            .is_none());
    }

    #[test]
    fn invitation_transaction_recovers_complete_result_at_every_fault_point() {
        use crate::transaction::{inject_test_fault, TestFaultPoint};

        for (index, point) in [
            TestFaultPoint::AfterJournal,
            TestFaultPoint::AfterRatchet,
            TestFaultPoint::AfterVault,
            TestFaultPoint::BeforeJournalRemoval,
        ]
        .into_iter()
        .enumerate()
        {
            let fixture = ProductionFixture::initialized();
            let selector = SecretSelectorV1::tuple(["app", "db"]);
            set_secret(
                &fixture.paths,
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                b"value",
            )
            .unwrap();
            let locked = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            let root_identity =
                Identity::from_master_seed(&fixture.crypto, fixture.root.master_seed()).unwrap();
            let mut session =
                UnlockedSession::with_identity(locked, &fixture.crypto, root_identity).unwrap();
            let prepared = session
                .prepare_invite_user(
                    &fixture.crypto,
                    Some(format!("alice-{index}")),
                    vec![GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(
                        ["app"],
                    ))],
                )
                .unwrap();
            let user_id = prepared.output.user_id.clone();
            let handle_id = prepared.output.handle.clone().unwrap();
            let grant_id = prepared.output.grants[0].clone();
            assert_eq!(prepared.output.reconcile.encrypted, vec![selector.clone()]);

            inject_test_fault(point);
            assert!(session
                .commit_invite_user(&fixture.crypto, prepared)
                .is_err());

            let recovered = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            assert!(recovered.effective().users.contains_key(&user_id));
            assert_eq!(
                recovered
                    .effective()
                    .handles
                    .get(&handle_id)
                    .unwrap()
                    .user_id,
                user_id
            );
            assert_eq!(
                recovered
                    .effective()
                    .grants
                    .get(&grant_id)
                    .unwrap()
                    .subject_id,
                PrincipalRefV1::User(user_id.clone())
            );
            assert_eq!(
                recovered.effective().classify_secret_for_user(
                    &selector,
                    &user_id,
                    &fixture.crypto
                ),
                SecretState::ActiveDecryptable
            );
        }
    }

    #[test]
    fn claim_rejects_invitation_for_another_root_before_storing_identity() {
        let fixture = ProductionFixture::initialized();
        let keychain = root_keychain(&fixture);
        let mut invited = invite_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            Some("alice".into()),
            vec![],
        )
        .unwrap()
        .invite;
        invited.trusted_root = HashValue(vec![99; 32]);
        let recipient_keychain = PassphraseKeychain::new(
            fixture._temp.path.join("recipient-keychain"),
            thorax_keychain::StaticPassphraseProvider::new("recipient passphrase"),
        );
        let error = claim_invite_with_keychain(
            &fixture
                .paths
                .clone()
                .with_state_dir(fixture._temp.path.join("recipient-state")),
            &fixture.crypto,
            &recipient_keychain,
            &invited,
        )
        .unwrap_err();
        assert!(matches!(error, OpsError::InviteRootMismatch));
    }

    #[test]
    fn claim_rejects_vault_rolled_back_past_invite_baseline() {
        let fixture = ProductionFixture::initialized();
        let keychain = PassphraseKeychain::new(
            fixture._temp.path.join("keychain"),
            thorax_keychain::StaticPassphraseProvider::new("root keychain passphrase"),
        );
        let root_signing_public_key_hash =
            key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        save_identity_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            &root_signing_public_key_hash,
            &fixture.root,
        )
        .unwrap();

        // Invite alice, then delete her.
        let alice = invite_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            Some("alice".to_string()),
            vec![],
        )
        .unwrap();
        delete_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            alice.user_id.clone(),
            None,
        )
        .unwrap();

        // Invite carol *after* the deletion: her bundle baseline carries the watermark the
        // deletion raised at alice's user key.
        let carol = invite_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            Some("carol".to_string()),
            vec![],
        )
        .unwrap();
        let alice_key = RecordKey::User {
            user_id: alice.user_id.clone(),
        };
        assert!(
            carol
                .invite
                .rollback_baseline
                .as_ref()
                .expect("new invitations carry a full baseline internally")
                .records
                .iter()
                .any(|record| record.key().as_ref() == Some(&alice_key)),
            "invite baseline must carry the watermark raised by the deletion"
        );

        // A returning user / same machine would catch this via remembered trust, so claim
        // on a fresh machine (no prior local trust) to prove the *baseline* is what rejects
        // the rollback.
        let carol_paths = fixture
            .paths
            .clone()
            .with_state_dir(fixture._temp.path.join("carol-state"));
        let carol_keychain = PassphraseKeychain::new(
            fixture._temp.path.join("carol-keychain"),
            thorax_keychain::StaticPassphraseProvider::new("carol keychain passphrase"),
        );

        // Sanity: against the honest vault, carol's claim succeeds.
        claim_invite_with_keychain(
            &carol_paths,
            &fixture.crypto,
            &carol_keychain,
            &carol.invite,
        )
        .expect("claim should succeed against the honest vault");

        // Now an attacker rolls the vault back: drop alice's deletion record (but keep
        // carol), and have carol claim again on a different fresh machine.
        let mut vault = read_vault(&fixture.paths).unwrap();
        let VaultStore::V1(ref mut v1) = vault;
        let before = v1.records.len();
        v1.records = v1
            .records
            .iter()
            .filter(|record| !matches!(record.body.known(), Some(RecordBodyV1::UserDeleted(_))))
            .cloned()
            .collect();
        assert!(
            v1.records.len() < before,
            "expected to drop a deletion record"
        );
        write_vault_atomic(&fixture.paths, &vault).unwrap();

        let attacker_paths = fixture
            .paths
            .clone()
            .with_state_dir(fixture._temp.path.join("carol-state-2"));
        let attacker_keychain = PassphraseKeychain::new(
            fixture._temp.path.join("carol-keychain-2"),
            thorax_keychain::StaticPassphraseProvider::new("carol keychain passphrase"),
        );
        let result = claim_invite_with_keychain(
            &attacker_paths,
            &fixture.crypto,
            &attacker_keychain,
            &carol.invite,
        );
        assert!(
            matches!(result, Err(OpsError::ClaimRolledBack)),
            "claim must reject a vault rolled back past the invite baseline, got {result:?}"
        );
    }

    #[test]
    fn compact_claim_starts_local_rollback_protection_but_ci_requires_a_baseline() {
        let fixture = ProductionFixture::initialized();
        let keychain = root_keychain(&fixture);
        let alice = invite_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            Some("alice".to_string()),
            vec![],
        )
        .unwrap();
        let mut compact = alice.invite.clone();
        compact.rollback_baseline = None;

        let claim_paths = fixture
            .paths
            .clone()
            .with_state_dir(fixture._temp.path.join("compact-claim-state"));
        let recipient_keychain = PassphraseKeychain::new(
            fixture._temp.path.join("compact-claim-keychain"),
            thorax_keychain::StaticPassphraseProvider::new("recipient passphrase"),
        );
        let claimed = claim_invite_with_keychain(
            &claim_paths,
            &fixture.crypto,
            &recipient_keychain,
            &compact,
        )
        .expect("an interactive compact claim uses trust on first use");
        assert!(!claimed.rollback_protected);
        assert!(read_ratchet_for_root(&claim_paths, &claimed.trusted_root)
            .unwrap()
            .is_some());

        let ci_paths = fixture
            .paths
            .clone()
            .with_state_dir(fixture._temp.path.join("compact-ci-state"));
        assert!(matches!(
            ensure_ratchet_from_invite(&ci_paths, &fixture.crypto, &compact),
            Err(OpsError::InviteRollbackBaselineRequired)
        ));
    }

    #[test]
    fn claim_rejects_vault_missing_the_claimers_trust_root() {
        let fixture = ProductionFixture::initialized();
        let keychain = PassphraseKeychain::new(
            fixture._temp.path.join("keychain"),
            thorax_keychain::StaticPassphraseProvider::new("root keychain passphrase"),
        );
        let root_signing_public_key_hash =
            key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        save_identity_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            &root_signing_public_key_hash,
            &fixture.root,
        )
        .unwrap();

        let alice = invite_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            Some("alice".to_string()),
            vec![],
        )
        .unwrap();

        // Strip alice's self-signed entry-point record. Without her commitment to the root,
        // the validator no longer treats her as an effective user at all. (Entry points
        // are identified by their envelope signing key, resolved via alice's user record.)
        let mut vault = read_vault(&fixture.paths).unwrap();
        let VaultStore::V1(ref mut v1) = vault;
        let alice_signing_key = v1
            .records
            .iter()
            .find_map(|record| match record.body.known() {
                Some(RecordBodyV1::User(user)) if user.id == alice.user_id => {
                    Some(user.signing_public_key.clone())
                }
                _ => None,
            })
            .expect("alice's user record must exist");
        let before = v1.records.len();
        v1.records = v1
            .records
            .iter()
            .filter(|record| {
                !(matches!(record.body.known(), Some(RecordBodyV1::EntryPoint(_)))
                    && record.signing_public_key == alice_signing_key)
            })
            .cloned()
            .collect();
        assert!(
            v1.records.len() < before,
            "expected to drop alice's entry-point record"
        );
        write_vault_atomic(&fixture.paths, &vault).unwrap();

        let alice_paths = fixture
            .paths
            .clone()
            .with_state_dir(fixture._temp.path.join("alice-state"));
        let alice_keychain = PassphraseKeychain::new(
            fixture._temp.path.join("alice-keychain"),
            thorax_keychain::StaticPassphraseProvider::new("alice keychain passphrase"),
        );
        let result = claim_invite_with_keychain(
            &alice_paths,
            &fixture.crypto,
            &alice_keychain,
            &alice.invite,
        );
        assert!(
            matches!(result, Err(OpsError::ClaimNotAMember(_))),
            "a claimer whose entry-point record is missing is not an effective member, got {result:?}"
        );
    }
}
