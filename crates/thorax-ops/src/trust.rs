use std::collections::BTreeSet;

use thorax_core::crypto::{derive_user_id as core_derive_user_id, key_hash, signed_record_message};
use thorax_core::hazmat::{entry_point_record, vault_root_record};
use thorax_core::{
    validate_vault, ConflictKind, ConflictReport, CryptoProvider, HashValue, Ratchet, RecordBodyV1,
    RecordSigner, ValidationReport, VaultStore, VaultStoreV1,
};
use thorax_store::{
    acquire_root_state_lock, acquire_root_state_shared_lock, acquire_workspace_lock, ratchet_path,
    read_ratchet_for_root, read_vault, write_ratchet_atomic, write_vault_atomic, WorkspacePaths,
};

use thorax_crypto::Crypto;
use thorax_keychain::{IdentityKeychain, KeyUsePurpose, KeychainRequest};

use crate::{
    AbandonTransactionOutput, CheckMergedVaultOutput, InitVaultOutput, OpsError,
    ResetRatchetOutput, Result, UserId,
};

pub fn init_vault(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    root: &impl RecordSigner,
) -> Result<InitVaultOutput> {
    if paths.vault_path.exists() {
        return Err(OpsError::VaultAlreadyInitialized(paths.vault_path.clone()));
    }

    // The root vouches for itself: every user, root included, carries a self-signed
    // EntryPointRecord so the trust chain (key -> UserId -> EntryPointRecord -> root) is
    // re-derivable from the vault alone.
    let root_signed = vault_root_record(crypto, root)?;
    // The genesis entry point is the first LWW record in an otherwise-empty vault, so its
    // Lamport counter starts at 0.
    let root_entry_point = entry_point_record(crypto, root, root.user_id().clone(), 0)?;
    let vault = VaultStore::V1(VaultStoreV1 {
        records: vec![root_signed, root_entry_point].into(),
    });
    let root_signing_public_key_hash = key_hash(crypto, root.signing_public_key())?;
    let mut ratchet = Ratchet::new(root_signing_public_key_hash.clone());
    let report = validate_vault(&vault, &ratchet, crypto)?;
    ensure_no_issues(&report)?;
    ratchet.apply_update(&report.ratchet_update);

    let _root_lock = acquire_root_state_lock(paths, &root_signing_public_key_hash)?;
    let _workspace_lock = acquire_workspace_lock(paths)?;
    if paths.vault_path.exists() {
        return Err(OpsError::VaultAlreadyInitialized(paths.vault_path.clone()));
    }

    write_ratchet_atomic(paths, &ratchet)?;
    write_vault_atomic(paths, &vault)?;

    Ok(InitVaultOutput {
        paths: paths.clone(),
        root_user_id: root.user_id().clone(),
        root_signing_public_key_hash,
        vault,
        ratchet,
        report,
    })
}

/// `reset_ratchet` gated on an identity unlock — the public form. Discarding
/// rollback memory is the most consequential action the CLI offers, so it sits behind the
/// passphrase/user-presence channel like every other key use. The unlock is deliberately
/// *not* the session funnel: a rollback may have conflicted the very entry point that
/// makes the actor an effective member, so requiring membership here would deadlock the
/// recovery — possession (per-root keychain + root-in-AAD already bind the identity to
/// this vault family) is the right gate. `dry_run` is gated too: what the reset *would*
/// discard is itself trust-state information.
pub fn reset_ratchet_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    user_id: &UserId,
    dry_run: bool,
) -> Result<ResetRatchetOutput> {
    let vault = read_vault(paths)?;
    let trusted_root = trusted_root_candidate(&vault, crypto)?;
    let request = KeychainRequest::new(
        paths,
        trusted_root,
        user_id.clone(),
        KeyUsePurpose::SignAdminChange {
            summary: "reset local trust (accept this vault's current, possibly older, state)"
                .to_string(),
        },
    );
    let identity = keychain.unlock_identity(crypto, &request)?;
    if identity.user_id() != user_id {
        return Err(OpsError::KeychainIdentityMismatch {
            expected: user_id.clone(),
            actual: identity.user_id().clone(),
        });
    }
    reset_ratchet(paths, crypto, dry_run)
}

pub fn abandon_transaction_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    user_id: &UserId,
) -> Result<AbandonTransactionOutput> {
    let vault = read_vault(paths)?;
    let trusted_root = trusted_root_candidate(&vault, crypto)?;
    let request = KeychainRequest::new(
        paths,
        trusted_root.clone(),
        user_id.clone(),
        KeyUsePurpose::SignAdminChange {
            summary: "abandon an interrupted local transaction".to_string(),
        },
    );
    let identity = keychain.unlock_identity(crypto, &request)?;
    if identity.user_id() != user_id {
        return Err(OpsError::KeychainIdentityMismatch {
            expected: user_id.clone(),
            actual: identity.user_id().clone(),
        });
    }
    let abandoned = crate::transaction::abandon_transaction(paths, &trusted_root, crypto)?;
    Ok(AbandonTransactionOutput {
        trusted_root,
        transaction_id: abandoned.transaction_id,
        operation: abandoned.operation,
        origin: abandoned.origin,
    })
}

/// Recovery flow for a suspected rollback: re-establish this machine's local trust from the
/// current vault, deliberately accepting its present state. This is the *only* way to
/// proceed past a detected rollback — it discards remembered removals the vault no longer
/// carries, so it requires explicit user intent at the call site. With `dry_run`, it reports
/// what would be discarded without writing anything. Crate-internal: the public surface is
/// [`reset_ratchet_with_keychain`], which fronts it with an identity unlock.
pub(crate) fn reset_ratchet(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    dry_run: bool,
) -> Result<ResetRatchetOutput> {
    let vault = read_vault(paths)?;
    let trusted_root = trusted_root_candidate(&vault, crypto)?;
    let _root_lock = acquire_root_state_lock(paths, &trusted_root)?;
    let _workspace_lock = acquire_workspace_lock(paths)?;
    crate::transaction::ensure_no_pending_transaction_locked(paths, &trusted_root, crypto)?;
    let vault = read_vault(paths)?;
    let reread_root = trusted_root_candidate(&vault, crypto)?;
    if reread_root != trusted_root {
        return Err(thorax_store::StoreError::TrustRootMismatch {
            stored: reread_root,
            requested: trusted_root,
        }
        .into());
    }
    let existing = read_ratchet_for_root(paths, &trusted_root)?
        .ok_or_else(|| OpsError::MissingRatchet(ratchet_path(paths, &trusted_root)))?;

    // Derive trust from the vault alone — exactly what the repository currently justifies.
    // With empty starting trust there are no rollback issues to discover; only structural
    // corruption would fail here, in which case we must not accept the vault.
    let mut fresh = Ratchet::new(trusted_root.clone());
    let report = validate_vault(&vault, &fresh, crypto)?;
    ensure_no_issues(&report)?;
    fresh.apply_update(&report.ratchet_update);

    // What protection the reset gives up: keys whose remembered watermark the vault has
    // fallen below (a value/deletion rollback we are now accepting).
    let mut dropped_watermarks = Vec::new();
    for (key, counter) in &existing.watermarks {
        if fresh.watermarks.get(key).copied().unwrap_or(0) < *counter {
            dropped_watermarks.push(key.clone());
        }
    }

    if !dry_run {
        write_ratchet_atomic(paths, &fresh)?;
    }

    Ok(ResetRatchetOutput {
        trusted_root,
        dropped_watermarks,
        applied: !dry_run,
    })
}

pub fn check_merged_vault(
    paths: &WorkspacePaths,
    vault: &VaultStore,
    crypto: &impl CryptoProvider,
) -> Result<CheckMergedVaultOutput> {
    let trusted_root = trusted_root_candidate(vault, crypto)?;
    let _root_lock = acquire_root_state_shared_lock(paths, &trusted_root)?;
    let (ratchet, ratchet_checked) =
        match crate::transaction::read_strongest_ratchet_optional_locked(
            paths,
            &trusted_root,
            crypto,
        )? {
            Some(ratchet) => (ratchet, true),
            None => (Ratchet::new(trusted_root), false),
        };
    let report = validate_vault(vault, &ratchet, crypto)?;
    let conflicts: Vec<ConflictReport> = report.effective.conflicted.values().cloned().collect();
    Ok(CheckMergedVaultOutput {
        issues: report.issues,
        conflicts,
        ratchet_checked,
    })
}

pub(crate) fn has_suspected_rollback(report: &ValidationReport) -> bool {
    report
        .effective
        .conflicted
        .values()
        .any(|conflict| matches!(conflict.kind, ConflictKind::Rollback { .. }))
}

pub fn trusted_root_candidate(
    vault: &VaultStore,
    crypto: &impl CryptoProvider,
) -> Result<HashValue> {
    let VaultStore::V1(v1) = vault;
    let mut candidates = BTreeSet::new();

    for signed in &v1.records {
        let Some(RecordBodyV1::VaultRoot(root)) = signed.body.known() else {
            continue;
        };
        // Self-signed: the root's signing key is the envelope's.
        if root.id
            != core_derive_user_id(crypto, &signed.signing_public_key, &root.hpke_public_key)?
        {
            continue;
        }
        let message = signed_record_message(signed)?;
        if !crypto.verify_signature(
            "thorax.signed.v1",
            &signed.signing_public_key,
            &message,
            &signed.signature,
        ) {
            continue;
        }
        candidates.insert(key_hash(crypto, &signed.signing_public_key)?);
    }

    match candidates.len() {
        0 => Err(OpsError::MissingTrustedRootCandidate),
        1 => Ok(candidates.into_iter().next().expect("one candidate")),
        _ => Err(OpsError::AmbiguousTrustedRootCandidates(
            candidates.into_iter().collect(),
        )),
    }
}

pub(crate) fn ensure_no_issues(report: &ValidationReport) -> Result<()> {
    if report.issues.is_empty() {
        Ok(())
    } else {
        Err(OpsError::ValidationFailed(report.issues.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::RecordKey;

    #[test]
    fn init_vault_writes_valid_vault_and_ratchet() {
        let fixture = Fixture::new();

        let initialized = init_vault(&fixture.paths, &fixture.crypto, &fixture.root).unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert_eq!(initialized.root_user_id, fixture.root.id);
        assert_eq!(loaded.effective().root_user_id, Some(fixture.root.id));
        assert_eq!(
            loaded.ratchet().trusted_root,
            key_hash(&fixture.crypto, &fixture.root.signing_public_key).unwrap()
        );
        assert!(
            ratchet_path(&fixture.paths, &initialized.root_signing_public_key_hash)
                .starts_with(fixture._temp.path.join("machine-state"))
        );
        assert!(ratchet_path(&fixture.paths, &initialized.root_signing_public_key_hash).exists());
        assert_ne!(
            ratchet_path(&fixture.paths, &initialized.root_signing_public_key_hash).parent(),
            Some(fixture.paths.thorax_dir.as_path())
        );
    }

    #[test]
    fn reset_with_keychain_unlocks_then_resets() {
        let fixture = ProductionFixture::initialized();
        let keychain = crate::ManualIdentityKeychain::new(
            crate::FixedIdentityProvider::from_master_seed(
                &fixture.crypto,
                fixture.root.master_seed(),
            )
            .unwrap(),
        );
        let output = reset_ratchet_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            true,
        )
        .unwrap();
        assert!(!output.applied);

        // An identity the keychain cannot release fails the gate before anything resets.
        let stranger = crate::Identity::generate(&fixture.crypto).unwrap();
        let error = reset_ratchet_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            stranger.user_id(),
            true,
        )
        .unwrap_err();
        assert!(matches!(error, OpsError::Keychain(_)), "{error:?}");
    }

    #[test]
    fn reset_ratchet_discards_watermarks_above_the_vault() {
        let fixture = ProductionFixture::initialized();
        let trusted_root = key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();

        // Plant a remembered watermark the vault does not justify — i.e. simulate having
        // seen a newer state that a later (rolled-back) checkout no longer contains.
        let mut trust = read_ratchet_for_root(&fixture.paths, &trusted_root)
            .unwrap()
            .unwrap();
        let ghost =
            core_derive_user_id(&fixture.crypto, b"ghost-signing-key", b"ghost-hpke-key").unwrap();
        let ghost_key = RecordKey::User {
            user_id: ghost.clone(),
        };
        trust.watermarks.insert(ghost_key.clone(), 1_000);
        write_ratchet_atomic(&fixture.paths, &trust).unwrap();

        // The workspace now looks rolled back: the ghost key is a rollback conflict.
        let loaded = load_session(&fixture.paths, &fixture.crypto);
        assert!(matches!(
            loaded.effective().conflicted.get(&ghost_key),
            Some(conflict) if matches!(conflict.kind, ConflictKind::Rollback { .. })
        ));

        // Dry run reports the drop and changes nothing.
        let plan = reset_ratchet(&fixture.paths, &fixture.crypto, true).unwrap();
        assert!(plan.dropped_watermarks.contains(&ghost_key));
        assert!(!plan.applied);
        let loaded = load_session(&fixture.paths, &fixture.crypto);
        assert!(
            !loaded.effective().conflicted.is_empty(),
            "dry run must not write"
        );

        // Applying it accepts the current vault and clears the suspicion.
        let done = reset_ratchet(&fixture.paths, &fixture.crypto, false).unwrap();
        assert!(done.applied);
        assert!(done.dropped_watermarks.contains(&ghost_key));
        let loaded = load_session(&fixture.paths, &fixture.crypto);
        assert!(
            loaded.effective().conflicted.is_empty(),
            "after reset, no conflicts remain: {:?}",
            loaded.effective().conflicted
        );
    }
}
