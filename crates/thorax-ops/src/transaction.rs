use std::{io, path::PathBuf};

use thorax_core::{decode_vault, CryptoProvider, HashValue, Ratchet};
use thorax_crypto::random_seed;
use thorax_store::{
    acquire_root_state_lock, acquire_root_state_shared_lock, acquire_workspace_lock,
    decode_ratchet, read_file_bounded, read_ratchet_for_root, read_transaction, read_vault_bytes,
    remove_file_durable, transaction_path, write_ratchet_atomic, write_ratchet_bytes_atomic,
    write_transaction_atomic, write_vault_bytes_atomic, FilePreconditionV1, NativePathV1,
    TransactionV1, WorkspacePaths, MAX_RATCHET_BYTES,
};

use crate::{trusted_root_candidate, OpsError, Result};

pub const TRANSACTION_HASH_DOMAIN: &str = "thorax.transaction-file.v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TestFaultPoint {
    AfterJournal,
    AfterRatchet,
    AfterVault,
    BeforeJournalRemoval,
}

#[cfg(test)]
pub(crate) fn inject_test_fault(point: TestFaultPoint) {
    TEST_FAULT.with(|fault| fault.set(Some(point)));
}

#[cfg(test)]
thread_local! {
    static TEST_FAULT: std::cell::Cell<Option<TestFaultPoint>> = const { std::cell::Cell::new(None) };
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTransaction {
    pub transaction_id: Vec<u8>,
    pub operation: String,
    pub origin: Option<PathBuf>,
    pub recoverable_here: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecoveryDisposition {
    None,
    Recovered,
    PendingElsewhere,
}

fn recover_transaction_if_origin(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<RecoveryDisposition> {
    let read_lock = acquire_root_state_shared_lock(paths, trusted_root)?;
    let Some(transaction) = read_transaction(paths, trusted_root)? else {
        return Ok(RecoveryDisposition::None);
    };
    validate_transaction(&transaction, crypto, paths)?;
    let is_origin = transaction
        .origin_vault_path
        .matches_canonical(&paths.vault_path)?;
    if !is_origin {
        return Ok(RecoveryDisposition::PendingElsewhere);
    }
    drop(read_lock);

    let _root_lock = acquire_root_state_lock(paths, trusted_root)?;
    let _workspace_lock = acquire_workspace_lock(paths)?;
    let Some(transaction) = read_transaction(paths, trusted_root)? else {
        return Ok(RecoveryDisposition::Recovered);
    };
    validate_transaction(&transaction, crypto, paths)?;
    if !transaction
        .origin_vault_path
        .matches_canonical(&paths.vault_path)?
    {
        return Ok(RecoveryDisposition::PendingElsewhere);
    }
    complete_transaction_locked(paths, &transaction, crypto)?;
    Ok(RecoveryDisposition::Recovered)
}

pub(crate) fn recover_for_root(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<RecoveryDisposition> {
    let coexistence_lock = acquire_root_state_shared_lock(paths, trusted_root)?;
    let has_transaction = read_transaction(paths, trusted_root)?.is_some();
    let has_legacy_join = crate::enrollment::join_commit_present(paths, trusted_root)?;
    drop(coexistence_lock);
    if has_transaction && has_legacy_join {
        return Err(OpsError::MultipleRecoveryTransactions);
    }
    let disposition = recover_transaction_if_origin(paths, trusted_root, crypto)?;
    if disposition != RecoveryDisposition::None {
        return Ok(disposition);
    }
    if crate::enrollment::recover_join_commit(paths, trusted_root)? {
        Ok(RecoveryDisposition::Recovered)
    } else {
        Ok(RecoveryDisposition::None)
    }
}

pub fn recover_current_workspace_if_needed(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
) -> Result<bool> {
    let vault_bytes = read_vault_bytes(paths)?;
    let vault =
        decode_vault(&vault_bytes).map_err(|source| thorax_store::StoreError::InvalidVault {
            path: paths.vault_path.clone(),
            source,
        })?;
    let trusted_root = trusted_root_candidate(&vault, crypto)?;
    Ok(matches!(
        recover_for_root(paths, &trusted_root, crypto)?,
        RecoveryDisposition::Recovered
    ))
}

/// Read the root's strongest rollback state while the caller holds the shared or
/// exclusive root-state lock. A durable journal contributes its after-image immediately.
pub(crate) fn read_strongest_ratchet_locked(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<(Ratchet, Option<PendingTransaction>)> {
    let (ratchet, pending) =
        read_strongest_ratchet_optional_with_pending_locked(paths, trusted_root, crypto)?;
    let ratchet = ratchet
        .ok_or_else(|| OpsError::MissingRatchet(thorax_store::ratchet_path(paths, trusted_root)))?;
    Ok((ratchet, pending))
}

pub(crate) fn read_strongest_ratchet_optional_locked(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<Option<Ratchet>> {
    Ok(read_strongest_ratchet_optional_with_pending_locked(paths, trusted_root, crypto)?.0)
}

fn read_strongest_ratchet_optional_with_pending_locked(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<(Option<Ratchet>, Option<PendingTransaction>)> {
    let mut ratchet = read_ratchet_for_root(paths, trusted_root)?;
    let Some(transaction) = read_transaction(paths, trusted_root)? else {
        return Ok((ratchet, None));
    };
    let next_ratchet = validate_transaction(&transaction, crypto, paths)?;
    let current = ratchet.get_or_insert_with(|| Ratchet::new(trusted_root.clone()));
    merge_ratchet(current, &next_ratchet)?;
    let recoverable_here = transaction
        .origin_vault_path
        .matches_canonical(&paths.vault_path)?;
    Ok((
        ratchet,
        Some(PendingTransaction {
            transaction_id: transaction.transaction_id,
            operation: transaction.operation,
            origin: transaction.origin_vault_path.to_path_buf(),
            recoverable_here,
        }),
    ))
}

/// Persist a fully prepared existing-vault mutation. The caller holds the exclusive root
/// lock and then the current workspace lock, and has validated the operation against the
/// supplied exact before-images.
#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_after_images_locked(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
    operation: &str,
    expected_vault_bytes: &[u8],
    expected_ratchet_bytes: &[u8],
    next_vault_bytes: Vec<u8>,
    next_ratchet_bytes: Vec<u8>,
) -> Result<()> {
    if crate::enrollment::join_commit_present(paths, trusted_root)? {
        return Err(OpsError::MultipleRecoveryTransactions);
    }
    if let Some(pending) = read_transaction(paths, trusted_root)? {
        return Err(pending_error(&pending));
    }

    if read_vault_bytes(paths)? != expected_vault_bytes {
        return Err(OpsError::TransactionPreconditionChanged("vault"));
    }
    let current_ratchet = read_current_file(
        thorax_store::ratchet_path(paths, trusted_root),
        MAX_RATCHET_BYTES,
    )?
    .ok_or(OpsError::TransactionPreconditionChanged("ratchet"))?;
    if current_ratchet != expected_ratchet_bytes {
        return Err(OpsError::TransactionPreconditionChanged("ratchet"));
    }

    let transaction = TransactionV1 {
        transaction_id: random_seed().0,
        trusted_root: trusted_root.clone(),
        origin_vault_path: NativePathV1::canonical(&paths.vault_path)?,
        operation: operation.to_string(),
        vault_before: FilePreconditionV1::Hash(file_hash(crypto, expected_vault_bytes)),
        ratchet_before: FilePreconditionV1::Hash(file_hash(crypto, expected_ratchet_bytes)),
        next_vault_bytes,
        next_ratchet_bytes,
    };
    validate_transaction(&transaction, crypto, paths)?;
    write_transaction_atomic(paths, &transaction)?;
    maybe_inject_fault(
        paths,
        &transaction.trusted_root,
        TestFaultPoint::AfterJournal,
    )?;
    complete_transaction_locked(paths, &transaction, crypto)
}

pub(crate) fn ensure_no_pending_transaction_locked(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<()> {
    if crate::enrollment::join_commit_present(paths, trusted_root)? {
        return Err(OpsError::MultipleRecoveryTransactions);
    }
    if let Some(transaction) = read_transaction(paths, trusted_root)? {
        validate_transaction(&transaction, crypto, paths)?;
        return Err(pending_error(&transaction));
    }
    Ok(())
}

pub(crate) fn abandon_transaction(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Result<PendingTransaction> {
    let _root_lock = acquire_root_state_lock(paths, trusted_root)?;
    let transaction =
        read_transaction(paths, trusted_root)?.ok_or(OpsError::NoPendingTransaction)?;
    let after = validate_transaction(&transaction, crypto, paths)?;
    let mut persisted = read_ratchet_for_root(paths, trusted_root)?
        .ok_or_else(|| OpsError::MissingRatchet(thorax_store::ratchet_path(paths, trusted_root)))?;
    merge_ratchet(&mut persisted, &after)?;
    write_ratchet_atomic(paths, &persisted)?;
    remove_file_durable(transaction_path(paths, trusted_root))?;
    Ok(PendingTransaction {
        transaction_id: transaction.transaction_id,
        operation: transaction.operation,
        origin: transaction.origin_vault_path.to_path_buf(),
        recoverable_here: false,
    })
}

fn complete_transaction_locked(
    paths: &WorkspacePaths,
    transaction: &TransactionV1,
    crypto: &impl CryptoProvider,
) -> Result<()> {
    let current_vault = read_current_file(paths.vault_path.clone(), thorax_core::MAX_VAULT_BYTES)?;
    let current_ratchet = read_current_file(
        thorax_store::ratchet_path(paths, &transaction.trusted_root),
        MAX_RATCHET_BYTES,
    )?;

    let vault_is_after = classify_file(
        crypto,
        current_vault.as_deref(),
        &transaction.vault_before,
        &transaction.next_vault_bytes,
    )?;
    let ratchet_is_after = classify_file(
        crypto,
        current_ratchet.as_deref(),
        &transaction.ratchet_before,
        &transaction.next_ratchet_bytes,
    )?;

    if !ratchet_is_after {
        write_ratchet_bytes_atomic(
            paths,
            &transaction.trusted_root,
            &transaction.next_ratchet_bytes,
        )?;
    }
    maybe_inject_fault(
        paths,
        &transaction.trusted_root,
        TestFaultPoint::AfterRatchet,
    )?;
    if !vault_is_after {
        write_vault_bytes_atomic(paths, &transaction.next_vault_bytes)?;
    }
    maybe_inject_fault(paths, &transaction.trusted_root, TestFaultPoint::AfterVault)?;

    let reopened_ratchet = read_current_file(
        thorax_store::ratchet_path(paths, &transaction.trusted_root),
        MAX_RATCHET_BYTES,
    )?;
    let reopened_vault = read_current_file(paths.vault_path.clone(), thorax_core::MAX_VAULT_BYTES)?;
    if reopened_ratchet.as_deref() != Some(transaction.next_ratchet_bytes.as_slice())
        || reopened_vault.as_deref() != Some(transaction.next_vault_bytes.as_slice())
    {
        return Err(OpsError::TransactionRecoveryConflict);
    }

    maybe_inject_fault(
        paths,
        &transaction.trusted_root,
        TestFaultPoint::BeforeJournalRemoval,
    )?;
    remove_file_durable(transaction_path(paths, &transaction.trusted_root))?;
    Ok(())
}

fn validate_transaction(
    transaction: &TransactionV1,
    crypto: &impl CryptoProvider,
    paths: &WorkspacePaths,
) -> Result<Ratchet> {
    let vault = decode_vault(&transaction.next_vault_bytes).map_err(|source| {
        thorax_store::StoreError::InvalidVault {
            path: transaction_path(paths, &transaction.trusted_root),
            source,
        }
    })?;
    let vault_root = trusted_root_candidate(&vault, crypto)?;
    if vault_root != transaction.trusted_root {
        return Err(OpsError::TransactionRecoveryConflict);
    }
    let ratchet = decode_ratchet(
        transaction_path(paths, &transaction.trusted_root),
        &transaction.next_ratchet_bytes,
    )?;
    if ratchet.trusted_root != transaction.trusted_root {
        return Err(OpsError::TransactionRecoveryConflict);
    }
    Ok(ratchet)
}

fn classify_file(
    crypto: &impl CryptoProvider,
    current: Option<&[u8]>,
    before: &FilePreconditionV1,
    after: &[u8],
) -> Result<bool> {
    let is_before = match (current, before) {
        (None, FilePreconditionV1::Missing) => true,
        (Some(bytes), FilePreconditionV1::Hash(expected)) => file_hash(crypto, bytes) == *expected,
        _ => false,
    };
    let is_after =
        current.is_some_and(|bytes| file_hash(crypto, bytes) == file_hash(crypto, after));
    if !is_before && !is_after {
        return Err(OpsError::TransactionRecoveryConflict);
    }
    Ok(is_after)
}

fn file_hash(crypto: &impl CryptoProvider, bytes: &[u8]) -> HashValue {
    crypto.hash(TRANSACTION_HASH_DOMAIN, bytes)
}

fn read_current_file(path: PathBuf, max_bytes: usize) -> Result<Option<Vec<u8>>> {
    match read_file_bounded(&path, max_bytes) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(thorax_store::StoreError::Io { path, source }.into()),
    }
}

fn merge_ratchet(current: &mut Ratchet, after: &Ratchet) -> Result<()> {
    if current.trusted_root != after.trusted_root {
        return Err(OpsError::TransactionRecoveryConflict);
    }
    for record in after.to_records() {
        current.absorb_record(&record);
    }
    for unknown in &after.unknown_records {
        if !current.unknown_records.contains(unknown) {
            current.unknown_records.push(unknown.clone());
        }
    }
    Ok(())
}

fn pending_error(transaction: &TransactionV1) -> OpsError {
    let origin = transaction
        .origin_vault_path
        .to_path_buf()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<another platform path>".to_string());
    OpsError::PendingTransaction {
        transaction_id: transaction_id_hex(&transaction.transaction_id),
        origin,
    }
}

pub(crate) fn pending_barrier_error(pending: &PendingTransaction) -> OpsError {
    OpsError::PendingTransaction {
        transaction_id: transaction_id_hex(&pending.transaction_id),
        origin: pending
            .origin
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<another platform path>".to_string()),
    }
}

fn transaction_id_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
fn maybe_inject_fault(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
    point: TestFaultPoint,
) -> Result<()> {
    let should_fail = TEST_FAULT.with(|fault| {
        if fault.get() == Some(point) {
            fault.set(None);
            true
        } else {
            false
        }
    });
    if should_fail {
        return Err(thorax_store::StoreError::Io {
            path: transaction_path(paths, trusted_root),
            source: io::Error::new(
                io::ErrorKind::Interrupted,
                format!("injected transaction fault at {point:?}"),
            ),
        }
        .into());
    }
    Ok(())
}

#[cfg(not(test))]
fn maybe_inject_fault(
    _paths: &WorkspacePaths,
    _trusted_root: &HashValue,
    _point: TestFaultPoint,
) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use thorax_crypto::Identity;
    use thorax_store::{
        create_workspace_dirs, encode_ratchet, read_ratchet_bytes_for_root, transaction_path,
        write_ratchet_bytes_atomic, write_transaction_atomic, write_vault_bytes_atomic,
    };

    use super::*;
    use crate::test_util::{add_user, ProductionFixture};
    use crate::{KeyUsePurpose, LockedSession, ManualIdentityKeychain, UnlockedSession};

    #[derive(Clone, Debug)]
    struct PanicIdentityProvider;

    impl thorax_keychain::ManualIdentityProvider for PanicIdentityProvider {
        fn request_identity(
            &self,
            _request: &thorax_keychain::KeychainRequest,
        ) -> thorax_keychain::Result<Option<thorax_keychain::LocalIdentityV1>> {
            panic!("pending mutation must fail before asking the keychain")
        }
    }

    struct Images {
        vault: Vec<u8>,
        ratchet: Vec<u8>,
    }

    fn images(paths: &WorkspacePaths, root: &HashValue) -> Images {
        Images {
            vault: read_vault_bytes(paths).unwrap(),
            ratchet: read_ratchet_bytes_for_root(paths, root).unwrap().unwrap(),
        }
    }

    fn restore(paths: &WorkspacePaths, root: &HashValue, images: &Images) {
        write_ratchet_bytes_atomic(paths, root, &images.ratchet).unwrap();
        write_vault_bytes_atomic(paths, &images.vault).unwrap();
    }

    fn pending_transaction(
        fixture: &ProductionFixture,
        root: &HashValue,
        before: &Images,
        after: &Images,
    ) -> TransactionV1 {
        TransactionV1 {
            transaction_id: vec![7; 32],
            trusted_root: root.clone(),
            origin_vault_path: NativePathV1::canonical(&fixture.paths.vault_path).unwrap(),
            operation: "test mutation".into(),
            vault_before: FilePreconditionV1::Hash(file_hash(&fixture.crypto, &before.vault)),
            ratchet_before: FilePreconditionV1::Hash(file_hash(&fixture.crypto, &before.ratchet)),
            next_vault_bytes: after.vault.clone(),
            next_ratchet_bytes: after.ratchet.clone(),
        }
    }

    #[test]
    fn origin_recovers_when_only_ratchet_after_image_was_written() {
        let fixture = ProductionFixture::initialized();
        let root = LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .ratchet()
            .trusted_root
            .clone();
        let before = images(&fixture.paths, &root);
        let invited = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &invited).unwrap();
        let after = images(&fixture.paths, &root);
        restore(&fixture.paths, &root, &before);

        let transaction = pending_transaction(&fixture, &root, &before, &after);
        write_transaction_atomic(&fixture.paths, &transaction).unwrap();
        write_ratchet_bytes_atomic(&fixture.paths, &root, &after.ratchet).unwrap();

        let recovered = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();

        assert!(recovered.recovered_transaction());
        assert_eq!(images(&fixture.paths, &root).vault, after.vault);
        assert_eq!(images(&fixture.paths, &root).ratchet, after.ratchet);
        assert!(!transaction_path(&fixture.paths, &root).exists());
    }

    #[test]
    fn another_clone_reads_strongest_pending_ratchet_but_cannot_write() {
        let fixture = ProductionFixture::initialized();
        let root = LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .ratchet()
            .trusted_root
            .clone();
        let before = images(&fixture.paths, &root);
        let invited = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &invited).unwrap();
        let after = images(&fixture.paths, &root);
        restore(&fixture.paths, &root, &before);
        write_transaction_atomic(
            &fixture.paths,
            &pending_transaction(&fixture, &root, &before, &after),
        )
        .unwrap();

        let clone_root = fixture._temp.path().join("clone-b");
        let clone_paths =
            WorkspacePaths::from_root(&clone_root).with_state_dir(fixture.paths.state_dir.clone());
        create_workspace_dirs(&clone_paths).unwrap();
        write_vault_bytes_atomic(&clone_paths, &before.vault).unwrap();
        let clone_vault_before = fs::read(&clone_paths.vault_path).unwrap();

        let mut clone_session = LockedSession::load(&clone_paths, &fixture.crypto).unwrap();
        let pending = clone_session.pending_transaction().unwrap();
        assert!(!pending.recoverable_here);
        let invited_key = thorax_core::RecordKey::User {
            user_id: invited.user_id().clone(),
        };
        assert!(clone_session
            .ratchet()
            .watermarks
            .contains_key(&invited_key));
        let error = clone_session
            .commit(&fixture.crypto, |_, _| Ok(()), |_: &(), _| Ok(()))
            .unwrap_err();
        assert!(matches!(error, OpsError::PendingTransaction { .. }));
        assert_eq!(
            fs::read(&clone_paths.vault_path).unwrap(),
            clone_vault_before
        );
        assert_eq!(fs::read(&fixture.paths.vault_path).unwrap(), before.vault);

        let error = match UnlockedSession::promote(
            clone_session,
            &fixture.crypto,
            &ManualIdentityKeychain::new(PanicIdentityProvider),
            fixture.root.user_id(),
            KeyUsePurpose::SignAdminChange {
                summary: "blocked mutation".into(),
            },
        ) {
            Ok(_) => panic!("pending transaction unexpectedly allowed a mutation unlock"),
            Err(error) => error,
        };
        assert!(matches!(error, OpsError::PendingTransaction { .. }));
    }

    #[test]
    fn third_state_preserves_journal_and_writes_nothing() {
        let fixture = ProductionFixture::initialized();
        let root = LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .ratchet()
            .trusted_root
            .clone();
        let before = images(&fixture.paths, &root);

        let first = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &first).unwrap();
        let committed_after = images(&fixture.paths, &root);

        restore(&fixture.paths, &root, &before);
        let second = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &second).unwrap();
        let third = images(&fixture.paths, &root);

        let transaction = pending_transaction(&fixture, &root, &before, &committed_after);
        write_transaction_atomic(&fixture.paths, &transaction).unwrap();
        let error = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap_err();

        assert!(matches!(error, OpsError::TransactionRecoveryConflict));
        assert_eq!(images(&fixture.paths, &root).vault, third.vault);
        assert_eq!(images(&fixture.paths, &root).ratchet, third.ratchet);
        assert!(transaction_path(&fixture.paths, &root).exists());
    }

    #[test]
    fn abandonment_keeps_after_image_watermarks_without_writing_the_vault() {
        let fixture = ProductionFixture::initialized();
        let root = LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .ratchet()
            .trusted_root
            .clone();
        let before = images(&fixture.paths, &root);
        let invited = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &invited).unwrap();
        let after = images(&fixture.paths, &root);
        restore(&fixture.paths, &root, &before);
        write_transaction_atomic(
            &fixture.paths,
            &pending_transaction(&fixture, &root, &before, &after),
        )
        .unwrap();

        let abandoned = abandon_transaction(&fixture.paths, &root, &fixture.crypto).unwrap();

        assert_eq!(abandoned.operation, "test mutation");
        assert_eq!(read_vault_bytes(&fixture.paths).unwrap(), before.vault);
        let retained = read_ratchet_for_root(&fixture.paths, &root)
            .unwrap()
            .unwrap();
        assert!(retained
            .watermarks
            .contains_key(&thorax_core::RecordKey::User {
                user_id: invited.user_id().clone(),
            }));
        assert!(!transaction_path(&fixture.paths, &root).exists());
    }

    #[test]
    fn every_persistence_boundary_recovers_the_exact_committed_operation() {
        for point in [
            TestFaultPoint::AfterJournal,
            TestFaultPoint::AfterRatchet,
            TestFaultPoint::AfterVault,
            TestFaultPoint::BeforeJournalRemoval,
        ] {
            let fixture = ProductionFixture::initialized();
            let root = LockedSession::load(&fixture.paths, &fixture.crypto)
                .unwrap()
                .ratchet()
                .trusted_root
                .clone();
            let invited = Identity::generate(&fixture.crypto).unwrap();
            TEST_FAULT.with(|fault| fault.set(Some(point)));

            let error = add_user(&fixture.paths, &fixture.crypto, &fixture.root, &invited)
                .expect_err("the injected persistence boundary must interrupt the caller");
            assert!(matches!(error, OpsError::Store(_)), "{point:?}: {error}");
            assert!(transaction_path(&fixture.paths, &root).exists());

            let recovered = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            assert!(recovered.recovered_transaction(), "{point:?}");
            assert!(recovered.effective().users.contains_key(invited.user_id()));
            assert!(!transaction_path(&fixture.paths, &root).exists());
        }
    }

    #[test]
    fn encoded_after_images_are_canonical_ratchet_bytes() {
        let fixture = ProductionFixture::initialized();
        let session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        assert_eq!(
            encode_ratchet(session.ratchet()).unwrap(),
            read_ratchet_bytes_for_root(&fixture.paths, &session.ratchet().trusted_root)
                .unwrap()
                .unwrap()
        );
    }
}
