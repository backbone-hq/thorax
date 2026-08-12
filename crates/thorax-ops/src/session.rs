//! The reusable resolved vault snapshot.
//!
//! [`LockedSession`] is the in-memory, trusted, queryable representation of one
//! workspace's vault + local state: read, decoded, and validated **once**. Read
//! operations borrow it (`&self`) and cost no further validation; mutating
//! operations take `&mut self`, validate only the post-commit state, and leave
//! the session already updated to it.

use std::collections::BTreeSet;

use thorax_core::{
    decode_vault, encode_vault, validate_vault_with_verified, Bytes, CryptoProvider,
    EffectiveState, HashValue, Ratchet, RecordSigner, ValidationReport, VaultStore,
};
use thorax_crypto::{Crypto, Identity};
use thorax_keychain::{default_keychain_dir, read_current_user};
use thorax_store::{
    acquire_root_state_lock, acquire_root_state_shared_lock, acquire_workspace_lock,
    read_ratchet_for_root, read_vault_bytes, read_verification_cache, verification_cache_message,
    write_ratchet_atomic, write_verification_cache_atomic, StoreError, VerificationCacheV1,
    WorkspacePaths, CACHE_SIGNATURE_DOMAIN,
};

use crate::{
    ensure_no_issues, trusted_root_candidate, AccessChange, IdentityKeychain, KeyUsePurpose,
    OpsError, Result,
};

#[derive(Clone, Debug)]
pub struct LockedSession {
    paths: WorkspacePaths,
    vault: VaultStore,
    /// Canonical encoded bytes of `vault` as last seen on (or written to) disk. This is
    /// the staleness fingerprint: the snapshot is stale iff the file's bytes differ.
    vault_bytes: Vec<u8>,
    ratchet: Ratchet,
    report: ValidationReport,
    verifications: Verifications,
    pending_transaction: Option<crate::PendingTransaction>,
    recovered_transaction: bool,
    persistence: PersistenceMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PersistenceMode {
    Live,
    Prepared,
}

/// How this session's signature checks are vouched for.
///
/// `Direct`: every accepted envelope signature was verified by this process — possession
/// grade by construction.
///
/// `Cached { signer }`: validation skipped signatures attested by the on-disk verification
/// cache, whose own signature verified against its *embedded* key. That tier is exactly as
/// trustworthy as the rest of the machine-local state no-unlock paths already lean on (the
/// trusted-root pin lives in the same agent-writable directory), so status/list-style
/// reads use it as-is. Unlock-gated operations must not: the keychain unlock funnel calls
/// [`LockedSession::attest_verifications`], which re-validates everything directly unless
/// the cache signer *is* the unlocked identity (the possession check).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Verifications {
    Direct,
    Cached { signer: Bytes },
}

impl LockedSession {
    /// Read + decode + validate the workspace's vault exactly once.
    ///
    /// The session is returned even when validation finds issues — `report().issues`
    /// powers status/validate views and block screens; operations call
    /// [`LockedSession::ensure_valid`] first. When the report is clean and raised the
    /// watermark ratchet, the raises are applied in memory unconditionally and
    /// persisted to the state file best-effort: if the workspace lock is contended the
    /// read still succeeds, this session keeps validating against the raised values,
    /// and the next successful commit persists them. Unlike a commit, a load never
    /// rewrites the vault file.
    pub fn load(paths: &WorkspacePaths, crypto: &impl CryptoProvider) -> Result<Self> {
        let initial_vault_bytes = read_vault_bytes(paths)?;
        let initial_vault =
            decode_vault(&initial_vault_bytes).map_err(|source| StoreError::InvalidVault {
                path: paths.vault_path.clone(),
                source,
            })?;
        let trusted_root = trusted_root_candidate(&initial_vault, crypto)?;
        let recovery = crate::transaction::recover_for_root(paths, &trusted_root, crypto)?;
        let root_lock = acquire_root_state_shared_lock(paths, &trusted_root)?;
        let vault_bytes = read_vault_bytes(paths)?;
        let vault = decode_vault(&vault_bytes).map_err(|source| StoreError::InvalidVault {
            path: paths.vault_path.clone(),
            source,
        })?;
        let (ratchet, pending_transaction) =
            crate::transaction::read_strongest_ratchet_locked(paths, &trusted_root, crypto)?;
        let (verified, verifications) =
            match read_trusted_cache(paths, &vault, &trusted_root, crypto) {
                Some(cache) => (
                    cache.verified_record_hashes.iter().cloned().collect(),
                    Verifications::Cached {
                        signer: cache.signing_public_key,
                    },
                ),
                None => (BTreeSet::new(), Verifications::Direct),
            };
        let report = validate_vault_with_verified(&vault, &ratchet, crypto, &verified)?;

        let mut session = Self {
            paths: paths.clone(),
            vault,
            vault_bytes,
            ratchet,
            report,
            verifications,
            pending_transaction,
            recovered_transaction: matches!(
                recovery,
                crate::transaction::RecoveryDisposition::Recovered
            ),
            persistence: PersistenceMode::Live,
        };
        drop(root_lock);
        session.absorb_clean_trust_raises(crypto)?;
        Ok(session)
    }

    pub fn paths(&self) -> &WorkspacePaths {
        &self.paths
    }

    pub fn vault(&self) -> &VaultStore {
        &self.vault
    }

    /// The exact validated encrypted bytes represented by this snapshot.
    pub fn vault_bytes(&self) -> &[u8] {
        &self.vault_bytes
    }

    pub fn report(&self) -> &ValidationReport {
        &self.report
    }

    pub fn effective(&self) -> &EffectiveState {
        &self.report.effective
    }

    pub fn ratchet(&self) -> &Ratchet {
        &self.ratchet
    }

    pub fn pending_transaction(&self) -> Option<&crate::PendingTransaction> {
        self.pending_transaction.as_ref()
    }

    pub fn recovered_transaction(&self) -> bool {
        self.recovered_transaction
    }

    /// Fail with `ValidationFailed` if the snapshot's report carries any issue.
    pub fn ensure_valid(&self) -> Result<()> {
        ensure_no_issues(&self.report)
    }

    /// Re-read the vault file; if its bytes differ from the snapshot, fully reload and
    /// revalidate (vault and local trust). Returns whether a reload happened. The
    /// common case is a cheap byte compare with no validation.
    pub fn reload_if_stale(&mut self, crypto: &impl CryptoProvider) -> Result<bool> {
        let root = self.ratchet.trusted_root.clone();
        let _root_lock = acquire_root_state_shared_lock(&self.paths, &root)?;
        self.reload_if_stale_locked(crypto)
    }

    fn reload_if_stale_locked(&mut self, crypto: &impl CryptoProvider) -> Result<bool> {
        let vault_bytes = read_vault_bytes(&self.paths)?;
        let trusted_root = self.ratchet.trusted_root.clone();
        let (ratchet, pending_transaction) =
            crate::transaction::read_strongest_ratchet_locked(&self.paths, &trusted_root, crypto)?;
        if vault_bytes == self.vault_bytes && ratchet == self.ratchet {
            self.pending_transaction = pending_transaction;
            return Ok(false);
        }
        let vault = decode_vault(&vault_bytes).map_err(|source| StoreError::InvalidVault {
            path: self.paths.vault_path.clone(),
            source,
        })?;
        let reread_root = trusted_root_candidate(&vault, crypto)?;
        if reread_root != trusted_root {
            return Err(StoreError::TrustRootMismatch {
                stored: reread_root,
                requested: trusted_root,
            }
            .into());
        }
        // Revalidate over the delta: hashes this session already accepted skip the curve
        // math. Sound at the session's current trust tier — `verifications` carries the
        // provenance forward unchanged.
        let verified = self.report.effective.verified_record_hashes();
        let report = validate_vault_with_verified(&vault, &ratchet, crypto, &verified)?;
        self.vault = vault;
        self.vault_bytes = vault_bytes;
        self.ratchet = ratchet;
        self.report = report;
        self.pending_transaction = pending_transaction;
        Ok(true)
    }

    /// The commit core: append records via `update`, verify the result via `check`,
    /// write atomically, and leave the session at the post-commit state.
    ///
    /// The snapshot's existing report is the pre-validation; only the post-state is
    /// validated fresh. Divergence on disk (e.g. a git pull or another process raced
    /// this session) is detected under the lock by exact byte comparison and resolved
    /// by transparently revalidating — the mutation then applies against the current
    /// state, and `check` still guards effectiveness.
    ///
    /// Crate-internal: a generic record append is exactly the surface the untrusted
    /// session must not offer. External mutations go through [`UnlockedSession`]'s
    /// named operations.
    pub(crate) fn commit<T>(
        &mut self,
        crypto: &impl CryptoProvider,
        update: impl FnOnce(&mut VaultStore, &ValidationReport) -> Result<T>,
        check: impl FnOnce(&T, &ValidationReport) -> Result<()>,
    ) -> Result<T> {
        if self.persistence == PersistenceMode::Prepared {
            return self.apply_prepared_mutation(crypto, update, check);
        }
        let _root_lock = acquire_root_state_lock(&self.paths, &self.ratchet.trusted_root)?;
        let _lock = acquire_workspace_lock(&self.paths)?;
        crate::transaction::ensure_no_pending_transaction_locked(
            &self.paths,
            &self.ratchet.trusted_root,
            crypto,
        )?;
        self.reload_if_stale_locked(crypto)?;
        ensure_no_issues(&self.report)?;
        let expected_ratchet_bytes = thorax_store::encode_ratchet(&self.ratchet)?;
        let mut next_ratchet = self.ratchet.clone();
        next_ratchet.apply_update(&self.report.ratchet_update);

        let mut next_vault = self.vault.clone();
        let output = update(&mut next_vault, &self.report)?;
        let verified = self.report.effective.verified_record_hashes();
        let post_report =
            validate_vault_with_verified(&next_vault, &next_ratchet, crypto, &verified)?;
        ensure_no_issues(&post_report)?;
        check(&output, &post_report)?;
        next_ratchet.apply_update(&post_report.ratchet_update);

        let vault_bytes = encode_vault(&next_vault)?;
        let next_ratchet_bytes = thorax_store::encode_ratchet(&next_ratchet)?;
        crate::transaction::commit_after_images_locked(
            &self.paths,
            &self.ratchet.trusted_root,
            crypto,
            "vault mutation",
            &self.vault_bytes,
            &expected_ratchet_bytes,
            vault_bytes.clone(),
            next_ratchet_bytes,
        )?;

        self.vault = next_vault;
        self.vault_bytes = vault_bytes;
        self.ratchet = next_ratchet;
        self.report = post_report;
        self.pending_transaction = None;
        Ok(output)
    }

    fn apply_prepared_mutation<T>(
        &mut self,
        crypto: &impl CryptoProvider,
        update: impl FnOnce(&mut VaultStore, &ValidationReport) -> Result<T>,
        check: impl FnOnce(&T, &ValidationReport) -> Result<()>,
    ) -> Result<T> {
        ensure_no_issues(&self.report)?;
        let mut next_ratchet = self.ratchet.clone();
        next_ratchet.apply_update(&self.report.ratchet_update);
        let mut next_vault = self.vault.clone();
        let output = update(&mut next_vault, &self.report)?;
        let verified = self.report.effective.verified_record_hashes();
        let post_report =
            validate_vault_with_verified(&next_vault, &next_ratchet, crypto, &verified)?;
        ensure_no_issues(&post_report)?;
        check(&output, &post_report)?;
        next_ratchet.apply_update(&post_report.ratchet_update);
        self.vault_bytes = encode_vault(&next_vault)?;
        self.vault = next_vault;
        self.ratchet = next_ratchet;
        self.report = post_report;
        Ok(output)
    }

    pub(crate) fn prepared_clone(&self) -> Self {
        let mut prepared = self.clone();
        prepared.persistence = PersistenceMode::Prepared;
        prepared
    }

    pub(crate) fn commit_prepared(
        &mut self,
        crypto: &impl CryptoProvider,
        mut prepared: Self,
        operation: &str,
        expected_vault_bytes: &[u8],
        expected_ratchet_bytes: &[u8],
    ) -> Result<()> {
        if prepared.persistence != PersistenceMode::Prepared
            || prepared.ratchet.trusted_root != self.ratchet.trusted_root
            || self.vault_bytes != expected_vault_bytes
            || thorax_store::encode_ratchet(&self.ratchet)? != expected_ratchet_bytes
        {
            return Err(OpsError::TransactionPreconditionChanged("prepared session"));
        }
        let trusted_root = self.ratchet.trusted_root.clone();
        let _root_lock = acquire_root_state_lock(&self.paths, &trusted_root)?;
        let _workspace_lock = acquire_workspace_lock(&self.paths)?;
        crate::transaction::ensure_no_pending_transaction_locked(
            &self.paths,
            &trusted_root,
            crypto,
        )?;
        let next_ratchet_bytes = thorax_store::encode_ratchet(&prepared.ratchet)?;
        crate::transaction::commit_after_images_locked(
            &self.paths,
            &trusted_root,
            crypto,
            operation,
            expected_vault_bytes,
            expected_ratchet_bytes,
            prepared.vault_bytes.clone(),
            next_ratchet_bytes,
        )?;
        prepared.persistence = PersistenceMode::Live;
        *self = prepared;
        Ok(())
    }

    /// Deliberately rewrite this machine's local trust under the workspace lock —
    /// the (rare) fail-open counterpart of the commit core, for explicit recovery
    /// flows that *weaken* the ratchet (accepting a rollback). `mutate` edits the
    /// freshly re-read trust; the result is persisted and the session revalidated
    /// against it. Never touches the vault file.
    pub(crate) fn rewrite_ratchet(
        &mut self,
        crypto: &impl CryptoProvider,
        mutate: impl FnOnce(&mut Ratchet),
    ) -> Result<()> {
        let _root_lock = acquire_root_state_lock(&self.paths, &self.ratchet.trusted_root)?;
        let _lock = acquire_workspace_lock(&self.paths)?;
        crate::transaction::ensure_no_pending_transaction_locked(
            &self.paths,
            &self.ratchet.trusted_root,
            crypto,
        )?;
        self.reload_if_stale_locked(crypto)?;
        let mut trust = read_ratchet_for_root(&self.paths, &self.ratchet.trusted_root)?
            .unwrap_or_else(|| Ratchet::new(self.ratchet.trusted_root.clone()));
        mutate(&mut trust);
        write_ratchet_atomic(&self.paths, &trust)?;
        let verified = self.report.effective.verified_record_hashes();
        self.report = validate_vault_with_verified(&self.vault, &trust, crypto, &verified)?;
        self.ratchet = trust;
        Ok(())
    }

    /// Bring this session to possession grade for `identity`, then persist the refreshed
    /// verification cache. The keychain unlock funnel calls this, so every unlock-gated
    /// operation runs on possession-grade state:
    ///
    /// - If the session leaned on a cache signed by anyone *other* than `identity`
    ///   (the embedded-key tier), the whole vault is re-validated with every signature
    ///   checked directly — slow, never wrong — and the result must be clean.
    /// - Then the now-attested verified set is signed by `identity` and written to
    ///   `<state_dir>/<root>/<user>/cache.cord`, best effort: a write failure costs the
    ///   next load speed, never correctness.
    pub(crate) fn attest_verifications(
        &mut self,
        crypto: &Crypto,
        identity: &Identity,
    ) -> Result<()> {
        if matches!(
            &self.verifications,
            Verifications::Cached { signer } if signer.as_slice() != identity.signing_public_key()
        ) {
            self.report =
                validate_vault_with_verified(&self.vault, &self.ratchet, crypto, &BTreeSet::new())?;
            self.verifications = Verifications::Direct;
            // A cache that misled the embedded-key tier surfaces here as real issues
            // (e.g. InvalidSignature) — fail the unlock loudly rather than proceed on a
            // report the pre-unlock checks no longer describe.
            ensure_no_issues(&self.report)?;
        }
        if self.report.issues.is_empty() {
            let _ = self.write_verification_cache(identity);
            self.verifications = Verifications::Direct;
        }
        Ok(())
    }

    fn write_verification_cache(&self, identity: &Identity) -> Result<()> {
        let hashes: Vec<HashValue> = self
            .report
            .effective
            .verified_record_hashes()
            .into_iter()
            .collect();
        let verified_record_hashes = cord::Set::from(hashes);
        let trusted_root = self.ratchet.trusted_root.clone();
        let format_version = self.vault.format_version();
        let message =
            verification_cache_message(&trusted_root, format_version, &verified_record_hashes)
                .map_err(OpsError::from)?;
        let cache = VerificationCacheV1 {
            trusted_root,
            format_version,
            verified_record_hashes,
            signing_public_key: identity.signing_public_key().to_vec(),
            signature: identity.sign(CACHE_SIGNATURE_DOMAIN, &message),
        };
        write_verification_cache_atomic(&self.paths, identity.user_id(), &cache)?;
        Ok(())
    }

    /// Whether this session's report is vouched for by direct verification (or a
    /// possession-checked cache) rather than the embedded-key tier. Exposed for tests.
    #[cfg(test)]
    pub(crate) fn verifications_are_direct(&self) -> bool {
        self.verifications == Verifications::Direct
    }

    /// Apply a clean report's watermark raises in memory, and persist them to the
    /// state file if the root lock is available. On contention the raises stay in
    /// memory only — this session still validates against them, and the next
    /// successful commit writes them out. Never touches the vault file.
    fn absorb_clean_trust_raises(&mut self, crypto: &impl CryptoProvider) -> Result<()> {
        if !self.report.issues.is_empty() || self.report.ratchet_update.raised_watermarks.is_empty()
        {
            return Ok(());
        }
        self.ratchet.apply_update(&self.report.ratchet_update);
        if self.pending_transaction.is_some() {
            return Ok(());
        }
        match acquire_root_state_lock(&self.paths, &self.ratchet.trusted_root) {
            Ok(_lock) => {
                crate::transaction::ensure_no_pending_transaction_locked(
                    &self.paths,
                    &self.ratchet.trusted_root,
                    crypto,
                )?;
                // Re-read under the lock and merge: another process may have raised
                // other watermarks since our (unlocked) read, and watermark merges are
                // monotone maxes, so folding our raises into the fresh copy never
                // regresses either side.
                let mut current = read_ratchet_for_root(&self.paths, &self.ratchet.trusted_root)?
                    .unwrap_or_else(|| Ratchet::new(self.ratchet.trusted_root.clone()));
                current.apply_update(&self.report.ratchet_update);
                write_ratchet_atomic(&self.paths, &current)?;
                self.ratchet = current;
            }
            Err(StoreError::LockAlreadyHeld(_)) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
}

/// A [`LockedSession`] whose trust is anchored in an unlocked identity rather than in
/// machine-local hints: the verification cache has passed the possession check, the vault
/// validated cleanly, and the identity is an effective member of it (the in-vault half of
/// the seed → `EntryPoint` → root chain — a substituted vault cannot carry your entry
/// point, so a membership failure is a loud root-substitution/exclusion signal, not a
/// rendering detail). This is the session type frontends should hold for every surface
/// that can unlock — and it is where the *entire* operation vocabulary lives: the family
/// modules (`secrets`, `principals`, `invite`, `conflicts`, `reconcile`) implement their
/// public ops on this type, acting as the held identity. The plain [`LockedSession`]
/// remains a read-only snapshot for the intrinsically untrusted surfaces (the merge
/// driver, pre-membership onboarding, the validation-failure read fallback).
///
/// The per-use purpose moves to construction: `open`/`promote` take the
/// [`KeyUsePurpose`] naming what this session is for, so the keychain prompt describes
/// the command — there is no second prompt per operation.
pub struct UnlockedSession {
    session: LockedSession,
    identity: Identity,
}

impl UnlockedSession {
    /// Promote an already-loaded session: require it valid, unlock `user_id` (the funnel
    /// possession-checks the verification cache and pins membership), and bind the
    /// identity to the session.
    pub fn promote(
        mut session: LockedSession,
        crypto: &Crypto,
        keychain: &(impl IdentityKeychain + ?Sized),
        user_id: &thorax_core::UserId,
        purpose: KeyUsePurpose,
    ) -> Result<Self> {
        if purpose_is_mutation(&purpose) {
            if let Some(pending) = session.pending_transaction() {
                return Err(crate::transaction::pending_barrier_error(pending));
            }
        }
        session.ensure_valid()?;
        let identity = session.unlock(crypto, keychain, user_id, purpose)?;
        session.ensure_valid()?;
        Ok(Self { session, identity })
    }

    /// Load + promote in one step — the standard open for trust-anchored commands.
    pub fn open(
        paths: &WorkspacePaths,
        crypto: &Crypto,
        keychain: &(impl IdentityKeychain + ?Sized),
        user_id: &thorax_core::UserId,
        purpose: KeyUsePurpose,
    ) -> Result<Self> {
        Self::promote(
            LockedSession::load(paths, crypto)?,
            crypto,
            keychain,
            user_id,
            purpose,
        )
    }

    /// Anchor a session to an identity the caller already holds (init, claim, CI's
    /// injected invite, the TUI's cached gate unlock): possession is established by
    /// construction, so this attests the verifications directly and pins membership
    /// without a keychain round trip.
    pub fn with_identity(
        mut session: LockedSession,
        crypto: &Crypto,
        identity: Identity,
    ) -> Result<Self> {
        session.ensure_valid()?;
        session.attest_verifications(crypto, &identity)?;
        session.ensure_valid()?;
        ensure_member(&session, identity.user_id())?;
        Ok(Self { session, identity })
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn user_id(&self) -> &thorax_core::UserId {
        self.identity.user_id()
    }

    pub fn session(&self) -> &LockedSession {
        &self.session
    }

    pub fn paths(&self) -> &WorkspacePaths {
        self.session.paths()
    }

    pub fn report(&self) -> &ValidationReport {
        self.session.report()
    }

    pub fn effective(&self) -> &EffectiveState {
        self.session.effective()
    }

    /// The selectors from every effective capability that confers read access to this
    /// identity. This is an authority view, not a projection wish-list: Kubernetes may
    /// expose any subset of it and cannot widen it.
    pub fn effective_read_grants(&self) -> Vec<thorax_core::KeyspaceSelectorV1> {
        let authority = self.effective().authority_for_user(self.user_id());
        if authority.administer {
            return vec![thorax_core::KeyspaceSelectorV1::all()];
        }
        let mut selectors = authority.read;
        for selector in authority.write {
            if !selectors.contains(&selector) {
                selectors.push(selector);
            }
        }
        for manage in authority.manage {
            if !selectors.contains(&manage.selector) {
                selectors.push(manage.selector);
            }
        }
        selectors
    }

    /// The mutation halves, split for the family modules: the session to commit through
    /// and the identity to sign as. Crate-internal — outside `thorax-ops` the only way to
    /// drive a mutation is one of the named operation methods.
    pub(crate) fn parts(&mut self) -> (&mut LockedSession, &Identity) {
        (&mut self.session, &self.identity)
    }

    /// Run an access *addition*: apply the authorization mutation, then converge readers
    /// with the same identity.
    ///
    /// CRITICAL INVARIANT: access-changing ops must converge internally, in one op —
    /// frontends never sequence mutate-then-reconcile (see [`AccessChange`]).
    pub(crate) fn access_addition<T>(
        &mut self,
        crypto: &Crypto,
        op: impl FnOnce(&mut LockedSession, &Identity) -> Result<T>,
    ) -> Result<AccessChange<T>> {
        let (session, identity) = self.parts();
        let output = op(session, identity)?;
        let reconcile = session.converge_readers(crypto, identity)?;
        Ok(AccessChange { output, reconcile })
    }

    /// Drop the identity, downgrading to the untrusted session (e.g. a TUI relock).
    pub fn lock(self) -> LockedSession {
        self.session
    }
}

fn purpose_is_mutation(purpose: &KeyUsePurpose) -> bool {
    matches!(
        purpose,
        KeyUsePurpose::SignSecretWrite { .. }
            | KeyUsePurpose::MoveSecret { .. }
            | KeyUsePurpose::SignSecretDelete { .. }
            | KeyUsePurpose::SignAdminChange { .. }
            | KeyUsePurpose::StoreIdentity
    )
}

/// The membership pin: the unlocked identity must be an effective user of this vault.
/// Skipped when the report already carries blocking issues — the operation's own
/// `ensure_valid` produces the more precise error there, and recovery flows must still be
/// able to unlock against a broken vault.
pub(crate) fn ensure_member(session: &LockedSession, user_id: &thorax_core::UserId) -> Result<()> {
    if session.report().issues.is_empty() && !session.effective().users.contains_key(user_id) {
        return Err(OpsError::NotAVaultMember(user_id.clone()));
    }
    Ok(())
}

/// The on-disk verification cache for this vault's `CurrentUser`, if one exists and its
/// own signature verifies against its embedded key (plus root/format bindings). Best
/// effort throughout — no keychain, no `CurrentUser`, no cache, or any mismatch is simply
/// `None` and every signature gets verified directly. The possession check deliberately
/// does NOT happen here (no seed is in hand at load time); it happens in
/// [`LockedSession::attest_verifications`] on the unlock funnel.
fn read_trusted_cache(
    paths: &WorkspacePaths,
    vault: &VaultStore,
    trusted_root: &HashValue,
    crypto: &impl CryptoProvider,
) -> Option<VerificationCacheV1> {
    let base = default_keychain_dir().ok()?;
    let current = read_current_user(&base, trusted_root).ok()??;
    let cache = read_verification_cache(paths, trusted_root, &current.user_id)?;
    if &cache.trusted_root != trusted_root || cache.format_version != vault.format_version() {
        return None;
    }
    let message = verification_cache_message(
        &cache.trusted_root,
        cache.format_version,
        &cache.verified_record_hashes,
    )
    .ok()?;
    crypto
        .verify_signature(
            CACHE_SIGNATURE_DOMAIN,
            &cache.signing_public_key,
            &message,
            &cache.signature,
        )
        .then_some(cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_hash;
    use crate::test_util::{set_secret, ProductionFixture};
    use crate::{FixedIdentityProvider, ManualIdentityKeychain, OpsError, OutputSink};
    use thorax_core::{record_hash, SecretSelectorV1};
    use thorax_crypto::SigningKeypair;
    use thorax_keychain::{write_current_user, CurrentUserV1};
    use thorax_store::{read_vault, write_vault_atomic};

    // `THORAX_KEYCHAIN_DIR` is process-global; serialize the tests that set it (mirrors
    // the TUI test helper). Tests running concurrently *without* it see either an unset
    // var (no keychain → no cache → full verify) or another test's temp dir (no
    // CurrentUser for their root → same) — benign either way.
    static KEYCHAIN_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_keychain_dir<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
        let _guard = KEYCHAIN_ENV.lock().unwrap_or_else(|p| p.into_inner());
        std::env::set_var("THORAX_KEYCHAIN_DIR", dir);
        let result = f();
        std::env::remove_var("THORAX_KEYCHAIN_DIR");
        result
    }

    fn root_keychain(fixture: &ProductionFixture) -> ManualIdentityKeychain<FixedIdentityProvider> {
        ManualIdentityKeychain::new(
            FixedIdentityProvider::from_master_seed(&fixture.crypto, fixture.root.master_seed())
                .unwrap(),
        )
    }

    fn select_current_user(
        fixture: &ProductionFixture,
        keychain_dir: &std::path::Path,
    ) -> HashValue {
        let root_hash = key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        write_current_user(
            keychain_dir,
            &root_hash,
            Some(CurrentUserV1 {
                user_id: fixture.root.user_id().clone(),
                handle: None,
            }),
        )
        .unwrap();
        root_hash
    }

    #[test]
    fn unlocked_ops_write_a_cache_that_later_loads_trust_and_attest() {
        let fixture = ProductionFixture::initialized();
        let keychain_dir = fixture.paths.root.join("keychain");
        let root_hash = select_current_user(&fixture, &keychain_dir);
        let keychain = root_keychain(&fixture);
        let selector = SecretSelectorV1::tuple(["app", "db"]);

        with_keychain_dir(&keychain_dir, || {
            // First session: no cache yet — every signature verified directly.
            let first = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            assert!(first.verifications_are_direct());
            let mut first = UnlockedSession::promote(
                first,
                &fixture.crypto,
                &keychain,
                fixture.root.user_id(),
                KeyUsePurpose::SignSecretWrite {
                    selector: selector.clone(),
                },
            )
            .unwrap();
            first
                .set_secret(&fixture.crypto, selector.clone(), b"v")
                .unwrap();
            // The promotion attested: the cache exists, signed by the root identity.
            let cache = read_verification_cache(&fixture.paths, &root_hash, fixture.root.user_id())
                .expect("the unlock funnel writes the verification cache");
            assert_eq!(
                cache.signing_public_key,
                fixture.root.signing_public_key().to_vec()
            );

            // Second session: the cache carries the verifications (embedded-key tier)…
            let second = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            assert!(!second.verifications_are_direct());
            assert!(second.report().issues.is_empty());
            // …and the promotion possession-checks it (signer == unlocked identity), so
            // the read proceeds without a rebuild and re-attests.
            let second = UnlockedSession::promote(
                second,
                &fixture.crypto,
                &keychain,
                fixture.root.user_id(),
                KeyUsePurpose::DecryptSecret {
                    selector: selector.clone(),
                    sink: OutputSink::Stdout,
                },
            )
            .expect("possession-checked promotion must succeed");
            let plaintext = second
                .get_secret(&fixture.crypto, selector)
                .expect("possession-checked read must succeed");
            assert_eq!(plaintext.plaintext.as_slice(), b"v");
            assert!(second.session().verifications_are_direct());
        });
    }

    #[test]
    fn a_poisoned_cache_cannot_leak_plaintext_through_an_unlock() {
        let fixture = ProductionFixture::initialized();
        let keychain_dir = fixture.paths.root.join("keychain");
        let root_hash = select_current_user(&fixture, &keychain_dir);
        let keychain = root_keychain(&fixture);
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v",
        )
        .unwrap();

        // The repo-local agent's move: append a forged record (corrupted signature) to the
        // vault, then plant a cache vouching for EVERY record — signed by the agent's own
        // keypair, since it does not hold the user's seed.
        let mut vault = read_vault(&fixture.paths).unwrap();
        {
            let VaultStore::V1(v1) = &mut vault;
            // Records are a set (no order). Forge a copy of a *non-root* record: corrupting a
            // second copy of the root would manufacture an `AmbiguousRoot` instead of testing
            // the cache path.
            let mut forged = v1
                .records
                .iter()
                .find(|signed| {
                    !matches!(
                        signed.body.known(),
                        Some(thorax_core::RecordBodyV1::VaultRoot(_))
                    )
                })
                .unwrap()
                .clone();
            forged.signature[0] ^= 1;
            v1.records.insert(forged);
        }
        write_vault_atomic(&fixture.paths, &vault).unwrap();
        let VaultStore::V1(v1) = &vault;
        let hashes: Vec<HashValue> = v1
            .records
            .iter()
            .map(|signed| record_hash(&fixture.crypto, signed).unwrap())
            .collect();
        let verified_record_hashes = cord::Set::from(hashes);
        let agent_key = SigningKeypair::generate();
        let message =
            verification_cache_message(&root_hash, vault.format_version(), &verified_record_hashes)
                .unwrap();
        let poisoned = VerificationCacheV1 {
            trusted_root: root_hash.clone(),
            format_version: vault.format_version(),
            verified_record_hashes,
            signing_public_key: agent_key.public_key_bytes(),
            signature: agent_key.sign(CACHE_SIGNATURE_DOMAIN, &message),
        };
        write_verification_cache_atomic(&fixture.paths, fixture.root.user_id(), &poisoned).unwrap();

        with_keychain_dir(&keychain_dir, || {
            // Embedded-key tier: the load accepts the cache and the forgery sails through —
            // exactly the exposure no-unlock paths already have via the trusted-root pin.
            let session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            assert!(!session.verifications_are_direct());
            assert!(session.report().issues.is_empty());

            // The unlock funnel possession-checks: foreign signer → full re-validation →
            // the forgery surfaces and the promotion fails closed before any key use.
            let error = match UnlockedSession::promote(
                session,
                &fixture.crypto,
                &keychain,
                fixture.root.user_id(),
                KeyUsePurpose::DecryptSecret {
                    selector,
                    sink: OutputSink::Stdout,
                },
            ) {
                Ok(_) => panic!("a poisoned cache must not anchor a session"),
                Err(error) => error,
            };
            assert!(matches!(error, OpsError::ValidationFailed(_)), "{error:?}");
        });
    }

    #[test]
    fn unlocked_session_pins_membership() {
        let fixture = ProductionFixture::initialized();
        let keychain = root_keychain(&fixture);

        // A member identity opens: valid, possession-checked, member-pinned.
        let unlocked = UnlockedSession::open(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            KeyUsePurpose::InspectVault,
        )
        .unwrap();
        assert_eq!(unlocked.user_id(), fixture.root.user_id());

        // A held identity that is NOT a member of this vault fails the pin loudly — the
        // root-substitution / not-yet-claimed signal.
        let outsider = Identity::generate(&fixture.crypto).unwrap();
        let outsider_keychain = ManualIdentityKeychain::new(
            FixedIdentityProvider::from_master_seed(&fixture.crypto, outsider.master_seed())
                .unwrap(),
        );
        let error = UnlockedSession::open(
            &fixture.paths,
            &fixture.crypto,
            &outsider_keychain,
            outsider.user_id(),
            KeyUsePurpose::InspectVault,
        )
        .map(|_| ())
        .unwrap_err();
        assert!(matches!(error, OpsError::NotAVaultMember(_)), "{error:?}");
    }

    #[test]
    fn unlocked_session_operates_directly_and_locks_down() {
        let fixture = ProductionFixture::initialized();
        let keychain = root_keychain(&fixture);
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        let mut unlocked = UnlockedSession::open(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            KeyUsePurpose::InspectVault,
        )
        .unwrap();

        // Ops run as the held identity — no keychain round trip, no second prompt.
        unlocked
            .set_secret(&Crypto, selector.clone(), b"v")
            .unwrap();

        // Downgrading keeps the (already-attested) session, drops the identity.
        let session = unlocked.lock();
        assert!(session
            .effective()
            .secret_record(&selector, &fixture.crypto)
            .unwrap()
            .is_some());
    }

    #[test]
    fn a_cache_with_a_bad_signature_is_ignored_at_load() {
        let fixture = ProductionFixture::initialized();
        let keychain_dir = fixture.paths.root.join("keychain");
        let root_hash = select_current_user(&fixture, &keychain_dir);
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector,
            b"v",
        )
        .unwrap();

        let vault = read_vault(&fixture.paths).unwrap();
        let VaultStore::V1(v1) = &vault;
        let hashes: Vec<HashValue> = v1
            .records
            .iter()
            .map(|signed| record_hash(&fixture.crypto, signed).unwrap())
            .collect();
        let verified_record_hashes = cord::Set::from(hashes);
        let agent_key = SigningKeypair::generate();
        let message =
            verification_cache_message(&root_hash, vault.format_version(), &verified_record_hashes)
                .unwrap();
        let mut cache = VerificationCacheV1 {
            trusted_root: root_hash.clone(),
            format_version: vault.format_version(),
            verified_record_hashes,
            signing_public_key: agent_key.public_key_bytes(),
            signature: agent_key.sign(CACHE_SIGNATURE_DOMAIN, &message),
        };
        cache.signature[0] ^= 1;
        write_verification_cache_atomic(&fixture.paths, fixture.root.user_id(), &cache).unwrap();

        with_keychain_dir(&keychain_dir, || {
            // An unverifiable cache is simply not used: full direct verification.
            let session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
            assert!(session.verifications_are_direct());
            assert!(session.report().issues.is_empty());
        });
    }
}
