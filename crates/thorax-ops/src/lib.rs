//! Shared high-level operation layer for all Thorax consumers.
//!
//! CLI, TUI, `thorax run`, and language bindings should call this crate rather
//! than manipulating signed records directly.

use std::path::PathBuf;

pub use thorax_core::crypto::key_hash;
use thorax_core::hazmat::append_record;
pub use thorax_core::ids::{is_valid_handle, normalize_handle};
pub use thorax_core::RecordSigner;
pub use thorax_core::{
    decode_vault, encode_vault, next_counter, record_hash, record_key_for, selector_matches,
    selector_subsumes, validate_vault, ActiveSecretV1, Bytes, CryptoProvider, EffectiveState,
    EntryPointRecordV1, GrantDeletedRecordV1, GrantId, GrantPermissionV1, GrantRecordV1,
    GroupDeletedRecordV1, GroupId, GroupMemberDeletedRecordV1, GroupMemberId, GroupMemberRecordV1,
    GroupRecordV1, HashValue, IdSeed, InvitationMaterial, Invite, InviteV1, InviteV2,
    JoinApprovalV1, JoinCandidateV1, JoinPurposeV1, KeyOrigin, KeyspaceGrantClassV1,
    KeyspaceLabelMatcherV1, KeyspaceSelectorV1, LabelMatcherV1, ManageKeyspaceGrantV1,
    PrincipalRefV1, Ratchet, RatchetBaselineV1, RatchetRecordV1, RecipientSlotV1, RecordBodyV1,
    RecordKey, SealedPayloadV1, SecretDeletedRecordV1, SecretFieldEntryV1, SecretId, SecretLabelV1,
    SecretRecordV1, SecretSelectorV1, SecretState, SecretValueV1, TupleMatcherV1,
    UserDeletedRecordV1, UserHandleId, UserHandleRecordV1, UserId, UserRecordV1, ValidationIssue,
    ValidationReport, ValidationWarning, VaultHandleId, VaultHandleRecordV1, VaultRecordV1,
    VaultRootRecordV1, VaultStore, VaultStoreV1, INVITE_MAGIC, MAX_INVITE_BYTES,
};
pub use thorax_core::{merge_vaults, ConflictKind, ConflictReport, MergeOutcome, MergeRefusal};
pub use thorax_crypto::{Crypto, Identity};
#[allow(deprecated)]
pub use thorax_keychain::{
    current_user_path, default_keychain_dir, identity_path, keychain_path, read_current_user,
    write_current_user, AutoKeychain, CurrentUserV1, FixedIdentityProvider, IdentityKeychain,
    KeyUsePurpose, KeychainError, KeychainIdentityRef, KeychainRequest, ManualIdentityKeychain,
    ManualIdentityProvider, NoManualIdentityProvider, OutputSink, PassphraseKeychain,
    PassphraseProvider, StaticPassphraseProvider, StdinPassphraseProvider,
};
pub use thorax_store::{
    acquire_root_state_lock, acquire_root_state_shared_lock, acquire_workspace_lock,
    create_workspace_dirs, default_state_dir, default_thorax_dir, default_vault_path,
    find_workspace, ratchet_path, read_file_bounded, read_ratchet_for_root, read_vault,
    remove_file_durable, require_workspace, root_state_lock_path, write_private_output,
    write_ratchet_atomic, write_vault_atomic, FileRatchetBackend, RatchetBackend,
    RatchetCasOutcome, RatchetSnapshot, RootStateLock, StoreError, WorkspaceLock, WorkspacePaths,
    STATE_DIR_ENV,
};
use zeroize::Zeroizing;

mod conflicts;
mod enrollment;
mod invite;
mod principals;
mod reconcile;
mod secrets;
mod session;
#[cfg(test)]
pub(crate) mod test_util;
mod transaction;
mod trust;

pub use conflicts::ensure_can_resolve_conflict;
pub use enrollment::{
    commit_join_approval_plan, create_join_candidate, open_join_baseline,
    validate_approval_bindings, validate_join_candidate, JoinApprovalPlan,
};
pub use invite::{
    claim_invite_with_keychain, ensure_ratchet_from_invite, save_identity_with_keychain,
    save_identity_with_keychain_labeled, PreparedInviteUser,
};
pub use principals::resolve_user_ref;
use principals::{primary_handle_for_user, primary_vault_handle};
pub use session::{LockedSession, UnlockedSession};
pub(crate) use trust::ensure_no_issues;
pub use trust::{
    abandon_transaction_with_keychain, check_merged_vault, init_vault, reset_ratchet_with_keychain,
    trusted_root_candidate,
};

pub type Result<T> = std::result::Result<T, OpsError>;

#[derive(Debug, thiserror::Error)]
pub enum OpsError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("core error: {0}")]
    Core(#[from] thorax_core::CoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] thorax_crypto::CryptoError),
    #[error("Cord error: {0}")]
    Cord(#[from] cord::CordError),
    #[error("hazmat error: {0}")]
    Hazmat(#[from] thorax_core::hazmat::HazmatError),
    #[error("{0}")]
    Keychain(#[from] KeychainError),
    #[error("vault is already initialized at {0}")]
    VaultAlreadyInitialized(PathBuf),
    #[error("workspace is missing ratchet state at {0}")]
    MissingRatchet(PathBuf),
    #[error("validation failed: {0:?}")]
    ValidationFailed(Vec<ValidationIssue>),
    #[error("operation did not become effective: {0}")]
    OperationNotEffective(&'static str),
    #[error("validated vault is missing an effective root")]
    MissingEffectiveRoot,
    #[error("identity {0:?} is not an effective member of this vault")]
    NotAVaultMember(UserId),
    #[error(
        "vault does not contain a self-signed root record that can identify its ratchet state"
    )]
    MissingTrustedRootCandidate,
    #[error(
        "vault contains multiple self-signed root records that could identify ratchet state: {0:?}"
    )]
    AmbiguousTrustedRootCandidates(Vec<HashValue>),
    #[error("secret is missing")]
    SecretMissing,
    #[error("secret is not decryptable for this identity: {0:?}")]
    SecretNotDecryptable(SecretState),
    #[error("authenticated secret plaintext has an invalid or unsupported envelope")]
    InvalidSecretPlaintext,
    #[error("secret is not writable by this identity")]
    SecretNotWritable,
    #[error("recipient slot is missing for {0:?}")]
    RecipientSlotMissing(UserId),
    #[error("reader {0:?} is missing an active user record")]
    MissingReaderUser(UserId),
    #[error("writer {0:?} is missing an active user record")]
    MissingWriterUser(UserId),
    #[error("user {0:?} is missing an active user record")]
    MissingUser(UserId),
    #[error("user handle @{0} does not exist")]
    UserHandleNotFound(String),
    #[error("user handle @{handle} points to missing user {user:?}")]
    UserHandleTargetMissing { handle: String, user: UserId },
    #[error("invalid user handle {handle:?}: {reason}")]
    InvalidUserHandle {
        handle: String,
        reason: &'static str,
    },
    #[error("invalid vault handle {handle:?}: {reason}")]
    InvalidVaultHandle {
        handle: String,
        reason: &'static str,
    },
    #[error("invalid group handle {handle:?}: {reason}")]
    InvalidGroupHandle {
        handle: String,
        reason: &'static str,
    },
    #[error("user {0:?} cannot administer the principal graph")]
    AdministerRequired(UserId),
    #[error("user {0:?} cannot confer all of this group's authority")]
    CannotConferGroupAuthority(UserId),
    #[error("keychain returned identity {actual:?}, expected {expected:?}")]
    KeychainIdentityMismatch { expected: UserId, actual: UserId },
    #[error("claimed identity {0:?} is not a current member of this vault")]
    ClaimNotAMember(UserId),
    #[error("the vault has been rolled back past the invite baseline")]
    ClaimRolledBack,
    #[error("the invitation is for a different vault root")]
    InviteRootMismatch,
    #[error("a rollback-protected invitation is required to establish trust non-interactively")]
    InviteRollbackBaselineRequired,
    #[error("no conflict candidate has record hash {0:?}")]
    ConflictCandidateNotFound(HashValue),
    #[error("conflict cannot be resolved: {0}")]
    ConflictNotResolvable(&'static str),
    #[error("secret is conflicted and has no current value until the conflict is resolved")]
    SecretConflicted,
    #[error("the vault's Lamport counter is exhausted — a record carries an absurdly high counter, which no well-behaved client produces")]
    CounterExhausted,
    #[error("invalid join candidate: {0}")]
    InvalidJoinCandidate(&'static str),
    #[error("join request trusted root does not match this workspace")]
    JoinRootMismatch,
    #[error("join approval does not match its request")]
    JoinApprovalMismatch,
    #[error("join approval plan is stale; reload and approve again")]
    JoinPlanStale,
    #[error("a prepared Kubernetes enrollment transaction conflicts with local vault state")]
    JoinRecoveryConflict,
    #[error("a pending transaction {transaction_id} from {origin} blocks writes for this vault")]
    PendingTransaction {
        transaction_id: String,
        origin: String,
    },
    #[error("transaction recovery found a file that matches neither its before nor after state")]
    TransactionRecoveryConflict,
    #[error("transaction precondition changed for {0}; reload and retry")]
    TransactionPreconditionChanged(&'static str),
    #[error("there is no pending transaction for this vault")]
    NoPendingTransaction,
    #[error("both legacy and current recovery journals exist for this vault")]
    MultipleRecoveryTransactions,
}

pub use transaction::{recover_current_workspace_if_needed, PendingTransaction};

#[derive(Clone, Debug)]
pub struct InitVaultOutput {
    pub paths: WorkspacePaths,
    pub root_user_id: UserId,
    pub root_signing_public_key_hash: HashValue,
    pub vault: VaultStore,
    pub ratchet: Ratchet,
    pub report: ValidationReport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbandonTransactionOutput {
    pub trusted_root: HashValue,
    pub transaction_id: Bytes,
    pub operation: String,
    pub origin: Option<PathBuf>,
}

/// The result of an operation that changes *who may read* and therefore also drives the
/// cryptographic consequence of that change. `output` is the authorization mutation's result;
/// `reconcile` is the convergence step (re-encrypting existing secrets so newly-authorized readers
/// gain a slot) that the same op performed under a single keychain unlock. A caller never has to
/// remember to reconcile after granting — that obligation lives here, not in the frontends.
#[derive(Debug)]
pub struct AccessChange<T> {
    pub output: T,
    pub reconcile: ReconcileOutput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetSecretOutput {
    pub secret_id: SecretId,
    pub selector: SecretSelectorV1,
    pub sealed: SealedPayloadV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeleteSecretOutput {
    pub secret_id: SecretId,
    pub selector: SecretSelectorV1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UserRef {
    Id(UserId),
    Handle(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedUserRef {
    pub user_id: UserId,
    pub handle: Option<String>,
}

pub struct SecretPlaintext {
    pub selector: SecretSelectorV1,
    /// The secret's primary value — unchanged in meaning, the bytes a writer set.
    pub plaintext: Zeroizing<Bytes>,
    /// Zero or more additional decrypted key→value pairs, sorted by key. Present when the
    /// secret was written with fields; empty for primary-only and legacy values.
    pub fields: Vec<SecretField>,
}

/// One additional decrypted key→value pair attached to a secret. The value, like the primary,
/// is opaque bytes rendered as text or hex by the frontend.
pub struct SecretField {
    pub key: String,
    pub value: Zeroizing<Bytes>,
}

impl SecretField {
    /// Whether the field value is valid UTF-8 — mirrors [`SecretPlaintext::is_utf8`].
    pub fn is_utf8(&self) -> bool {
        std::str::from_utf8(&self.value).is_ok()
    }
}

impl SecretPlaintext {
    /// Whether the plaintext is valid UTF-8 — the single predicate that decides whether a
    /// frontend renders the value as text or as hex. Defined once so CLI and TUI never drift.
    pub fn is_utf8(&self) -> bool {
        std::str::from_utf8(&self.plaintext).is_ok()
    }

    /// Look up an additional field by key.
    pub fn field(&self, key: &str) -> Option<&SecretField> {
        self.fields.iter().find(|field| field.key == key)
    }

    /// Rebuild the sealable envelope (primary + fields) from this decrypted value. Used by the
    /// re-seal paths (relabel, reconcile, rotation) so additional fields survive a re-key.
    pub fn to_value(&self) -> SecretValueV1 {
        SecretValueV1 {
            primary: self.plaintext.to_vec(),
            fields: self.field_entries().collect::<Vec<_>>().into(),
        }
    }

    /// Replace the primary value, keeping every additional field — the read-modify-write a
    /// primary-only update (`thorax set` on a secret that already has fields) seals.
    pub fn to_value_with_primary(&self, primary: impl Into<Bytes>) -> SecretValueV1 {
        SecretValueV1 {
            primary: primary.into(),
            fields: self.field_entries().collect::<Vec<_>>().into(),
        }
    }

    /// Keep the primary value and insert-or-replace one additional field.
    pub fn with_field(&self, key: impl Into<String>, value: impl Into<Bytes>) -> SecretValueV1 {
        let key = key.into();
        let mut entries: Vec<SecretFieldEntryV1> = self
            .field_entries()
            .filter(|entry| entry.key != key)
            .collect();
        entries.push(SecretFieldEntryV1 {
            key,
            value: value.into(),
        });
        SecretValueV1 {
            primary: self.plaintext.to_vec(),
            fields: entries.into(),
        }
    }

    /// Keep the primary value and remove one additional field.
    pub fn without_field(&self, key: &str) -> SecretValueV1 {
        SecretValueV1 {
            primary: self.plaintext.to_vec(),
            fields: self
                .field_entries()
                .filter(|entry| entry.key != key)
                .collect::<Vec<_>>()
                .into(),
        }
    }

    fn field_entries(&self) -> impl Iterator<Item = SecretFieldEntryV1> + '_ {
        self.fields.iter().map(|field| SecretFieldEntryV1 {
            key: field.key.clone(),
            value: field.value.to_vec(),
        })
    }
}

/// Failure while releasing secrets for `thorax run`. Per-secret failures carry the selector so
/// frontends can name which of the requested secrets was the problem.
#[derive(Debug, thiserror::Error)]
pub enum RunSecretsError {
    #[error("{source}")]
    Secret {
        selector: SecretSelectorV1,
        #[source]
        source: Box<OpsError>,
    },
    #[error(transparent)]
    Ops(#[from] OpsError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelabelSecretOutput {
    pub from: SecretSelectorV1,
    pub to: SecretSelectorV1,
}

#[derive(Clone, Debug)]
pub struct InviteUserOutput {
    pub user_id: UserId,
    /// The self-contained invite: identity seed, intended root, and pre-invite rollback baseline.
    pub invite: InvitationMaterial,
    pub handle: Option<UserHandleId>,
    pub grants: Vec<GrantId>,
    /// Convergence for the grants carried in the invite: existing secrets re-encrypted so the new
    /// user can read them, plus any the inviter could not decrypt (left for a current reader).
    pub reconcile: ReconcileOutput,
}

#[derive(Debug)]
pub struct ClaimInviteOutput {
    pub user_id: UserId,
    pub trusted_root: HashValue,
    pub stored: KeychainIdentityRef,
    pub report: ValidationReport,
    /// True when first-sync validation used either the invite baseline or stronger existing local
    /// rollback state. False is an explicitly compact, trust-on-first-use claim.
    pub rollback_protected: bool,
}

/// Shared op scaffolding: the keychain unlock funnel and single-record commit core every
/// session-based operation builds on. Both are crate-internal — the public mutation
/// vocabulary lives on [`UnlockedSession`], in the per-family modules.
impl LockedSession {
    /// Unlock `user_id` from the keychain for `purpose`, with the request built from this
    /// snapshot: the trusted root from effective state plus the vault/user handle labels.
    /// Enforces that the keychain returned the requested identity, then brings the
    /// session's verifications to possession grade for it (see
    /// [`LockedSession::attest_verifications`]) — which is why unlocking takes `&mut self`:
    /// an unlock may rebuild the report.
    fn unlock(
        &mut self,
        crypto: &Crypto,
        keychain: &(impl IdentityKeychain + ?Sized),
        user_id: &UserId,
        purpose: KeyUsePurpose,
    ) -> Result<Identity> {
        let trusted_root = self
            .effective()
            .root_signing_public_key_hash
            .clone()
            .ok_or(OpsError::MissingEffectiveRoot)?;
        let request = KeychainRequest::new(self.paths(), trusted_root, user_id.clone(), purpose)
            .with_labels(
                primary_vault_handle(self.report()).map(|record| normalize_handle(&record.handle)),
                primary_handle_for_user(self.report(), user_id)
                    .map(|record| normalize_handle(&record.handle)),
            );
        let identity = keychain.unlock_identity(crypto, &request)?;
        if identity.user_id() != user_id {
            return Err(OpsError::KeychainIdentityMismatch {
                expected: user_id.clone(),
                actual: identity.user_id().clone(),
            });
        }
        self.attest_verifications(crypto, &identity)?;
        // The membership pin: the seed → EntryPoint → root chain's in-vault half. A
        // substituted vault cannot carry this identity's entry point (forging it needs the
        // seed), so unlocking against one fails loudly here instead of proceeding on a
        // vault the actor is not actually part of.
        session::ensure_member(self, identity.user_id())?;
        Ok(identity)
    }

    /// The single-record commit core: `build` signs exactly one record against the
    /// pre-state and the vault's next Lamport counter; `effective` checks the post-state,
    /// receiving the appended record's hash for exact-winner checks (LWW shadowing by a
    /// concurrent higher-counter record must fail the op).
    ///
    /// The counter is floored above any rollback conflict's remembered watermark: in a
    /// rolled-back vault the in-file maximum may sit below what this machine once verified,
    /// and a write must re-pass the local ratchet, not land under it.
    fn commit_record<T>(
        &mut self,
        crypto: &impl CryptoProvider,
        build: impl FnOnce(&ValidationReport, u64) -> Result<(VaultRecordV1, T)>,
        effective: impl FnOnce(&T, &HashValue, &ValidationReport) -> Result<()>,
    ) -> Result<T> {
        let (output, _hash) = self.commit(
            crypto,
            |vault, pre_report| {
                let counter = next_counter(&pre_report.effective)
                    .max(pre_report.effective.rollback_counter_floor());
                // Refuse to mint a counter past the ceiling: it would be rejected as
                // corrupt anyway, and reaching here means an existing record sits at the
                // ceiling — restore the vault file from git history.
                if counter > thorax_core::MAX_LWW_COUNTER {
                    return Err(OpsError::CounterExhausted);
                }
                let (signed, output) = build(pre_report, counter)?;
                let hash = record_hash(crypto, &signed)?;
                append_record(vault, signed);
                Ok((output, hash))
            },
            |(output, hash), post_report| effective(output, hash, post_report),
        )?;
        Ok(output)
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReconcileOutput {
    /// Secrets that were encrypted to include the current reader set.
    pub encrypted: Vec<SecretSelectorV1>,
    /// Secrets a missing reader needs, but that the actor could not decrypt, so could not
    /// encrypt. A current reader must encrypt them before that reader can decrypt.
    pub needs_rotation: Vec<SecretSelectorV1>,
}

#[derive(Debug)]
pub struct ResetRatchetOutput {
    pub trusted_root: HashValue,
    /// Keys whose remembered watermark the vault has fallen below — protection the reset
    /// deliberately gives up (a value or deletion rollback we are now accepting).
    pub dropped_watermarks: Vec<RecordKey>,
    pub applied: bool,
}

/// Validation outcome for a merge driver's union vault: the issues and conflicts found,
/// and whether a local trust ratchet participated. Rollback can only be checked when this
/// machine holds state for the union's root (a fresh CI checkout has none); signature,
/// structure, and authority validation run either way. The check is read-only — the
/// ratchet advances on the user's next real operation, never inside a merge.
#[derive(Clone, Debug)]
pub struct CheckMergedVaultOutput {
    pub issues: Vec<ValidationIssue>,
    /// The authority-aware conflict set (same-counter ties, suspected rollbacks) the union
    /// validates to on this machine.
    pub conflicts: Vec<ConflictReport>,
    pub ratchet_checked: bool,
}

pub struct ResolveConflictWithKeychainRequest<'a> {
    pub resolver_id: &'a UserId,
    /// Record hash of the chosen candidate (as listed in [`ConflictReport::candidates`]).
    pub pick: &'a HashValue,
}

#[derive(Clone, Debug)]
pub struct ResolveConflictOutput {
    pub key: RecordKey,
    /// The fresh Lamport counter the winner was re-signed at: one above the global max,
    /// and above any rollback conflict's remembered watermark.
    pub counter: u64,
    /// Record hash of the newly signed winner.
    pub record_hash: HashValue,
}

/// What accepting a rollback gave up: the remembered counter this machine now forgets, and
/// the currently visible counter it accepts as trusted (`0` when nothing survives at the
/// key — the watermark is dropped entirely).
#[derive(Clone, Debug)]
pub struct AcceptRollbackOutput {
    pub key: RecordKey,
    pub remembered_counter: u64,
    pub accepted_counter: u64,
}

pub struct RevealConflictCandidatesWithKeychainRequest<'a> {
    pub user_id: &'a UserId,
    /// Record hashes of the secret-value conflict candidates to decrypt — typically every
    /// candidate of one conflict the caller holds a slot on, so the competing values can be
    /// compared side by side under a single keychain release.
    pub picks: &'a [HashValue],
    pub sink: OutputSink,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use std::fs;
    use thorax_core::hazmat::grant_record;
    use thorax_core::ids::derive_grant_id;
    use thorax_core::test_support::{secret_record, secret_selector, test_user};

    #[test]
    fn commits_refuse_to_mint_counters_past_the_ceiling() {
        // A hostile member can stamp a record at the counter ceiling (it is structurally
        // valid); the next honest write would need ceiling+1, which no well-behaved vault
        // ever reaches — the commit errors out loudly instead of producing a corrupt or
        // forever-tied record.
        let fixture = Fixture::initialized();
        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let selector = secret_selector(&["app", "wedge"]);
        session
            .commit(
                &fixture.crypto,
                |vault, _| {
                    append_record(
                        vault,
                        secret_record(
                            &fixture.crypto,
                            &fixture.root,
                            &selector,
                            &[&fixture.root],
                            thorax_core::MAX_LWW_COUNTER,
                        ),
                    );
                    Ok(())
                },
                |_: &(), _| Ok(()),
            )
            .unwrap();

        let error = session
            .delete_secret(&fixture.crypto, &fixture.root, selector)
            .unwrap_err();
        assert!(matches!(error, OpsError::CounterExhausted));
    }

    #[test]
    fn session_load_uses_root_specific_state() {
        let fixture = Fixture::initialized();
        let expected_root = key_hash(&fixture.crypto, &fixture.root.signing_public_key).unwrap();
        let unrelated = Ratchet::new(HashValue(vec![0x99; 32]));
        write_ratchet_atomic(&fixture.paths, &unrelated).unwrap();

        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert_eq!(loaded.ratchet().trusted_root, expected_root);
    }

    #[test]
    fn invalid_commit_is_rejected_before_write() {
        let fixture = Fixture::initialized();
        let before = record_count(&fixture.paths, &fixture.crypto);

        let error = LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .commit(
                &fixture.crypto,
                |vault, _| {
                    let seed = IdSeed::from_bytes(b"invalid-manage".to_vec());
                    let grant = derive_grant_id(&fixture.crypto, &seed)?;
                    append_record(
                        vault,
                        grant_record(
                            &fixture.crypto,
                            &fixture.root,
                            PrincipalRefV1::User(fixture.root.id.clone()),
                            GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                                selector: KeyspaceSelectorV1::all(),
                                grantable: Vec::new(),
                            }),
                            seed,
                            2,
                        )?,
                    );
                    Ok(grant)
                },
                |_: &GrantId, _| Ok(()),
            )
            .unwrap_err();
        let after = record_count(&fixture.paths, &fixture.crypto);

        assert!(matches!(error, OpsError::ValidationFailed(_)));
        assert_eq!(before, after);
    }

    #[test]
    fn session_commit_revalidates_when_disk_changed_under_it() {
        let fixture = Fixture::initialized();
        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();

        // Another process appends a user while this session holds the older snapshot.
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();

        // The commit detects the divergence under the lock, transparently revalidates,
        // and applies the mutation on top of the union of both changes.
        let bob = test_user(&fixture.crypto, "bob");
        session_add_user(&mut session, &fixture.crypto, &fixture.root, &bob);

        assert!(session.effective().users.contains_key(&alice.id));
        assert!(session.effective().users.contains_key(&bob.id));
    }

    #[test]
    fn session_commit_after_rollback_sees_the_conflict_and_keys_stay_inert() {
        let fixture = Fixture::initialized();
        let baseline_vault = fs::read(&fixture.paths.vault_path).unwrap();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();

        // Load at the newer state (watermarks remember alice), then roll the file back.
        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        fs::write(&fixture.paths.vault_path, &baseline_vault).unwrap();

        // A rollback is a per-key conflict, not a fatal load/commit error: the commit
        // revalidates against the rolled-back file and proceeds, while alice's dropped
        // keys surface as rollback conflicts and contribute nothing to effective state.
        session
            .commit(&fixture.crypto, |_, _| Ok(()), |_: &(), _| Ok(()))
            .unwrap();

        let alice_key = RecordKey::User {
            user_id: alice.id.clone(),
        };
        let conflict = session
            .effective()
            .conflicted
            .get(&alice_key)
            .expect("alice's dropped key is a rollback conflict");
        assert!(matches!(conflict.kind, ConflictKind::Rollback { .. }));
        assert!(!session.effective().users.contains_key(&alice.id));
    }

    #[test]
    fn session_load_persists_raised_watermarks_without_touching_the_vault() {
        let fixture = Fixture::initialized();
        let trusted_root = key_hash(&fixture.crypto, &fixture.root.signing_public_key).unwrap();
        let state_file = ratchet_path(&fixture.paths, &trusted_root);
        let stale_state = fs::read(&state_file).unwrap();

        // The vault advances; then this machine's ratchet is rolled back to the stale
        // copy, as if the records arrived via git from elsewhere.
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        fs::write(&state_file, &stale_state).unwrap();
        let vault_bytes_before = fs::read(&fixture.paths.vault_path).unwrap();

        let session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();

        // The load advanced and persisted the ratchet but never rewrote the vault.
        assert_ne!(fs::read(&state_file).unwrap(), stale_state);
        assert_eq!(
            fs::read(&fixture.paths.vault_path).unwrap(),
            vault_bytes_before
        );
        let alice_key = RecordKey::User {
            user_id: alice.id.clone(),
        };
        assert!(session.ratchet().watermarks.contains_key(&alice_key));
    }

    #[test]
    fn workspace_lock_does_not_serialize_shared_ratchet_persistence() {
        let fixture = Fixture::initialized();
        let trusted_root = key_hash(&fixture.crypto, &fixture.root.signing_public_key).unwrap();
        let state_file = ratchet_path(&fixture.paths, &trusted_root);
        let stale_state = fs::read(&state_file).unwrap();

        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        fs::write(&state_file, &stale_state).unwrap();

        // A lock in this workspace protects its vault only. It must not suppress a
        // machine-wide ratchet raise that protects every clone of this root.
        let guard = acquire_workspace_lock(&fixture.paths).unwrap();
        let session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        assert_ne!(fs::read(&state_file).unwrap(), stale_state);
        let alice_key = RecordKey::User {
            user_id: alice.id.clone(),
        };
        assert!(session.ratchet().watermarks.contains_key(&alice_key));
        drop(guard);
        let trust = read_ratchet_for_root(&fixture.paths, &trusted_root)
            .unwrap()
            .unwrap();
        assert!(trust.watermarks.contains_key(&alice_key));
    }

    #[test]
    fn session_reload_is_validation_free_while_disk_is_unchanged() {
        use thorax_core::test_support::CountingCrypto;

        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();

        let counting = CountingCrypto::default();
        let mut session = LockedSession::load(&fixture.paths, &counting).unwrap();
        let verified_during_load = counting.verifications.get();
        assert!(verified_during_load > 0, "load performs the one validation");

        // Repeated freshness checks against an unchanged file are byte compares only.
        assert!(!session.reload_if_stale(&counting).unwrap());
        assert!(!session.reload_if_stale(&counting).unwrap());
        assert_eq!(counting.verifications.get(), verified_during_load);
    }
}
