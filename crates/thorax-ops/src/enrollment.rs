use thorax_core::crypto::{derive_user_id, signed_record_message};
use thorax_core::hazmat::{append_record, grant_record, secret_record, user_record};
use thorax_core::{
    baseline_bytes, baseline_from_bytes, encode_vault, join_approval_message,
    join_candidate_message, next_counter, validate_vault, CryptoProvider, DeploymentContextV1,
    EncryptedBaselineV1, GrantPermissionV1, HashValue, JoinApprovalV1, JoinCandidateV1,
    JoinPurposeV1, PrincipalRefV1, RatchetBaselineV1, RatchetRecordV1, RecordBodyV1, RecordKey,
    RecordSigner, SecretSelectorV1, UserId,
};
use thorax_crypto::{hpke_open, hpke_seal, random_seed, Crypto, Identity};
#[cfg(test)]
use thorax_store::write_private_atomic;
use thorax_store::{
    acquire_root_state_lock, acquire_workspace_lock, decode_ratchet, encode_ratchet, ratchet_path,
    read_file_bounded, read_ratchet_for_root, read_vault_bytes, remove_file_durable,
    write_ratchet_atomic, write_vault_bytes_atomic, WorkspacePaths,
};

use crate::principals::{ensure_administer, ensure_can_create_permission};
use crate::secrets::{decrypt_secret_from_report, seal_secret_payload, SealContext};
use crate::{ensure_no_issues, OpsError, Result, UnlockedSession};

const JOIN_BASELINE_INFO: &[u8] = b"thorax.join-baseline.v1";
const JOIN_COMMIT_HASH_DOMAIN: &str = "thorax.join-commit.v1";
const JOIN_COMMIT_FILE: &str = "join-commit.cord";
const JOIN_COMMIT_MAGIC: &[u8] = b"thorax-join-commit\0";
const MAX_JOIN_COMMIT_BYTES: usize = thorax_core::MAX_VAULT_BYTES + 1024 * 1024;

#[derive(cord::Cord, Clone, Debug)]
enum JoinCommitJournal {
    #[cord(index = 0)]
    V1(JoinCommitJournalV1),
}

#[derive(cord::Cord, Clone, Debug)]
struct JoinCommitJournalV1 {
    trusted_root: HashValue,
    expected_vault_hash: HashValue,
    expected_ratchet_hash: HashValue,
    next_vault_bytes: Vec<u8>,
    next_ratchet_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct JoinApprovalPlan {
    approval: JoinApprovalV1,
    expected_vault_bytes: Vec<u8>,
    expected_ratchet: thorax_core::Ratchet,
    next_vault_bytes: Vec<u8>,
    next_ratchet: thorax_core::Ratchet,
    has_vault_mutation: bool,
}

impl JoinApprovalPlan {
    pub fn approval(&self) -> &JoinApprovalV1 {
        &self.approval
    }

    pub fn has_vault_mutation(&self) -> bool {
        self.has_vault_mutation
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_join_candidate(
    crypto: &Crypto,
    identity: &Identity,
    purpose: JoinPurposeV1,
    request_id: Vec<u8>,
    trusted_root: HashValue,
    trusted_root_user_id: UserId,
    deployment: DeploymentContextV1,
    mut suggested_selectors: Vec<SecretSelectorV1>,
) -> Result<JoinCandidateV1> {
    suggested_selectors.sort();
    suggested_selectors.dedup();
    let entry_point = match purpose {
        JoinPurposeV1::Enroll => Some(thorax_core::hazmat::entry_point_record(
            crypto,
            identity,
            trusted_root_user_id.clone(),
            0,
        )?),
        JoinPurposeV1::RestoreTrust => None,
    };
    let mut candidate = JoinCandidateV1 {
        purpose,
        request_id,
        trusted_root,
        trusted_root_user_id,
        deployment,
        user_id: identity.user_id().clone(),
        signing_public_key: identity.signing_public_key().to_vec(),
        hpke_public_key: identity.hpke_public_key().to_vec(),
        suggested_selectors,
        entry_point,
        proof: Vec::new(),
    };
    candidate.proof = identity.sign(
        thorax_core::JOIN_CANDIDATE_PROOF_DOMAIN,
        &join_candidate_message(&candidate)?,
    );
    Ok(candidate)
}

pub fn validate_join_candidate(crypto: &Crypto, candidate: &JoinCandidateV1) -> Result<()> {
    if candidate.request_id.len() != 32 {
        return Err(OpsError::InvalidJoinCandidate(
            "request ID must contain 32 bytes",
        ));
    }
    let derived = derive_user_id(
        crypto,
        &candidate.signing_public_key,
        &candidate.hpke_public_key,
    )?;
    if derived != candidate.user_id {
        return Err(OpsError::InvalidJoinCandidate(
            "user ID does not match the public keys",
        ));
    }
    if !candidate
        .suggested_selectors
        .windows(2)
        .all(|pair| pair[0] < pair[1])
    {
        return Err(OpsError::InvalidJoinCandidate(
            "suggested selectors are not canonical",
        ));
    }
    if !crypto.verify_signature(
        thorax_core::JOIN_CANDIDATE_PROOF_DOMAIN,
        &candidate.signing_public_key,
        &join_candidate_message(candidate)?,
        &candidate.proof,
    ) {
        return Err(OpsError::InvalidJoinCandidate("proof is invalid"));
    }
    match (&candidate.purpose, &candidate.entry_point) {
        (JoinPurposeV1::Enroll, Some(entry_point)) => {
            validate_candidate_entry_point(crypto, candidate, entry_point)
        }
        (JoinPurposeV1::Enroll, None) => Err(OpsError::InvalidJoinCandidate(
            "enrollment has no entry point",
        )),
        (JoinPurposeV1::RestoreTrust, None) => Ok(()),
        (JoinPurposeV1::RestoreTrust, Some(_)) => Err(OpsError::InvalidJoinCandidate(
            "trust restoration carries an entry point",
        )),
    }
}

impl UnlockedSession {
    pub fn plan_join_approval(
        &mut self,
        crypto: &Crypto,
        candidate: &JoinCandidateV1,
        approved_grants: Vec<GrantPermissionV1>,
        replaces_user_id: Option<UserId>,
    ) -> Result<JoinApprovalPlan> {
        self.session().ensure_valid()?;
        validate_join_candidate(crypto, candidate)?;
        let effective = self.effective();
        if effective.root_signing_public_key_hash.as_ref() != Some(&candidate.trusted_root)
            || effective.root_user_id.as_ref() != Some(&candidate.trusted_root_user_id)
        {
            return Err(OpsError::JoinRootMismatch);
        }
        ensure_administer(effective, self.user_id())?;

        match candidate.purpose {
            JoinPurposeV1::Enroll => {
                if effective.users.contains_key(&candidate.user_id) {
                    return Err(OpsError::InvalidJoinCandidate(
                        "candidate is already a member",
                    ));
                }
                for permission in &approved_grants {
                    if !matches!(permission, GrantPermissionV1::ReadKeyspace(_)) {
                        return Err(OpsError::InvalidJoinCandidate(
                            "Kubernetes identities may receive read grants only",
                        ));
                    }
                    ensure_can_create_permission(effective, self.user_id(), permission)?;
                }
            }
            JoinPurposeV1::RestoreTrust => {
                if !effective.users.contains_key(&candidate.user_id) {
                    return Err(OpsError::InvalidJoinCandidate(
                        "trust restoration identity is not a current member",
                    ));
                }
                if !approved_grants.is_empty() || replaces_user_id.is_some() {
                    return Err(OpsError::InvalidJoinCandidate(
                        "trust restoration cannot mutate authority",
                    ));
                }
            }
        }

        let expected_vault_bytes = encode_vault(self.session().vault())?;
        let mut next_vault = self.session().vault().clone();
        let mut post_report = self.report().clone();
        let has_vault_mutation = candidate.purpose == JoinPurposeV1::Enroll;

        if has_vault_mutation {
            let counter =
                next_counter(self.effective()).max(self.effective().rollback_counter_floor());
            append_record(
                &mut next_vault,
                user_record(
                    crypto,
                    self.identity(),
                    candidate.signing_public_key.clone(),
                    candidate.hpke_public_key.clone(),
                    counter,
                )?,
            );
            append_record(
                &mut next_vault,
                candidate
                    .entry_point
                    .clone()
                    .ok_or(OpsError::InvalidJoinCandidate(
                        "enrollment has no entry point",
                    ))?,
            );
            for permission in &approved_grants {
                append_record(
                    &mut next_vault,
                    grant_record(
                        crypto,
                        self.identity(),
                        PrincipalRefV1::User(candidate.user_id.clone()),
                        permission.clone(),
                        random_seed(),
                        counter,
                    )?,
                );
            }
            post_report = validate_vault(&next_vault, self.session().ratchet(), crypto)?;
            ensure_no_issues(&post_report)?;

            let candidate_authority = post_report.effective.authority_for_user(&candidate.user_id);
            let selectors = post_report
                .effective
                .secret_records()
                .into_iter()
                .map(|active| active.value.selector)
                .filter(|selector| candidate_authority.can_read(selector))
                .collect::<Vec<_>>();
            if !selectors.is_empty() {
                let reseal_counter = next_counter(&post_report.effective)
                    .max(post_report.effective.rollback_counter_floor());
                for selector in selectors {
                    let plaintext = decrypt_secret_from_report(
                        &post_report,
                        crypto,
                        self.identity(),
                        selector.clone(),
                    )?;
                    let secret_id = thorax_core::derive_secret_id(crypto, &selector)?;
                    let record_key = RecordKey::Secret {
                        secret_id: secret_id.clone(),
                    };
                    let sealed = seal_secret_payload(
                        &post_report.effective,
                        &SealContext {
                            record_key: &record_key,
                            signer_key: self.identity().signing_public_key(),
                            counter: reseal_counter,
                            secret_id: &secret_id,
                            selector: &selector,
                        },
                        &plaintext.to_value(),
                    )?;
                    append_record(
                        &mut next_vault,
                        secret_record(crypto, self.identity(), selector, sealed, reseal_counter)?,
                    );
                }
                post_report = validate_vault(&next_vault, self.session().ratchet(), crypto)?;
                ensure_no_issues(&post_report)?;
            }
        }

        let baseline = RatchetBaselineV1 {
            records: self
                .session()
                .ratchet()
                .to_records()
                .into_iter()
                .filter(|record| !matches!(record, RatchetRecordV1::TrustedRoot(_)))
                .collect(),
        };
        let candidate_message = join_candidate_message(candidate)?;
        let sealed = hpke_seal(
            &candidate.hpke_public_key,
            JOIN_BASELINE_INFO,
            &candidate_message,
            &baseline_bytes(&baseline)?,
        )?;
        let mut approval = JoinApprovalV1 {
            purpose: candidate.purpose.clone(),
            request_id: candidate.request_id.clone(),
            trusted_root: candidate.trusted_root.clone(),
            deployment: candidate.deployment.clone(),
            user_id: candidate.user_id.clone(),
            approved_grants,
            encrypted_baseline: EncryptedBaselineV1 {
                encapsulated_key: sealed.encapsulated_key,
                ciphertext: sealed.ciphertext,
            },
            replaces_user_id,
            approving_admin: self.user_id().clone(),
            approving_signing_public_key: self.identity().signing_public_key().to_vec(),
            signature: Vec::new(),
        };
        approval.signature = self.identity().sign(
            thorax_core::JOIN_APPROVAL_SIGNATURE_DOMAIN,
            &join_approval_message(&approval)?,
        );

        let mut next_ratchet = self.session().ratchet().clone();
        next_ratchet.apply_update(&post_report.ratchet_update);
        Ok(JoinApprovalPlan {
            approval,
            expected_vault_bytes,
            expected_ratchet: self.session().ratchet().clone(),
            next_vault_bytes: encode_vault(&next_vault)?,
            next_ratchet,
            has_vault_mutation,
        })
    }
}

pub fn commit_join_approval_plan(
    paths: &thorax_store::WorkspacePaths,
    plan: JoinApprovalPlan,
) -> Result<()> {
    let _root_lock = acquire_root_state_lock(paths, &plan.next_ratchet.trusted_root)?;
    let _lock = acquire_workspace_lock(paths)?;
    let current = read_vault_bytes(paths)?;
    if current != plan.expected_vault_bytes {
        return Err(OpsError::JoinPlanStale);
    }
    if !plan.has_vault_mutation {
        return Ok(());
    }
    let current_ratchet = read_ratchet_for_root(paths, &plan.next_ratchet.trusted_root)?
        .ok_or_else(|| {
            OpsError::MissingRatchet(thorax_store::ratchet_path(
                paths,
                &plan.next_ratchet.trusted_root,
            ))
        })?;
    if current_ratchet != plan.expected_ratchet {
        return Err(OpsError::JoinPlanStale);
    }
    crate::transaction::commit_after_images_locked(
        paths,
        &plan.next_ratchet.trusted_root,
        &Crypto,
        "approve join",
        &plan.expected_vault_bytes,
        &encode_ratchet(&plan.expected_ratchet)?,
        plan.next_vault_bytes,
        encode_ratchet(&plan.next_ratchet)?,
    )
}

/// Complete an interrupted approval transaction. Both files may independently be in the
/// expected or next state; any third state is a real conflict and remains fail-closed.
pub(crate) fn recover_join_commit(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<bool> {
    let path = join_commit_path(paths, trusted_root);
    let bytes = match read_file_bounded(&path, MAX_JOIN_COMMIT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(thorax_store::StoreError::Io { path, source }.into()),
    };
    let Some(payload) = bytes.strip_prefix(JOIN_COMMIT_MAGIC) else {
        return Err(OpsError::JoinRecoveryConflict);
    };
    let JoinCommitJournal::V1(journal) = cord::deserialize(payload)?;
    if &journal.trusted_root != trusted_root {
        return Err(OpsError::JoinRecoveryConflict);
    }
    let _root_lock = acquire_root_state_lock(paths, trusted_root)?;
    let _lock = acquire_workspace_lock(paths)?;
    complete_join_commit(paths, &journal, &Crypto)?;
    Ok(true)
}

fn complete_join_commit(
    paths: &WorkspacePaths,
    journal: &JoinCommitJournalV1,
    crypto: &Crypto,
) -> Result<()> {
    let current_vault = read_vault_bytes(paths)?;
    let current_vault_hash = crypto.hash(JOIN_COMMIT_HASH_DOMAIN, &current_vault);
    let next_vault_hash = crypto.hash(JOIN_COMMIT_HASH_DOMAIN, &journal.next_vault_bytes);
    if current_vault_hash != journal.expected_vault_hash && current_vault_hash != next_vault_hash {
        return Err(OpsError::JoinRecoveryConflict);
    }

    let current_ratchet = read_ratchet_for_root(paths, &journal.trusted_root)?
        .ok_or_else(|| OpsError::MissingRatchet(ratchet_path(paths, &journal.trusted_root)))?;
    let current_ratchet_hash =
        crypto.hash(JOIN_COMMIT_HASH_DOMAIN, &encode_ratchet(&current_ratchet)?);
    let next_ratchet_hash = crypto.hash(JOIN_COMMIT_HASH_DOMAIN, &journal.next_ratchet_bytes);
    if current_ratchet_hash != journal.expected_ratchet_hash
        && current_ratchet_hash != next_ratchet_hash
    {
        return Err(OpsError::JoinRecoveryConflict);
    }

    let next_ratchet = decode_ratchet(
        join_commit_path(paths, &journal.trusted_root),
        &journal.next_ratchet_bytes,
    )?;
    write_ratchet_atomic(paths, &next_ratchet)?;
    write_vault_bytes_atomic(paths, &journal.next_vault_bytes)?;

    // A successful commit means the bytes can be reopened, not merely that rename returned.
    let reopened_ratchet = read_ratchet_for_root(paths, &journal.trusted_root)?
        .ok_or_else(|| OpsError::MissingRatchet(ratchet_path(paths, &journal.trusted_root)))?;
    if read_vault_bytes(paths)? != journal.next_vault_bytes
        || encode_ratchet(&reopened_ratchet)? != journal.next_ratchet_bytes
    {
        return Err(OpsError::JoinRecoveryConflict);
    }
    remove_file_durable(join_commit_path(paths, &journal.trusted_root))?;
    Ok(())
}

#[cfg(test)]
fn write_join_commit_journal(paths: &WorkspacePaths, journal: &JoinCommitJournalV1) -> Result<()> {
    let payload = cord::serialize(&JoinCommitJournal::V1(journal.clone()))?;
    let mut bytes = Vec::with_capacity(JOIN_COMMIT_MAGIC.len() + payload.len());
    bytes.extend_from_slice(JOIN_COMMIT_MAGIC);
    bytes.extend(payload);
    if bytes.len() > MAX_JOIN_COMMIT_BYTES {
        return Err(thorax_core::CoreError::Validation(
            "join transaction exceeds supported size".to_string(),
        )
        .into());
    }
    write_private_atomic(join_commit_path(paths, &journal.trusted_root), &bytes)?;
    Ok(())
}

fn join_commit_path(paths: &WorkspacePaths, trusted_root: &HashValue) -> std::path::PathBuf {
    ratchet_path(paths, trusted_root).with_file_name(JOIN_COMMIT_FILE)
}

pub(crate) fn join_commit_present(
    paths: &WorkspacePaths,
    trusted_root: &HashValue,
) -> Result<bool> {
    let path = join_commit_path(paths, trusted_root);
    match read_file_bounded(&path, MAX_JOIN_COMMIT_BYTES) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(thorax_store::StoreError::Io { path, source }.into()),
    }
}

pub fn open_join_baseline(
    crypto: &Crypto,
    identity: &Identity,
    candidate: &JoinCandidateV1,
    approval: &JoinApprovalV1,
) -> Result<RatchetBaselineV1> {
    validate_approval_bindings(crypto, candidate, approval)?;
    let opened = hpke_open(
        &identity.keys().hpke,
        &approval.encrypted_baseline.encapsulated_key,
        JOIN_BASELINE_INFO,
        &join_candidate_message(candidate)?,
        &approval.encrypted_baseline.ciphertext,
    )?;
    baseline_from_bytes(&opened).map_err(Into::into)
}

pub fn validate_approval_bindings(
    crypto: &Crypto,
    candidate: &JoinCandidateV1,
    approval: &JoinApprovalV1,
) -> Result<()> {
    validate_join_candidate(crypto, candidate)?;
    if approval.purpose != candidate.purpose
        || approval.request_id != candidate.request_id
        || approval.trusted_root != candidate.trusted_root
        || approval.deployment != candidate.deployment
        || approval.user_id != candidate.user_id
    {
        return Err(OpsError::JoinApprovalMismatch);
    }
    if approval.purpose == JoinPurposeV1::RestoreTrust
        && (!approval.approved_grants.is_empty() || approval.replaces_user_id.is_some())
    {
        return Err(OpsError::JoinApprovalMismatch);
    }
    // The controller additionally resolves this signing key to `approving_admin` through
    // the verified vault. The standalone artifact carries no redundant admin HPKE key.
    if !crypto.verify_signature(
        thorax_core::JOIN_APPROVAL_SIGNATURE_DOMAIN,
        &approval.approving_signing_public_key,
        &join_approval_message(approval)?,
        &approval.signature,
    ) {
        return Err(OpsError::JoinApprovalMismatch);
    }
    Ok(())
}

fn validate_candidate_entry_point(
    crypto: &Crypto,
    candidate: &JoinCandidateV1,
    entry_point: &thorax_core::VaultRecordV1,
) -> Result<()> {
    if entry_point.signing_public_key != candidate.signing_public_key {
        return Err(OpsError::InvalidJoinCandidate(
            "entry point signing key differs from the candidate",
        ));
    }
    let Some(RecordBodyV1::EntryPoint(body)) = entry_point.body.known() else {
        return Err(OpsError::InvalidJoinCandidate(
            "entry point artifact has the wrong record type",
        ));
    };
    if body.trusted_root_user_id != candidate.trusted_root_user_id
        || body.hpke_public_key != candidate.hpke_public_key
        || body.counter != 0
    {
        return Err(OpsError::InvalidJoinCandidate(
            "entry point bindings differ from the candidate",
        ));
    }
    if !crypto.verify_signature(
        "thorax.signed.v1",
        &entry_point.signing_public_key,
        &signed_record_message(entry_point)?,
        &entry_point.signature,
    ) {
        return Err(OpsError::InvalidJoinCandidate(
            "entry point signature is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{get_secret, set_secret, ProductionFixture};
    use crate::{LockedSession, UnlockedSession};

    #[test]
    fn enrollment_is_planned_then_committed_atomically() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["db", "prod", "app"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"password",
        )
        .unwrap();
        let candidate_identity = Identity::generate(&fixture.crypto).unwrap();
        let locked = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let root = locked.effective().root_user_id.clone().unwrap();
        let trusted_root = locked
            .effective()
            .root_signing_public_key_hash
            .clone()
            .unwrap();
        let candidate = create_join_candidate(
            &fixture.crypto,
            &candidate_identity,
            JoinPurposeV1::Enroll,
            vec![9; 32],
            trusted_root,
            root,
            DeploymentContextV1 {
                namespace: "db".into(),
                vault_name: "payments".into(),
                vault_uid: "uid".into(),
            },
            vec![selector.clone()],
        )
        .unwrap();
        let mut admin =
            UnlockedSession::with_identity(locked, &fixture.crypto, fixture.root.clone()).unwrap();
        let plan = admin
            .plan_join_approval(
                &fixture.crypto,
                &candidate,
                vec![GrantPermissionV1::ReadKeyspace(
                    thorax_core::KeyspaceSelectorV1::exact(["db", "prod", "app"]),
                )],
                None,
            )
            .unwrap();
        assert!(get_secret(
            &fixture.paths,
            &fixture.crypto,
            &candidate_identity,
            selector.clone()
        )
        .is_err());
        let baseline = open_join_baseline(
            &fixture.crypto,
            &candidate_identity,
            &candidate,
            plan.approval(),
        )
        .unwrap();
        assert!(!baseline.records.is_empty());
        commit_join_approval_plan(&fixture.paths, plan).unwrap();
        assert_eq!(
            get_secret(
                &fixture.paths,
                &fixture.crypto,
                &candidate_identity,
                selector
            )
            .unwrap()
            .plaintext
            .as_slice(),
            b"password"
        );
    }

    #[test]
    fn prepared_enrollment_recovers_after_ratchet_only_crash() {
        let fixture = ProductionFixture::initialized();
        let candidate_identity = Identity::generate(&fixture.crypto).unwrap();
        let locked = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let trusted_root = locked
            .effective()
            .root_signing_public_key_hash
            .clone()
            .unwrap();
        let candidate = create_join_candidate(
            &fixture.crypto,
            &candidate_identity,
            JoinPurposeV1::Enroll,
            vec![7; 32],
            trusted_root.clone(),
            locked.effective().root_user_id.clone().unwrap(),
            DeploymentContextV1 {
                namespace: "test".into(),
                vault_name: "payments".into(),
                vault_uid: "uid".into(),
            },
            Vec::new(),
        )
        .unwrap();
        let mut admin =
            UnlockedSession::with_identity(locked, &fixture.crypto, fixture.root.clone()).unwrap();
        let plan = admin
            .plan_join_approval(&fixture.crypto, &candidate, Vec::new(), None)
            .unwrap();
        let journal = JoinCommitJournalV1 {
            trusted_root: trusted_root.clone(),
            expected_vault_hash: fixture
                .crypto
                .hash(JOIN_COMMIT_HASH_DOMAIN, &plan.expected_vault_bytes),
            expected_ratchet_hash: fixture.crypto.hash(
                JOIN_COMMIT_HASH_DOMAIN,
                &encode_ratchet(&plan.expected_ratchet).unwrap(),
            ),
            next_vault_bytes: plan.next_vault_bytes.clone(),
            next_ratchet_bytes: encode_ratchet(&plan.next_ratchet).unwrap(),
        };
        write_join_commit_journal(&fixture.paths, &journal).unwrap();
        write_ratchet_atomic(&fixture.paths, &plan.next_ratchet).unwrap();

        let recovered = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        assert!(recovered.effective().users.contains_key(&candidate.user_id));
        assert!(!join_commit_path(&fixture.paths, &trusted_root).exists());
        assert_eq!(
            read_vault_bytes(&fixture.paths).unwrap(),
            plan.next_vault_bytes
        );
    }

    #[test]
    fn candidate_proof_binds_deployment_context() {
        let fixture = ProductionFixture::initialized();
        let locked = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let identity = Identity::generate(&fixture.crypto).unwrap();
        let mut candidate = create_join_candidate(
            &fixture.crypto,
            &identity,
            JoinPurposeV1::Enroll,
            vec![1; 32],
            locked
                .effective()
                .root_signing_public_key_hash
                .clone()
                .unwrap(),
            locked.effective().root_user_id.clone().unwrap(),
            DeploymentContextV1 {
                namespace: "db".into(),
                vault_name: "payments".into(),
                vault_uid: "uid".into(),
            },
            Vec::new(),
        )
        .unwrap();
        candidate.deployment.namespace = "other".into();
        assert!(validate_join_candidate(&fixture.crypto, &candidate).is_err());
    }

    #[test]
    fn restore_trust_approval_is_baseline_only_and_never_mutates_the_vault() {
        let fixture = ProductionFixture::initialized();
        let locked = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let candidate = create_join_candidate(
            &fixture.crypto,
            &fixture.root,
            JoinPurposeV1::RestoreTrust,
            vec![4; 32],
            locked
                .effective()
                .root_signing_public_key_hash
                .clone()
                .unwrap(),
            locked.effective().root_user_id.clone().unwrap(),
            DeploymentContextV1 {
                namespace: "db".into(),
                vault_name: "payments".into(),
                vault_uid: "uid".into(),
            },
            Vec::new(),
        )
        .unwrap();
        let before = thorax_store::read_vault_bytes(&fixture.paths).unwrap();
        let mut admin =
            UnlockedSession::with_identity(locked, &fixture.crypto, fixture.root.clone()).unwrap();
        assert!(admin
            .plan_join_approval(
                &fixture.crypto,
                &candidate,
                vec![GrantPermissionV1::ReadKeyspace(
                    thorax_core::KeyspaceSelectorV1::all(),
                )],
                None,
            )
            .is_err());
        let plan = admin
            .plan_join_approval(&fixture.crypto, &candidate, Vec::new(), None)
            .unwrap();
        assert!(!plan.has_vault_mutation());
        open_join_baseline(&fixture.crypto, &fixture.root, &candidate, plan.approval()).unwrap();
        commit_join_approval_plan(&fixture.paths, plan).unwrap();
        assert_eq!(
            before,
            thorax_store::read_vault_bytes(&fixture.paths).unwrap()
        );
    }
}
