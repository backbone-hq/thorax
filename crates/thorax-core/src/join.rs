//! Transport-neutral wire artifacts for externally generated Thorax identities.

use cord::Cord;

use crate::{
    Bytes, GrantPermissionV1, HashValue, RatchetBaselineV1, SecretSelectorV1, UserId, VaultRecordV1,
};

pub const JOIN_CANDIDATE_PROOF_DOMAIN: &str = "thorax.join-candidate-proof.v1";
pub const JOIN_APPROVAL_SIGNATURE_DOMAIN: &str = "thorax.join-approval.v1";
const JOIN_CANDIDATE_MAGIC: &[u8] = b"thorax-join-candidate\0";
const JOIN_APPROVAL_MAGIC: &[u8] = b"thorax-join-approval\0";
const MAX_JOIN_ARTIFACT_BYTES: usize = 1024 * 1024;

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub enum JoinPurposeV1 {
    #[cord(index = 0)]
    Enroll,
    #[cord(index = 1)]
    RestoreTrust,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct DeploymentContextV1 {
    pub namespace: String,
    pub vault_name: String,
    pub vault_uid: String,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub enum JoinCandidateStore {
    #[cord(index = 0)]
    V1(JoinCandidateV1),
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct JoinCandidateV1 {
    pub purpose: JoinPurposeV1,
    pub request_id: Bytes,
    pub trusted_root: HashValue,
    pub trusted_root_user_id: UserId,
    pub deployment: DeploymentContextV1,
    pub user_id: UserId,
    pub signing_public_key: Bytes,
    pub hpke_public_key: Bytes,
    pub suggested_selectors: Vec<SecretSelectorV1>,
    pub entry_point: Option<VaultRecordV1>,
    pub proof: Bytes,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct JoinCandidateMessageV1 {
    pub purpose: JoinPurposeV1,
    pub request_id: Bytes,
    pub trusted_root: HashValue,
    pub trusted_root_user_id: UserId,
    pub deployment: DeploymentContextV1,
    pub user_id: UserId,
    pub signing_public_key: Bytes,
    pub hpke_public_key: Bytes,
    pub suggested_selectors: Vec<SecretSelectorV1>,
    pub entry_point: Option<VaultRecordV1>,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub enum JoinApprovalStore {
    #[cord(index = 0)]
    V1(JoinApprovalV1),
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct JoinApprovalV1 {
    pub purpose: JoinPurposeV1,
    pub request_id: Bytes,
    pub trusted_root: HashValue,
    pub deployment: DeploymentContextV1,
    pub user_id: UserId,
    pub approved_grants: Vec<GrantPermissionV1>,
    pub encrypted_baseline: EncryptedBaselineV1,
    pub replaces_user_id: Option<UserId>,
    pub approving_admin: UserId,
    pub approving_signing_public_key: Bytes,
    pub signature: Bytes,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct JoinApprovalMessageV1 {
    pub purpose: JoinPurposeV1,
    pub request_id: Bytes,
    pub trusted_root: HashValue,
    pub deployment: DeploymentContextV1,
    pub user_id: UserId,
    pub approved_grants: Vec<GrantPermissionV1>,
    pub encrypted_baseline: EncryptedBaselineV1,
    pub replaces_user_id: Option<UserId>,
    pub approving_admin: UserId,
    pub approving_signing_public_key: Bytes,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct EncryptedBaselineV1 {
    pub encapsulated_key: Bytes,
    pub ciphertext: Bytes,
}

impl JoinCandidateV1 {
    pub fn message(&self) -> JoinCandidateMessageV1 {
        JoinCandidateMessageV1 {
            purpose: self.purpose.clone(),
            request_id: self.request_id.clone(),
            trusted_root: self.trusted_root.clone(),
            trusted_root_user_id: self.trusted_root_user_id.clone(),
            deployment: self.deployment.clone(),
            user_id: self.user_id.clone(),
            signing_public_key: self.signing_public_key.clone(),
            hpke_public_key: self.hpke_public_key.clone(),
            suggested_selectors: self.suggested_selectors.clone(),
            entry_point: self.entry_point.clone(),
        }
    }
}

impl JoinApprovalV1 {
    pub fn message(&self) -> JoinApprovalMessageV1 {
        JoinApprovalMessageV1 {
            purpose: self.purpose.clone(),
            request_id: self.request_id.clone(),
            trusted_root: self.trusted_root.clone(),
            deployment: self.deployment.clone(),
            user_id: self.user_id.clone(),
            approved_grants: self.approved_grants.clone(),
            encrypted_baseline: self.encrypted_baseline.clone(),
            replaces_user_id: self.replaces_user_id.clone(),
            approving_admin: self.approving_admin.clone(),
            approving_signing_public_key: self.approving_signing_public_key.clone(),
        }
    }
}

pub fn encode_join_candidate(candidate: &JoinCandidateV1) -> crate::Result<Bytes> {
    encode_artifact(
        JOIN_CANDIDATE_MAGIC,
        &JoinCandidateStore::V1(candidate.clone()),
    )
}

pub fn decode_join_candidate(bytes: &[u8]) -> crate::Result<JoinCandidateV1> {
    let payload = artifact_payload(JOIN_CANDIDATE_MAGIC, bytes)?;
    match cord::deserialize(payload)? {
        JoinCandidateStore::V1(candidate) => Ok(candidate),
    }
}

pub fn encode_join_approval(approval: &JoinApprovalV1) -> crate::Result<Bytes> {
    encode_artifact(
        JOIN_APPROVAL_MAGIC,
        &JoinApprovalStore::V1(approval.clone()),
    )
}

pub fn decode_join_approval(bytes: &[u8]) -> crate::Result<JoinApprovalV1> {
    let payload = artifact_payload(JOIN_APPROVAL_MAGIC, bytes)?;
    match cord::deserialize(payload)? {
        JoinApprovalStore::V1(approval) => Ok(approval),
    }
}

pub fn join_candidate_message(candidate: &JoinCandidateV1) -> crate::Result<Bytes> {
    Ok(cord::serialize(&candidate.message())?)
}

pub fn join_approval_message(approval: &JoinApprovalV1) -> crate::Result<Bytes> {
    Ok(cord::serialize(&approval.message())?)
}

pub fn baseline_bytes(baseline: &RatchetBaselineV1) -> crate::Result<Bytes> {
    Ok(cord::serialize(baseline)?)
}

pub fn baseline_from_bytes(bytes: &[u8]) -> crate::Result<RatchetBaselineV1> {
    Ok(cord::deserialize(bytes)?)
}

fn encode_artifact(value_magic: &[u8], value: &impl serde::Serialize) -> crate::Result<Bytes> {
    let payload = cord::serialize(value)?;
    if payload.len() > MAX_JOIN_ARTIFACT_BYTES {
        return Err(crate::CoreError::Validation(
            "join artifact exceeds the 1 MiB limit".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(value_magic.len() + payload.len());
    bytes.extend_from_slice(value_magic);
    bytes.extend(payload);
    Ok(bytes)
}

fn artifact_payload<'a>(value_magic: &[u8], bytes: &'a [u8]) -> crate::Result<&'a [u8]> {
    if bytes.len() > MAX_JOIN_ARTIFACT_BYTES + value_magic.len() {
        return Err(crate::CoreError::Validation(
            "join artifact exceeds the 1 MiB limit".into(),
        ));
    }
    bytes.strip_prefix(value_magic).ok_or_else(|| {
        crate::CoreError::Validation("join artifact has an invalid magic prefix".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate() -> JoinCandidateV1 {
        JoinCandidateV1 {
            purpose: JoinPurposeV1::Enroll,
            request_id: vec![1; 32],
            trusted_root: HashValue(vec![2; 32]),
            trusted_root_user_id: UserId(HashValue(vec![3; 32])),
            deployment: DeploymentContextV1 {
                namespace: "db".into(),
                vault_name: "payments".into(),
                vault_uid: "uid".into(),
            },
            user_id: UserId(HashValue(vec![4; 32])),
            signing_public_key: vec![5; 32],
            hpke_public_key: vec![6; 32],
            suggested_selectors: vec![SecretSelectorV1::tuple(["db", "prod"])],
            entry_point: None,
            proof: vec![7; 64],
        }
    }

    #[test]
    fn candidate_round_trips_and_message_excludes_proof() {
        let candidate = candidate();
        assert_eq!(
            decode_join_candidate(&encode_join_candidate(&candidate).unwrap()).unwrap(),
            candidate
        );
        let mut changed = candidate.clone();
        changed.proof[0] ^= 1;
        assert_eq!(
            join_candidate_message(&candidate).unwrap(),
            join_candidate_message(&changed).unwrap()
        );
    }

    #[test]
    fn wrong_magic_is_rejected() {
        assert!(decode_join_candidate(b"not-a-candidate").is_err());
    }
}
