use std::collections::BTreeMap;

use k8s_openapi::{
    api::core::v1::Secret,
    apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference},
    ByteString,
};
use kube::{
    api::{Api, PostParams},
    Client,
};
use thorax_core::{HashValue, Ratchet, UserId};
use thorax_crypto::{ratchet_mac, verify_ratchet_mac, Identity};
use thorax_store::{RatchetBackend, RatchetCasOutcome, RatchetSnapshot};
use zeroize::Zeroize;

const RATCHET_KEY: &str = "ratchet.cord";
const MAC_KEY: &str = "ratchet.mac";
const ROOT_KEY: &str = "trusted-root";
const USER_KEY: &str = "user-id";

#[derive(Debug, thiserror::Error)]
pub enum RatchetStateError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("ratchet state is missing data key {0}")]
    MissingKey(&'static str),
    #[error("ratchet state scope does not match the requested root and identity")]
    ScopeMismatch,
    #[error("ratchet state is invalid: {0}")]
    Store(#[from] thorax_store::StoreError),
    #[error("ratchet state authentication failed")]
    Authentication,
    #[error("ratchet state is not owned by the expected ThoraxVault or has an invalid shape")]
    InvalidShape,
}

#[derive(Clone)]
pub struct KubernetesRatchetBackend {
    client: Client,
    namespace: String,
}

#[derive(Clone)]
pub struct KubernetesRatchetCredential {
    pub identity: Identity,
    pub owner_references: Vec<OwnerReference>,
}

struct SensitiveSecret(Secret);

impl Drop for SensitiveSecret {
    fn drop(&mut self) {
        if let Some(data) = self.0.data.as_mut() {
            for value in data.values_mut() {
                value.0.zeroize();
            }
        }
        if let Some(data) = self.0.string_data.as_mut() {
            for value in data.values_mut() {
                value.zeroize();
            }
        }
    }
}

impl KubernetesRatchetBackend {
    pub fn new(client: Client, namespace: impl Into<String>) -> Self {
        Self {
            client,
            namespace: namespace.into(),
        }
    }

    pub async fn load(
        &self,
        identity: &Identity,
        trusted_root: &HashValue,
        owner_references: &[OwnerReference],
    ) -> Result<Option<(Ratchet, String)>, RatchetStateError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &self.namespace);
        let name = ratchet_secret_name(trusted_root, identity.user_id());
        let Some(metadata) = api.get_metadata_opt(&name).await? else {
            return Ok(None);
        };
        validate_metadata(&metadata.metadata, owner_references)?;
        let secret = SensitiveSecret(api.get(&name).await?);
        validate_metadata(&secret.0.metadata, owner_references)?;
        if secret.0.type_.as_deref() != Some("Opaque") || secret.0.immutable == Some(true) {
            return Err(RatchetStateError::InvalidShape);
        }
        let revision = secret
            .0
            .metadata
            .resource_version
            .clone()
            .ok_or(RatchetStateError::MissingKey("metadata.resourceVersion"))?;
        let ratchet = decode_secret(&secret.0, identity, trusted_root)?;
        Ok(Some((ratchet, revision)))
    }

    pub async fn get_revision(
        &self,
        identity: &Identity,
        trusted_root: &HashValue,
        owner_references: &[OwnerReference],
    ) -> Result<Option<String>, RatchetStateError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &self.namespace);
        let Some(metadata) = api
            .get_metadata_opt(&ratchet_secret_name(trusted_root, identity.user_id()))
            .await?
        else {
            return Ok(None);
        };
        validate_metadata(&metadata.metadata, owner_references)?;
        Ok(Some(metadata.metadata.resource_version.ok_or(
            RatchetStateError::MissingKey("metadata.resourceVersion"),
        )?))
    }

    pub async fn save(
        &self,
        identity: &Identity,
        ratchet: &Ratchet,
        owner_references: Vec<OwnerReference>,
        previous_revision: Option<&str>,
    ) -> Result<String, RatchetStateError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &self.namespace);
        let name = ratchet_secret_name(&ratchet.trusted_root, identity.user_id());
        let mut secret = encode_secret(&name, identity, ratchet)?;
        secret.metadata.owner_references = Some(owner_references);
        let stored = if let Some(previous_revision) = previous_revision {
            // Ratchet Secrets are mutable only through resourceVersion CAS. Their payload
            // is authenticated; Kubernetes `immutable` would prevent monotone raises.
            secret.metadata.resource_version = Some(previous_revision.into());
            api.replace(&name, &PostParams::default(), &secret).await?
        } else {
            api.create(&PostParams::default(), &secret).await?
        };
        let stored = SensitiveSecret(stored);
        stored
            .0
            .metadata
            .resource_version
            .clone()
            .ok_or(RatchetStateError::MissingKey("metadata.resourceVersion"))
    }
}

impl RatchetBackend for KubernetesRatchetBackend {
    type Credential = KubernetesRatchetCredential;
    type Revision = String;
    type Error = RatchetStateError;

    async fn load(
        &self,
        trusted_root: &HashValue,
        user_id: &UserId,
        credential: &Self::Credential,
    ) -> Result<Option<RatchetSnapshot<Self::Revision>>, Self::Error> {
        if credential.identity.user_id() != user_id {
            return Err(RatchetStateError::ScopeMismatch);
        }
        let Some((ratchet, revision)) = KubernetesRatchetBackend::load(
            self,
            &credential.identity,
            trusted_root,
            &credential.owner_references,
        )
        .await?
        else {
            return Ok(None);
        };
        Ok(Some(RatchetSnapshot { ratchet, revision }))
    }

    async fn compare_and_swap(
        &self,
        trusted_root: &HashValue,
        user_id: &UserId,
        credential: &Self::Credential,
        expected_revision: Option<&Self::Revision>,
        ratchet: &Ratchet,
    ) -> Result<RatchetCasOutcome<Self::Revision>, Self::Error> {
        if credential.identity.user_id() != user_id || &ratchet.trusted_root != trusted_root {
            return Err(RatchetStateError::ScopeMismatch);
        }
        let previous_revision = self
            .get_revision(
                &credential.identity,
                trusted_root,
                &credential.owner_references,
            )
            .await?;
        match (expected_revision, previous_revision.as_ref()) {
            (None, None) => {}
            (Some(expected), Some(previous)) if previous == expected => {}
            _ => return Ok(RatchetCasOutcome::Conflict),
        }
        match self
            .save(
                &credential.identity,
                ratchet,
                credential.owner_references.clone(),
                previous_revision.as_deref(),
            )
            .await
        {
            Ok(revision) => Ok(RatchetCasOutcome::Stored(RatchetSnapshot {
                ratchet: ratchet.clone(),
                revision,
            })),
            Err(RatchetStateError::Kube(kube::Error::Api(response))) if response.code == 409 => {
                Ok(RatchetCasOutcome::Conflict)
            }
            Err(error) => Err(error),
        }
    }
}

fn validate_metadata(
    metadata: &ObjectMeta,
    expected_owner_references: &[OwnerReference],
) -> Result<(), RatchetStateError> {
    let expected_uids = expected_owner_references
        .iter()
        .filter(|owner| owner.controller == Some(true))
        .map(|owner| owner.uid.as_str())
        .collect::<Vec<_>>();
    let owned = metadata.owner_references.as_ref().is_some_and(|owners| {
        owners.iter().any(|owner| {
            owner.controller == Some(true) && expected_uids.contains(&owner.uid.as_str())
        })
    });
    let labeled = metadata.labels.as_ref().is_some_and(|labels| {
        labels
            .get("thorax.backbone.dev/component")
            .map(String::as_str)
            == Some("ratchet")
    });
    if !owned || !labeled {
        return Err(RatchetStateError::InvalidShape);
    }
    Ok(())
}

pub fn ratchet_secret_name(trusted_root: &HashValue, user_id: &UserId) -> String {
    format!(
        "thorax-ratchet-{}-{}",
        short_hex(&trusted_root.0),
        short_hex(&(user_id.0).0)
    )
}

fn encode_secret(
    name: &str,
    identity: &Identity,
    ratchet: &Ratchet,
) -> Result<Secret, RatchetStateError> {
    let ratchet_bytes = thorax_store::encode_ratchet(ratchet)?;
    let mac = ratchet_mac(
        identity,
        &ratchet.trusted_root,
        identity.user_id(),
        &ratchet_bytes,
    )
    .map_err(|_| RatchetStateError::Authentication)?;
    Ok(Secret {
        metadata: kube::core::ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(BTreeMap::from([
                (
                    "app.kubernetes.io/managed-by".into(),
                    "thorax-kubernetes-controller".into(),
                ),
                ("thorax.backbone.dev/component".into(), "ratchet".into()),
            ])),
            ..Default::default()
        },
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([
            (RATCHET_KEY.into(), ByteString(ratchet_bytes)),
            (MAC_KEY.into(), ByteString(mac)),
            (ROOT_KEY.into(), ByteString(ratchet.trusted_root.0.clone())),
            (
                USER_KEY.into(),
                ByteString((identity.user_id().0).0.clone()),
            ),
        ])),
        ..Default::default()
    })
}

fn decode_secret(
    secret: &Secret,
    identity: &Identity,
    trusted_root: &HashValue,
) -> Result<Ratchet, RatchetStateError> {
    let data = secret
        .data
        .as_ref()
        .ok_or(RatchetStateError::MissingKey(RATCHET_KEY))?;
    let ratchet_bytes = &data
        .get(RATCHET_KEY)
        .ok_or(RatchetStateError::MissingKey(RATCHET_KEY))?
        .0;
    let mac = &data
        .get(MAC_KEY)
        .ok_or(RatchetStateError::MissingKey(MAC_KEY))?
        .0;
    let root = &data
        .get(ROOT_KEY)
        .ok_or(RatchetStateError::MissingKey(ROOT_KEY))?
        .0;
    let user = &data
        .get(USER_KEY)
        .ok_or(RatchetStateError::MissingKey(USER_KEY))?
        .0;
    if root != &trusted_root.0 || user != &(identity.user_id().0).0 {
        return Err(RatchetStateError::ScopeMismatch);
    }
    verify_ratchet_mac(
        identity,
        trusted_root,
        identity.user_id(),
        ratchet_bytes,
        mac,
    )
    .map_err(|_| RatchetStateError::Authentication)?;
    let ratchet = thorax_store::decode_ratchet("kubernetes-secret", ratchet_bytes)?;
    if &ratchet.trusted_root != trusted_root {
        return Err(RatchetStateError::ScopeMismatch);
    }
    Ok(ratchet)
}

fn short_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use thorax_crypto::Crypto;

    #[test]
    fn state_secret_round_trips_and_detects_tampering() {
        let crypto = Crypto;
        let identity = Identity::generate(&crypto).unwrap();
        let root = HashValue(vec![7; 32]);
        let ratchet = Ratchet::new(root.clone());
        let mut secret = encode_secret("ratchet", &identity, &ratchet).unwrap();
        assert_eq!(decode_secret(&secret, &identity, &root).unwrap(), ratchet);
        secret
            .data
            .as_mut()
            .unwrap()
            .get_mut(RATCHET_KEY)
            .unwrap()
            .0
            .push(0);
        assert!(matches!(
            decode_secret(&secret, &identity, &root),
            Err(RatchetStateError::Authentication)
        ));
    }

    #[test]
    fn object_name_is_scoped_by_root_and_user() {
        let user = UserId(HashValue(vec![2; 32]));
        assert_ne!(
            ratchet_secret_name(&HashValue(vec![1; 32]), &user),
            ratchet_secret_name(&HashValue(vec![3; 32]), &user)
        );
    }
}
