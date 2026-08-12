use std::{collections::BTreeMap, ops::Deref};

use k8s_openapi::ByteString;
use thorax_crypto::{Crypto, Identity};
use thorax_kubernetes_api::ThoraxSecretSpec;
use thorax_ops::{LockedSession, Ratchet, SecretState, UnlockedSession, WorkspacePaths};
use zeroize::Zeroize;

// Kubernetes rejects Secrets whose decoded data exceeds one MiB. Enforce the same
// ceiling before constructing an API object so oversized projections fail closed and
// never leave a previous value looking successfully refreshed.
const MAX_PROJECTED_SECRET_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum RuntimeVaultError {
    #[error("Thorax operation failed: {0}")]
    Ops(#[from] thorax_ops::OpsError),
    #[error("Thorax store failed: {0}")]
    Store(#[from] thorax_store::StoreError),
    #[error("invalid Thorax selector {selector}: {message}")]
    InvalidSelector { selector: String, message: String },
    #[error("Thorax selector {selector} has no field {field}")]
    MissingField { selector: String, field: String },
    #[error("selector is outside the identity's effective read authority")]
    NotAuthorized,
    #[error("selector is authorized but has no recipient slot")]
    RecipientUnavailable,
    #[error("selector is conflicted")]
    Conflicted,
    #[error("selector is absent")]
    SourceMissing,
    #[error("all mapped sources are authenticated deletions")]
    AllSourcesDeleted,
    #[error("only some mapped sources are authenticated deletions")]
    SourcesPartiallyDeleted,
    #[error("selector state is invalid")]
    InvalidSource,
    #[error("projected Secret data exceeds the 1 MiB Kubernetes limit")]
    ProjectionTooLarge,
}

/// Secret material prepared for a single Kubernetes write. The wrapper deliberately
/// does not expose an ownership-consuming conversion: any bytes not transferred into a
/// separately guarded Kubernetes object are wiped on every return path.
pub struct ProjectedData(BTreeMap<String, ByteString>);

impl ProjectedData {
    pub(crate) fn take(&mut self) -> BTreeMap<String, ByteString> {
        std::mem::take(&mut self.0)
    }
}

impl Deref for ProjectedData {
    type Target = BTreeMap<String, ByteString>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ProjectedData {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.0.zeroize();
        }
    }
}

pub struct RuntimeVault {
    _temp: tempfile::TempDir,
    crypto: Crypto,
    session: UnlockedSession,
}

impl RuntimeVault {
    pub fn load(
        vault_bytes: &[u8],
        ratchet: &Ratchet,
        identity: Identity,
    ) -> Result<Self, RuntimeVaultError> {
        let temp = tempfile::tempdir().map_err(|source| thorax_store::StoreError::Io {
            path: std::env::temp_dir(),
            source,
        })?;
        let vault_path = temp.path().join(".thorax").join("vault.cord");
        let paths =
            WorkspacePaths::from_vault_path(vault_path).with_state_dir(temp.path().join("state"));
        thorax_store::write_ratchet_atomic(&paths, ratchet)?;
        thorax_store::write_vault_bytes_atomic(&paths, vault_bytes)?;
        let crypto = Crypto;
        let locked = LockedSession::load(&paths, &crypto)?;
        let session = UnlockedSession::with_identity(locked, &crypto, identity)?;
        Ok(Self {
            _temp: temp,
            crypto,
            session,
        })
    }

    pub fn value(&self, selector: &str, field: Option<&str>) -> Result<Vec<u8>, RuntimeVaultError> {
        let parsed = self.parse_selector(selector)?;
        let plaintext = self.session.get_secret(&self.crypto, parsed)?;
        match field {
            None => Ok(plaintext.plaintext.to_vec()),
            Some(field) => plaintext
                .field(field)
                .map(|entry| entry.value.to_vec())
                .ok_or_else(|| RuntimeVaultError::MissingField {
                    selector: selector.to_string(),
                    field: field.to_string(),
                }),
        }
    }

    fn parse_selector(
        &self,
        selector: &str,
    ) -> Result<thorax_ops::SecretSelectorV1, RuntimeVaultError> {
        thorax_frontend::parse_secret_selector(selector).map_err(|error| {
            RuntimeVaultError::InvalidSelector {
                selector: selector.to_string(),
                message: error.to_string(),
            }
        })
    }

    fn source_state(&self, selector: &str) -> Result<ProjectionSourceState, RuntimeVaultError> {
        let parsed = self.parse_selector(selector)?;
        if !self
            .session
            .effective()
            .authority_for_user(self.session.user_id())
            .can_read(&parsed)
        {
            return Ok(ProjectionSourceState::NotAuthorized);
        }
        Ok(
            match self.session.effective().classify_secret_for_user(
                &parsed,
                self.session.user_id(),
                &self.crypto,
            ) {
                SecretState::ActiveDecryptable => ProjectionSourceState::Active,
                SecretState::NotEncryptedForReader => ProjectionSourceState::RecipientUnavailable,
                SecretState::Unauthorized => ProjectionSourceState::NotAuthorized,
                SecretState::Missing => {
                    if self
                        .session
                        .effective()
                        .secret_is_deleted(&parsed, &self.crypto)
                        .map_err(|_| RuntimeVaultError::InvalidSource)?
                    {
                        ProjectionSourceState::Deleted
                    } else {
                        ProjectionSourceState::Missing
                    }
                }
                SecretState::Conflicted => ProjectionSourceState::Conflicted,
                SecretState::Invalid => ProjectionSourceState::Invalid,
            },
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProjectionSourceState {
    Active,
    Deleted,
    Missing,
    NotAuthorized,
    RecipientUnavailable,
    Conflicted,
    Invalid,
}

pub fn project_data(
    runtime: &RuntimeVault,
    spec: &ThoraxSecretSpec,
) -> Result<ProjectedData, RuntimeVaultError> {
    let states = spec
        .data
        .values()
        .map(|mapping| runtime.source_state(&mapping.selector))
        .collect::<Result<Vec<_>, _>>()?;
    let deleted = states
        .iter()
        .filter(|state| **state == ProjectionSourceState::Deleted)
        .count();
    if deleted == states.len() {
        return Err(RuntimeVaultError::AllSourcesDeleted);
    }
    if deleted > 0 {
        return Err(RuntimeVaultError::SourcesPartiallyDeleted);
    }
    for state in states {
        match state {
            ProjectionSourceState::Active => {}
            ProjectionSourceState::Missing => return Err(RuntimeVaultError::SourceMissing),
            ProjectionSourceState::NotAuthorized => return Err(RuntimeVaultError::NotAuthorized),
            ProjectionSourceState::RecipientUnavailable => {
                return Err(RuntimeVaultError::RecipientUnavailable)
            }
            ProjectionSourceState::Conflicted => return Err(RuntimeVaultError::Conflicted),
            ProjectionSourceState::Invalid => return Err(RuntimeVaultError::InvalidSource),
            ProjectionSourceState::Deleted => unreachable!("handled as an aggregate above"),
        }
    }
    let mut output = BTreeMap::new();
    let mut total_bytes = 0usize;
    for (key, mapping) in &spec.data {
        let mut value = runtime.value(&mapping.selector, mapping.field.as_deref())?;
        total_bytes = total_bytes
            .checked_add(key.len())
            .and_then(|total| total.checked_add(value.len()))
            .ok_or(RuntimeVaultError::ProjectionTooLarge)?;
        if total_bytes > MAX_PROJECTED_SECRET_BYTES {
            value.zeroize();
            for existing in output.values_mut() {
                let ByteString(bytes) = existing;
                bytes.zeroize();
            }
            return Err(RuntimeVaultError::ProjectionTooLarge);
        }
        output.insert(key.clone(), ByteString(value));
    }
    Ok(ProjectedData(output))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use thorax_kubernetes_api::{
        LocalObjectReference, ProjectionPolicy, SecretMapping, SecretTemplate,
        SecretTemplateMetadata,
    };
    use thorax_ops::{init_vault, SecretSelectorV1};

    #[test]
    fn projection_is_all_or_nothing_and_preserves_binary_values() {
        let temp = tempfile::tempdir().unwrap();
        let paths =
            WorkspacePaths::from_root(temp.path()).with_state_dir(temp.path().join("state"));
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let locked = LockedSession::load(&paths, &crypto).unwrap();
        let mut unlocked = UnlockedSession::with_identity(locked, &crypto, root.clone()).unwrap();
        let selector = SecretSelectorV1::tuple(["app", "binary"]);
        unlocked
            .set_secret(&crypto, selector, &[0, 255, 1])
            .unwrap();
        let vault_bytes = thorax_store::read_vault_bytes(&paths).unwrap();
        let ratchet = thorax_store::read_ratchet_for_root(
            &paths,
            unlocked
                .effective()
                .root_signing_public_key_hash
                .as_ref()
                .unwrap(),
        )
        .unwrap()
        .unwrap();
        let runtime = RuntimeVault::load(&vault_bytes, &ratchet, root).unwrap();
        let spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "vault".into(),
            },
            data: BTreeMap::from([(
                "payload".into(),
                SecretMapping {
                    selector: "app/binary".into(),
                    field: None,
                },
            )]),
            template: SecretTemplate {
                secret_type: "Opaque".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        assert_eq!(
            project_data(&runtime, &spec).unwrap()["payload"].0,
            vec![0, 255, 1]
        );

        let mut broken = spec;
        broken.data.insert(
            "missing".into(),
            SecretMapping {
                selector: "app/missing".into(),
                field: None,
            },
        );
        assert!(project_data(&runtime, &broken).is_err());
    }

    #[test]
    fn oversized_projection_fails_before_a_kubernetes_object_is_built() {
        let temp = tempfile::tempdir().unwrap();
        let paths =
            WorkspacePaths::from_root(temp.path()).with_state_dir(temp.path().join("state"));
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let locked = LockedSession::load(&paths, &crypto).unwrap();
        let mut unlocked = UnlockedSession::with_identity(locked, &crypto, root.clone()).unwrap();
        unlocked
            .set_secret(
                &crypto,
                SecretSelectorV1::tuple(["app", "oversized"]),
                &vec![7; MAX_PROJECTED_SECRET_BYTES + 1],
            )
            .unwrap();

        let spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "vault".into(),
            },
            data: BTreeMap::from([(
                "payload".into(),
                SecretMapping {
                    selector: "app/oversized".into(),
                    field: None,
                },
            )]),
            template: SecretTemplate {
                secret_type: "Opaque".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        let runtime = runtime_from(&paths, &crypto, root);
        assert!(matches!(
            project_data(&runtime, &spec),
            Err(RuntimeVaultError::ProjectionTooLarge)
        ));
    }

    #[test]
    fn authenticated_deletions_are_distinct_from_partial_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let paths =
            WorkspacePaths::from_root(temp.path()).with_state_dir(temp.path().join("state"));
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        let locked = LockedSession::load(&paths, &crypto).unwrap();
        let mut unlocked = UnlockedSession::with_identity(locked, &crypto, root.clone()).unwrap();
        let first = SecretSelectorV1::tuple(["app", "first"]);
        let second = SecretSelectorV1::tuple(["app", "second"]);
        unlocked.set_secret(&crypto, first.clone(), b"one").unwrap();
        unlocked
            .set_secret(&crypto, second.clone(), b"two")
            .unwrap();
        unlocked.delete_secret(&crypto, second.clone()).unwrap();

        let spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "vault".into(),
            },
            data: BTreeMap::from([
                (
                    "first".into(),
                    SecretMapping {
                        selector: "app/first".into(),
                        field: None,
                    },
                ),
                (
                    "second".into(),
                    SecretMapping {
                        selector: "app/second".into(),
                        field: None,
                    },
                ),
            ]),
            template: SecretTemplate {
                secret_type: "Opaque".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        let runtime = runtime_from(&paths, &crypto, root.clone());
        assert!(matches!(
            project_data(&runtime, &spec),
            Err(RuntimeVaultError::SourcesPartiallyDeleted)
        ));
        drop(runtime);

        unlocked.delete_secret(&crypto, first).unwrap();
        let runtime = runtime_from(&paths, &crypto, root);
        assert!(matches!(
            project_data(&runtime, &spec),
            Err(RuntimeVaultError::AllSourcesDeleted)
        ));
    }

    fn runtime_from(paths: &WorkspacePaths, crypto: &Crypto, identity: Identity) -> RuntimeVault {
        let vault_bytes = thorax_store::read_vault_bytes(paths).unwrap();
        let root = thorax_ops::trusted_root_candidate(
            &thorax_core::decode_vault(&vault_bytes).unwrap(),
            crypto,
        )
        .unwrap();
        let ratchet = thorax_store::read_ratchet_for_root(paths, &root)
            .unwrap()
            .unwrap();
        RuntimeVault::load(&vault_bytes, &ratchet, identity).unwrap()
    }
}
