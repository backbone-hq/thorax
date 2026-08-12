use std::{collections::BTreeMap, sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::{
    api::core::v1::{ConfigMap, Secret},
    apimachinery::pkg::apis::meta::v1::{Condition, OwnerReference, Time},
    ByteString,
};
use kube::{
    api::{Api, DeleteParams, ListParams, Patch, PatchParams, PostParams, Preconditions},
    runtime::{
        controller::Action,
        events::{Event, EventType, Recorder},
        watcher, Controller, WatchStreamExt,
    },
    Client, Resource, ResourceExt,
};
use serde_json::json;
use thorax_core::{
    selector_subsumes, CryptoProvider, GrantPermissionV1, HashValue, JoinPurposeV1, Ratchet,
    RatchetRecordV1, RecordBodyV1, UserId, VaultStore,
};
use thorax_crypto::{Crypto, Identity};
use thorax_kubernetes_api::{
    ProjectionPolicy, ThoraxJoinApproval, ThoraxJoinRequest, ThoraxJoinRequestSpec, ThoraxSecret,
    ThoraxSecretStatus, ThoraxVault, ThoraxVaultStatus, MANAGED_LABEL, MAX_VAULT_CONFIGMAP_BYTES,
    OBSERVED_GENERATION_ANNOTATION, VAULT_ANNOTATION, VAULT_REVISION_ANNOTATION,
};
use thorax_ops::{
    create_join_candidate, key_hash, open_join_baseline, trusted_root_candidate,
    validate_approval_bindings, validate_join_candidate,
};

use crate::{
    project_data, KubernetesRatchetBackend, KubernetesRatchetCredential, RatchetStateError,
    RuntimeVault,
};
use thorax_store::{RatchetBackend, RatchetCasOutcome};
use zeroize::Zeroize;

const IDENTITY_KEY: &str = "master-seed";
const STEADY_STATE_REQUEUE: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum ControllerError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("Thorax operation failed: {0}")]
    Ops(#[from] thorax_ops::OpsError),
    #[error("Thorax core failed: {0}")]
    Core(#[from] thorax_core::CoreError),
    #[error("Thorax crypto failed: {0}")]
    Crypto(#[from] thorax_crypto::CryptoError),
    #[error("Kubernetes API object is invalid: {0}")]
    Api(#[from] thorax_kubernetes_api::ApiError),
    #[error("ratchet persistence failed: {0}")]
    Ratchet(#[from] crate::RatchetStateError),
    #[error("runtime vault failed: {0}")]
    Runtime(#[from] crate::RuntimeVaultError),
    #[error("{0}")]
    Invalid(&'static str),
}

#[derive(Clone)]
struct Context {
    client: Client,
    namespace: String,
    crypto: Crypto,
    ratchets: KubernetesRatchetBackend,
    events: Recorder,
}

struct SensitiveSecret(Secret);

impl std::ops::Deref for SensitiveSecret {
    type Target = Secret;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for SensitiveSecret {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for SensitiveSecret {
    fn drop(&mut self) {
        wipe_secret_data(&mut self.0);
    }
}

fn wipe_secret_data(secret: &mut Secret) {
    if let Some(data) = secret.data.as_mut() {
        for value in data.values_mut() {
            value.0.zeroize();
        }
    }
    if let Some(data) = secret.string_data.as_mut() {
        for value in data.values_mut() {
            value.zeroize();
        }
    }
}

pub async fn run(client: Client, namespace: String) -> Result<(), ControllerError> {
    let context = Arc::new(Context {
        ratchets: KubernetesRatchetBackend::new(client.clone(), namespace.clone()),
        client: client.clone(),
        namespace: namespace.clone(),
        crypto: Crypto,
        events: Recorder::new(client.clone(), "thorax-kubernetes-controller".into()),
    });
    let vaults: Api<ThoraxVault> = Api::namespaced(client.clone(), &namespace);
    let join_requests: Api<ThoraxJoinRequest> = Api::namespaced(client.clone(), &namespace);
    let join_approvals: Api<ThoraxJoinApproval> = Api::namespaced(client.clone(), &namespace);
    let secrets: Api<ThoraxSecret> = Api::namespaced(client.clone(), &namespace);
    let watched_vaults: Api<ThoraxVault> = Api::namespaced(client, &namespace);
    let vault_changes = watcher::watcher(watched_vaults, watcher::Config::default())
        .default_backoff()
        .touched_objects()
        .filter_map(|event| futures::future::ready(event.ok().map(|_| ())));
    let vault_controller = Controller::new(vaults, watcher::Config::default())
        .owns(join_requests, watcher::Config::default())
        .owns(join_approvals, watcher::Config::default())
        .run(reconcile_vault, vault_error_policy, context.clone())
        .for_each(|result| async move {
            if let Err(error) = result {
                tracing::error!(%error, "ThoraxVault reconciliation failed");
            }
        });

    let secret_controller = Controller::new(secrets, watcher::Config::default())
        .reconcile_all_on(vault_changes)
        .run(reconcile_secret, secret_error_policy, context)
        .for_each(|result| async move {
            if let Err(error) = result {
                tracing::error!(%error, "ThoraxSecret reconciliation failed");
            }
        });

    futures::future::join(vault_controller, secret_controller).await;
    Ok(())
}

async fn reconcile_vault(
    vault: Arc<ThoraxVault>,
    context: Arc<Context>,
) -> Result<Action, ControllerError> {
    match reconcile_vault_inner(vault.clone(), context.clone()).await {
        Ok(action) => Ok(action),
        Err(error) => {
            let reason = match &error {
                ControllerError::Kube(_) => "ReconcileUnavailable",
                ControllerError::Ratchet(RatchetStateError::Kube(_)) => "TrustStateUnavailable",
                ControllerError::Ratchet(_) => "TrustStateTampered",
                ControllerError::Api(_) => "InvalidSpec",
                ControllerError::Ops(_) | ControllerError::Invalid(_) => "EnrollmentMismatch",
                ControllerError::Core(_)
                | ControllerError::Crypto(_)
                | ControllerError::Runtime(_) => "VaultUnverified",
            };
            tracing::warn!(reason, error = %error, vault = %vault.name_any(), "vault reconciliation failed closed");
            let previous = vault.status.as_ref();
            set_vault_status(
                &context,
                &vault,
                previous.and_then(|status| status.trusted_root.clone()),
                previous.and_then(|status| status.vault_revision.clone()),
                previous.and_then(|status| status.identity_user_id.clone()),
                condition(
                    "Ready",
                    "False",
                    reason,
                    "vault could not be verified; dependent projections are unavailable",
                ),
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_vault_inner(
    vault: Arc<ThoraxVault>,
    context: Arc<Context>,
) -> Result<Action, ControllerError> {
    vault.spec.validate()?;
    let namespace = required_namespace(vault.as_ref())?;
    let uid = required_uid(vault.as_ref())?;
    let owner = owner_reference(vault.as_ref())?;
    let config_maps: Api<ConfigMap> = Api::namespaced(context.client.clone(), &namespace);
    let config_map = match config_maps
        .get_opt(&vault.spec.source.config_map_ref.name)
        .await?
    {
        Some(value) => value,
        None => {
            set_vault_status(
                &context,
                &vault,
                None,
                None,
                None,
                condition(
                    "Ready",
                    "False",
                    "SourceUnavailable",
                    "source ConfigMap is absent",
                ),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    };
    let Some(vault_bytes) = config_map_bytes(&config_map, &vault.spec.source.config_map_ref.key)
    else {
        set_vault_status(
            &context,
            &vault,
            None,
            None,
            None,
            condition(
                "Ready",
                "False",
                "SourceUnavailable",
                "source ConfigMap key is absent or ambiguous",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    };
    if vault_bytes.len() > MAX_VAULT_CONFIGMAP_BYTES {
        set_vault_status(
            &context,
            &vault,
            None,
            None,
            None,
            condition(
                "Ready",
                "False",
                "SourceTooLarge",
                "source vault exceeds the 1 MiB controller limit",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }
    let store = thorax_core::decode_vault(&vault_bytes)?;
    let trusted_root = trusted_root_candidate(&store, &context.crypto)?;
    let trusted_root_user_id = root_user_id(&store, &trusted_root, &context.crypto)?;
    let revision = hex(&context
        .crypto
        .hash("thorax.kubernetes-vault.v1", &vault_bytes)
        .0);

    let identity = match load_or_create_identity(&context, &vault, &owner).await? {
        IdentityOutcome::Ready(identity) => *identity,
        IdentityOutcome::RecoveryRequired => {
            set_vault_status(
                &context,
                &vault,
                Some(hex(&trusted_root.0)),
                Some(revision),
                vault
                    .status
                    .as_ref()
                    .and_then(|status| status.identity_user_id.clone()),
                condition(
                    "Ready",
                    "False",
                    "RecoveryRequired",
                    "previously enrolled identity Secret is absent",
                ),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(300)));
        }
        IdentityOutcome::Unavailable => {
            set_vault_status(
                &context,
                &vault,
                Some(hex(&trusted_root.0)),
                Some(revision),
                None,
                condition(
                    "Ready",
                    "False",
                    "IdentityUnavailable",
                    "managed identity destination is invalid or owned by another object",
                ),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(300)));
        }
    };

    let trust_established = trust_was_established(&vault);
    let ratchet_credential = KubernetesRatchetCredential {
        identity: identity.clone(),
        owner_references: vec![owner.clone()],
    };
    let loaded_ratchet = RatchetBackend::load(
        &context.ratchets,
        &trusted_root,
        identity.user_id(),
        &ratchet_credential,
    )
    .await;
    let trust_state_tampered = loaded_ratchet.is_err();
    match &loaded_ratchet {
        Ok(Some(snapshot)) => {
            return finish_verified_vault(
                &context,
                &vault,
                &store,
                &identity,
                trusted_root,
                revision,
                snapshot.ratchet.clone(),
                Some(snapshot.revision.clone()),
                ratchet_credential,
            )
            .await;
        }
        Err(RatchetStateError::Kube(_)) => {
            set_vault_status(
                &context,
                &vault,
                Some(hex(&trusted_root.0)),
                Some(revision),
                Some(hex(&(identity.user_id().0).0)),
                condition(
                    "Ready",
                    "False",
                    "TrustStateUnavailable",
                    "rollback state could not be loaded or persisted",
                ),
            )
            .await?;
            return Ok(Action::requeue(Duration::from_secs(15)));
        }
        Ok(None) | Err(_) => {}
    }
    if !trust_established && loaded_ratchet.is_err() {
        set_vault_status(
            &context,
            &vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition(
                "Ready",
                "False",
                "TrustStateTampered",
                "rollback state failed authentication or scope validation",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(300)));
    }

    let purpose = if trust_established {
        JoinPurposeV1::RestoreTrust
    } else {
        JoinPurposeV1::Enroll
    };
    let request = ensure_join_request(
        &context,
        &vault,
        &identity,
        purpose.clone(),
        trusted_root.clone(),
        trusted_root_user_id,
        &owner,
    )
    .await?;
    let approvals: Api<ThoraxJoinApproval> = Api::namespaced(context.client.clone(), &namespace);
    let request_name = request.name_any();
    let Some(approval_object) = approvals.get_opt(&request_name).await? else {
        let (reason, message) = if purpose == JoinPurposeV1::RestoreTrust {
            if trust_state_tampered {
                (
                    "TrustStateTampered",
                    "rollback state failed authentication; RestoreTrust approval is required",
                )
            } else {
                (
                    "RecoveryRequired",
                    "rollback state is unavailable; RestoreTrust approval is required",
                )
            }
        } else {
            ("PendingApproval", "join request awaits approval")
        };
        set_vault_status(
            &context,
            &vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition("Ready", "False", reason, message),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    };
    if !is_controlled_by(&approval_object, &owner.uid)
        || approval_object.spec.request_ref.name != request_name
        || approval_object.spec.request_ref.uid != required_uid(&request)?
    {
        return Err(ControllerError::Invalid(
            "join approval is not bound to this request generation and vault",
        ));
    }
    let candidate = request.spec.candidate(&namespace, &uid)?;
    let approval = approval_object.spec.approval()?;
    validate_join_candidate(&context.crypto, &candidate)?;
    validate_approval_bindings(&context.crypto, &candidate, &approval)?;
    if candidate.purpose != purpose || approval.purpose != purpose {
        return Err(ControllerError::Invalid(
            "join artifacts have the wrong enrollment purpose",
        ));
    }
    let baseline = open_join_baseline(&context.crypto, &identity, &candidate, &approval)?;
    let mut ratchet = ratchet_from_baseline(trusted_root.clone(), baseline);
    let previous_revision = match loaded_ratchet {
        Ok(Some(snapshot)) => Some(snapshot.revision),
        Ok(None) => None,
        Err(_) => {
            context
                .ratchets
                .get_revision(
                    &identity,
                    &trusted_root,
                    &ratchet_credential.owner_references,
                )
                .await?
        }
    };
    let report = thorax_core::validate_vault(&store, &ratchet, &context.crypto)?;
    if !report.issues.is_empty() || report_has_rollback(&report) {
        let rollback = report_has_rollback(&report);
        set_vault_status(
            &context,
            &vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition(
                "Ready",
                "False",
                if rollback {
                    "RollbackSuspected"
                } else {
                    "VaultUnverified"
                },
                if rollback {
                    "vault is below the persisted rollback watermark"
                } else {
                    "vault verification failed"
                },
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    if !report.effective.users.contains_key(&candidate.user_id)
        || !report
            .effective
            .entry_points
            .contains_key(&candidate.user_id)
    {
        let (reason, message, delay) = if purpose == JoinPurposeV1::Enroll {
            (
                "PendingVaultPublication",
                "approval exists but matching vault membership has not arrived",
                15,
            )
        } else {
            (
                "EnrollmentMismatch",
                "RestoreTrust identity is not an effective member of this vault",
                300,
            )
        };
        set_vault_status(
            &context,
            &vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition("Ready", "False", reason, message),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(delay)));
    }
    validate_approving_admin(&report.effective, &approval)?;
    if purpose == JoinPurposeV1::Enroll {
        validate_approved_grants(&report.effective, &approval)?;
    }
    ratchet.apply_update(&report.ratchet_update);
    if matches!(
        RatchetBackend::compare_and_swap(
            &context.ratchets,
            &trusted_root,
            identity.user_id(),
            &ratchet_credential,
            previous_revision.as_ref(),
            &ratchet,
        )
        .await?,
        RatchetCasOutcome::Conflict
    ) {
        set_vault_status(
            &context,
            &vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition(
                "Ready",
                "False",
                "TrustStateUnavailable",
                "rollback state changed concurrently; revalidation is required",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(1)));
    }
    if purpose == JoinPurposeV1::RestoreTrust {
        approvals
            .delete(&request_name, &delete_params_for(&approval_object)?)
            .await?;
        let requests: Api<ThoraxJoinRequest> = Api::namespaced(context.client.clone(), &namespace);
        requests
            .delete(&request_name, &delete_params_for(&request)?)
            .await?;
    }
    let mut extra_conditions = Vec::new();
    if approval
        .replaces_user_id
        .as_ref()
        .is_some_and(|old| report.effective.users.contains_key(old))
    {
        extra_conditions.push(condition(
            "OldIdentityOutstanding",
            "True",
            "RevocationRequired",
            "the replaced identity remains an effective vault member; revoke it and rotate affected values",
        ));
    }
    set_vault_status_with_extra(
        &context,
        &vault,
        Some(hex(&trusted_root.0)),
        Some(revision),
        Some(hex(&(identity.user_id().0).0)),
        condition(
            "Ready",
            "True",
            "Verified",
            "vault and enrollment are verified",
        ),
        extra_conditions,
    )
    .await?;
    Ok(Action::requeue(STEADY_STATE_REQUEUE))
}

#[allow(clippy::too_many_arguments)]
async fn finish_verified_vault(
    context: &Context,
    vault: &ThoraxVault,
    store: &VaultStore,
    identity: &Identity,
    trusted_root: HashValue,
    revision: String,
    mut ratchet: Ratchet,
    expected_revision: Option<String>,
    credential: KubernetesRatchetCredential,
) -> Result<Action, ControllerError> {
    let report = thorax_core::validate_vault(store, &ratchet, &context.crypto)?;
    if !report.issues.is_empty() || report_has_rollback(&report) {
        let rollback = report_has_rollback(&report);
        set_vault_status(
            context,
            vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition(
                "Ready",
                "False",
                if rollback {
                    "RollbackSuspected"
                } else {
                    "VaultUnverified"
                },
                if rollback {
                    "vault is below the persisted rollback watermark"
                } else {
                    "vault verification failed"
                },
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    if !report.effective.users.contains_key(identity.user_id())
        || !report
            .effective
            .entry_points
            .contains_key(identity.user_id())
    {
        set_vault_status(
            context,
            vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition(
                "Ready",
                "False",
                "IdentityRevoked",
                "managed identity is not an effective vault member",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    ratchet.apply_update(&report.ratchet_update);
    if matches!(
        RatchetBackend::compare_and_swap(
            &context.ratchets,
            &trusted_root,
            identity.user_id(),
            &credential,
            expected_revision.as_ref(),
            &ratchet,
        )
        .await?,
        RatchetCasOutcome::Conflict
    ) {
        set_vault_status(
            context,
            vault,
            Some(hex(&trusted_root.0)),
            Some(revision),
            Some(hex(&(identity.user_id().0).0)),
            condition(
                "Ready",
                "False",
                "TrustStateUnavailable",
                "rollback state changed concurrently; revalidation is required",
            ),
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(1)));
    }
    let mut extra_conditions = Vec::new();
    if replacement_is_outstanding(context, vault, identity, &report.effective).await? {
        extra_conditions.push(condition(
            "OldIdentityOutstanding",
            "True",
            "RevocationRequired",
            "the replaced identity remains an effective vault member; revoke it and rotate affected values",
        ));
    }
    set_vault_status_with_extra(
        context,
        vault,
        Some(hex(&trusted_root.0)),
        Some(revision),
        Some(hex(&(identity.user_id().0).0)),
        condition(
            "Ready",
            "True",
            "Verified",
            "vault and rollback state are verified",
        ),
        extra_conditions,
    )
    .await?;
    Ok(Action::requeue(STEADY_STATE_REQUEUE))
}

async fn replacement_is_outstanding(
    context: &Context,
    vault: &ThoraxVault,
    identity: &Identity,
    effective: &thorax_core::EffectiveState,
) -> Result<bool, ControllerError> {
    let approvals: Api<ThoraxJoinApproval> =
        Api::namespaced(context.client.clone(), &context.namespace);
    let request_name = bounded_name(&vault.name_any(), &short_hex(&(identity.user_id().0).0));
    let Some(approval) = approvals.get_opt(&request_name).await? else {
        return Ok(false);
    };
    let approval = approval.spec.approval()?;
    Ok(approval
        .replaces_user_id
        .as_ref()
        .is_some_and(|old| effective.users.contains_key(old)))
}

async fn reconcile_secret(
    projection: Arc<ThoraxSecret>,
    context: Arc<Context>,
) -> Result<Action, ControllerError> {
    match reconcile_secret_inner(projection.clone(), context.clone()).await {
        Ok(action) => Ok(action),
        Err(_) => {
            fail_projection(
                &context,
                &projection,
                "ProjectionFailed",
                "projection could not be derived from a verified source",
            )
            .await?;
            Ok(Action::requeue(Duration::from_secs(30)))
        }
    }
}

async fn reconcile_secret_inner(
    projection: Arc<ThoraxSecret>,
    context: Arc<Context>,
) -> Result<Action, ControllerError> {
    projection.spec.validate()?;
    let namespace = required_namespace(projection.as_ref())?;
    let vaults: Api<ThoraxVault> = Api::namespaced(context.client.clone(), &namespace);
    let Some(vault) = vaults.get_opt(&projection.spec.vault_ref.name).await? else {
        fail_projection(
            &context,
            &projection,
            "VaultNotReady",
            "referenced vault is absent",
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    };
    if !is_ready(vault.status.as_ref().map(|status| &status.conditions)) {
        fail_projection(
            &context,
            &projection,
            "VaultNotReady",
            "referenced vault is not Ready",
        )
        .await?;
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    let (vault_bytes, identity, ratchet, revision) = load_ready_vault(&context, &vault).await?;
    let runtime = RuntimeVault::load(&vault_bytes, &ratchet, identity)?;
    let data = match project_data(&runtime, &projection.spec) {
        Ok(data) => data,
        Err(error) => {
            handle_projection_source_error(&context, &projection, error).await?;
            return Ok(Action::requeue(Duration::from_secs(30)));
        }
    };
    if !write_projection(&context, &projection, data, &revision).await? {
        return Ok(Action::requeue(Duration::from_secs(30)));
    }
    set_secret_status(
        &context,
        &projection,
        Some(revision),
        condition(
            "Ready",
            "True",
            "Projected",
            "all keys projected atomically",
        ),
    )
    .await?;
    Ok(Action::requeue(STEADY_STATE_REQUEUE))
}

async fn handle_projection_source_error(
    context: &Context,
    projection: &ThoraxSecret,
    error: crate::RuntimeVaultError,
) -> Result<(), ControllerError> {
    use crate::RuntimeVaultError;
    match error {
        RuntimeVaultError::AllSourcesDeleted => {
            if projection.spec.source_deletion_policy == ProjectionPolicy::Delete {
                delete_owned_projection(context, projection).await?;
            }
            set_secret_status(
                context,
                projection,
                None,
                condition(
                    "Ready",
                    "False",
                    "SourceDeleted",
                    "all mapped sources were authentically deleted",
                ),
            )
            .await
        }
        RuntimeVaultError::SourcesPartiallyDeleted => {
            fail_projection(
                context,
                projection,
                "SourcePartiallyDeleted",
                "only some mapped sources were authentically deleted",
            )
            .await
        }
        RuntimeVaultError::NotAuthorized => {
            fail_projection(
                context,
                projection,
                "NotAuthorized",
                "a mapped source is outside the identity's read authority",
            )
            .await
        }
        RuntimeVaultError::RecipientUnavailable => {
            fail_projection(
                context,
                projection,
                "RecipientUnavailable",
                "an authorized source is not encrypted to this identity",
            )
            .await
        }
        RuntimeVaultError::Conflicted => {
            fail_projection(
                context,
                projection,
                "Conflicted",
                "a mapped source has no verified winner",
            )
            .await
        }
        RuntimeVaultError::SourceMissing => {
            fail_projection(
                context,
                projection,
                "SourceMissing",
                "a mapped source has no current value",
            )
            .await
        }
        RuntimeVaultError::MissingField { .. } => {
            fail_projection(
                context,
                projection,
                "SourceMissing",
                "a mapped field has no current value",
            )
            .await
        }
        RuntimeVaultError::ProjectionTooLarge => {
            fail_projection(
                context,
                projection,
                "ProjectionTooLarge",
                "projected Secret data exceeds the 1 MiB limit",
            )
            .await
        }
        RuntimeVaultError::InvalidSource
        | RuntimeVaultError::InvalidSelector { .. }
        | RuntimeVaultError::Ops(_)
        | RuntimeVaultError::Store(_) => {
            fail_projection(
                context,
                projection,
                "ProjectionFailed",
                "a mapped source could not be verified",
            )
            .await
        }
    }
}

enum IdentityOutcome {
    Ready(Box<Identity>),
    RecoveryRequired,
    Unavailable,
}

async fn load_or_create_identity(
    context: &Context,
    vault: &ThoraxVault,
    owner: &OwnerReference,
) -> Result<IdentityOutcome, ControllerError> {
    let api: Api<Secret> = Api::namespaced(context.client.clone(), &context.namespace);
    let name = &vault.spec.identity.managed_secret_name;
    if let Some(metadata) = api.get_metadata_opt(name).await? {
        if !is_controlled_by(&metadata, &owner.uid) {
            return Ok(IdentityOutcome::Unavailable);
        }
        let secret = SensitiveSecret(api.get(name).await?);
        if !is_controlled_by(&*secret, &owner.uid)
            || secret.immutable != Some(true)
            || secret.type_.as_deref() != Some("Opaque")
        {
            return Ok(IdentityOutcome::Unavailable);
        }
        let Some(seed) = secret.data.as_ref().and_then(|data| data.get(IDENTITY_KEY)) else {
            return Ok(IdentityOutcome::RecoveryRequired);
        };
        let identity = match Identity::from_master_seed(&context.crypto, &seed.0) {
            Ok(identity) => identity,
            Err(_) => return Ok(IdentityOutcome::RecoveryRequired),
        };
        if vault
            .status
            .as_ref()
            .and_then(|status| status.identity_user_id.as_deref())
            .is_some_and(|expected| expected != hex(&(identity.user_id().0).0))
        {
            return Ok(IdentityOutcome::RecoveryRequired);
        }
        return Ok(IdentityOutcome::Ready(Box::new(identity)));
    }
    if vault
        .status
        .as_ref()
        .and_then(|status| status.identity_user_id.as_ref())
        .is_some()
    {
        return Ok(IdentityOutcome::RecoveryRequired);
    }
    let identity = Identity::generate(&context.crypto)?;
    let secret = SensitiveSecret(Secret {
        metadata: kube::core::ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(context.namespace.clone()),
            owner_references: Some(vec![owner.clone()]),
            labels: Some(BTreeMap::from([(
                "thorax.backbone.dev/component".into(),
                "identity".into(),
            )])),
            ..Default::default()
        },
        immutable: Some(true),
        type_: Some("Opaque".into()),
        data: Some(BTreeMap::from([(
            IDENTITY_KEY.into(),
            ByteString(identity.master_seed().to_vec()),
        )])),
        ..Default::default()
    });
    match api.create(&PostParams::default(), &secret).await {
        Ok(created) => {
            drop(SensitiveSecret(created));
            Ok(IdentityOutcome::Ready(Box::new(identity)))
        }
        Err(kube::Error::Api(response)) if response.code == 409 => {
            // A create race has no trustworthy provenance. Reconcile again and apply
            // the full immutable-shape and status-pinning checks above.
            Ok(IdentityOutcome::Unavailable)
        }
        Err(error) => Err(error.into()),
    }
}

fn is_controlled_by(resource: &impl ResourceExt, uid: &str) -> bool {
    resource
        .meta()
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners
                .iter()
                .any(|owner| owner.controller == Some(true) && owner.uid == uid)
        })
}

async fn ensure_join_request(
    context: &Context,
    vault: &ThoraxVault,
    identity: &Identity,
    purpose: JoinPurposeV1,
    trusted_root: HashValue,
    trusted_root_user_id: UserId,
    owner: &OwnerReference,
) -> Result<ThoraxJoinRequest, ControllerError> {
    let api: Api<ThoraxJoinRequest> = Api::namespaced(context.client.clone(), &context.namespace);
    let identity_suffix = short_hex(&(identity.user_id().0).0);
    if purpose == JoinPurposeV1::Enroll {
        let name = bounded_name(&vault.name_any(), &identity_suffix);
        if let Some(existing) = api.get_opt(&name).await? {
            if !is_controlled_by(&existing, &owner.uid) {
                return Err(ControllerError::Invalid(
                    "existing join request is not owned by this vault",
                ));
            }
            validate_existing_request(
                context,
                vault,
                identity,
                &purpose,
                &trusted_root,
                &existing,
            )?;
            return Ok(existing);
        }
    } else {
        let mut existing = api
            .list(&ListParams::default())
            .await?
            .items
            .into_iter()
            .filter(|request| {
                request.spec.vault_ref.name == vault.name_any()
                    && request.spec.purpose == thorax_kubernetes_api::JoinPurpose::RestoreTrust
                    && request.spec.user_id == hex(&(identity.user_id().0).0)
            })
            .collect::<Vec<_>>();
        existing.sort_by_key(ResourceExt::name_any);
        if let Some(existing) = existing.into_iter().next() {
            if !is_controlled_by(&existing, &owner.uid) {
                return Err(ControllerError::Invalid(
                    "existing trust-restoration request is not owned by this vault",
                ));
            }
            validate_existing_request(
                context,
                vault,
                identity,
                &purpose,
                &trusted_root,
                &existing,
            )?;
            return Ok(existing);
        }
    }
    // Projection declarations are intentionally not copied into enrollment requests.
    // Grants and projections are separate security decisions; mirroring an unbounded,
    // editor-controlled set here adds memory pressure and risks turning suggestions into
    // de-facto authorization prompts. Administrators choose grants explicitly in the CLI.
    let selectors = Vec::new();
    let request_id = thorax_crypto::random_bytes(32).to_vec();
    let name = match purpose {
        JoinPurposeV1::Enroll => bounded_name(&vault.name_any(), &identity_suffix),
        JoinPurposeV1::RestoreTrust => bounded_name(
            &vault.name_any(),
            &format!("{identity_suffix}-restore-{}", short_hex(&request_id)),
        ),
    };
    let candidate = create_join_candidate(
        &context.crypto,
        identity,
        purpose,
        request_id,
        trusted_root,
        trusted_root_user_id,
        thorax_core::DeploymentContextV1 {
            namespace: context.namespace.clone(),
            vault_name: vault.name_any(),
            vault_uid: required_uid(vault)?,
        },
        selectors,
    )?;
    let spec = ThoraxJoinRequestSpec::from_candidate(&candidate)?;
    let mut request = ThoraxJoinRequest::new(&name, spec);
    request.metadata.namespace = Some(context.namespace.clone());
    request.metadata.owner_references = Some(vec![owner.clone()]);
    Ok(api.create(&PostParams::default(), &request).await?)
}

fn validate_existing_request(
    context: &Context,
    vault: &ThoraxVault,
    identity: &Identity,
    purpose: &JoinPurposeV1,
    trusted_root: &HashValue,
    existing: &ThoraxJoinRequest,
) -> Result<(), ControllerError> {
    let candidate = existing
        .spec
        .candidate(&context.namespace, &required_uid(vault)?)?;
    validate_join_candidate(&context.crypto, &candidate)?;
    if &candidate.purpose != purpose
        || candidate.user_id != *identity.user_id()
        || &candidate.trusted_root != trusted_root
    {
        return Err(ControllerError::Invalid(
            "existing join request does not match managed identity and purpose",
        ));
    }
    Ok(())
}

async fn load_ready_vault(
    context: &Context,
    vault: &ThoraxVault,
) -> Result<(Vec<u8>, Identity, Ratchet, String), ControllerError> {
    let config_maps: Api<ConfigMap> = Api::namespaced(context.client.clone(), &context.namespace);
    let source = config_maps
        .get(&vault.spec.source.config_map_ref.name)
        .await?;
    let bytes = config_map_bytes(&source, &vault.spec.source.config_map_ref.key)
        .ok_or(ControllerError::Invalid("source ConfigMap key is absent"))?;
    let trusted_root =
        trusted_root_candidate(&thorax_core::decode_vault(&bytes)?, &context.crypto)?;
    let secrets: Api<Secret> = Api::namespaced(context.client.clone(), &context.namespace);
    let identity_metadata = secrets
        .get_metadata(&vault.spec.identity.managed_secret_name)
        .await?;
    if !is_controlled_by(&identity_metadata, &required_uid(vault)?) {
        return Err(ControllerError::Invalid(
            "identity Secret is not owned by this vault",
        ));
    }
    let identity_secret = SensitiveSecret(
        secrets
            .get(&vault.spec.identity.managed_secret_name)
            .await?,
    );
    if !is_controlled_by(&*identity_secret, &required_uid(vault)?)
        || identity_secret.immutable != Some(true)
        || identity_secret.type_.as_deref() != Some("Opaque")
    {
        return Err(ControllerError::Invalid(
            "identity Secret ownership or immutable shape is invalid",
        ));
    }
    let seed = identity_secret
        .data
        .as_ref()
        .and_then(|data| data.get(IDENTITY_KEY))
        .ok_or(ControllerError::Invalid(
            "identity Secret has no master seed",
        ))?;
    let identity = Identity::from_master_seed(&context.crypto, &seed.0)?;
    let owner_references = [owner_reference(vault)?];
    let (ratchet, _) = context
        .ratchets
        .load(&identity, &trusted_root, &owner_references)
        .await?
        .ok_or(ControllerError::Invalid("Ready vault has no ratchet state"))?;
    let revision = hex(&context.crypto.hash("thorax.kubernetes-vault.v1", &bytes).0);
    Ok((bytes, identity, ratchet, revision))
}

async fn write_projection(
    context: &Context,
    projection: &ThoraxSecret,
    mut data: crate::ProjectedData,
    revision: &str,
) -> Result<bool, ControllerError> {
    let api: Api<Secret> = Api::namespaced(context.client.clone(), &context.namespace);
    let name = projection.name_any();
    let uid = required_uid(projection)?;
    let existing = api.get_metadata_opt(&name).await?;
    if let Some(existing) = &existing {
        let owned = existing
            .metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| {
                owners
                    .iter()
                    .any(|owner| owner.controller == Some(true) && owner.uid == uid)
            });
        if !owned {
            set_secret_status(
                context,
                projection,
                None,
                condition(
                    "Ready",
                    "False",
                    "DestinationConflict",
                    "destination Secret is not owned by this ThoraxSecret",
                ),
            )
            .await?;
            return Ok(false);
        }
    }
    let mut labels = projection.spec.template.metadata.labels.clone();
    labels.insert(MANAGED_LABEL.into(), "true".into());
    let mut annotations = projection.spec.template.metadata.annotations.clone();
    annotations.insert(
        VAULT_ANNOTATION.into(),
        projection.spec.vault_ref.name.clone(),
    );
    annotations.insert(VAULT_REVISION_ANNOTATION.into(), revision.into());
    annotations.insert(
        OBSERVED_GENERATION_ANNOTATION.into(),
        projection
            .metadata
            .generation
            .unwrap_or_default()
            .to_string(),
    );
    let mut secret = SensitiveSecret(Secret {
        metadata: kube::core::ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(context.namespace.clone()),
            labels: Some(labels),
            annotations: Some(annotations),
            owner_references: Some(vec![owner_reference(projection)?]),
            ..Default::default()
        },
        type_: Some(projection.spec.template.secret_type.clone()),
        data: Some(data.take()),
        ..Default::default()
    });
    if let Some(existing) = existing {
        // The metadata-only read supplies the CAS token without copying the old
        // plaintext into this process. Whole-object replacement is required: a JSON
        // merge patch would retain data keys removed from the ThoraxSecret mapping.
        secret.metadata.resource_version = existing.metadata.resource_version;
        match api.replace(&name, &PostParams::default(), &secret).await {
            Ok(updated) => drop(SensitiveSecret(updated)),
            Err(_) => {
                fail_projection(
                    context,
                    projection,
                    "ProjectionBlocked",
                    "owned destination Secret could not be updated",
                )
                .await?;
                return Ok(false);
            }
        }
    } else {
        match api.create(&PostParams::default(), &secret).await {
            Ok(created) => drop(SensitiveSecret(created)),
            Err(_) => {
                fail_projection(
                    context,
                    projection,
                    "ProjectionBlocked",
                    "destination Secret could not be created",
                )
                .await?;
                return Ok(false);
            }
        }
    }
    Ok(true)
}

async fn fail_projection(
    context: &Context,
    projection: &ThoraxSecret,
    reason: &str,
    message: &str,
) -> Result<(), ControllerError> {
    if projection.spec.failure_policy == ProjectionPolicy::Delete {
        delete_owned_projection(context, projection).await?;
    }
    set_secret_status(
        context,
        projection,
        None,
        condition("Ready", "False", reason, message),
    )
    .await
}

async fn delete_owned_projection(
    context: &Context,
    projection: &ThoraxSecret,
) -> Result<(), ControllerError> {
    let api: Api<Secret> = Api::namespaced(context.client.clone(), &context.namespace);
    if let Some(existing) = api.get_metadata_opt(&projection.name_any()).await? {
        let uid = required_uid(projection)?;
        let owned = existing
            .metadata
            .owner_references
            .as_ref()
            .is_some_and(|owners| {
                owners
                    .iter()
                    .any(|owner| owner.controller == Some(true) && owner.uid == uid)
            });
        if owned {
            api.delete(&projection.name_any(), &delete_params_for(&existing)?)
                .await?;
        }
    }
    Ok(())
}

fn validate_approving_admin(
    effective: &thorax_core::EffectiveState,
    approval: &thorax_core::JoinApprovalV1,
) -> Result<(), ControllerError> {
    let resolved = effective
        .user_for_signing_key(&approval.approving_signing_public_key)
        .ok_or(ControllerError::Invalid(
            "approval signer is not a current vault user",
        ))?;
    if resolved != &approval.approving_admin || !effective.authority_for_user(resolved).administer {
        return Err(ControllerError::Invalid(
            "approval signer is not a current Thorax administrator",
        ));
    }
    Ok(())
}

fn validate_approved_grants(
    effective: &thorax_core::EffectiveState,
    approval: &thorax_core::JoinApprovalV1,
) -> Result<(), ControllerError> {
    let authority = effective.authority_for_user(&approval.user_id);
    for permission in &approval.approved_grants {
        let GrantPermissionV1::ReadKeyspace(expected) = permission else {
            return Err(ControllerError::Invalid(
                "approval contains a non-read grant",
            ));
        };
        let covered = authority.administer
            || authority
                .read
                .iter()
                .any(|actual| selector_subsumes(actual, expected))
            || authority
                .write
                .iter()
                .any(|actual| selector_subsumes(actual, expected))
            || authority
                .manage
                .iter()
                .any(|actual| selector_subsumes(&actual.selector, expected));
        if !covered {
            return Err(ControllerError::Invalid(
                "published vault does not contain every approved grant",
            ));
        }
    }
    Ok(())
}

fn ratchet_from_baseline(root: HashValue, baseline: thorax_core::RatchetBaselineV1) -> Ratchet {
    let mut ratchet = Ratchet::new(root);
    for record in baseline.records {
        if !matches!(record, RatchetRecordV1::TrustedRoot(_)) {
            ratchet.absorb_record(&record);
        }
    }
    ratchet
}

fn root_user_id(
    vault: &VaultStore,
    trusted_root: &HashValue,
    crypto: &Crypto,
) -> Result<UserId, ControllerError> {
    let VaultStore::V1(vault) = vault;
    for record in &vault.records {
        let Some(RecordBodyV1::VaultRoot(root)) = record.body.known() else {
            continue;
        };
        if key_hash(crypto, &record.signing_public_key)? == *trusted_root {
            return Ok(root.id.clone());
        }
    }
    Err(ControllerError::Invalid("trusted root user is absent"))
}

fn config_map_bytes(config_map: &ConfigMap, key: &str) -> Option<Vec<u8>> {
    match (
        config_map.data.as_ref().and_then(|data| data.get(key)),
        config_map
            .binary_data
            .as_ref()
            .and_then(|data| data.get(key)),
    ) {
        (Some(_), Some(_)) => None,
        (Some(text), None) => Some(text.as_bytes().to_vec()),
        (None, Some(bytes)) => Some(bytes.0.clone()),
        (None, None) => None,
    }
}

fn report_has_rollback(report: &thorax_core::ValidationReport) -> bool {
    report.issues.iter().any(|issue| {
        matches!(
            issue,
            thorax_core::ValidationIssue::FormatVersionRegression { .. }
        )
    }) || report
        .effective
        .conflicted
        .values()
        .any(|conflict| matches!(conflict.kind, thorax_core::ConflictKind::Rollback { .. }))
}

async fn set_vault_status(
    context: &Context,
    vault: &ThoraxVault,
    trusted_root: Option<String>,
    revision: Option<String>,
    identity_user_id: Option<String>,
    condition: Condition,
) -> Result<(), ControllerError> {
    set_vault_status_with_extra(
        context,
        vault,
        trusted_root,
        revision,
        identity_user_id,
        condition,
        Vec::new(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn set_vault_status_with_extra(
    context: &Context,
    vault: &ThoraxVault,
    trusted_root: Option<String>,
    revision: Option<String>,
    identity_user_id: Option<String>,
    condition: Condition,
    mut extra_conditions: Vec<Condition>,
) -> Result<(), ControllerError> {
    let api: Api<ThoraxVault> = Api::namespaced(context.client.clone(), &context.namespace);
    let ready_now = condition.type_ == "Ready" && condition.status == "True";
    let established = trust_was_established(vault) || ready_now;
    let join_request_name = identity_user_id.as_ref().map(|user_id| {
        format!(
            "{}-{}",
            vault.name_any(),
            user_id.chars().take(16).collect::<String>()
        )
    });
    let mut conditions = vec![condition];
    if established {
        conditions.push(self_condition(
            "TrustEstablished",
            "True",
            "BaselinePersisted",
            "rollback trust has been established for this identity",
        ));
    }
    conditions.append(&mut extra_conditions);
    let status = ThoraxVaultStatus {
        trusted_root,
        vault_revision: revision,
        identity_user_id,
        join_request_name,
        conditions,
    };
    if vault
        .status
        .as_ref()
        .is_some_and(|current| vault_status_semantically_equal(current, &status))
    {
        return Ok(());
    }
    api.patch_status(
        &vault.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({"status": status})),
    )
    .await?;
    publish_condition_events(context, vault.object_ref(&()), &status.conditions).await;
    Ok(())
}

async fn set_secret_status(
    context: &Context,
    projection: &ThoraxSecret,
    revision: Option<String>,
    condition: Condition,
) -> Result<(), ControllerError> {
    let api: Api<ThoraxSecret> = Api::namespaced(context.client.clone(), &context.namespace);
    let status = ThoraxSecretStatus {
        observed_generation: projection.metadata.generation,
        observed_vault_revision: revision,
        conditions: vec![condition],
    };
    if projection
        .status
        .as_ref()
        .is_some_and(|current| secret_status_semantically_equal(current, &status))
    {
        return Ok(());
    }
    api.patch_status(
        &projection.name_any(),
        &PatchParams::default(),
        &Patch::Merge(json!({"status": status})),
    )
    .await?;
    publish_condition_events(context, projection.object_ref(&()), &status.conditions).await;
    Ok(())
}

async fn publish_condition_events(
    context: &Context,
    reference: k8s_openapi::api::core::v1::ObjectReference,
    conditions: &[Condition],
) {
    for condition in conditions {
        let event = Event {
            type_: if condition.status == "True"
                && matches!(condition.type_.as_str(), "Ready" | "TrustEstablished")
            {
                EventType::Normal
            } else {
                EventType::Warning
            },
            reason: condition.reason.clone(),
            note: Some(condition.message.clone()),
            action: "Reconcile".into(),
            secondary: None,
        };
        if context.events.publish(&event, &reference).await.is_err() {
            tracing::warn!(
                object = %reference.name.as_deref().unwrap_or("unknown"),
                "Kubernetes Event publication failed"
            );
        }
    }
}

fn condition(type_: &str, status: &str, reason: &str, message: &str) -> Condition {
    self_condition(type_, status, reason, message)
}

fn self_condition(type_: &str, status: &str, reason: &str, message: &str) -> Condition {
    Condition {
        type_: type_.into(),
        status: status.into(),
        reason: reason.into(),
        message: message.into(),
        observed_generation: None,
        last_transition_time: Time(k8s_openapi::jiff::Timestamp::now()),
    }
}

fn vault_status_semantically_equal(left: &ThoraxVaultStatus, right: &ThoraxVaultStatus) -> bool {
    left.trusted_root == right.trusted_root
        && left.vault_revision == right.vault_revision
        && left.identity_user_id == right.identity_user_id
        && left.join_request_name == right.join_request_name
        && conditions_semantically_equal(&left.conditions, &right.conditions)
}

fn secret_status_semantically_equal(left: &ThoraxSecretStatus, right: &ThoraxSecretStatus) -> bool {
    left.observed_generation == right.observed_generation
        && left.observed_vault_revision == right.observed_vault_revision
        && conditions_semantically_equal(&left.conditions, &right.conditions)
}

fn conditions_semantically_equal(left: &[Condition], right: &[Condition]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left, right)| {
            left.type_ == right.type_
                && left.status == right.status
                && left.reason == right.reason
                && left.message == right.message
                && left.observed_generation == right.observed_generation
        })
}

fn trust_was_established(vault: &ThoraxVault) -> bool {
    vault.status.as_ref().is_some_and(|status| {
        status.conditions.iter().any(|condition| {
            (condition.type_ == "TrustEstablished" || condition.type_ == "Ready")
                && condition.status == "True"
        })
    })
}

fn is_ready(conditions: Option<&Vec<Condition>>) -> bool {
    conditions.is_some_and(|conditions| {
        conditions
            .iter()
            .any(|condition| condition.type_ == "Ready" && condition.status == "True")
    })
}

fn required_namespace(resource: &impl ResourceExt) -> Result<String, ControllerError> {
    resource
        .namespace()
        .ok_or(ControllerError::Invalid("resource has no namespace"))
}

fn required_uid(resource: &impl ResourceExt) -> Result<String, ControllerError> {
    resource
        .meta()
        .uid
        .clone()
        .ok_or(ControllerError::Invalid("resource has no UID"))
}

fn delete_params_for(resource: &impl ResourceExt) -> Result<DeleteParams, ControllerError> {
    Ok(DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(required_uid(resource)?),
            resource_version: resource.meta().resource_version.clone(),
        }),
        ..Default::default()
    })
}

fn owner_reference(
    resource: &impl ResourceExt<DynamicType = ()>,
) -> Result<OwnerReference, ControllerError> {
    resource
        .controller_owner_ref(&())
        .ok_or(ControllerError::Invalid("resource cannot be an owner"))
}

fn short_hex(bytes: &[u8]) -> String {
    hex(bytes).chars().take(16).collect()
}

fn bounded_name(prefix: &str, suffix: &str) -> String {
    let available = 253usize.saturating_sub(suffix.len() + 1);
    let prefix = &prefix[..prefix.len().min(available)];
    format!("{prefix}-{suffix}")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vault_error_policy(
    _object: Arc<ThoraxVault>,
    error: &ControllerError,
    _context: Arc<Context>,
) -> Action {
    tracing::warn!(%error, "ThoraxVault reconcile error");
    Action::requeue(Duration::from_secs(30))
}

fn secret_error_policy(
    _object: Arc<ThoraxSecret>,
    error: &ControllerError,
    _context: Arc<Context>,
) -> Action {
    tracing::warn!(%error, "ThoraxSecret reconcile error");
    Action::requeue(Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_map_source_rejects_ambiguous_keys() {
        let map = ConfigMap {
            data: Some(BTreeMap::from([("vault.cord".into(), "text".into())])),
            binary_data: Some(BTreeMap::from([("vault.cord".into(), ByteString(vec![1]))])),
            ..Default::default()
        };
        assert!(config_map_bytes(&map, "vault.cord").is_none());
    }

    #[test]
    fn vault_size_limit_is_exactly_one_mibibyte() {
        assert_eq!(MAX_VAULT_CONFIGMAP_BYTES, 1_048_576);
        assert!(vec![0_u8; MAX_VAULT_CONFIGMAP_BYTES].len() <= MAX_VAULT_CONFIGMAP_BYTES);
        assert!(vec![0_u8; MAX_VAULT_CONFIGMAP_BYTES + 1].len() > MAX_VAULT_CONFIGMAP_BYTES);
    }

    #[test]
    fn status_comparison_ignores_transition_time_but_not_meaning() {
        let first = condition("Ready", "False", "PendingApproval", "awaiting approval");
        let mut later = first.clone();
        later.last_transition_time = Time(
            first
                .last_transition_time
                .0
                .checked_add(k8s_openapi::jiff::SignedDuration::from_secs(1))
                .unwrap(),
        );
        assert!(conditions_semantically_equal(
            std::slice::from_ref(&first),
            std::slice::from_ref(&later)
        ));
        later.reason = "Different".into();
        assert!(!conditions_semantically_equal(&[first], &[later]));
    }
}
