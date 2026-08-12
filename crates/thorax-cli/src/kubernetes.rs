use std::{collections::BTreeMap, process::ExitCode, time::Duration};

use k8s_openapi::{api::core::v1::ConfigMap, ByteString};
use kube::{
    api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams, Preconditions},
    Client, Config, Resource, ResourceExt,
};
use serde_json::json;
use thorax_frontend::{
    confirm_destructive, hash_hex, parse_secret_query, parse_secret_selector,
    remember_user_if_explicit, resolve_cli_user_ref_with_report, FrontendError,
};
use thorax_kubernetes_api::{
    ObjectReference, ThoraxJoinApproval, ThoraxJoinApprovalSpec, ThoraxJoinRequest, ThoraxVault,
    MAX_VAULT_CONFIGMAP_BYTES, PUBLISHED_REVISION_ANNOTATION,
};
use thorax_ops::{
    commit_join_approval_plan, selector_subsumes, validate_approval_bindings, CryptoProvider,
    GrantPermissionV1, JoinApprovalV1, JoinCandidateV1, JoinPurposeV1, KeyUsePurpose,
    KeyspaceLabelMatcherV1, KeyspaceSelectorV1, LabelMatcherV1, SecretSelectorV1, TupleMatcherV1,
};

use crate::args::{KubernetesApproveArgs, KubernetesCommand, KubernetesPublishArgs};
use crate::CliContext;

pub(crate) fn cmd_kubernetes(
    cli: &CliContext,
    command: KubernetesCommand,
) -> Result<ExitCode, FrontendError> {
    match command {
        KubernetesCommand::Approve(args) => {
            let runtime = tokio::runtime::Runtime::new().map_err(FrontendError::Stdio)?;
            runtime.block_on(cmd_approve(cli, args))
        }
        KubernetesCommand::Publish(args) => {
            let runtime = tokio::runtime::Runtime::new().map_err(FrontendError::Stdio)?;
            runtime.block_on(cmd_publish(cli, args))
        }
    }
}

async fn cmd_approve(
    cli: &CliContext,
    args: KubernetesApproveArgs,
) -> Result<ExitCode, FrontendError> {
    let config = Config::infer().await.map_err(kubernetes_error)?;
    validate_kubernetes_transport(&config)?;
    let cluster_url = config.cluster_url.to_string();
    let namespace = args
        .namespace
        .clone()
        .unwrap_or_else(|| config.default_namespace.clone());
    let client = Client::try_from(config).map_err(kubernetes_error)?;
    let requests: Api<ThoraxJoinRequest> = Api::namespaced(client.clone(), &namespace);
    let vaults: Api<ThoraxVault> = Api::namespaced(client.clone(), &namespace);
    let approvals: Api<ThoraxJoinApproval> = Api::namespaced(client.clone(), &namespace);

    let vault = vaults.get(&args.vault).await.map_err(kubernetes_error)?;
    let vault_uid = required(&vault.metadata.uid, "ThoraxVault UID")?;
    let request_name = active_request_name(&vault)?;
    let request = requests
        .get(&request_name)
        .await
        .map_err(kubernetes_error)?;
    if request.spec.vault_ref.name != vault.name_any() || !is_controlled_by(&request, &vault_uid) {
        return Err(external(
            "active join request is not owned by the named ThoraxVault",
        ));
    }
    let request_uid = required(&request.metadata.uid, "join request UID")?;
    let request_resource_version = required(
        &request.metadata.resource_version,
        "join request resourceVersion",
    )?;
    let candidate = request
        .spec
        .candidate(&namespace, &vault_uid)
        .map_err(api_error)?;

    let session = cli.valid_session()?;
    if session.effective().root_signing_public_key_hash.as_ref() != Some(&candidate.trusted_root) {
        return Err(external(
            "join request names a different trusted Thorax root",
        ));
    }
    let mut permissions = Vec::new();
    for selector in &args.read {
        permissions.push(GrantPermissionV1::ReadKeyspace(parse_secret_query(
            selector,
        )?));
    }
    for selector in &args.read_exact {
        let selector = parse_secret_selector(selector)?;
        permissions.push(GrantPermissionV1::ReadKeyspace(exact_keyspace(selector)));
    }
    let mut canonical_permissions = permissions
        .into_iter()
        .map(|permission| {
            cord::serialize(&permission)
                .map(|encoded| (encoded, permission))
                .map_err(FrontendError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical_permissions.sort_by(|left, right| left.0.cmp(&right.0));
    canonical_permissions.dedup_by(|left, right| left.0 == right.0);
    let permissions = canonical_permissions
        .into_iter()
        .map(|(_, permission)| permission)
        .collect::<Vec<_>>();

    let replaces_user_id = args
        .replaces_user
        .as_deref()
        .map(|value| {
            resolve_cli_user_ref_with_report(
                session.paths(),
                session.report(),
                &thorax_ops::Crypto,
                Some(value),
            )
            .map(|user| user.resolved.user_id)
        })
        .transpose()?;
    if candidate.purpose == thorax_ops::JoinPurposeV1::RestoreTrust
        && (replaces_user_id.is_some() || !permissions.is_empty())
    {
        return Err(external(
            "RestoreTrust approval cannot grant access or replace an identity",
        ));
    }

    let action = format!(
        "approve Kubernetes {} request {} for ThoraxVault {} in namespace {} on API {} with {} read grant{}",
        match candidate.purpose {
            thorax_ops::JoinPurposeV1::Enroll => "enrollment",
            thorax_ops::JoinPurposeV1::RestoreTrust => "trust restoration",
        },
        request.name_any(),
        vault.name_any(),
        namespace,
        cluster_url,
        permissions.len(),
        if permissions.len() == 1 { "" } else { "s" },
    );
    if !confirm_destructive(&action, args.yes, false)? {
        return Ok(ExitCode::SUCCESS);
    }

    let (mut admin, user) = cli.promote_for_action(
        session,
        args.user.as_deref(),
        KeyUsePurpose::SignAdminChange {
            summary: "approve Kubernetes identity".into(),
        },
    )?;
    let existing_approval = approvals
        .get_opt(&request.name_any())
        .await
        .map_err(kubernetes_error)?;
    if let Some(existing) = &existing_approval {
        if !is_controlled_by(existing, &vault_uid)
            || existing.spec.request_ref.name != request.name_any()
            || existing.spec.request_ref.uid != request_uid
        {
            return Err(external(
                "existing approval refers to a different join request generation",
            ));
        }
        let signed = existing.spec.approval().map_err(api_error)?;
        validate_approval_bindings(&thorax_ops::Crypto, &candidate, &signed)?;
        if signed.approved_grants != permissions || signed.replaces_user_id != replaces_user_id {
            return Err(external(
                "existing approval has different grants or replacement intent",
            ));
        }
        let signer = admin
            .effective()
            .user_for_signing_key(&signed.approving_signing_public_key)
            .ok_or_else(|| external("existing approval signer is not a current vault user"))?;
        if signer != &signed.approving_admin
            || !admin.effective().authority_for_user(signer).administer
        {
            return Err(external(
                "existing approval signer is not a current Thorax administrator",
            ));
        }
        if candidate.purpose == JoinPurposeV1::RestoreTrust
            || enrollment_is_fully_committed(admin.effective(), &candidate, &signed)?
        {
            let paths = admin.paths().clone();
            remember_user_if_explicit(&paths, &user)?;
            return print_approval_result(cli, &namespace, &request, &candidate);
        }
    }
    let plan = admin.plan_join_approval(
        &thorax_ops::Crypto,
        &candidate,
        permissions.clone(),
        replaces_user_id.clone(),
    )?;
    let spec = ThoraxJoinApprovalSpec::from_approval(
        plan.approval(),
        ObjectReference {
            name: request.name_any(),
            uid: request_uid.clone(),
        },
    )
    .map_err(|error| external(&error.to_string()))?;
    let mut approval = ThoraxJoinApproval::new(&request.name_any(), spec);
    approval.metadata.namespace = Some(namespace.clone());
    approval.metadata.owner_references = vault.controller_owner_ref(&()).map(|owner| vec![owner]);

    let mut created_approval = None;
    let approval_confirmed = match existing_approval {
        Some(existing) => {
            let signed = existing.spec.approval().map_err(api_error)?;
            signed.approved_grants == permissions && signed.replaces_user_id == replaces_user_id
        }
        None => match approvals.create(&PostParams::default(), &approval).await {
            Ok(created) => {
                let confirmed = created.spec == approval.spec;
                created_approval = Some(created);
                confirmed
            }
            Err(kube::Error::Api(response)) if response.code == 409 => {
                let existing = approvals
                    .get(&request.name_any())
                    .await
                    .map_err(kubernetes_error)?;
                if !is_controlled_by(&existing, &vault_uid) {
                    return Err(external(
                        "existing approval is not owned by the referenced ThoraxVault",
                    ));
                }
                let signed = existing.spec.approval().map_err(api_error)?;
                validate_approval_bindings(&thorax_ops::Crypto, &candidate, &signed)?;
                signed.approved_grants == permissions && signed.replaces_user_id == replaces_user_id
            }
            Err(error) => return Err(kubernetes_error(error)),
        },
    };
    if !approval_confirmed {
        if let Some(created) = &created_approval {
            cleanup_approval(&approvals, created).await;
        }
        return Err(external(
            "an approval with this name already exists with different signed content",
        ));
    }

    let current_request = requests
        .get(&request_name)
        .await
        .map_err(kubernetes_error)?;
    if current_request.metadata.uid.as_deref() != Some(&request_uid)
        || current_request.metadata.resource_version.as_deref()
            != Some(request_resource_version.as_str())
    {
        if let Some(created) = &created_approval {
            cleanup_approval(&approvals, created).await;
        }
        return Err(external(
            "join request changed while approval was being prepared; nothing was committed",
        ));
    }

    let paths = admin.paths().clone();
    if let Err(error) = commit_join_approval_plan(&paths, plan) {
        // The local commit may already be durably prepared. Preserve the signed approval so
        // retry/recovery stays idempotent instead of creating a cross-system split brain.
        return Err(error.into());
    }
    remember_user_if_explicit(&paths, &user)?;

    print_approval_result(cli, &namespace, &request, &candidate)
}

async fn cmd_publish(
    cli: &CliContext,
    args: KubernetesPublishArgs,
) -> Result<ExitCode, FrontendError> {
    let config = Config::infer().await.map_err(kubernetes_error)?;
    validate_kubernetes_transport(&config)?;
    let namespace = args
        .namespace
        .clone()
        .unwrap_or_else(|| config.default_namespace.clone());
    let client = Client::try_from(config).map_err(kubernetes_error)?;
    let vaults: Api<ThoraxVault> = Api::namespaced(client.clone(), &namespace);
    let config_maps: Api<ConfigMap> = Api::namespaced(client, &namespace);
    let vault = vaults.get(&args.vault).await.map_err(kubernetes_error)?;

    let session = cli.valid_session()?;
    let vault_bytes = session.vault_bytes();
    if vault_bytes.len() > MAX_VAULT_CONFIGMAP_BYTES {
        return Err(external(&format!(
            "encoded vault is {} bytes; Kubernetes publication is limited to {} bytes",
            vault_bytes.len(),
            MAX_VAULT_CONFIGMAP_BYTES
        )));
    }
    let local_root = &session.ratchet().trusted_root;
    if let Some(observed_root) = vault
        .status
        .as_ref()
        .and_then(|status| status.trusted_root.as_deref())
    {
        if observed_root != hash_hex(local_root) {
            return Err(external(
                "local workspace trusted root does not match the ThoraxVault",
            ));
        }
    }

    let revision = hash_hex(&thorax_ops::Crypto.hash("thorax.kubernetes-vault.v1", vault_bytes));
    let source = &vault.spec.source.config_map_ref;
    publish_config_map(
        &config_maps,
        &namespace,
        &source.name,
        &source.key,
        vault_bytes,
    )
    .await?;
    // The controller deliberately has exact-name ConfigMap `get`, not namespace-wide
    // list/watch. Touching the referring object gives direct publication immediate
    // reconciliation without widening the controller's metadata visibility. Other
    // producers are still repaired by the controller's bounded periodic requeue.
    vaults
        .patch(
            &args.vault,
            &PatchParams::default(),
            &Patch::Merge(json!({
                "metadata": {
                    "annotations": { (PUBLISHED_REVISION_ANNOTATION): revision }
                }
            })),
        )
        .await
        .map_err(kubernetes_error)?;

    let observed = wait_for_revision(
        &vaults,
        &args.vault,
        &revision,
        Duration::from_secs(args.timeout),
    )
    .await?;
    let ready = observed.status.as_ref().and_then(|status| {
        status
            .conditions
            .iter()
            .find(|condition| condition.type_ == "Ready")
    });
    if cli.json {
        println!(
            "{}",
            json!({
                "published": args.vault,
                "namespace": namespace,
                "config_map": source.name,
                "key": source.key,
                "vault_revision": revision,
                "ready": ready.map(|condition| condition.status.as_str()),
                "reason": ready.map(|condition| condition.reason.as_str()),
            })
        );
    } else {
        println!(
            "published {}/{} to ConfigMap {}/{} key {}",
            namespace, args.vault, namespace, source.name, source.key
        );
        match ready {
            Some(condition) => println!(
                "controller observed revision: Ready={} ({})",
                condition.status, condition.reason
            ),
            None => println!("controller observed revision"),
        }
    }
    Ok(ExitCode::SUCCESS)
}

async fn publish_config_map(
    api: &Api<ConfigMap>,
    namespace: &str,
    name: &str,
    key: &str,
    vault_bytes: &[u8],
) -> Result<(), FrontendError> {
    let bytes = ByteString(vault_bytes.to_vec());
    match api.get_opt(name).await.map_err(kubernetes_error)? {
        Some(mut config_map) => {
            set_config_map_value(&mut config_map, key, bytes)?;
            api.replace(name, &PostParams::default(), &config_map)
                .await
                .map_err(kubernetes_error)?;
        }
        None => {
            let config_map = ConfigMap {
                metadata: ObjectMeta {
                    name: Some(name.to_string()),
                    namespace: Some(namespace.to_string()),
                    ..Default::default()
                },
                binary_data: Some(BTreeMap::from([(key.to_string(), bytes)])),
                ..Default::default()
            };
            api.create(&PostParams::default(), &config_map)
                .await
                .map_err(kubernetes_error)?;
        }
    }
    Ok(())
}

fn set_config_map_value(
    config_map: &mut ConfigMap,
    key: &str,
    bytes: ByteString,
) -> Result<(), FrontendError> {
    if config_map.immutable == Some(true) {
        return Err(external("source ConfigMap is immutable"));
    }
    if let Some(data) = config_map.data.as_mut() {
        data.remove(key);
        if data.is_empty() {
            config_map.data = None;
        }
    }
    config_map
        .binary_data
        .get_or_insert_with(BTreeMap::new)
        .insert(key.to_string(), bytes);
    Ok(())
}

async fn wait_for_revision(
    vaults: &Api<ThoraxVault>,
    name: &str,
    expected: &str,
    timeout: Duration,
) -> Result<ThoraxVault, FrontendError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let vault = vaults.get(name).await.map_err(kubernetes_error)?;
        if vault
            .status
            .as_ref()
            .and_then(|status| status.vault_revision.as_deref())
            == Some(expected)
        {
            return Ok(vault);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(external(
                "timed out waiting for the controller to observe the published vault revision",
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn active_request_name(vault: &ThoraxVault) -> Result<String, FrontendError> {
    vault
        .status
        .as_ref()
        .and_then(|status| status.join_request_name.clone())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| external("ThoraxVault has no active join request"))
}

fn print_approval_result(
    cli: &CliContext,
    namespace: &str,
    request: &ThoraxJoinRequest,
    candidate: &JoinCandidateV1,
) -> Result<ExitCode, FrontendError> {
    if cli.json {
        println!(
            "{}",
            json!({
                "approved": request.name_any(),
                "vault": request.spec.vault_ref.name,
                "namespace": namespace,
                "vault_changed": candidate.purpose == JoinPurposeV1::Enroll,
            })
        );
    } else {
        println!("approved {}/{}", namespace, request.name_any());
        if candidate.purpose == JoinPurposeV1::Enroll {
            println!(
                "publish it with `thorax kubernetes publish {} --namespace {}` or through the configured ConfigMap producer",
                request.spec.vault_ref.name, namespace
            );
        } else {
            println!("the controller can now restore authenticated rollback state");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn enrollment_is_fully_committed(
    effective: &thorax_ops::EffectiveState,
    candidate: &JoinCandidateV1,
    approval: &JoinApprovalV1,
) -> Result<bool, FrontendError> {
    let Some(user) = effective.users.get(&candidate.user_id) else {
        return Ok(false);
    };
    let Some(entry) = effective.entry_points.get(&candidate.user_id) else {
        return Err(external(
            "candidate membership exists without its self-signed entry point",
        ));
    };
    if user.signing_public_key != candidate.signing_public_key
        || user.hpke_public_key != candidate.hpke_public_key
        || entry.trusted_root_user_id != candidate.trusted_root_user_id
    {
        return Err(external(
            "effective candidate membership differs from the signed request",
        ));
    }
    let authority = effective.authority_for_user(&candidate.user_id);
    for permission in &approval.approved_grants {
        let GrantPermissionV1::ReadKeyspace(expected) = permission else {
            return Err(external("Kubernetes approval contains non-read authority"));
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
            return Err(external(
                "candidate membership exists without every approved grant",
            ));
        }
    }
    for active in effective.secret_records() {
        if authority.can_read(&active.value.selector)
            && !active
                .value
                .sealed
                .recipient_slots
                .iter()
                .any(|slot| slot.recipient_id == candidate.user_id)
        {
            return Err(external(
                "candidate membership exists but recipient-slot convergence is incomplete",
            ));
        }
    }
    Ok(true)
}

async fn cleanup_approval(api: &Api<ThoraxJoinApproval>, approval: &ThoraxJoinApproval) {
    let name = approval.name_any();
    let params = DeleteParams {
        preconditions: Some(Preconditions {
            uid: approval.metadata.uid.clone(),
            resource_version: approval.metadata.resource_version.clone(),
        }),
        ..Default::default()
    };
    if let Err(error) = api.delete(&name, &params).await {
        eprintln!("warning: could not remove inert ThoraxJoinApproval {name}: {error}");
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

fn exact_keyspace(selector: SecretSelectorV1) -> KeyspaceSelectorV1 {
    KeyspaceSelectorV1 {
        tuple: TupleMatcherV1::Exact(selector.tuple),
        labels: selector
            .labels
            .into_iter()
            .map(|label| KeyspaceLabelMatcherV1 {
                key: label.key,
                matcher: LabelMatcherV1::Equals(label.value),
            })
            .collect(),
    }
}

fn required(value: &Option<String>, field: &str) -> Result<String, FrontendError> {
    value
        .clone()
        .ok_or_else(|| external(&format!("Kubernetes object has no {field}")))
}

fn api_error(error: thorax_kubernetes_api::ApiError) -> FrontendError {
    external(&error.to_string())
}

fn kubernetes_error(error: impl std::fmt::Display) -> FrontendError {
    FrontendError::ExternalService {
        service: "Kubernetes",
        message: error.to_string(),
    }
}

fn validate_kubernetes_transport(config: &Config) -> Result<(), FrontendError> {
    if config.accept_invalid_certs {
        return Err(external(
            "refusing kubeconfig with insecure TLS certificate verification",
        ));
    }
    if config.cluster_url.scheme_str() != Some("https") {
        return Err(external(
            "refusing non-HTTPS Kubernetes API for Thorax Kubernetes operations",
        ));
    }
    Ok(())
}

fn external(message: &str) -> FrontendError {
    FrontendError::ExternalService {
        service: "Kubernetes enrollment",
        message: message.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_with_request(request: Option<&str>) -> ThoraxVault {
        serde_json::from_value(json!({
            "apiVersion": "thorax.backbone.dev/v1alpha1",
            "kind": "ThoraxVault",
            "metadata": {"name": "payments"},
            "spec": {
                "source": {"configMapRef": {"name": "vault", "key": "vault.cord"}},
                "identity": {"managedSecretName": "identity"}
            },
            "status": request.map(|name| json!({"joinRequestName": name}))
        }))
        .unwrap()
    }

    #[test]
    fn exact_grants_preserve_concrete_label_bindings() {
        let selector = exact_keyspace(SecretSelectorV1 {
            tuple: vec!["db".into(), "prod".into()],
            labels: vec![thorax_ops::SecretLabelV1 {
                key: "tenant".into(),
                value: "payments".into(),
            }],
        });
        assert_eq!(
            selector,
            KeyspaceSelectorV1 {
                tuple: TupleMatcherV1::Exact(vec!["db".into(), "prod".into()]),
                labels: vec![KeyspaceLabelMatcherV1 {
                    key: "tenant".into(),
                    matcher: LabelMatcherV1::Equals("payments".into()),
                }],
            }
        );
    }

    #[test]
    fn approval_refuses_unverified_or_plaintext_kubernetes_transports() {
        let plaintext = Config::new("http://127.0.0.1:8080".parse().unwrap());
        assert!(validate_kubernetes_transport(&plaintext).is_err());

        let mut insecure = Config::new("https://cluster.example".parse().unwrap());
        insecure.accept_invalid_certs = true;
        assert!(validate_kubernetes_transport(&insecure).is_err());

        let verified = Config::new("https://cluster.example".parse().unwrap());
        validate_kubernetes_transport(&verified).unwrap();
    }

    #[test]
    fn approval_resolves_request_only_from_the_named_vault_status() {
        assert_eq!(
            active_request_name(&vault_with_request(Some("payments-candidate"))).unwrap(),
            "payments-candidate"
        );
        assert!(active_request_name(&vault_with_request(None)).is_err());
        assert!(active_request_name(&vault_with_request(Some(""))).is_err());
    }

    #[test]
    fn publish_replaces_only_the_selected_config_map_key() {
        let mut config_map = ConfigMap {
            data: Some(BTreeMap::from([
                ("vault.cord".into(), "old text encoding".into()),
                ("sentinel".into(), "preserved".into()),
            ])),
            binary_data: Some(BTreeMap::from([(
                "unrelated.bin".into(),
                ByteString(vec![9]),
            )])),
            ..Default::default()
        };
        set_config_map_value(
            &mut config_map,
            "vault.cord",
            ByteString(vec![0, 1, 2, 255]),
        )
        .unwrap();
        assert_eq!(
            config_map.data.as_ref().unwrap().get("sentinel"),
            Some(&"preserved".to_string())
        );
        assert!(!config_map.data.as_ref().unwrap().contains_key("vault.cord"));
        assert_eq!(
            config_map.binary_data.as_ref().unwrap().get("vault.cord"),
            Some(&ByteString(vec![0, 1, 2, 255]))
        );
        assert!(config_map
            .binary_data
            .as_ref()
            .unwrap()
            .contains_key("unrelated.bin"));
    }

    #[test]
    fn publish_refuses_immutable_config_map() {
        let mut config_map = ConfigMap {
            immutable: Some(true),
            ..Default::default()
        };
        assert!(set_config_map_value(&mut config_map, "vault.cord", ByteString(vec![1])).is_err());
    }
}
