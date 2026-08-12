//! Kubernetes API types for Thorax projection and in-cluster enrollment.

use std::collections::BTreeMap;

use base64::Engine;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
    CustomResourceDefinition, ValidationRule,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::{CustomResource, CustomResourceExt};
use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

pub const API_GROUP: &str = "thorax.backbone.dev";
pub const API_VERSION: &str = "v1alpha1";
pub const MANAGED_LABEL: &str = "thorax.backbone.dev/managed";
pub const VAULT_ANNOTATION: &str = "thorax.backbone.dev/vault";
pub const VAULT_REVISION_ANNOTATION: &str = "thorax.backbone.dev/vault-revision";
pub const OBSERVED_GENERATION_ANNOTATION: &str = "thorax.backbone.dev/observed-generation";
pub const PUBLISHED_REVISION_ANNOTATION: &str = "thorax.backbone.dev/published-revision";
/// Maximum encoded vault size accepted through a Kubernetes ConfigMap.
pub const MAX_VAULT_CONFIGMAP_BYTES: usize = 1024 * 1024;

const MAX_DATA_MAPPINGS: usize = 256;
const MAX_METADATA_ENTRIES: usize = 64;
const MAX_METADATA_KEY_BYTES: usize = 253;
const MAX_LABEL_VALUE_BYTES: usize = 63;
const MAX_ANNOTATION_VALUE_BYTES: usize = 4096;
const MAX_SELECTOR_BYTES: usize = 1024;
const MAX_FIELD_BYTES: usize = 1024;
const MAX_REVIEW_FIELD_BYTES: usize = 4096;
const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
const MAX_GRANTS: usize = 256;
const MAX_MATCHER_VALUES: usize = 256;

/// The installable CRDs, including admission rules that cannot be expressed by
/// schemars alone. Rust validation repeats the same security-sensitive rules for callers
/// that construct objects without an API server.
pub fn crds() -> Vec<CustomResourceDefinition> {
    let mut vault = ThoraxVault::crd();
    let mut secret = ThoraxSecret::crd();
    let mut request = ThoraxJoinRequest::crd();
    let mut approval = ThoraxJoinApproval::crd();

    add_rules(
        &mut secret,
        &[
            ("size(self.spec.data) > 0", "at least one data mapping is required"),
            ("size(self.spec.data) <= 256", "at most 256 data mappings are allowed"),
            ("self.spec.template.type != 'kubernetes.io/service-account-token' && self.spec.template.type != 'bootstrap.kubernetes.io/token'", "Kubernetes-generated credential types cannot be projected"),
            ("self.spec.template.type != 'kubernetes.io/basic-auth' || ('username' in self.spec.data && 'password' in self.spec.data)", "basic-auth requires username and password mappings"),
            ("self.spec.template.type != 'kubernetes.io/tls' || ('tls.crt' in self.spec.data && 'tls.key' in self.spec.data)", "TLS requires tls.crt and tls.key mappings"),
            ("self.spec.template.type != 'kubernetes.io/dockerconfigjson' || '.dockerconfigjson' in self.spec.data", "dockerconfigjson requires .dockerconfigjson"),
            ("self.spec.template.type != 'kubernetes.io/ssh-auth' || 'ssh-privatekey' in self.spec.data", "ssh-auth requires ssh-privatekey"),
            ("!has(self.spec.template.metadata) || !has(self.spec.template.metadata.labels) || self.spec.template.metadata.labels.all(key, !key.startsWith('thorax.backbone.dev/'))", "controller-reserved labels are forbidden"),
            ("!has(self.spec.template.metadata) || !has(self.spec.template.metadata.annotations) || self.spec.template.metadata.annotations.all(key, !key.startsWith('thorax.backbone.dev/') && !key.startsWith('kubernetes.io/service-account.'))", "controller-reserved and service-account annotations are forbidden"),
            ("!has(self.spec.template.metadata) || !has(self.spec.template.metadata.labels) || self.spec.template.metadata.labels.all(key, size(key) <= 253 && size(self.spec.template.metadata.labels[key]) <= 63)", "label keys and values exceed the projection limits"),
            ("!has(self.spec.template.metadata) || !has(self.spec.template.metadata.annotations) || self.spec.template.metadata.annotations.all(key, size(key) <= 253 && size(self.spec.template.metadata.annotations[key]) <= 4096)", "annotation keys and values exceed the projection limits"),
            ("self.spec.data.all(key, key.matches('^[-._a-zA-Z0-9]+$'))", "every projected data key must use Kubernetes Secret key syntax"),
            ("self.spec.data.all(key, self.spec.data[key].selector != '')", "selectors must identify explicit non-empty records"),
        ],
    );
    add_rules(
        &mut request,
        &[
            (
                "self.spec == oldSelf.spec",
                "join request specs are immutable",
            ),
            (
                "self.spec.purpose != 'Enroll' || has(self.spec.entryPoint)",
                "Enroll requires an entry point",
            ),
            (
                "self.spec.purpose != 'RestoreTrust' || !has(self.spec.entryPoint)",
                "RestoreTrust cannot carry an entry point",
            ),
        ],
    );
    add_rules(
        &mut approval,
        &[
            ("self.spec == oldSelf.spec", "join approval specs are immutable"),
            ("self.spec.purpose != 'RestoreTrust' || ((!has(self.spec.approvedGrants) || size(self.spec.approvedGrants) == 0) && !has(self.spec.replacesUserID))", "RestoreTrust cannot change grants or replace an identity"),
        ],
    );
    // Keep this binding immutable within one object generation. Re-enrollment is an
    // explicit delete-and-recreate operation, yielding a new UID and identity.
    add_rules(
        &mut vault,
        &[(
            "self.spec == oldSelf.spec",
            "ThoraxVault specs are immutable; replace the object to re-enroll",
        )],
    );

    vec![vault, secret, request, approval]
}

fn add_rules(crd: &mut CustomResourceDefinition, rules: &[(&str, &str)]) {
    let schema = crd.spec.versions[0]
        .schema
        .as_mut()
        .and_then(|schema| schema.open_api_v3_schema.as_mut())
        .expect("derived CRD must carry an OpenAPI schema");
    schema.x_kubernetes_validations = Some(
        rules
            .iter()
            .map(|(rule, message)| ValidationRule {
                rule: (*rule).to_string(),
                message: Some((*message).to_string()),
                ..Default::default()
            })
            .collect(),
    );
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "thorax.backbone.dev",
    version = "v1alpha1",
    kind = "ThoraxVault",
    plural = "thoraxvaults",
    namespaced,
    status = "ThoraxVaultStatus",
    shortname = "tvault"
)]
#[serde(rename_all = "camelCase")]
pub struct ThoraxVaultSpec {
    pub source: VaultSource,
    pub identity: ManagedIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VaultSource {
    pub config_map_ref: ConfigMapKeyRef,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ConfigMapKeyRef {
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    #[schemars(length(min = 1, max = 253))]
    pub key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ManagedIdentity {
    #[schemars(length(min = 1, max = 253))]
    pub managed_secret_name: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ThoraxVaultStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "identityUserID")]
    pub identity_user_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_request_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "thorax.backbone.dev",
    version = "v1alpha1",
    kind = "ThoraxSecret",
    plural = "thoraxsecrets",
    namespaced,
    status = "ThoraxSecretStatus",
    shortname = "tsecret"
)]
#[serde(rename_all = "camelCase")]
pub struct ThoraxSecretSpec {
    pub vault_ref: LocalObjectReference,
    #[schemars(schema_with = "secret_data_schema")]
    pub data: BTreeMap<String, SecretMapping>,
    pub template: SecretTemplate,
    #[serde(default)]
    pub failure_policy: ProjectionPolicy,
    #[serde(default)]
    pub source_deletion_policy: ProjectionPolicy,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LocalObjectReference {
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ObjectReference {
    #[schemars(length(min = 1, max = 253))]
    pub name: String,
    #[schemars(length(min = 1, max = 128))]
    pub uid: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SecretMapping {
    /// Canonical Thorax selector syntax, for example `app/prod/db@env=prod`.
    #[schemars(length(min = 1, max = 1024))]
    pub selector: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 1024))]
    pub field: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SecretTemplate {
    #[serde(rename = "type")]
    #[schemars(length(min = 1, max = 253))]
    pub secret_type: String,
    #[serde(default)]
    pub metadata: SecretTemplateMetadata,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct SecretTemplateMetadata {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(schema_with = "label_map_schema")]
    pub labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(schema_with = "annotation_map_schema")]
    pub annotations: BTreeMap<String, String>,
}

fn secret_data_schema(generator: &mut SchemaGenerator) -> Schema {
    let mut schema = generator.subschema_for::<BTreeMap<String, SecretMapping>>();
    schema.insert("minProperties".into(), serde_json::json!(1));
    schema.insert("maxProperties".into(), serde_json::json!(MAX_DATA_MAPPINGS));
    schema
}

fn label_map_schema(generator: &mut SchemaGenerator) -> Schema {
    bounded_metadata_map_schema(generator, MAX_LABEL_VALUE_BYTES)
}

fn annotation_map_schema(generator: &mut SchemaGenerator) -> Schema {
    bounded_metadata_map_schema(generator, MAX_ANNOTATION_VALUE_BYTES)
}

fn bounded_metadata_map_schema(generator: &mut SchemaGenerator, max_value_bytes: usize) -> Schema {
    let mut schema = generator.subschema_for::<BTreeMap<String, String>>();
    schema.insert(
        "maxProperties".into(),
        serde_json::json!(MAX_METADATA_ENTRIES),
    );
    if let Some(serde_json::Value::Object(value_schema)) =
        schema.ensure_object().get_mut("additionalProperties")
    {
        value_schema.insert("maxLength".into(), serde_json::json!(max_value_bytes));
    }
    schema
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum ProjectionPolicy {
    #[default]
    Delete,
    Retain,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ThoraxSecretStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_vault_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<Condition>,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "thorax.backbone.dev",
    version = "v1alpha1",
    kind = "ThoraxJoinRequest",
    plural = "thoraxjoinrequests",
    namespaced,
    status = "ThoraxJoinRequestStatus",
    shortname = "tjoin"
)]
#[serde(rename_all = "camelCase")]
pub struct ThoraxJoinRequestSpec {
    pub vault_ref: LocalObjectReference,
    pub purpose: JoinPurpose,
    #[serde(rename = "requestID")]
    #[schemars(length(min = 1, max = 4096))]
    pub request_id: String,
    #[schemars(length(min = 1, max = 4096))]
    pub trusted_root: String,
    #[serde(rename = "userID")]
    #[schemars(length(min = 1, max = 4096))]
    pub user_id: String,
    #[schemars(length(min = 1, max = 4096))]
    pub signing_public_key: String,
    #[schemars(length(min = 1, max = 4096))]
    pub encryption_public_key: String,
    #[serde(default)]
    #[schemars(length(max = 256), inner(length(min = 1, max = 1024)))]
    pub suggested_selectors: Vec<String>,
    #[schemars(length(min = 1, max = 4096))]
    pub proof: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 262144))]
    pub entry_point: Option<String>,
    /// Base64 of the canonical `JoinCandidateStore` bytes. Mirrored fields above are
    /// reviewable indexes and must match this signed artifact exactly.
    #[schemars(length(min = 1, max = 262144))]
    pub artifact: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum JoinPurpose {
    Enroll,
    RestoreTrust,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ThoraxJoinRequestStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[kube(
    group = "thorax.backbone.dev",
    version = "v1alpha1",
    kind = "ThoraxJoinApproval",
    plural = "thoraxjoinapprovals",
    namespaced,
    shortname = "tapproval"
)]
#[serde(rename_all = "camelCase")]
pub struct ThoraxJoinApprovalSpec {
    pub request_ref: ObjectReference,
    pub purpose: JoinPurpose,
    #[serde(rename = "requestID")]
    #[schemars(length(min = 1, max = 4096))]
    pub request_id: String,
    #[schemars(length(min = 1, max = 4096))]
    pub trusted_root: String,
    #[serde(rename = "userID")]
    #[schemars(length(min = 1, max = 4096))]
    pub user_id: String,
    #[serde(default)]
    #[schemars(length(max = 256))]
    pub approved_grants: Vec<ReadGrantSpec>,
    #[schemars(length(min = 1, max = 262144))]
    pub encrypted_baseline: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(rename = "replacesUserID")]
    #[schemars(length(max = 4096))]
    pub replaces_user_id: Option<String>,
    #[schemars(length(min = 1, max = 4096))]
    pub approving_admin: String,
    #[schemars(length(min = 1, max = 4096))]
    pub signature: String,
    /// Base64 of the canonical `JoinApprovalStore` bytes.
    #[schemars(length(min = 1, max = 262144))]
    pub artifact: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct ReadGrantSpec {
    pub read: KeyspaceSelectorSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct KeyspaceSelectorSpec {
    pub tuple: TupleMatcherSpec,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[schemars(length(max = 64))]
    pub labels: BTreeMap<String, LabelMatcherSpec>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct TupleMatcherSpec {
    pub kind: TupleMatcherKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256), inner(length(max = 1024)))]
    pub values: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum TupleMatcherKind {
    Any,
    Exact,
    Prefix,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LabelMatcherSpec {
    pub kind: LabelMatcherKind,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 256), inner(length(max = 1024)))]
    pub values: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum LabelMatcherKind {
    Any,
    Equals,
    In,
    Absent,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApiError {
    #[error("{field} must be a valid non-empty Kubernetes object name")]
    InvalidObjectName { field: &'static str },
    #[error("at least one data mapping is required")]
    EmptyData,
    #[error("invalid Kubernetes Secret data key: {0}")]
    InvalidDataKey(String),
    #[error("selector for data key {0} is empty")]
    EmptySelector(String),
    #[error("invalid Thorax selector for data key {key}: {reason}")]
    InvalidSelector { key: String, reason: String },
    #[error("metadata key {0} uses the controller-reserved prefix")]
    ReservedMetadata(String),
    #[error("annotation {0} may request a Kubernetes-generated service-account credential")]
    ServiceAccountAnnotation(String),
    #[error("Kubernetes-generated Secret type {0} cannot be projected")]
    ForbiddenSecretType(String),
    #[error("Secret type {secret_type} requires data mapping {key}")]
    MissingTypedKey {
        secret_type: String,
        key: &'static str,
    },
    #[error("Enroll requests require a self-signed entry point")]
    MissingEntryPoint,
    #[error("RestoreTrust requests must not carry an entry point")]
    UnexpectedEntryPoint,
    #[error("RestoreTrust approvals cannot change grants or replace an identity")]
    InvalidRestoreTrustApproval,
    #[error("invalid canonical enrollment artifact: {0}")]
    InvalidArtifact(String),
    #[error("{field} exceeds its security limit of {max}")]
    LimitExceeded { field: &'static str, max: usize },
}

pub type Result<T> = std::result::Result<T, ApiError>;

impl ThoraxVaultSpec {
    pub fn validate(&self) -> Result<()> {
        validate_object_name("source.configMapRef.name", &self.source.config_map_ref.name)?;
        validate_object_name(
            "identity.managedSecretName",
            &self.identity.managed_secret_name,
        )?;
        if self.source.config_map_ref.key.is_empty() {
            return Err(ApiError::InvalidObjectName {
                field: "source.configMapRef.key",
            });
        }
        if !is_secret_data_key(&self.source.config_map_ref.key) {
            return Err(ApiError::InvalidObjectName {
                field: "source.configMapRef.key",
            });
        }
        Ok(())
    }
}

impl ThoraxSecretSpec {
    pub fn validate(&self) -> Result<()> {
        validate_object_name("vaultRef.name", &self.vault_ref.name)?;
        if self.data.is_empty() {
            return Err(ApiError::EmptyData);
        }
        check_count("data", self.data.len(), MAX_DATA_MAPPINGS)?;
        check_count(
            "template.metadata.labels",
            self.template.metadata.labels.len(),
            MAX_METADATA_ENTRIES,
        )?;
        check_count(
            "template.metadata.annotations",
            self.template.metadata.annotations.len(),
            MAX_METADATA_ENTRIES,
        )?;
        check_bytes("template.type", &self.template.secret_type, 253)?;
        for (key, mapping) in &self.data {
            if !is_secret_data_key(key) {
                return Err(ApiError::InvalidDataKey(key.clone()));
            }
            if mapping.selector.is_empty() {
                return Err(ApiError::EmptySelector(key.clone()));
            }
            check_bytes("data.selector", &mapping.selector, MAX_SELECTOR_BYTES)?;
            if let Some(field) = &mapping.field {
                check_bytes("data.field", field, MAX_FIELD_BYTES)?;
            }
            thorax_frontend::parse_secret_selector(&mapping.selector).map_err(|error| {
                ApiError::InvalidSelector {
                    key: key.clone(),
                    reason: error.to_string(),
                }
            })?;
        }
        for key in self
            .template
            .metadata
            .labels
            .keys()
            .chain(self.template.metadata.annotations.keys())
        {
            check_bytes("template.metadata.key", key, MAX_METADATA_KEY_BYTES)?;
            if key.starts_with("thorax.backbone.dev/") {
                return Err(ApiError::ReservedMetadata(key.clone()));
            }
        }
        for value in self.template.metadata.labels.values() {
            check_bytes(
                "template.metadata.labels.value",
                value,
                MAX_LABEL_VALUE_BYTES,
            )?;
        }
        for value in self.template.metadata.annotations.values() {
            check_bytes(
                "template.metadata.annotations.value",
                value,
                MAX_ANNOTATION_VALUE_BYTES,
            )?;
        }
        for key in self.template.metadata.annotations.keys() {
            if key.starts_with("kubernetes.io/service-account.") {
                return Err(ApiError::ServiceAccountAnnotation(key.clone()));
            }
        }
        validate_secret_type(&self.template.secret_type, &self.data)
    }
}

impl ThoraxJoinRequestSpec {
    pub fn validate(&self) -> Result<()> {
        validate_object_name("vaultRef.name", &self.vault_ref.name)?;
        validate_join_request_limits(self)?;
        match (self.purpose, self.entry_point.is_some()) {
            (JoinPurpose::Enroll, false) => Err(ApiError::MissingEntryPoint),
            (JoinPurpose::RestoreTrust, true) => Err(ApiError::UnexpectedEntryPoint),
            _ => Ok(()),
        }
    }

    pub fn from_candidate(
        candidate: &thorax_core::JoinCandidateV1,
    ) -> std::result::Result<Self, thorax_core::CoreError> {
        let artifact = thorax_core::encode_join_candidate(candidate)?;
        Ok(Self {
            vault_ref: LocalObjectReference {
                name: candidate.deployment.vault_name.clone(),
            },
            purpose: candidate.purpose.clone().into(),
            request_id: base64_encode(&candidate.request_id),
            trusted_root: hex_encode(&candidate.trusted_root.0),
            user_id: hex_encode(&(candidate.user_id.0).0),
            signing_public_key: base64_encode(&candidate.signing_public_key),
            encryption_public_key: base64_encode(&candidate.hpke_public_key),
            suggested_selectors: candidate
                .suggested_selectors
                .iter()
                .map(thorax_frontend::selector_string)
                .collect(),
            proof: base64_encode(&candidate.proof),
            entry_point: candidate
                .entry_point
                .as_ref()
                .map(cord::serialize)
                .transpose()?
                .map(|bytes| base64_encode(&bytes)),
            artifact: base64_encode(&artifact),
        })
    }

    pub fn candidate(
        &self,
        namespace: &str,
        vault_uid: &str,
    ) -> Result<thorax_core::JoinCandidateV1> {
        self.validate()?;
        let artifact = base64_decode(&self.artifact)?;
        let candidate = thorax_core::decode_join_candidate(&artifact)
            .map_err(|error| ApiError::InvalidArtifact(error.to_string()))?;
        let mirrored = Self::from_candidate(&candidate)
            .map_err(|error| ApiError::InvalidArtifact(error.to_string()))?;
        if mirrored.vault_ref != self.vault_ref
            || mirrored.purpose != self.purpose
            || mirrored.request_id != self.request_id
            || mirrored.trusted_root != self.trusted_root
            || mirrored.user_id != self.user_id
            || mirrored.signing_public_key != self.signing_public_key
            || mirrored.encryption_public_key != self.encryption_public_key
            || mirrored.suggested_selectors != self.suggested_selectors
            || mirrored.proof != self.proof
            || mirrored.entry_point != self.entry_point
            || candidate.deployment.namespace != namespace
            || candidate.deployment.vault_uid != vault_uid
        {
            return Err(ApiError::InvalidArtifact(
                "reviewable fields differ from the signed payload".into(),
            ));
        }
        Ok(candidate)
    }
}

impl ThoraxJoinApprovalSpec {
    pub fn validate(&self) -> Result<()> {
        validate_object_name("requestRef.name", &self.request_ref.name)?;
        check_bytes("requestRef.uid", &self.request_ref.uid, 128)?;
        check_count("approvedGrants", self.approved_grants.len(), MAX_GRANTS)?;
        for grant in &self.approved_grants {
            validate_selector_spec(&grant.read)?;
        }
        for (field, value) in [
            ("requestID", self.request_id.as_str()),
            ("trustedRoot", self.trusted_root.as_str()),
            ("userID", self.user_id.as_str()),
            ("approvingAdmin", self.approving_admin.as_str()),
            ("signature", self.signature.as_str()),
        ] {
            check_nonempty_bytes(field, value, MAX_REVIEW_FIELD_BYTES)?;
        }
        if let Some(user) = &self.replaces_user_id {
            check_bytes("replacesUserID", user, MAX_REVIEW_FIELD_BYTES)?;
        }
        check_nonempty_bytes(
            "encryptedBaseline",
            &self.encrypted_baseline,
            MAX_ARTIFACT_BYTES,
        )?;
        check_nonempty_bytes("artifact", &self.artifact, MAX_ARTIFACT_BYTES)?;
        if self.purpose == JoinPurpose::RestoreTrust
            && (!self.approved_grants.is_empty() || self.replaces_user_id.is_some())
        {
            return Err(ApiError::InvalidRestoreTrustApproval);
        }
        Ok(())
    }

    pub fn from_approval(
        approval: &thorax_core::JoinApprovalV1,
        request_ref: ObjectReference,
    ) -> std::result::Result<Self, thorax_core::CoreError> {
        let artifact = thorax_core::encode_join_approval(approval)?;
        Ok(Self {
            request_ref,
            purpose: approval.purpose.clone().into(),
            request_id: base64_encode(&approval.request_id),
            trusted_root: hex_encode(&approval.trusted_root.0),
            user_id: hex_encode(&(approval.user_id.0).0),
            approved_grants: approval
                .approved_grants
                .iter()
                .map(ReadGrantSpec::from_core)
                .collect::<std::result::Result<Vec<_>, _>>()?,
            encrypted_baseline: base64_encode(&cord::serialize(&approval.encrypted_baseline)?),
            replaces_user_id: approval
                .replaces_user_id
                .as_ref()
                .map(|user| hex_encode(&(user.0).0)),
            approving_admin: hex_encode(&(approval.approving_admin.0).0),
            signature: base64_encode(&approval.signature),
            artifact: base64_encode(&artifact),
        })
    }

    pub fn approval(&self) -> Result<thorax_core::JoinApprovalV1> {
        self.validate()?;
        let artifact = base64_decode(&self.artifact)?;
        let approval = thorax_core::decode_join_approval(&artifact)
            .map_err(|error| ApiError::InvalidArtifact(error.to_string()))?;
        let mirrored = Self::from_approval(&approval, self.request_ref.clone())
            .map_err(|error| ApiError::InvalidArtifact(error.to_string()))?;
        if &mirrored != self {
            return Err(ApiError::InvalidArtifact(
                "reviewable fields differ from the signed payload".into(),
            ));
        }
        Ok(approval)
    }
}

impl From<thorax_core::JoinPurposeV1> for JoinPurpose {
    fn from(value: thorax_core::JoinPurposeV1) -> Self {
        match value {
            thorax_core::JoinPurposeV1::Enroll => Self::Enroll,
            thorax_core::JoinPurposeV1::RestoreTrust => Self::RestoreTrust,
        }
    }
}

impl ReadGrantSpec {
    fn from_core(
        permission: &thorax_core::GrantPermissionV1,
    ) -> std::result::Result<Self, thorax_core::CoreError> {
        let thorax_core::GrantPermissionV1::ReadKeyspace(selector) = permission else {
            return Err(thorax_core::CoreError::Validation(
                "Kubernetes join approval contains non-read authority".into(),
            ));
        };
        Ok(Self {
            read: KeyspaceSelectorSpec::from_core(selector),
        })
    }
}

impl KeyspaceSelectorSpec {
    fn from_core(selector: &thorax_core::KeyspaceSelectorV1) -> Self {
        use thorax_core::{LabelMatcherV1, TupleMatcherV1};
        let tuple = match &selector.tuple {
            TupleMatcherV1::Any => TupleMatcherSpec {
                kind: TupleMatcherKind::Any,
                values: Vec::new(),
            },
            TupleMatcherV1::Exact(values) => TupleMatcherSpec {
                kind: TupleMatcherKind::Exact,
                values: values.clone(),
            },
            TupleMatcherV1::Prefix(values) => TupleMatcherSpec {
                kind: TupleMatcherKind::Prefix,
                values: values.clone(),
            },
        };
        let labels = selector
            .labels
            .iter()
            .map(|label| {
                let matcher = match &label.matcher {
                    LabelMatcherV1::Any => LabelMatcherSpec {
                        kind: LabelMatcherKind::Any,
                        values: Vec::new(),
                    },
                    LabelMatcherV1::Equals(value) => LabelMatcherSpec {
                        kind: LabelMatcherKind::Equals,
                        values: vec![value.clone()],
                    },
                    LabelMatcherV1::In(values) => LabelMatcherSpec {
                        kind: LabelMatcherKind::In,
                        values: values.clone(),
                    },
                    LabelMatcherV1::Absent => LabelMatcherSpec {
                        kind: LabelMatcherKind::Absent,
                        values: Vec::new(),
                    },
                };
                (label.key.clone(), matcher)
            })
            .collect();
        Self { tuple, labels }
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(value: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|error| ApiError::InvalidArtifact(error.to_string()))
}

fn validate_join_request_limits(spec: &ThoraxJoinRequestSpec) -> Result<()> {
    for (field, value) in [
        ("requestID", spec.request_id.as_str()),
        ("trustedRoot", spec.trusted_root.as_str()),
        ("userID", spec.user_id.as_str()),
        ("signingPublicKey", spec.signing_public_key.as_str()),
        ("encryptionPublicKey", spec.encryption_public_key.as_str()),
        ("proof", spec.proof.as_str()),
    ] {
        check_nonempty_bytes(field, value, MAX_REVIEW_FIELD_BYTES)?;
    }
    check_count(
        "suggestedSelectors",
        spec.suggested_selectors.len(),
        MAX_DATA_MAPPINGS,
    )?;
    for selector in &spec.suggested_selectors {
        check_nonempty_bytes("suggestedSelectors", selector, MAX_SELECTOR_BYTES)?;
    }
    if let Some(entry_point) = &spec.entry_point {
        check_bytes("entryPoint", entry_point, MAX_ARTIFACT_BYTES)?;
    }
    check_nonempty_bytes("artifact", &spec.artifact, MAX_ARTIFACT_BYTES)
}

fn validate_selector_spec(spec: &KeyspaceSelectorSpec) -> Result<()> {
    check_count(
        "grant.tuple.values",
        spec.tuple.values.len(),
        MAX_MATCHER_VALUES,
    )?;
    for value in &spec.tuple.values {
        check_bytes("grant.tuple.values", value, MAX_SELECTOR_BYTES)?;
    }
    check_count("grant.labels", spec.labels.len(), MAX_METADATA_ENTRIES)?;
    for (key, matcher) in &spec.labels {
        check_bytes("grant.labels.key", key, MAX_SELECTOR_BYTES)?;
        check_count(
            "grant.labels.values",
            matcher.values.len(),
            MAX_MATCHER_VALUES,
        )?;
        for value in &matcher.values {
            check_bytes("grant.labels.values", value, MAX_SELECTOR_BYTES)?;
        }
    }
    Ok(())
}

fn check_nonempty_bytes(field: &'static str, value: &str, max: usize) -> Result<()> {
    if value.is_empty() {
        return Err(ApiError::LimitExceeded { field, max });
    }
    check_bytes(field, value, max)
}

fn check_bytes(field: &'static str, value: &str, max: usize) -> Result<()> {
    check_count(field, value.len(), max)
}

fn check_count(field: &'static str, actual: usize, max: usize) -> Result<()> {
    if actual > max {
        Err(ApiError::LimitExceeded { field, max })
    } else {
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validate_secret_type(secret_type: &str, data: &BTreeMap<String, SecretMapping>) -> Result<()> {
    if secret_type == "kubernetes.io/service-account-token"
        || secret_type == "bootstrap.kubernetes.io/token"
    {
        return Err(ApiError::ForbiddenSecretType(secret_type.to_string()));
    }
    let required: &[&'static str] = match secret_type {
        "kubernetes.io/basic-auth" => &["username", "password"],
        "kubernetes.io/tls" => &["tls.crt", "tls.key"],
        "kubernetes.io/dockerconfigjson" => &[".dockerconfigjson"],
        "kubernetes.io/ssh-auth" => &["ssh-privatekey"],
        _ => &[],
    };
    for key in required {
        if !data.contains_key(*key) {
            return Err(ApiError::MissingTypedKey {
                secret_type: secret_type.to_string(),
                key,
            });
        }
    }
    Ok(())
}

fn validate_object_name(field: &'static str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        });
    if valid {
        Ok(())
    } else {
        Err(ApiError::InvalidObjectName { field })
    }
}

fn is_secret_data_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mapping(selector: &str) -> SecretMapping {
        SecretMapping {
            selector: selector.to_string(),
            field: None,
        }
    }

    #[test]
    fn policies_default_to_delete() {
        let spec: ThoraxSecretSpec = serde_yaml::from_str(
            r#"
vaultRef: { name: payments }
data:
  username: { selector: db/prod/app, field: username }
  password: { selector: db/prod/app }
template:
  type: kubernetes.io/basic-auth
"#,
        )
        .unwrap();
        assert_eq!(spec.failure_policy, ProjectionPolicy::Delete);
        assert_eq!(spec.source_deletion_policy, ProjectionPolicy::Delete);
        spec.validate().unwrap();
    }

    #[test]
    fn public_yaml_uses_the_documented_id_and_policy_fields() {
        let yaml = serde_yaml::to_string(&ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "payments".into(),
            },
            data: BTreeMap::from([
                (
                    "username".into(),
                    SecretMapping {
                        selector: "db/prod/app".into(),
                        field: Some("username".into()),
                    },
                ),
                ("password".into(), mapping("db/prod/app")),
            ]),
            template: SecretTemplate {
                secret_type: "kubernetes.io/basic-auth".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        })
        .unwrap();
        assert!(yaml.contains("vaultRef:"));
        assert!(yaml.contains("failurePolicy: Delete"));
        assert!(yaml.contains("sourceDeletionPolicy: Delete"));

        let status = ThoraxVaultStatus {
            identity_user_id: Some("user".into()),
            ..Default::default()
        };
        assert!(serde_yaml::to_string(&status)
            .unwrap()
            .contains("identityUserID: user"));
    }

    #[test]
    fn typed_secret_shape_is_validated() {
        let spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "payments".into(),
            },
            data: BTreeMap::from([("password".into(), mapping("db/prod/app"))]),
            template: SecretTemplate {
                secret_type: "kubernetes.io/basic-auth".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        assert!(matches!(
            spec.validate(),
            Err(ApiError::MissingTypedKey {
                key: "username",
                ..
            })
        ));
    }

    #[test]
    fn generated_credentials_and_reserved_metadata_are_rejected() {
        let mut spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "payments".into(),
            },
            data: BTreeMap::from([("token".into(), mapping("cluster/token"))]),
            template: SecretTemplate {
                secret_type: "kubernetes.io/service-account-token".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        assert!(matches!(
            spec.validate(),
            Err(ApiError::ForbiddenSecretType(_))
        ));
        spec.template.secret_type = "Opaque".into();
        spec.template
            .metadata
            .annotations
            .insert(VAULT_ANNOTATION.into(), "forged".into());
        assert!(matches!(
            spec.validate(),
            Err(ApiError::ReservedMetadata(_))
        ));
        spec.template.metadata.annotations.clear();
        spec.template.metadata.annotations.insert(
            "kubernetes.io/service-account.name".into(),
            "privileged".into(),
        );
        assert!(matches!(
            spec.validate(),
            Err(ApiError::ServiceAccountAnnotation(_))
        ));
    }

    #[test]
    fn selectors_are_parsed_and_non_read_approval_grants_are_unrepresentable() {
        let mut spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "team.example".into(),
            },
            data: BTreeMap::from([("value".into(), mapping("app//db"))]),
            template: SecretTemplate {
                secret_type: "Opaque".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        assert!(matches!(
            spec.validate(),
            Err(ApiError::InvalidSelector { .. })
        ));
        spec.data.get_mut("value").unwrap().selector = "app/db".into();
        spec.validate().unwrap();

        assert!(
            ReadGrantSpec::from_core(&thorax_core::GrantPermissionV1::WriteKeyspace(
                thorax_core::KeyspaceSelectorV1::all(),
            ))
            .is_err()
        );
    }

    #[test]
    fn restore_trust_has_no_authority_mutation() {
        let approval = ThoraxJoinApprovalSpec {
            request_ref: ObjectReference {
                name: "payments-request".into(),
                uid: "uid".into(),
            },
            purpose: JoinPurpose::RestoreTrust,
            request_id: "request".into(),
            trusted_root: "root".into(),
            user_id: "user".into(),
            approved_grants: vec![ReadGrantSpec {
                read: KeyspaceSelectorSpec {
                    tuple: TupleMatcherSpec {
                        kind: TupleMatcherKind::Any,
                        values: Vec::new(),
                    },
                    labels: BTreeMap::new(),
                },
            }],
            encrypted_baseline: "baseline".into(),
            replaces_user_id: None,
            approving_admin: "admin".into(),
            signature: "signature".into(),
            artifact: "artifact".into(),
        };
        assert_eq!(
            approval.validate(),
            Err(ApiError::InvalidRestoreTrustApproval)
        );
    }

    #[test]
    fn all_crds_are_namespaced_and_structural() {
        for crd in crds() {
            assert_eq!(crd.spec.scope, "Namespaced");
            assert_eq!(crd.spec.group, API_GROUP);
            assert_eq!(crd.spec.versions.len(), 1);
            assert!(crd.spec.versions[0].schema.is_some());
        }
    }

    #[test]
    fn admission_rules_cover_immutability_and_secure_secret_shapes() {
        let generated = crds();
        let rules = generated
            .iter()
            .flat_map(|crd| {
                crd.spec.versions[0]
                    .schema
                    .as_ref()
                    .unwrap()
                    .open_api_v3_schema
                    .as_ref()
                    .unwrap()
                    .x_kubernetes_validations
                    .as_ref()
                    .unwrap()
            })
            .map(|rule| rule.rule.as_str())
            .collect::<Vec<_>>();
        assert!(rules.contains(&"self.spec == oldSelf.spec"));
        assert!(rules
            .iter()
            .any(|rule| rule.contains("service-account-token")));
        assert!(rules.iter().any(|rule| rule.contains("basic-auth")));
        assert!(rules.iter().any(|rule| {
            rule.contains("labels.all(key,") && rule.contains("metadata.labels[key]")
        }));
        assert!(rules.iter().any(|rule| {
            rule.contains("annotations.all(key,") && rule.contains("metadata.annotations[key]")
        }));
        assert!(rules.iter().all(|rule| !rule.contains("all(key, value,")));
    }

    #[test]
    fn attacker_controlled_collections_and_artifacts_are_bounded() {
        let mut spec = ThoraxSecretSpec {
            vault_ref: LocalObjectReference {
                name: "payments".into(),
            },
            data: BTreeMap::new(),
            template: SecretTemplate {
                secret_type: "Opaque".into(),
                metadata: SecretTemplateMetadata::default(),
            },
            failure_policy: ProjectionPolicy::Delete,
            source_deletion_policy: ProjectionPolicy::Delete,
        };
        for index in 0..=MAX_DATA_MAPPINGS {
            spec.data
                .insert(format!("key-{index}"), mapping("db/prod/app"));
        }
        assert_eq!(
            spec.validate(),
            Err(ApiError::LimitExceeded {
                field: "data",
                max: MAX_DATA_MAPPINGS,
            })
        );

        spec.data.clear();
        spec.data.insert("value".into(), mapping("db/prod/app"));
        spec.template.metadata.labels.insert(
            "example.com/label".into(),
            "x".repeat(MAX_LABEL_VALUE_BYTES + 1),
        );
        assert_eq!(
            spec.validate(),
            Err(ApiError::LimitExceeded {
                field: "template.metadata.labels.value",
                max: MAX_LABEL_VALUE_BYTES,
            })
        );
        spec.template.metadata.labels.clear();
        spec.template.metadata.annotations.insert(
            "example.com/annotation".into(),
            "x".repeat(MAX_ANNOTATION_VALUE_BYTES + 1),
        );
        assert_eq!(
            spec.validate(),
            Err(ApiError::LimitExceeded {
                field: "template.metadata.annotations.value",
                max: MAX_ANNOTATION_VALUE_BYTES,
            })
        );

        let request = ThoraxJoinRequestSpec {
            vault_ref: LocalObjectReference {
                name: "payments".into(),
            },
            purpose: JoinPurpose::Enroll,
            request_id: "request".into(),
            trusted_root: "root".into(),
            user_id: "user".into(),
            signing_public_key: "signing".into(),
            encryption_public_key: "encryption".into(),
            suggested_selectors: Vec::new(),
            proof: "proof".into(),
            entry_point: Some("entry".into()),
            artifact: "x".repeat(MAX_ARTIFACT_BYTES + 1),
        };
        assert_eq!(
            request.validate(),
            Err(ApiError::LimitExceeded {
                field: "artifact",
                max: MAX_ARTIFACT_BYTES,
            })
        );

        let generated = ThoraxSecret::crd();
        let spec_schema = generated.spec.versions[0]
            .schema
            .as_ref()
            .unwrap()
            .open_api_v3_schema
            .as_ref()
            .unwrap()
            .properties
            .as_ref()
            .unwrap()["spec"]
            .properties
            .as_ref()
            .unwrap();
        assert_eq!(spec_schema["data"].max_properties, Some(256));
    }
}
