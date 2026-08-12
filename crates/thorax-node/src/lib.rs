//! napi-rs bindings for Thorax.

#![allow(non_snake_case)]

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use napi::bindgen_prelude::{AsyncTask, Buffer, Either, Either3, Uint8Array};
use napi::{Env, Error, JsObject, Result, Status, Task};
use napi_derive::napi;
use thorax_frontend::{parse_secret_selector, resolve_cli_user_ref_with_report, selector_string};
use thorax_ops::{
    ensure_ratchet_from_invite, AutoKeychain, Crypto, Identity, Invite, KeyUsePurpose,
    KeyspaceLabelMatcherV1, KeyspaceSelectorV1, LabelMatcherV1, LockedSession,
    NoManualIdentityProvider, OpsError, PassphraseKeychain, SecretLabelV1, SecretSelectorV1,
    StaticPassphraseProvider, TupleMatcherV1, UnlockedSession, WorkspacePaths, INVITE_MAGIC,
    MAX_INVITE_BYTES,
};

type SessionCell = Arc<Mutex<Option<UnlockedSession>>>;

#[derive(Clone)]
enum AuthInner {
    Keychain {
        user: Option<String>,
        passphrase: Option<String>,
    },
    Invite(BundleMaterial),
    Env {
        invite: String,
        invite_file: String,
    },
}

#[derive(Clone)]
enum BundleMaterial {
    Text(String),
    Bytes(Vec<u8>),
}

#[napi]
#[derive(Clone)]
pub struct Auth {
    inner: AuthInner,
}

#[napi]
impl Auth {
    #[napi(factory)]
    pub fn from_keychain(config: Option<KeychainConfig>) -> Self {
        let config = config.unwrap_or_default();
        Self {
            inner: AuthInner::Keychain {
                user: config.user,
                passphrase: config.passphrase,
            },
        }
    }

    #[napi(factory)]
    pub fn from_invite(invite: Either<String, Buffer>) -> Self {
        Self {
            inner: AuthInner::Invite(material_from_either(invite)),
        }
    }

    #[napi(factory)]
    pub fn from_env(config: Option<EnvConfig>) -> Self {
        let config = config.unwrap_or_default();
        Self {
            inner: AuthInner::Env {
                invite: config
                    .invite
                    .unwrap_or_else(|| thorax_frontend::INVITE_ENV.to_string()),
                invite_file: config
                    .inviteFile
                    .unwrap_or_else(|| thorax_frontend::INVITE_FILE_ENV.to_string()),
            },
        }
    }

    #[napi(js_name = "toString")]
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        match self.inner {
            AuthInner::Keychain { .. } => "Auth.fromKeychain(...)",
            AuthInner::Invite { .. } => "Auth.fromInvite(...)",
            AuthInner::Env { .. } => "Auth.fromEnv(...)",
        }
        .to_string()
    }
}

#[napi(object)]
#[derive(Default)]
pub struct KeychainConfig {
    pub user: Option<String>,
    pub passphrase: Option<String>,
}

#[napi(object)]
#[derive(Default)]
#[allow(non_snake_case)]
pub struct EnvConfig {
    pub invite: Option<String>,
    pub inviteFile: Option<String>,
}

#[napi(object)]
#[derive(Clone)]
pub struct Selector {
    pub path: Vec<String>,
    pub labels: Option<BTreeMap<String, String>>,
}

#[napi(object)]
#[allow(non_snake_case)]
pub struct GetOptions {
    pub asBuffer: Option<bool>,
}

#[napi]
pub struct Vault {
    session: SessionCell,
    path: String,
    vault_path: String,
}

#[napi]
impl Vault {
    #[napi]
    pub fn open(env: Env, config: Option<JsObject>) -> Result<AsyncTask<OpenTask>> {
        let (path, auth) = open_config_from_js(&env, config)?;
        Ok(AsyncTask::new(OpenTask { path, auth }))
    }

    #[napi(getter)]
    pub fn path(&self) -> String {
        self.path.clone()
    }

    #[napi(getter)]
    pub fn vault_path(&self) -> String {
        self.vault_path.clone()
    }

    #[napi]
    pub fn get(
        &self,
        selector: Either<String, Selector>,
        options: Option<GetOptions>,
    ) -> Result<AsyncTask<GetTask>> {
        let (selector, display) = selector_from_js(selector)?;
        Ok(AsyncTask::new(GetTask {
            session: Arc::clone(&self.session),
            selector,
            display,
            as_buffer: options
                .and_then(|options| options.asBuffer)
                .unwrap_or(false),
        }))
    }

    #[napi]
    pub fn set(
        &self,
        selector: Either<String, Selector>,
        value: Either3<String, Buffer, Uint8Array>,
    ) -> Result<AsyncTask<SetTask>> {
        let (selector, display) = selector_from_js(selector)?;
        let value = secret_value_from_js(value);
        Ok(AsyncTask::new(SetTask {
            session: Arc::clone(&self.session),
            selector,
            display,
            value,
        }))
    }

    #[napi]
    pub fn delete(&self, selector: Either<String, Selector>) -> Result<AsyncTask<DeleteTask>> {
        let (selector, display) = selector_from_js(selector)?;
        Ok(AsyncTask::new(DeleteTask {
            session: Arc::clone(&self.session),
            selector,
            display,
        }))
    }

    /// The secret's additional key→value fields as an object. Values are strings (UTF-8) or, with
    /// `{ asBuffer: true }`, Buffers.
    #[napi]
    pub fn fields(
        &self,
        selector: Either<String, Selector>,
        options: Option<GetOptions>,
    ) -> Result<AsyncTask<FieldsTask>> {
        let (selector, display) = selector_from_js(selector)?;
        Ok(AsyncTask::new(FieldsTask {
            session: Arc::clone(&self.session),
            selector,
            display,
            as_buffer: options
                .and_then(|options| options.asBuffer)
                .unwrap_or(false),
        }))
    }

    /// One additional field's value, as a string (UTF-8) or, with `{ asBuffer: true }`, a Buffer.
    #[napi]
    pub fn getField(
        &self,
        selector: Either<String, Selector>,
        key: String,
        options: Option<GetOptions>,
    ) -> Result<AsyncTask<GetFieldTask>> {
        let (selector, display) = selector_from_js(selector)?;
        Ok(AsyncTask::new(GetFieldTask {
            session: Arc::clone(&self.session),
            selector,
            display,
            key,
            as_buffer: options
                .and_then(|options| options.asBuffer)
                .unwrap_or(false),
        }))
    }

    /// Insert or replace one additional field, preserving the primary value and other fields.
    #[napi]
    pub fn setField(
        &self,
        selector: Either<String, Selector>,
        key: String,
        value: Either3<String, Buffer, Uint8Array>,
    ) -> Result<AsyncTask<SetFieldTask>> {
        let (selector, display) = selector_from_js(selector)?;
        Ok(AsyncTask::new(SetFieldTask {
            session: Arc::clone(&self.session),
            selector,
            display,
            key,
            value: secret_value_from_js(value),
        }))
    }

    /// Remove one additional field, preserving the primary value and other fields.
    #[napi]
    pub fn deleteField(
        &self,
        selector: Either<String, Selector>,
        key: String,
    ) -> Result<AsyncTask<DeleteFieldTask>> {
        let (selector, display) = selector_from_js(selector)?;
        Ok(AsyncTask::new(DeleteFieldTask {
            session: Arc::clone(&self.session),
            selector,
            display,
            key,
        }))
    }

    #[napi]
    pub fn list(&self, selector: Option<Either<String, Selector>>) -> Result<AsyncTask<ListTask>> {
        let filter = selector.map(selector_from_js).transpose()?.map(|(s, _)| s);
        Ok(AsyncTask::new(ListTask {
            session: Arc::clone(&self.session),
            filter,
        }))
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| js_error("internal", "Thorax vault session lock is poisoned"))?;
        *session = None;
        Ok(())
    }
}

pub struct OpenTask {
    path: String,
    auth: AuthInner,
}

pub struct OpenedVault {
    session: UnlockedSession,
    paths: WorkspacePaths,
}

impl Task for OpenTask {
    type Output = OpenedVault;
    type JsValue = Vault;

    fn compute(&mut self) -> Result<Self::Output> {
        let paths = paths_from_thorax_dir(&self.path);
        let session = open_session(&paths, self.auth.clone())?;
        Ok(OpenedVault { session, paths })
    }

    fn resolve(&mut self, _env: Env, opened: Self::Output) -> Result<Self::JsValue> {
        let path = opened.paths.thorax_dir.display().to_string();
        let vault_path = opened.paths.vault_path.display().to_string();
        Ok(Vault {
            session: Arc::new(Mutex::new(Some(opened.session))),
            path,
            vault_path,
        })
    }
}

pub struct GetTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
    as_buffer: bool,
}

pub struct GetOutput {
    bytes: Vec<u8>,
    as_buffer: bool,
}

impl Task for GetTask {
    type Output = GetOutput;
    type JsValue = Either<String, Buffer>;

    fn compute(&mut self) -> Result<Self::Output> {
        let bytes = with_session(&self.session, |session| {
            session
                .get_secret(&Crypto, self.selector.clone())
                .map(|secret| secret.plaintext.as_slice().to_vec())
                .map_err(|error| secret_error(error, &self.display))
        })?;
        Ok(GetOutput {
            bytes,
            as_buffer: self.as_buffer,
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        if output.as_buffer {
            Ok(Either::B(Buffer::from(output.bytes)))
        } else {
            String::from_utf8(output.bytes)
                .map(Either::A)
                .map_err(|_| js_error("invalid_utf8", "secret is not valid UTF-8"))
        }
    }
}

pub struct SetTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
    value: Vec<u8>,
}

impl Task for SetTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            session
                .set_secret(&Crypto, self.selector.clone(), &self.value)
                .map(|_| ())
                .map_err(|error| secret_error(error, &self.display))
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct FieldsTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
    as_buffer: bool,
}

impl Task for FieldsTask {
    type Output = Vec<(String, Vec<u8>)>;
    type JsValue = std::collections::HashMap<String, Either<String, Buffer>>;

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            session
                .get_secret(&Crypto, self.selector.clone())
                .map(|secret| {
                    secret
                        .fields
                        .iter()
                        .map(|field| (field.key.clone(), field.value.as_slice().to_vec()))
                        .collect()
                })
                .map_err(|error| secret_error(error, &self.display))
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        output
            .into_iter()
            .map(|(key, value)| Ok((key, field_js_value(value, self.as_buffer)?)))
            .collect()
    }
}

pub struct GetFieldTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
    key: String,
    as_buffer: bool,
}

impl Task for GetFieldTask {
    type Output = Vec<u8>;
    type JsValue = Either<String, Buffer>;

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            let opened = session
                .get_secret(&Crypto, self.selector.clone())
                .map_err(|error| secret_error(error, &self.display))?;
            opened
                .field(&self.key)
                .map(|field| field.value.as_slice().to_vec())
                .ok_or_else(|| {
                    js_error(
                        "not_found",
                        format!("secret {} has no field {:?}", self.display, self.key),
                    )
                })
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        field_js_value(output, self.as_buffer)
    }
}

pub struct SetFieldTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
    key: String,
    value: Vec<u8>,
}

impl Task for SetFieldTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            let previous = session
                .get_secret(&Crypto, self.selector.clone())
                .map_err(|error| secret_error(error, &self.display))?;
            session
                .set_secret_value(
                    &Crypto,
                    self.selector.clone(),
                    previous.with_field(self.key.clone(), self.value.clone()),
                )
                .map(|_| ())
                .map_err(|error| secret_error(error, &self.display))
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct DeleteFieldTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
    key: String,
}

impl Task for DeleteFieldTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            let previous = session
                .get_secret(&Crypto, self.selector.clone())
                .map_err(|error| secret_error(error, &self.display))?;
            if previous.field(&self.key).is_none() {
                return Err(js_error(
                    "not_found",
                    format!("secret {} has no field {:?}", self.display, self.key),
                ));
            }
            session
                .set_secret_value(
                    &Crypto,
                    self.selector.clone(),
                    previous.without_field(&self.key),
                )
                .map(|_| ())
                .map_err(|error| secret_error(error, &self.display))
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct DeleteTask {
    session: SessionCell,
    selector: SecretSelectorV1,
    display: String,
}

impl Task for DeleteTask {
    type Output = ();
    type JsValue = ();

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            session
                .delete_secret(&Crypto, self.selector.clone())
                .map(|_| ())
                .map_err(|error| secret_error(error, &self.display))
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

pub struct ListTask {
    session: SessionCell,
    filter: Option<SecretSelectorV1>,
}

impl Task for ListTask {
    type Output = Vec<Selector>;
    type JsValue = Vec<Selector>;

    fn compute(&mut self) -> Result<Self::Output> {
        with_session(&self.session, |session| {
            let mut selectors: Vec<Selector> = session
                .effective()
                .secret_records()
                .into_iter()
                .map(|record| record.value.selector)
                .filter(|candidate| {
                    self.filter
                        .as_ref()
                        .is_none_or(|filter| selector_is_under(candidate, filter))
                })
                .map(selector_from_secret_selector)
                .collect();
            selectors.sort_by_key(selector_display);
            Ok(selectors)
        })
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

fn paths_from_thorax_dir(path: impl Into<PathBuf>) -> WorkspacePaths {
    WorkspacePaths::from_vault_path(path.into().join("vault.cord"))
}

fn open_config_from_js(env: &Env, config: Option<JsObject>) -> Result<(String, AuthInner)> {
    let default_auth = || AuthInner::Keychain {
        user: None,
        passphrase: None,
    };
    let Some(config) = config else {
        return Ok((".thorax".to_string(), default_auth()));
    };

    let path = config
        .get_named_property::<Option<String>>("path")?
        .unwrap_or_else(|| ".thorax".to_string());
    let auth = match config.get_named_property::<Option<JsObject>>("auth")? {
        Some(auth_object) => env.unwrap::<Auth>(&auth_object)?.inner.clone(),
        None => default_auth(),
    };

    Ok((path, auth))
}

fn open_session(paths: &WorkspacePaths, auth: AuthInner) -> Result<UnlockedSession> {
    let session = match auth {
        AuthInner::Keychain { user, passphrase } => open_with_keychain(paths, user, passphrase),
        AuthInner::Invite(invite) => open_with_invite(paths, invite),
        AuthInner::Env {
            invite,
            invite_file,
        } => {
            let invite = auth_from_env(&invite, &invite_file)?;
            open_with_invite(paths, invite)
        }
    }?;
    ensure_no_sdk_conflicts(session.effective())?;
    Ok(session)
}

fn ensure_no_sdk_conflicts(effective: &thorax_ops::EffectiveState) -> Result<()> {
    let count = effective.conflicted.len();
    if count == 0 {
        Ok(())
    } else {
        Err(js_error(
            "conflict",
            format!(
                "vault has {count} unresolved conflict(s); resolve conflicts before using the Thorax Node SDK"
            ),
        ))
    }
}

fn open_with_keychain(
    paths: &WorkspacePaths,
    user: Option<String>,
    passphrase: Option<String>,
) -> Result<UnlockedSession> {
    let locked = LockedSession::load(paths, &Crypto).map_err(js_from_display)?;
    let user = resolve_cli_user_ref_with_report(paths, locked.report(), &Crypto, user.as_deref())
        .map_err(js_from_display)?;
    let purpose = KeyUsePurpose::SignAdminChange {
        summary: "use this identity from the Thorax Node SDK".to_string(),
    };
    match passphrase {
        Some(passphrase) => {
            let base_dir = PassphraseKeychain::<StaticPassphraseProvider>::default_base_dir()
                .map_err(js_from_display)?;
            let keychain = AutoKeychain::new(
                PassphraseKeychain::new(base_dir, StaticPassphraseProvider::new(passphrase)),
                NoManualIdentityProvider,
            );
            UnlockedSession::promote(locked, &Crypto, &keychain, &user.resolved.user_id, purpose)
                .map_err(js_from_display)
        }
        None => {
            let keychain = AutoKeychain::default_interactive().map_err(js_from_display)?;
            UnlockedSession::promote(locked, &Crypto, &keychain, &user.resolved.user_id, purpose)
                .map_err(js_from_display)
        }
    }
}

fn open_with_invite(paths: &WorkspacePaths, invite: BundleMaterial) -> Result<UnlockedSession> {
    let invite = parse_invite(invite)?;
    ensure_ratchet_from_invite(paths, &Crypto, &invite).map_err(js_from_display)?;
    let identity =
        Identity::from_master_seed(&Crypto, &invite.master_seed).map_err(js_from_display)?;
    let locked = LockedSession::load(paths, &Crypto).map_err(js_from_display)?;
    UnlockedSession::with_identity(locked, &Crypto, identity).map_err(js_from_display)
}

fn auth_from_env(invite_var: &str, invite_file_var: &str) -> Result<BundleMaterial> {
    let invite = env_material(invite_var, invite_file_var, true)?;
    let invite = invite.ok_or_else(|| {
        js_error(
            "identity",
            format!("neither {invite_var} nor {invite_file_var} is set"),
        )
    })?;
    Ok(invite)
}

fn env_material(
    string_var: &str,
    file_var: &str,
    required: bool,
) -> Result<Option<BundleMaterial>> {
    let string = env::var(string_var).ok();
    let file = env::var_os(file_var).map(PathBuf::from);
    match (string, file) {
        (Some(_), Some(_)) => Err(js_error(
            "identity",
            format!("set only one of {string_var} or {file_var}"),
        )),
        (Some(value), None) => Ok(Some(BundleMaterial::Text(value))),
        (None, Some(path)) => read_bundle_file(&path).map(Some),
        (None, None) if required => Ok(None),
        (None, None) => Ok(None),
    }
}

fn read_bundle_file(path: &Path) -> Result<BundleMaterial> {
    let bytes = thorax_ops::read_file_bounded(path, MAX_INVITE_BYTES).map_err(|source| {
        js_error(
            "identity",
            format!("failed to read {}: {source}", path.display()),
        )
    })?;
    Ok(BundleMaterial::Bytes(bytes))
}

fn parse_invite(material: BundleMaterial) -> Result<thorax_ops::InviteV1> {
    match material {
        BundleMaterial::Text(text) => {
            thorax_frontend::read_invite(Some(text), None).map_err(js_from_display)
        }
        BundleMaterial::Bytes(bytes) => {
            let payload = bytes
                .strip_prefix(INVITE_MAGIC)
                .ok_or_else(|| js_error("identity", "invite file is missing its magic prefix"))?;
            match cord::deserialize::<Invite>(payload).map_err(js_from_display)? {
                Invite::V1(invite) => Ok(invite),
            }
        }
    }
}

fn material_from_either(value: Either<String, Buffer>) -> BundleMaterial {
    match value {
        Either::A(text) => BundleMaterial::Text(text),
        Either::B(bytes) => BundleMaterial::Bytes(bytes.to_vec()),
    }
}

fn selector_from_js(value: Either<String, Selector>) -> Result<(SecretSelectorV1, String)> {
    match value {
        Either::A(text) => {
            let selector = parse_secret_selector(&text).map_err(js_from_display)?;
            let display = selector_string(&selector);
            Ok((selector, display))
        }
        Either::B(selector) => {
            let selector = selector_to_secret_selector(selector)?;
            let display = selector_string(&selector);
            Ok((selector, display))
        }
    }
}

fn selector_to_secret_selector(selector: Selector) -> Result<SecretSelectorV1> {
    if selector.path.is_empty() || selector.path.iter().any(|part| part.is_empty()) {
        return Err(js_error(
            "invalid_input",
            "selector path must contain at least one non-empty segment",
        ));
    }
    let labels = selector.labels.unwrap_or_default();
    if labels
        .iter()
        .any(|(key, value)| key.is_empty() || value.is_empty())
    {
        return Err(js_error(
            "invalid_input",
            "selector label names and values must be non-empty",
        ));
    }
    Ok(SecretSelectorV1 {
        tuple: selector.path,
        labels: labels
            .into_iter()
            .map(|(key, value)| SecretLabelV1 { key, value })
            .collect(),
    })
}

/// Render a decrypted field value for JS: a Buffer when `as_buffer`, else a string (erroring if
/// the value is not valid UTF-8) — mirrors `Vault.get`.
fn field_js_value(value: Vec<u8>, as_buffer: bool) -> Result<Either<String, Buffer>> {
    if as_buffer {
        Ok(Either::B(Buffer::from(value)))
    } else {
        String::from_utf8(value)
            .map(Either::A)
            .map_err(|_| js_error("invalid_utf8", "field value is not valid UTF-8"))
    }
}

fn selector_from_secret_selector(selector: SecretSelectorV1) -> Selector {
    Selector {
        path: selector.tuple,
        labels: if selector.labels.is_empty() {
            None
        } else {
            Some(
                selector
                    .labels
                    .into_iter()
                    .map(|label| (label.key, label.value))
                    .collect(),
            )
        },
    }
}

fn selector_display(selector: &Selector) -> String {
    let selector = SecretSelectorV1 {
        tuple: selector.path.clone(),
        labels: selector
            .labels
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(key, value)| SecretLabelV1 { key, value })
            .collect(),
    };
    selector_string(&selector)
}

/// A secret value is opaque bytes: a JS string is encoded as UTF-8, a Buffer/Uint8Array is
/// taken verbatim. How it reads back (string vs Buffer) is the caller's choice at `get`.
fn secret_value_from_js(value: Either3<String, Buffer, Uint8Array>) -> Vec<u8> {
    match value {
        Either3::A(text) => text.into_bytes(),
        Either3::B(bytes) => bytes.to_vec(),
        Either3::C(bytes) => bytes.to_vec(),
    }
}

fn selector_is_under(candidate: &SecretSelectorV1, filter: &SecretSelectorV1) -> bool {
    let query = KeyspaceSelectorV1 {
        tuple: TupleMatcherV1::Prefix(filter.tuple.clone()),
        labels: filter
            .labels
            .iter()
            .map(|label| KeyspaceLabelMatcherV1 {
                key: label.key.clone(),
                matcher: LabelMatcherV1::Equals(label.value.clone()),
            })
            .collect(),
    };
    thorax_ops::selector_matches(&query, candidate)
}

fn with_session<T>(
    session: &SessionCell,
    op: impl FnOnce(&mut UnlockedSession) -> Result<T>,
) -> Result<T> {
    let mut guard = session
        .lock()
        .map_err(|_| js_error("internal", "Thorax vault session lock is poisoned"))?;
    let session = guard
        .as_mut()
        .ok_or_else(|| js_error("closed", "Thorax vault is closed"))?;
    op(session)
}

fn js_error(code: &'static str, message: impl std::fmt::Display) -> Error {
    Error::new(Status::GenericFailure, format!("{code}: {message}"))
}

fn js_from_display(error: impl std::fmt::Display + std::fmt::Debug + 'static) -> Error {
    let message = error.to_string();
    if message.contains("validation failed") {
        js_error("validation", message)
    } else if message.contains("keychain")
        || message.contains("identity")
        || message.contains("default Thorax identity")
        || message.contains("ratchet state")
    {
        js_error("identity", message)
    } else {
        js_error("thorax", message)
    }
}

fn secret_error(error: OpsError, selector: &str) -> Error {
    match error {
        OpsError::SecretMissing => js_error("not_found", format!("secret {selector} not found")),
        OpsError::SecretConflicted => {
            js_error("conflict", format!("secret {selector} is conflicted"))
        }
        OpsError::SecretNotDecryptable(thorax_ops::SecretState::Unauthorized)
        | OpsError::SecretNotDecryptable(thorax_ops::SecretState::NotEncryptedForReader)
        | OpsError::SecretNotWritable => js_error(
            "permission_denied",
            format!("not authorized for secret {selector}"),
        ),
        OpsError::ValidationFailed(_) => js_error("validation", error),
        OpsError::Keychain(_) => js_error("identity", error),
        other => js_from_display(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conflicted_effective() -> thorax_ops::EffectiveState {
        let key = thorax_ops::RecordKey::EntryPoint {
            user_id: thorax_ops::UserId(thorax_ops::HashValue(vec![1])),
        };
        let mut effective = thorax_ops::EffectiveState::default();
        effective.conflicted.insert(
            key.clone(),
            thorax_ops::ConflictReport {
                key,
                counter: 1,
                kind: thorax_ops::ConflictKind::Tie,
                candidates: Vec::new(),
                origin: None,
            },
        );
        effective
    }

    #[test]
    fn sdk_conflict_guard_accepts_clean_vault() {
        let effective = thorax_ops::EffectiveState::default();
        assert!(ensure_no_sdk_conflicts(&effective).is_ok());
    }

    #[test]
    fn sdk_conflict_guard_rejects_any_conflict() {
        let error = ensure_no_sdk_conflicts(&conflicted_effective()).unwrap_err();
        assert!(format!("{error:?}").contains("unresolved conflict"));
    }
}
