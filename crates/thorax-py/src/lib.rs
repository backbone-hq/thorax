//! PyO3 bindings for Thorax.

use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyString, PyTuple, PyType};
use thorax_frontend::{parse_secret_selector, resolve_cli_user_ref_with_report, selector_string};
use thorax_ops::{
    ensure_ratchet_from_invite, KeyUsePurpose, KeyspaceLabelMatcherV1, KeyspaceSelectorV1,
    LabelMatcherV1, LockedSession, OpsError, PassphraseKeychain, SecretLabelV1, SecretSelectorV1,
    StaticPassphraseProvider, TupleMatcherV1, UnlockedSession, WorkspacePaths, INVITE_MAGIC,
    MAX_INVITE_BYTES,
};
use thorax_ops::{AutoKeychain, Crypto, Identity, Invite, NoManualIdentityProvider};

create_exception!(thorax, ThoraxError, PyException);
create_exception!(thorax, NotFound, ThoraxError);
create_exception!(thorax, PermissionDenied, ThoraxError);
create_exception!(thorax, ConflictError, ThoraxError);
create_exception!(thorax, ValidationError, ThoraxError);
create_exception!(thorax, IdentityError, ThoraxError);

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

#[pyclass(module = "thorax", skip_from_py_object)]
#[derive(Clone)]
pub struct Auth {
    inner: AuthInner,
}

#[pymethods]
impl Auth {
    #[classmethod]
    #[pyo3(signature = (user=None, *, passphrase=None))]
    fn from_keychain(
        _cls: &Bound<'_, PyType>,
        user: Option<String>,
        passphrase: Option<String>,
    ) -> Self {
        Self {
            inner: AuthInner::Keychain { user, passphrase },
        }
    }

    #[classmethod]
    #[pyo3(signature = (invite))]
    fn from_invite(_cls: &Bound<'_, PyType>, invite: &Bound<'_, PyAny>) -> PyResult<Self> {
        Ok(Self {
            inner: AuthInner::Invite(material_from_py(invite)?),
        })
    }

    #[classmethod]
    #[pyo3(
        signature = (
            *,
            invite = thorax_frontend::INVITE_ENV.to_string(),
            invite_file = thorax_frontend::INVITE_FILE_ENV.to_string()
        )
    )]
    fn from_env(_cls: &Bound<'_, PyType>, invite: String, invite_file: String) -> Self {
        Self {
            inner: AuthInner::Env {
                invite,
                invite_file,
            },
        }
    }

    fn __repr__(&self) -> &'static str {
        match self.inner {
            AuthInner::Keychain { .. } => "Auth.from_keychain(...)",
            AuthInner::Invite { .. } => "Auth.from_invite(...)",
            AuthInner::Env { .. } => "Auth.from_env(...)",
        }
    }
}

#[pyclass(module = "thorax", skip_from_py_object)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selector {
    path: Vec<String>,
    labels: BTreeMap<String, String>,
}

#[pymethods]
impl Selector {
    #[new]
    #[pyo3(signature = (path, labels=None))]
    fn new(path: Vec<String>, labels: Option<BTreeMap<String, String>>) -> PyResult<Self> {
        let selector = Self {
            path,
            labels: labels.unwrap_or_default(),
        };
        selector.validate()?;
        Ok(selector)
    }

    #[getter]
    fn path<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
        PyTuple::new(py, self.path.iter())
    }

    #[getter]
    fn labels<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let dict = PyDict::new(py);
        for (key, value) in &self.labels {
            dict.set_item(key, value)?;
        }
        Ok(dict)
    }

    fn __str__(&self) -> String {
        selector_string(&self.to_secret_selector())
    }

    fn __repr__(&self) -> String {
        if self.labels.is_empty() {
            format!("Selector({:?})", self.path)
        } else {
            format!("Selector({:?}, labels={:?})", self.path, self.labels)
        }
    }
}

impl Selector {
    fn validate(&self) -> PyResult<()> {
        if self.path.is_empty() || self.path.iter().any(|part| part.is_empty()) {
            return Err(ThoraxError::new_err(
                "selector path must contain at least one non-empty segment",
            ));
        }
        if self
            .labels
            .iter()
            .any(|(key, value)| key.is_empty() || value.is_empty())
        {
            return Err(ThoraxError::new_err(
                "selector label names and values must be non-empty",
            ));
        }
        Ok(())
    }

    fn to_secret_selector(&self) -> SecretSelectorV1 {
        SecretSelectorV1 {
            tuple: self.path.clone(),
            labels: self
                .labels
                .iter()
                .map(|(key, value)| SecretLabelV1 {
                    key: key.clone(),
                    value: value.clone(),
                })
                .collect(),
        }
    }

    fn from_secret_selector(selector: SecretSelectorV1) -> Self {
        Self {
            path: selector.tuple,
            labels: selector
                .labels
                .into_iter()
                .map(|label| (label.key, label.value))
                .collect(),
        }
    }
}

#[pyclass(module = "thorax")]
pub struct Vault {
    session: Mutex<UnlockedSession>,
}

#[pymethods]
impl Vault {
    #[new]
    #[pyo3(signature = (path=".thorax".to_string(), *, auth=None))]
    fn new(py: Python<'_>, path: String, auth: Option<Py<Auth>>) -> PyResult<Self> {
        let auth = match auth {
            Some(auth) => auth.borrow(py).inner.clone(),
            None => AuthInner::Keychain {
                user: None,
                passphrase: None,
            },
        };
        let paths = paths_from_thorax_dir(path);
        let session = open_session(&paths, auth)?;
        Ok(Self {
            session: Mutex::new(session),
        })
    }

    #[pyo3(signature = (selector, *, as_bytes=false))]
    fn get(
        &self,
        py: Python<'_>,
        selector: &Bound<'_, PyAny>,
        as_bytes: bool,
    ) -> PyResult<Py<PyAny>> {
        let (selector, display) = selector_from_py(selector)?;
        let opened = py.detach(|| {
            let session = self.lock_session()?;
            session
                .get_secret(&Crypto, selector)
                .map_err(|error| secret_error(error, &display))
        })?;
        let plaintext = opened.plaintext.as_slice();
        if as_bytes {
            Ok(PyBytes::new(py, plaintext).into_any().unbind())
        } else {
            let text = std::str::from_utf8(plaintext)
                .map_err(|_| ThoraxError::new_err("secret is not valid UTF-8"))?;
            Ok(PyString::new(py, text).into_any().unbind())
        }
    }

    fn set(
        &self,
        py: Python<'_>,
        selector: &Bound<'_, PyAny>,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let (selector, display) = selector_from_py(selector)?;
        let value = secret_value_from_py(value)?;
        py.detach(|| {
            let mut session = self.lock_session()?;
            session
                .set_secret(&Crypto, selector, &value)
                .map(|_| ())
                .map_err(|error| secret_error(error, &display))
        })
    }

    fn delete(&self, py: Python<'_>, selector: &Bound<'_, PyAny>) -> PyResult<()> {
        let (selector, display) = selector_from_py(selector)?;
        py.detach(|| {
            let mut session = self.lock_session()?;
            session
                .delete_secret(&Crypto, selector)
                .map(|_| ())
                .map_err(|error| secret_error(error, &display))
        })
    }

    /// The secret's additional key→value fields as a dict. Values come back as `str` (UTF-8) or,
    /// with `as_bytes=True`, as `bytes`.
    #[pyo3(signature = (selector, *, as_bytes=false))]
    fn fields(
        &self,
        py: Python<'_>,
        selector: &Bound<'_, PyAny>,
        as_bytes: bool,
    ) -> PyResult<Py<PyAny>> {
        let (selector, display) = selector_from_py(selector)?;
        let opened = py.detach(|| {
            let session = self.lock_session()?;
            session
                .get_secret(&Crypto, selector)
                .map_err(|error| secret_error(error, &display))
        })?;
        let dict = PyDict::new(py);
        for field in &opened.fields {
            dict.set_item(&field.key, field_value_to_py(py, &field.value, as_bytes)?)?;
        }
        Ok(dict.into_any().unbind())
    }

    /// One additional field's value, as `str` (UTF-8) or, with `as_bytes=True`, as `bytes`.
    #[pyo3(signature = (selector, key, *, as_bytes=false))]
    fn get_field(
        &self,
        py: Python<'_>,
        selector: &Bound<'_, PyAny>,
        key: String,
        as_bytes: bool,
    ) -> PyResult<Py<PyAny>> {
        let (selector, display) = selector_from_py(selector)?;
        let opened = py.detach(|| {
            let session = self.lock_session()?;
            session
                .get_secret(&Crypto, selector)
                .map_err(|error| secret_error(error, &display))
        })?;
        let field = opened
            .field(&key)
            .ok_or_else(|| NotFound::new_err(format!("secret {display} has no field {key:?}")))?;
        field_value_to_py(py, &field.value, as_bytes)
    }

    /// Insert or replace one additional field, preserving the primary value and other fields.
    fn set_field(
        &self,
        py: Python<'_>,
        selector: &Bound<'_, PyAny>,
        key: String,
        value: &Bound<'_, PyAny>,
    ) -> PyResult<()> {
        let (selector, display) = selector_from_py(selector)?;
        let value = secret_value_from_py(value)?;
        py.detach(|| {
            let mut session = self.lock_session()?;
            let previous = session
                .get_secret(&Crypto, selector.clone())
                .map_err(|error| secret_error(error, &display))?;
            session
                .set_secret_value(&Crypto, selector, previous.with_field(key, value))
                .map(|_| ())
                .map_err(|error| secret_error(error, &display))
        })
    }

    /// Remove one additional field, preserving the primary value and other fields.
    fn delete_field(
        &self,
        py: Python<'_>,
        selector: &Bound<'_, PyAny>,
        key: String,
    ) -> PyResult<()> {
        let (selector, display) = selector_from_py(selector)?;
        py.detach(|| {
            let mut session = self.lock_session()?;
            let previous = session
                .get_secret(&Crypto, selector.clone())
                .map_err(|error| secret_error(error, &display))?;
            if previous.field(&key).is_none() {
                return Err(NotFound::new_err(format!(
                    "secret {display} has no field {key:?}"
                )));
            }
            session
                .set_secret_value(&Crypto, selector, previous.without_field(&key))
                .map(|_| ())
                .map_err(|error| secret_error(error, &display))
        })
    }

    #[pyo3(signature = (selector=None))]
    fn list(&self, py: Python<'_>, selector: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<Selector>> {
        let filter = selector.map(selector_from_py).transpose()?.map(|(s, _)| s);
        py.detach(|| {
            let session = self.lock_session()?;
            let mut selectors: Vec<Selector> = session
                .effective()
                .secret_records()
                .into_iter()
                .map(|record| record.value.selector)
                .filter(|candidate| {
                    filter
                        .as_ref()
                        .is_none_or(|filter| selector_is_under(candidate, filter))
                })
                .map(Selector::from_secret_selector)
                .collect();
            selectors.sort_by_key(|selector| selector.__str__());
            Ok(selectors)
        })
    }

    fn __enter__(slf: PyRefMut<'_, Self>) -> PyRefMut<'_, Self> {
        slf
    }

    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyAny>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        false
    }
}

impl Vault {
    fn lock_session(&self) -> PyResult<std::sync::MutexGuard<'_, UnlockedSession>> {
        self.session
            .lock()
            .map_err(|_| ThoraxError::new_err("Thorax vault session lock is poisoned"))
    }
}

#[pymodule]
fn thorax(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Auth>()?;
    m.add_class::<Selector>()?;
    m.add_class::<Vault>()?;
    m.add("ThoraxError", py.get_type::<ThoraxError>())?;
    m.add("NotFound", py.get_type::<NotFound>())?;
    m.add("PermissionDenied", py.get_type::<PermissionDenied>())?;
    m.add("ConflictError", py.get_type::<ConflictError>())?;
    m.add("ValidationError", py.get_type::<ValidationError>())?;
    m.add("IdentityError", py.get_type::<IdentityError>())?;
    Ok(())
}

fn paths_from_thorax_dir(path: impl Into<PathBuf>) -> WorkspacePaths {
    WorkspacePaths::from_vault_path(path.into().join("vault.cord"))
}

fn open_session(paths: &WorkspacePaths, auth: AuthInner) -> PyResult<UnlockedSession> {
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

fn ensure_no_sdk_conflicts(effective: &thorax_ops::EffectiveState) -> PyResult<()> {
    let count = effective.conflicted.len();
    if count == 0 {
        Ok(())
    } else {
        Err(ConflictError::new_err(format!(
            "vault has {count} unresolved conflict(s); resolve conflicts before using the Thorax Python SDK"
        )))
    }
}

fn open_with_keychain(
    paths: &WorkspacePaths,
    user: Option<String>,
    passphrase: Option<String>,
) -> PyResult<UnlockedSession> {
    let locked = LockedSession::load(paths, &Crypto).map_err(py_err)?;
    let user = resolve_cli_user_ref_with_report(paths, locked.report(), &Crypto, user.as_deref())
        .map_err(py_err)?;
    let purpose = KeyUsePurpose::SignAdminChange {
        summary: "use this identity from the Thorax Python SDK".to_string(),
    };
    match passphrase {
        Some(passphrase) => {
            let base_dir = PassphraseKeychain::<StaticPassphraseProvider>::default_base_dir()
                .map_err(py_err)?;
            let keychain = AutoKeychain::new(
                PassphraseKeychain::new(base_dir, StaticPassphraseProvider::new(passphrase)),
                NoManualIdentityProvider,
            );
            UnlockedSession::promote(locked, &Crypto, &keychain, &user.resolved.user_id, purpose)
                .map_err(py_err)
        }
        None => {
            let keychain = AutoKeychain::default_interactive().map_err(py_err)?;
            UnlockedSession::promote(locked, &Crypto, &keychain, &user.resolved.user_id, purpose)
                .map_err(py_err)
        }
    }
}

fn open_with_invite(paths: &WorkspacePaths, invite: BundleMaterial) -> PyResult<UnlockedSession> {
    let invite = parse_invite(invite)?;
    ensure_ratchet_from_invite(paths, &Crypto, &invite).map_err(py_err)?;
    let identity = Identity::from_master_seed(&Crypto, &invite.master_seed).map_err(py_err)?;
    let locked = LockedSession::load(paths, &Crypto).map_err(py_err)?;
    UnlockedSession::with_identity(locked, &Crypto, identity).map_err(py_err)
}

fn auth_from_env(invite_var: &str, invite_file_var: &str) -> PyResult<BundleMaterial> {
    let invite = env_material(invite_var, invite_file_var, true)?;
    let invite = invite.ok_or_else(|| {
        IdentityError::new_err(format!("neither {invite_var} nor {invite_file_var} is set"))
    })?;
    Ok(invite)
}

fn env_material(
    string_var: &str,
    file_var: &str,
    required: bool,
) -> PyResult<Option<BundleMaterial>> {
    let string = env::var(string_var).ok();
    let file = env::var_os(file_var).map(PathBuf::from);
    match (string, file) {
        (Some(_), Some(_)) => Err(IdentityError::new_err(format!(
            "set only one of {string_var} or {file_var}"
        ))),
        (Some(value), None) => Ok(Some(BundleMaterial::Text(value))),
        (None, Some(path)) => read_bundle_file(&path).map(Some),
        (None, None) if required => Ok(None),
        (None, None) => Ok(None),
    }
}

fn read_bundle_file(path: &Path) -> PyResult<BundleMaterial> {
    let bytes = thorax_ops::read_file_bounded(path, MAX_INVITE_BYTES).map_err(|source| {
        IdentityError::new_err(format!("failed to read {}: {source}", path.display()))
    })?;
    Ok(BundleMaterial::Bytes(bytes))
}

fn material_from_py(value: &Bound<'_, PyAny>) -> PyResult<BundleMaterial> {
    if let Ok(text) = value.extract::<String>() {
        return Ok(BundleMaterial::Text(text));
    }
    if let Ok(bytes) = value.extract::<Vec<u8>>() {
        return Ok(BundleMaterial::Bytes(bytes));
    }
    let read = value
        .call_method0("read")
        .map_err(|_| ThoraxError::new_err("expected a string or file-like object"))?;
    material_from_py(&read)
}

fn parse_invite(material: BundleMaterial) -> PyResult<thorax_ops::InviteV1> {
    match material {
        BundleMaterial::Text(text) => {
            thorax_frontend::read_invite(Some(text), None).map_err(py_err)
        }
        BundleMaterial::Bytes(bytes) => {
            let payload = bytes
                .strip_prefix(INVITE_MAGIC)
                .ok_or_else(|| IdentityError::new_err("invite file is missing its magic prefix"))?;
            match cord::deserialize::<Invite>(payload).map_err(py_err)? {
                Invite::V1(invite) => Ok(invite),
            }
        }
    }
}

fn selector_from_py(value: &Bound<'_, PyAny>) -> PyResult<(SecretSelectorV1, String)> {
    if let Ok(text) = value.extract::<String>() {
        let selector = parse_secret_selector(&text).map_err(py_err)?;
        let display = selector_string(&selector);
        return Ok((selector, display));
    }
    if let Ok(selector) = value.extract::<PyRef<'_, Selector>>() {
        let selector = selector.to_secret_selector();
        let display = selector_string(&selector);
        return Ok((selector, display));
    }
    Err(ThoraxError::new_err(
        "expected a selector string or Selector",
    ))
}

/// A secret value is opaque bytes: `str` is encoded as UTF-8, `bytes` is taken verbatim.
/// How it reads back (str vs bytes) is the caller's choice at `get`, not stored here.
fn secret_value_from_py(value: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(text) = value.extract::<String>() {
        return Ok(text.into_bytes());
    }
    if let Ok(bytes) = value.extract::<Vec<u8>>() {
        return Ok(bytes);
    }
    Err(ThoraxError::new_err("secret value must be str or bytes"))
}

/// Render a decrypted field value for Python: `bytes` when `as_bytes`, else `str` (erroring if
/// the value is not valid UTF-8) — mirrors `Vault.get`.
fn field_value_to_py(py: Python<'_>, value: &[u8], as_bytes: bool) -> PyResult<Py<PyAny>> {
    if as_bytes {
        Ok(PyBytes::new(py, value).into_any().unbind())
    } else {
        let text = std::str::from_utf8(value)
            .map_err(|_| ThoraxError::new_err("field value is not valid UTF-8"))?;
        Ok(PyString::new(py, text).into_any().unbind())
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

fn py_err(error: impl std::fmt::Display + std::fmt::Debug + 'static) -> PyErr {
    let message = error.to_string();
    if message.contains("validation failed") {
        ValidationError::new_err(message)
    } else if message.contains("keychain")
        || message.contains("identity")
        || message.contains("default Thorax identity")
        || message.contains("ratchet state")
    {
        IdentityError::new_err(message)
    } else {
        ThoraxError::new_err(message)
    }
}

fn secret_error(error: OpsError, selector: &str) -> PyErr {
    match error {
        OpsError::SecretMissing => NotFound::new_err(format!("secret {selector} not found")),
        OpsError::SecretConflicted => {
            ConflictError::new_err(format!("secret {selector} is conflicted"))
        }
        OpsError::SecretNotDecryptable(thorax_ops::SecretState::Unauthorized)
        | OpsError::SecretNotDecryptable(thorax_ops::SecretState::NotEncryptedForReader)
        | OpsError::SecretNotWritable => {
            PermissionDenied::new_err(format!("not authorized for secret {selector}"))
        }
        OpsError::ValidationFailed(_) => ValidationError::new_err(error.to_string()),
        OpsError::Keychain(_) => IdentityError::new_err(error.to_string()),
        other => py_err(other),
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
        Python::initialize();
        let error = ensure_no_sdk_conflicts(&conflicted_effective()).unwrap_err();
        assert!(format!("{error}").contains("unresolved conflict"));
    }
}
