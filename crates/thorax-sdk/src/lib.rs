//! Native Rust SDK for Thorax.
//!
//! The SDK is a small application-facing facade over Thorax's shared operation
//! layer. It uses the same vault validation, authorization, keychain, and
//! cryptography as the CLI, TUI, Python SDK, and Node SDK.
//!
//! ```no_run
//! use thorax_sdk::Vault;
//!
//! # fn main() -> Result<(), thorax_sdk::Error> {
//! let vault = Vault::open(".")?;
//! let database_url = vault.get_string("app/prod/db")?;
//! # let _ = database_url;
//! # Ok(())
//! # }
//! ```

use std::collections::BTreeMap;
use std::path::Path;

use thorax_frontend::{
    ci_invite, map_secret_error, parse_secret_selector, read_invite,
    resolve_cli_user_ref_with_report, selector_string, FrontendError,
};
use thorax_ops::{
    ensure_ratchet_from_invite, AutoKeychain, Crypto, Identity, InviteV1, KeyUsePurpose,
    KeychainError, LockedSession, NoManualIdentityProvider, OpsError, PassphraseKeychain,
    StaticPassphraseProvider, UnlockedSession, WorkspacePaths,
};

/// A Thorax SDK result.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by the Rust SDK.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Frontend(#[from] FrontendError),
    #[error(transparent)]
    Ops(#[from] OpsError),
    #[error(transparent)]
    Keychain(#[from] KeychainError),
    #[error("environment authentication requires a Thorax invite")]
    MissingEnvironmentInvite,
    #[error(
        "vault has {0} unresolved conflict(s); resolve conflicts before using the Thorax Rust SDK"
    )]
    ConflictedVault(usize),
    #[error("secret {selector} is not valid UTF-8")]
    InvalidUtf8 { selector: String },
    #[error("secret {selector} has no field {key:?}")]
    FieldNotFound { selector: String, key: String },
}

/// Optional settings for local keychain authentication.
#[derive(Default, PartialEq, Eq)]
pub struct KeychainConfig {
    /// A user handle or user ID. The configured default identity is used when omitted.
    pub user: Option<String>,
    /// A passphrase supplied by a noninteractive caller.
    pub passphrase: Option<String>,
}

impl std::fmt::Debug for KeychainConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KeychainConfig")
            .field("user", &self.user)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// How a [`Vault`] obtains its Thorax identity.
pub struct Auth {
    inner: AuthInner,
}

enum AuthInner {
    Keychain(KeychainConfig),
    Invite(InviteV1),
    Environment,
}

impl Auth {
    /// Use the configured local identity and interactive keychain.
    pub fn from_keychain() -> Self {
        Self::from_keychain_with(KeychainConfig::default())
    }

    /// Use a local keychain with explicit identity or passphrase settings.
    pub fn from_keychain_with(config: KeychainConfig) -> Self {
        Self {
            inner: AuthInner::Keychain(config),
        }
    }

    /// Use a private `thrx1...` invite capability directly.
    pub fn from_invite(invite: impl Into<String>) -> Result<Self> {
        let invite = read_invite(Some(invite.into()), None)?;
        Ok(Self {
            inner: AuthInner::Invite(invite),
        })
    }

    /// Read self-contained invitation material from Thorax's standard environment variables.
    pub fn from_env() -> Self {
        Self {
            inner: AuthInner::Environment,
        }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self::from_keychain()
    }
}

/// An authenticated, validated Thorax vault.
pub struct Vault {
    session: UnlockedSession,
}

impl Vault {
    /// Open the vault below `root` with the configured local keychain identity.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(root, Auth::default())
    }

    /// Open the vault below `root` with explicit authentication.
    pub fn open_with(root: impl AsRef<Path>, auth: Auth) -> Result<Self> {
        let paths = WorkspacePaths::from_root(root.as_ref());
        let session = open_session(&paths, auth)?;
        Ok(Self { session })
    }

    /// The project root containing this vault.
    pub fn root(&self) -> &Path {
        &self.session.paths().root
    }

    /// The encrypted vault file used by this session.
    pub fn vault_path(&self) -> &Path {
        &self.session.paths().vault_path
    }

    /// Return a secret's primary value as opaque bytes.
    pub fn get(&self, selector: &str) -> Result<Vec<u8>> {
        let parsed = parse_secret_selector(selector)?;
        self.session
            .get_secret(&Crypto, parsed)
            .map(|secret| secret.plaintext.to_vec())
            .map_err(|error| map_secret(error, selector))
    }

    /// Return a secret's primary value as UTF-8 text.
    pub fn get_string(&self, selector: &str) -> Result<String> {
        String::from_utf8(self.get(selector)?).map_err(|_| Error::InvalidUtf8 {
            selector: selector.to_string(),
        })
    }

    /// Set a secret's primary value. This replaces any existing additional fields.
    pub fn set(&mut self, selector: &str, value: impl AsRef<[u8]>) -> Result<()> {
        let parsed = parse_secret_selector(selector)?;
        self.session
            .set_secret(&Crypto, parsed, value.as_ref())
            .map(|_| ())
            .map_err(|error| map_secret(error, selector))
    }

    /// Delete a secret.
    pub fn delete(&mut self, selector: &str) -> Result<()> {
        let parsed = parse_secret_selector(selector)?;
        self.session
            .delete_secret(&Crypto, parsed)
            .map(|_| ())
            .map_err(|error| map_secret(error, selector))
    }

    /// Move a secret to another path or label set without exposing its value.
    pub fn move_secret(&mut self, from: &str, to: &str) -> Result<()> {
        let parsed_from = parse_secret_selector(from)?;
        let parsed_to = parse_secret_selector(to)?;
        self.session
            .relabel_secret(&Crypto, parsed_from, parsed_to)
            .map(|_| ())
            .map_err(|error| map_secret(error, from))
    }

    /// List the canonical selectors in the vault.
    pub fn list(&self) -> Vec<String> {
        let mut selectors: Vec<String> = self
            .session
            .effective()
            .secret_records()
            .into_iter()
            .map(|record| selector_string(&record.value.selector))
            .collect();
        selectors.sort();
        selectors
    }

    /// Return all additional fields on a secret as opaque bytes.
    pub fn fields(&self, selector: &str) -> Result<BTreeMap<String, Vec<u8>>> {
        let parsed = parse_secret_selector(selector)?;
        let secret = self
            .session
            .get_secret(&Crypto, parsed)
            .map_err(|error| map_secret(error, selector))?;
        Ok(secret
            .fields
            .into_iter()
            .map(|field| (field.key, field.value.to_vec()))
            .collect())
    }

    /// Return one additional field as opaque bytes.
    pub fn get_field(&self, selector: &str, key: &str) -> Result<Vec<u8>> {
        self.fields(selector)?
            .remove(key)
            .ok_or_else(|| Error::FieldNotFound {
                selector: selector.to_string(),
                key: key.to_string(),
            })
    }

    /// Return one additional field as UTF-8 text.
    pub fn get_field_string(&self, selector: &str, key: &str) -> Result<String> {
        String::from_utf8(self.get_field(selector, key)?).map_err(|_| Error::InvalidUtf8 {
            selector: format!("{selector} field {key:?}"),
        })
    }

    /// Insert or replace one additional field while preserving the primary value.
    pub fn set_field(
        &mut self,
        selector: &str,
        key: impl Into<String>,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        let parsed = parse_secret_selector(selector)?;
        let previous = self
            .session
            .get_secret(&Crypto, parsed.clone())
            .map_err(|error| map_secret(error, selector))?;
        self.session
            .set_secret_value(
                &Crypto,
                parsed,
                previous.with_field(key, value.as_ref().to_vec()),
            )
            .map(|_| ())
            .map_err(|error| map_secret(error, selector))
    }

    /// Delete one additional field while preserving the primary value.
    pub fn delete_field(&mut self, selector: &str, key: &str) -> Result<()> {
        let parsed = parse_secret_selector(selector)?;
        let previous = self
            .session
            .get_secret(&Crypto, parsed.clone())
            .map_err(|error| map_secret(error, selector))?;
        if previous.field(key).is_none() {
            return Err(Error::FieldNotFound {
                selector: selector.to_string(),
                key: key.to_string(),
            });
        }
        self.session
            .set_secret_value(&Crypto, parsed, previous.without_field(key))
            .map(|_| ())
            .map_err(|error| map_secret(error, selector))
    }
}

fn open_session(paths: &WorkspacePaths, auth: Auth) -> Result<UnlockedSession> {
    let session = match auth.inner {
        AuthInner::Keychain(config) => open_with_keychain(paths, config)?,
        AuthInner::Invite(invite) => open_with_invite(paths, invite)?,
        AuthInner::Environment => {
            let invite = ci_invite()?.ok_or(Error::MissingEnvironmentInvite)?;
            open_with_invite(paths, invite)?
        }
    };
    let conflict_count = session.effective().conflicted.len();
    if conflict_count != 0 {
        return Err(Error::ConflictedVault(conflict_count));
    }
    Ok(session)
}

fn open_with_keychain(paths: &WorkspacePaths, config: KeychainConfig) -> Result<UnlockedSession> {
    let locked = LockedSession::load(paths, &Crypto)?;
    let user =
        resolve_cli_user_ref_with_report(paths, locked.report(), &Crypto, config.user.as_deref())?;
    let purpose = KeyUsePurpose::SignAdminChange {
        summary: "use this identity from the Thorax Rust SDK".to_string(),
    };
    match config.passphrase {
        Some(passphrase) => {
            let base_dir = PassphraseKeychain::<StaticPassphraseProvider>::default_base_dir()?;
            let keychain = AutoKeychain::new(
                PassphraseKeychain::new(base_dir, StaticPassphraseProvider::new(passphrase)),
                NoManualIdentityProvider,
            );
            Ok(UnlockedSession::promote(
                locked,
                &Crypto,
                &keychain,
                &user.resolved.user_id,
                purpose,
            )?)
        }
        None => {
            let keychain = AutoKeychain::default_interactive()?;
            Ok(UnlockedSession::promote(
                locked,
                &Crypto,
                &keychain,
                &user.resolved.user_id,
                purpose,
            )?)
        }
    }
}

fn open_with_invite(paths: &WorkspacePaths, invite: InviteV1) -> Result<UnlockedSession> {
    ensure_ratchet_from_invite(paths, &Crypto, &invite)?;
    let identity =
        Identity::from_master_seed(&Crypto, &invite.master_seed).map_err(OpsError::from)?;
    let locked = LockedSession::load(paths, &Crypto)?;
    Ok(UnlockedSession::with_identity(locked, &Crypto, identity)?)
}

fn map_secret(error: OpsError, selector: &str) -> Error {
    Error::Frontend(map_secret_error(error, selector))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use thorax_ops::{create_workspace_dirs, init_vault};

    fn initialized_vault() -> (TempDir, Vault) {
        let directory = TempDir::new().unwrap();
        let paths = WorkspacePaths::from_root(directory.path())
            .with_state_dir(directory.path().join("state"));
        create_workspace_dirs(&paths).unwrap();
        let identity = Identity::generate(&Crypto).unwrap();
        init_vault(&paths, &Crypto, &identity).unwrap();
        let locked = LockedSession::load(&paths, &Crypto).unwrap();
        let session = UnlockedSession::with_identity(locked, &Crypto, identity).unwrap();
        (directory, Vault { session })
    }

    #[test]
    fn reads_writes_moves_and_deletes_secrets() {
        let (_directory, mut vault) = initialized_vault();

        vault.set("app/prod/db", "postgres://localhost").unwrap();
        assert_eq!(
            vault.get_string("app/prod/db").unwrap(),
            "postgres://localhost"
        );
        assert_eq!(vault.list(), ["app/prod/db"]);

        vault.move_secret("app/prod/db", "app/live/db").unwrap();
        assert_eq!(vault.list(), ["app/live/db"]);
        vault.delete("app/live/db").unwrap();
        assert!(vault.list().is_empty());
    }

    #[test]
    fn preserves_primary_value_while_editing_fields() {
        let (_directory, mut vault) = initialized_vault();

        vault.set("app/prod/db", "primary").unwrap();
        vault
            .set_field("app/prod/db", "username", "thorax")
            .unwrap();
        assert_eq!(vault.get_string("app/prod/db").unwrap(), "primary");
        assert_eq!(
            vault.get_field_string("app/prod/db", "username").unwrap(),
            "thorax"
        );

        vault.delete_field("app/prod/db", "username").unwrap();
        assert!(matches!(
            vault.get_field("app/prod/db", "username"),
            Err(Error::FieldNotFound { .. })
        ));
    }

    #[test]
    fn rejects_invalid_invite_strings() {
        assert!(Auth::from_invite("not-an-invite").is_err());
    }
}
