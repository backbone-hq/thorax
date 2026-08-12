use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use thorax_core::hazmat::{entry_point_record, user_record};
use thorax_core::test_support::{test_user, TestUser};
use thorax_core::DeterministicCrypto;

use crate::*;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

// Session-based test shims: one session load + one session method each, mirroring how
// frontends drive the ops layer.

pub(crate) fn load_session(paths: &WorkspacePaths, crypto: &impl CryptoProvider) -> LockedSession {
    LockedSession::load(paths, crypto).unwrap()
}

pub(crate) fn valid_session(paths: &WorkspacePaths, crypto: &impl CryptoProvider) -> LockedSession {
    let session = load_session(paths, crypto);
    session.ensure_valid().unwrap();
    session
}

pub(crate) fn add_user(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    admin: &impl RecordSigner,
    user: &impl RecordSigner,
) -> Result<UserId> {
    LockedSession::load(paths, crypto)?.add_user(crypto, admin, user)
}

pub(crate) fn grant_permission(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    issuer: &impl RecordSigner,
    subject: PrincipalRefV1,
    permission: GrantPermissionV1,
    seed: IdSeed,
) -> Result<GrantId> {
    LockedSession::load(paths, crypto)?.grant_permission(crypto, issuer, subject, permission, seed)
}

pub(crate) fn set_user_handle(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    handle: impl Into<String>,
    user: UserId,
) -> Result<UserHandleId> {
    LockedSession::load(paths, crypto)?.set_user_handle(crypto, signer, handle, user)
}

pub(crate) fn set_vault_handle(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    handle: impl Into<String>,
) -> Result<VaultHandleId> {
    LockedSession::load(paths, crypto)?.set_vault_handle(crypto, signer, handle)
}

/// Returns the post-commit session so tests can assert on the deletion's effects.
pub(crate) fn delete_user(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    user: UserId,
    reason: Option<String>,
) -> Result<LockedSession> {
    let mut session = LockedSession::load(paths, crypto)?;
    session.delete_user(crypto, signer, user, reason)?;
    Ok(session)
}

pub(crate) fn create_group(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    seed: IdSeed,
    handle: impl Into<String>,
) -> Result<GroupId> {
    LockedSession::load(paths, crypto)?.create_group(crypto, signer, seed, handle)
}

pub(crate) fn add_group_member(
    paths: &WorkspacePaths,
    crypto: &impl CryptoProvider,
    signer: &impl RecordSigner,
    group: GroupId,
    member: PrincipalRefV1,
) -> Result<GroupMemberId> {
    LockedSession::load(paths, crypto)?.add_group_member(crypto, signer, group, member)
}

pub(crate) fn set_secret(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    signer: &Identity,
    selector: SecretSelectorV1,
    plaintext: &[u8],
) -> Result<SetSecretOutput> {
    LockedSession::load(paths, crypto)?.set_secret_value(
        crypto,
        signer,
        selector,
        SecretValueV1::from_primary(plaintext),
    )
}

pub(crate) fn delete_secret(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    signer: &Identity,
    selector: SecretSelectorV1,
) -> Result<DeleteSecretOutput> {
    LockedSession::load(paths, crypto)?.delete_secret(crypto, signer, selector)
}

pub(crate) fn get_secret(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    identity: &Identity,
    selector: SecretSelectorV1,
) -> Result<SecretPlaintext> {
    let session = LockedSession::load(paths, crypto)?;
    session.ensure_valid()?;
    session.get_secret(crypto, identity, selector)
}

// UnlockedSession-based test shims: one open (load + funnel unlock) + one operation method
// each, mirroring how frontends drive the unlocked ops surface.

pub(crate) fn set_secret_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    user: &UserId,
    selector: SecretSelectorV1,
    plaintext: &[u8],
) -> Result<SetSecretOutput> {
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        user,
        KeyUsePurpose::SignSecretWrite {
            selector: selector.clone(),
        },
    )?;
    unlocked.set_secret(crypto, selector, plaintext)
}

pub(crate) fn get_secret_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    user: &UserId,
    selector: SecretSelectorV1,
    sink: OutputSink,
) -> Result<SecretPlaintext> {
    let unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        user,
        KeyUsePurpose::DecryptSecret {
            selector: selector.clone(),
            sink,
        },
    )?;
    unlocked.get_secret(crypto, selector)
}

pub(crate) fn delete_secret_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    user: &UserId,
    selector: SecretSelectorV1,
) -> Result<DeleteSecretOutput> {
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        user,
        KeyUsePurpose::SignSecretDelete {
            selector: selector.clone(),
        },
    )?;
    unlocked.delete_secret(crypto, selector)
}

pub(crate) fn set_user_handle_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    admin: &UserId,
    handle: impl Into<String>,
    target: UserId,
) -> Result<UserHandleId> {
    let handle = handle.into();
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        admin,
        KeyUsePurpose::SignAdminChange {
            summary: format!("set user handle {handle}"),
        },
    )?;
    unlocked.set_user_handle(crypto, handle, target)
}

pub(crate) fn set_vault_handle_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    admin: &UserId,
    handle: impl Into<String>,
) -> Result<VaultHandleId> {
    let handle = handle.into();
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        admin,
        KeyUsePurpose::SignAdminChange {
            summary: format!("set vault name {handle}"),
        },
    )?;
    unlocked.set_vault_handle(crypto, handle)
}

pub(crate) fn invite_user_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    admin: &UserId,
    handle: Option<String>,
    grants: Vec<GrantPermissionV1>,
) -> Result<InviteUserOutput> {
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        admin,
        KeyUsePurpose::SignAdminChange {
            summary: "invite user".to_string(),
        },
    )?;
    unlocked.invite_user(crypto, handle, grants)
}

pub(crate) fn delete_user_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    admin: &UserId,
    target: UserId,
    reason: Option<String>,
) -> Result<UserId> {
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        admin,
        KeyUsePurpose::SignAdminChange {
            summary: "delete user".to_string(),
        },
    )?;
    unlocked.delete_user(crypto, target, reason)
}

pub(crate) fn reconcile_readers_with_keychain(
    paths: &WorkspacePaths,
    crypto: &Crypto,
    keychain: &(impl IdentityKeychain + ?Sized),
    actor: &UserId,
) -> Result<ReconcileOutput> {
    let mut unlocked = UnlockedSession::open(
        paths,
        crypto,
        keychain,
        actor,
        KeyUsePurpose::SignAdminChange {
            summary: "reconcile readers".to_string(),
        },
    )?;
    unlocked.reconcile_readers(crypto)
}

pub(crate) fn record_count(paths: &WorkspacePaths, crypto: &DeterministicCrypto) -> usize {
    let loaded = load_session(paths, crypto);
    let VaultStore::V1(v1) = loaded.vault();
    v1.records.len()
}

pub(crate) struct Fixture {
    pub(crate) _temp: TestDir,
    pub(crate) paths: WorkspacePaths,
    pub(crate) crypto: DeterministicCrypto,
    pub(crate) root: TestUser,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path())
            .with_state_dir(temp.path().join("machine-state"));
        let crypto = DeterministicCrypto;
        let root = test_user(&crypto, "root");
        Self {
            _temp: temp,
            paths,
            crypto,
            root,
        }
    }

    pub(crate) fn initialized() -> Self {
        let fixture = Self::new();
        init_vault(&fixture.paths, &fixture.crypto, &fixture.root).unwrap();
        fixture
    }
}

/// Append `user` (with its entry point) through `session`, the way `add_user` does
/// through a fresh load — the session-test mutation primitive.
pub(crate) fn session_add_user(
    session: &mut LockedSession,
    crypto: &DeterministicCrypto,
    admin: &TestUser,
    user: &TestUser,
) {
    session
        .commit(
            crypto,
            |vault, report| {
                let counter = next_counter(&report.effective);
                append_record(
                    vault,
                    user_record(
                        crypto,
                        admin,
                        user.signing_public_key.clone(),
                        user.hpke_public_key.clone(),
                        counter,
                    )?,
                );
                let root_user = report
                    .effective
                    .root_user_id
                    .clone()
                    .ok_or(OpsError::MissingEffectiveRoot)?;
                append_record(vault, entry_point_record(crypto, user, root_user, counter)?);
                Ok(())
            },
            |_, _| Ok(()),
        )
        .unwrap();
}

pub(crate) struct ProductionFixture {
    pub(crate) _temp: TestDir,
    pub(crate) paths: WorkspacePaths,
    pub(crate) crypto: Crypto,
    pub(crate) root: Identity,
}

impl ProductionFixture {
    pub(crate) fn initialized() -> Self {
        let temp = TestDir::new();
        let paths = WorkspacePaths::from_root(temp.path())
            .with_state_dir(temp.path().join("machine-state"));
        let crypto = Crypto;
        let root = Identity::generate(&crypto).unwrap();
        init_vault(&paths, &crypto, &root).unwrap();
        Self {
            _temp: temp,
            paths,
            crypto,
            root,
        }
    }
}

pub(crate) struct TestDir {
    pub(crate) path: PathBuf,
}

impl TestDir {
    pub(crate) fn new() -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "thorax-ops-test-{}-{nanos}-{counter}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
