//! Identity unlock state: the in-memory identity held for the lifetime of the UI.
//!
//! The passphrase keychain derives its key-encryption-key with Argon2id (64 MiB, 3 passes) on
//! every `unlock_identity` — deliberately ~1–2s to resist brute force. Running that per
//! operation made reveal/save/unlock feel sluggish, so we pay it **once** at the gate: derive
//! the identity, cache it here, and promote the model's session to an
//! [`thorax_ops::UnlockedSession`] anchored to it — every later op runs as that identity with
//! no keychain round trip. Idle relock drops the cache.

use thorax_frontend::{build_keychain_with_passphrase, FrontendError};
use thorax_ops::{
    Crypto, HashValue, Identity, KeyUsePurpose, KeychainRequest, UserId, WorkspacePaths,
};

#[derive(Default)]
pub struct UnlockSession {
    identity: Option<Identity>,
}

impl UnlockSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_locked(&self) -> bool {
        self.identity.is_none()
    }

    /// Unlock by passphrase: run the (expensive) KDF once to derive the identity, verify it, and
    /// cache it for the session. A wrong passphrase returns an error and leaves the session locked.
    /// Returns the unlocked identity so the caller can promote its session to it
    /// (possession-check the verifications + pin membership) before rendering anything.
    pub fn unlock(
        &mut self,
        passphrase: String,
        crypto: &Crypto,
        paths: &WorkspacePaths,
        user: &UserId,
        root_hash: &HashValue,
    ) -> Result<Identity, String> {
        let inner = build_keychain_with_passphrase(passphrase)
            .map_err(|e| thorax_frontend::diagnose(&e).message)?;
        let request = KeychainRequest::new(
            paths,
            root_hash.clone(),
            user.clone(),
            KeyUsePurpose::StoreIdentity,
        );
        let identity = inner
            .unlock_identity(crypto, &request)
            .map_err(|e| thorax_frontend::diagnose(&FrontendError::from(e)).message)?;
        self.identity = Some(identity.clone());
        Ok(identity)
    }

    /// Cache an already-unlocked identity (e.g. right after `init` or `claim`, which have it in
    /// hand) so the session promotes without a re-KDF.
    pub fn set_cached(&mut self, identity: Identity) {
        self.identity = Some(identity);
    }

    /// The unlocked identity, for promoting sessions ([`thorax_ops::UnlockedSession`]).
    pub fn identity(&self) -> Option<&Identity> {
        self.identity.as_ref()
    }

    pub fn lock(&mut self) {
        self.identity = None;
    }
}
