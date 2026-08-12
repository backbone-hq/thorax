use thorax_core::hazmat::{append_record, secret_record};
use thorax_core::ids::derive_secret_id;
use thorax_core::{next_counter, RecordKey, SecretSelectorV1, ValidationReport};
use thorax_crypto::{Crypto, Identity};

use crate::secrets::{decrypt_secret_from_report, seal_secret_payload, SealContext};
use crate::{LockedSession, ReconcileOutput, Result, UnlockedSession};

impl LockedSession {
    /// Convergence with an *already-unlocked* identity: re-encrypt every secret missing a
    /// reader that `identity` can decrypt. Runs against this session's current report —
    /// callers invoke it *after* their mutation committed, and the `&mut` flow guarantees
    /// that report is the post-mutation state. This is the shared core of both the
    /// standalone reconcile op and the access-changing intent ops — the latter reuse the
    /// single identity they unlocked for the mutation, so granting + converging costs one
    /// unlock.
    ///
    /// It can only encrypt secrets the identity can currently decrypt (encrypting requires
    /// the content key, which requires decrypting). Secrets it cannot read are returned in
    /// `needs_rotation` for a current reader to encrypt later.
    pub(crate) fn converge_readers(
        &mut self,
        crypto: &Crypto,
        identity: &Identity,
    ) -> Result<ReconcileOutput> {
        let candidates = missing_reader_candidates(self.report(), crypto);
        if candidates.is_empty() {
            return Ok(ReconcileOutput::default());
        }

        let mut opened = Vec::new();
        let mut needs_rotation = Vec::new();
        for selector in candidates {
            match decrypt_secret_from_report(self.report(), crypto, identity, selector.clone()) {
                Ok(plaintext) => opened.push(plaintext),
                Err(_) => needs_rotation.push(selector),
            }
        }

        if opened.is_empty() {
            return Ok(ReconcileOutput {
                encrypted: Vec::new(),
                needs_rotation,
            });
        }

        let encrypted: Vec<SecretSelectorV1> = opened
            .iter()
            .map(|secret| secret.selector.clone())
            .collect();

        self.commit(
            crypto,
            |vault, pre_report| {
                // One counter for the whole batch: each re-encrypted value targets a
                // distinct secret key and need only beat its own prior value, which
                // `next_counter` already exceeds.
                let counter = next_counter(&pre_report.effective);
                for secret in &opened {
                    let secret_id = derive_secret_id(crypto, &secret.selector)?;
                    let record_key = RecordKey::Secret {
                        secret_id: secret_id.clone(),
                    };
                    let sealed = seal_secret_payload(
                        &pre_report.effective,
                        &SealContext {
                            record_key: &record_key,
                            signer_key: identity.signing_public_key(),
                            counter,
                            secret_id: &secret_id,
                            selector: &secret.selector,
                        },
                        // Re-seal the whole value — primary and additional fields — so a reader
                        // added by reconcile can decrypt the fields too, not just the primary.
                        &secret.to_value(),
                    )?;
                    append_record(
                        vault,
                        secret_record(crypto, identity, secret.selector.clone(), sealed, counter)?,
                    );
                }
                Ok(())
            },
            |_, _| Ok(()),
        )?;

        Ok(ReconcileOutput {
            encrypted,
            needs_rotation,
        })
    }
}

/// The reconcile family of operations, acting as the session's unlocked identity.
impl UnlockedSession {
    /// After an access *addition*, encrypt the secrets the actor can decrypt so every
    /// authorized reader has a recipient slot — the automatic, implicit form of `encrypt`.
    ///
    /// This is what makes "invite a user with read access" actually grant them access to
    /// existing secrets without a separate manual step. It can only encrypt secrets the
    /// actor can currently decrypt: encrypting requires the content key, which requires
    /// decrypting. Secrets the actor cannot read are left for a current reader, and the
    /// caller surfaces those (e.g. via `status`). One commit for the whole batch.
    pub fn reconcile_readers(&mut self, crypto: &Crypto) -> Result<ReconcileOutput> {
        let (session, identity) = self.parts();
        session.converge_readers(crypto, identity)
    }
}

/// Secrets that are missing a current reader's recipient slot — the candidates for convergence.
///
/// Reconciliation only ever *adds* missing readers: it re-encrypts existing secrets so every
/// authorized reader can decrypt them. It deliberately ignores extra slots for former readers —
/// removing access is not an encryption (the removed party already had the value; confidentiality
/// from them is restored only when the value next changes, with a fresh key).
fn missing_reader_candidates(report: &ValidationReport, crypto: &Crypto) -> Vec<SecretSelectorV1> {
    report
        .effective
        .secret_records()
        .into_iter()
        .map(|record| record.value.selector.clone())
        .filter(|selector| {
            report
                .effective
                .secret_missing_reader(selector, crypto)
                .unwrap_or(false)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn reconcile_encrypts_on_add_and_delete_is_a_no_op() {
        let fixture = ProductionFixture::initialized();
        let keychain = PassphraseKeychain::new(
            fixture._temp.path.join("keychain"),
            thorax_keychain::StaticPassphraseProvider::new("root keychain passphrase"),
        );
        let root_signing_public_key_hash =
            key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        save_identity_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            &root_signing_public_key_hash,
            &fixture.root,
        )
        .unwrap();

        let selector = SecretSelectorV1::tuple(["app", "db"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v",
        )
        .unwrap();

        // Invite bob with read on app: the existing secret is now stale (missing bob's slot).
        let bob = invite_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            Some("bob".to_string()),
            vec![GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(
                ["app"],
            ))],
        )
        .unwrap();

        // The invite converged its own grant under the same unlock: the existing secret was
        // re-encrypted to bob (root could decrypt it), so he can read it immediately — without any
        // separate reconcile step. This is the access-addition obligation living in ops.
        assert_eq!(bob.reconcile.encrypted, vec![selector.clone()]);
        assert!(bob.reconcile.needs_rotation.is_empty());
        // A standalone reconcile now finds nothing missing — invite already did the work.
        let out = reconcile_readers_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
        )
        .unwrap();
        assert!(
            out.encrypted.is_empty(),
            "invite already converged its grant"
        );
        assert!(out.needs_rotation.is_empty());
        let loaded = load_session(&fixture.paths, &fixture.crypto);
        assert_eq!(
            loaded
                .effective()
                .classify_secret_for_user(&selector, &bob.user_id, &fixture.crypto),
            SecretState::ActiveDecryptable
        );

        // Delete bob. We deliberately do NOT encrypt: bob already had the value, so stripping
        // his slot from the current record buys nothing. Root can still read it, and reconcile
        // is a no-op because no current reader is missing.
        delete_user_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            bob.user_id.clone(),
            None,
        )
        .unwrap();
        let loaded = load_session(&fixture.paths, &fixture.crypto);
        assert_eq!(
            loaded.effective().classify_secret_for_user(
                &selector,
                fixture.root.user_id(),
                &fixture.crypto
            ),
            SecretState::ActiveDecryptable
        );
        let out = reconcile_readers_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
        )
        .unwrap();
        assert!(
            out.encrypted.is_empty(),
            "deletion leaves nothing to encrypt"
        );
        assert!(out.needs_rotation.is_empty());

        // Confidentiality from bob is restored when the value next changes: a fresh content
        // key encrypted only to the current readers, which bob's stale slot cannot open.
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v2",
        )
        .unwrap();
        let loaded = load_session(&fixture.paths, &fixture.crypto);
        let value = loaded
            .effective()
            .secret_record(&selector, &fixture.crypto)
            .unwrap()
            .expect("expected an active value")
            .value;
        assert!(
            !value
                .sealed
                .recipient_slots
                .iter()
                .any(|slot| slot.recipient_id == bob.user_id),
            "the rotated value must not be readable by the deleted user"
        );
    }
}
