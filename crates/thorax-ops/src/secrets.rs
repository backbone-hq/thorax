use thorax_core::hazmat::{ensure_identity_consistent, secret_deleted_record, secret_record};
use thorax_core::ids::derive_secret_id;
use thorax_core::{
    ActiveSecretV1, Bytes, CryptoProvider, EffectiveState, HashValue, RecipientSlotV1, RecordKey,
    RecordSigner, SealedPayloadV1, SecretId, SecretRecordV1, SecretSelectorV1, SecretState,
    SecretValueV1, UserId, ValidationReport, VaultRecordV1,
};
use zeroize::Zeroizing;

use crate::SecretField;
use thorax_crypto::{Crypto, Identity};

use crate::{
    DeleteSecretOutput, LockedSession, OpsError, RelabelSecretOutput, Result, RunSecretsError,
    SecretPlaintext, SetSecretOutput, UnlockedSession,
};

const SEALED_VALUE_PREFIX: &[u8] = b"thorax-secret-";
const SEALED_VALUE_V1_MAGIC: &[u8] = b"thorax-secret-v1\0";

/// Both AAD bundles bind `trusted_root` (the hash of the vault root's signing key — the
/// same value local trust anchors on) so a sealed payload only opens inside the vault it
/// was written for. Cross-vault splices already fail on signer authority; the root
/// binding removes the remaining dependence on per-vault key freshness (an identical
/// keypair deliberately introduced into two vaults would otherwise carry valid AAD in
/// both). Neither carries a `domain` tag: each AAD's key is single-use for this purpose
/// (a fresh per-secret content key; the reader's HPKE key, only ever used for slot
/// wrapping), so there is no other context to separate from — the bound fields do the work.
#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
struct SecretContentAadV1 {
    trusted_root: HashValue,
    record_key: RecordKey,
    signing_public_key: Bytes,
    counter: u64,
    secret_id: SecretId,
    selector: SecretSelectorV1,
    nonce: Bytes,
    recipient_slots: Vec<RecipientSlotV1>,
}

#[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
struct RecipientSlotBindingV1 {
    trusted_root: HashValue,
    secret_id: SecretId,
    selector: SecretSelectorV1,
    recipient_id: UserId,
}

/// The secrets family of operations, acting as the session's unlocked identity: reads
/// cost no validation beyond the session's own load; writes validate only their
/// post-commit state. Authorization preconditions are checked against the (already
/// possession-grade) report before any key use; validation at commit remains the final
/// arbiter.
impl UnlockedSession {
    /// Write a secret's primary value, with no additional fields. The common case and a blind
    /// full write — any fields a prior value carried are dropped. Field-preserving updates go
    /// through [`UnlockedSession::set_secret_value`].
    pub fn set_secret(
        &mut self,
        crypto: &Crypto,
        selector: SecretSelectorV1,
        plaintext: &[u8],
    ) -> Result<SetSecretOutput> {
        self.set_secret_value(crypto, selector, SecretValueV1::from_primary(plaintext))
    }

    /// Write a secret's full value: primary plus zero or more additional encrypted key→value
    /// pairs. The whole envelope is sealed to the secret's current readers exactly as a
    /// primary-only value is, so the fields inherit the same integrity and access guarantees.
    pub fn set_secret_value(
        &mut self,
        crypto: &Crypto,
        selector: SecretSelectorV1,
        value: SecretValueV1,
    ) -> Result<SetSecretOutput> {
        let (session, identity) = self.parts();
        ensure_secret_writable(session.effective(), &selector, identity.user_id())?;
        session.set_secret_value(crypto, identity, selector, value)
    }

    pub fn delete_secret(
        &mut self,
        crypto: &Crypto,
        selector: SecretSelectorV1,
    ) -> Result<DeleteSecretOutput> {
        let (session, identity) = self.parts();
        ensure_secret_writable(session.effective(), &selector, identity.user_id())?;
        session.delete_secret(crypto, identity, selector)
    }

    /// Relabel or move a secret from one selector to another as a single operation:
    /// decrypt the old value and seal it at the new selector.
    ///
    /// A secret's identity is its **whole selector** (tuple + labels), so *any* change to
    /// the selector — a different tuple or a different label set — is a re-key: seal at the
    /// new key, then tombstone the old one. Only a no-op (`from == to`) stays in place. The
    /// new value is sealed to the *target* selector's current reader set, so it is
    /// self-converging — no separate reconcile is needed (unlike an access addition).
    pub fn relabel_secret(
        &mut self,
        crypto: &Crypto,
        from: SecretSelectorV1,
        to: SecretSelectorV1,
    ) -> Result<RelabelSecretOutput> {
        let (session, identity) = self.parts();
        // The actor must be able to read the source (to re-encrypt it) and write both
        // selectors (to seal the new value and, on a move, tombstone the old).
        ensure_secret_decryptable(session.effective(), &from, identity.user_id(), crypto)?;
        ensure_secret_writable(session.effective(), &to, identity.user_id())?;
        ensure_secret_writable(session.effective(), &from, identity.user_id())?;

        // Decrypt the source against the state validated above; the plaintext lives only
        // for this op.
        let plaintext =
            decrypt_secret_from_report(session.report(), crypto, identity, from.clone())?;
        // Seal at the new selector (to all of its current readers — self-converging). The whole
        // value — primary and additional fields — is carried across so a relabel/move never
        // silently drops fields.
        session.set_secret_value(crypto, identity, to.clone(), plaintext.to_value())?;
        // A move to a different key vacates the old one; tombstone it. (A no-op `from == to`
        // must NOT — the set above already superseded at that key, and a tombstone would
        // out-vote it.) If the tombstone fails the new copy already exists, so surface the
        // error rather than silently leaving a duplicate.
        if from != to {
            session.delete_secret(crypto, identity, from.clone())?;
        }

        Ok(RelabelSecretOutput { from, to })
    }

    pub fn get_secret(
        &self,
        crypto: &Crypto,
        selector: SecretSelectorV1,
    ) -> Result<SecretPlaintext> {
        self.session().get_secret(crypto, self.identity(), selector)
    }

    /// Release every secret selected for a `thorax run` invocation. The keychain approval
    /// for the release happened at open: `thorax run` promotes its session with
    /// [`thorax_keychain::KeyUsePurpose::RunWithSecrets`], scoping the prompt to the
    /// selector set and the child command.
    ///
    /// All selectors are validated decryptable up front so a typo'd or unauthorized
    /// selector fails closed before any plaintext is released.
    pub fn get_secrets_for_run(
        &self,
        crypto: &Crypto,
        selectors: Vec<SecretSelectorV1>,
    ) -> std::result::Result<Vec<SecretPlaintext>, RunSecretsError> {
        for selector in &selectors {
            ensure_secret_decryptable(self.effective(), selector, self.user_id(), crypto).map_err(
                |source| RunSecretsError::Secret {
                    selector: selector.clone(),
                    source: Box::new(source),
                },
            )?;
        }
        selectors
            .into_iter()
            .map(|selector| {
                decrypt_secret_from_report(self.report(), crypto, self.identity(), selector.clone())
                    .map_err(|source| RunSecretsError::Secret {
                        selector,
                        source: Box::new(source),
                    })
            })
            .collect()
    }
}

/// The signer-direct inner halves: crate-internal, so the untrusted session type carries
/// no mutation vocabulary outside this crate.
impl LockedSession {
    pub(crate) fn set_secret_value(
        &mut self,
        crypto: &Crypto,
        signer: &Identity,
        selector: SecretSelectorV1,
        value: SecretValueV1,
    ) -> Result<SetSecretOutput> {
        ensure_identity_consistent(crypto, signer)?;
        let secret = derive_secret_id(crypto, &selector)?;
        let record_key = RecordKey::Secret {
            secret_id: secret.clone(),
        };
        self.commit_record(
            crypto,
            |pre_report, counter| {
                let sealed = seal_secret_payload(
                    &pre_report.effective,
                    &SealContext {
                        record_key: &record_key,
                        signer_key: signer.signing_public_key(),
                        counter,
                        secret_id: &secret,
                        selector: &selector,
                    },
                    &value,
                )?;
                let signed =
                    secret_record(crypto, signer, selector.clone(), sealed.clone(), counter)?;
                Ok((
                    signed,
                    SetSecretOutput {
                        secret_id: secret.clone(),
                        selector: selector.clone(),
                        sealed,
                    },
                ))
            },
            // The appended record must have become the LWW winner. (A higher-counter
            // deletion or a concurrent write would shadow it.)
            |_output, hash, report| {
                if report.effective.secret_record_is_current(hash) {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective(
                        "secret value did not take effect",
                    ))
                }
            },
        )
    }

    pub(crate) fn delete_secret(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        selector: SecretSelectorV1,
    ) -> Result<DeleteSecretOutput> {
        let _signer_id = ensure_identity_consistent(crypto, signer)?;
        let secret = derive_secret_id(crypto, &selector)?;
        self.commit_record(
            crypto,
            |_pre_report, counter| {
                let signed = secret_deleted_record(crypto, signer, selector.clone(), counter)?;
                Ok((
                    signed,
                    DeleteSecretOutput {
                        secret_id: secret.clone(),
                        selector: selector.clone(),
                    },
                ))
            },
            // The deletion record must have become the LWW winner — i.e. an authorized
            // deletion by us actually landed and isn't shadowed by a value.
            |_output, hash, report| {
                if report.effective.secret_record_is_current(hash) {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective(
                        "secret deletion did not take effect",
                    ))
                }
            },
        )
    }

    pub(crate) fn get_secret(
        &self,
        crypto: &Crypto,
        identity: &Identity,
        selector: SecretSelectorV1,
    ) -> Result<SecretPlaintext> {
        ensure_secret_decryptable(self.effective(), &selector, identity.user_id(), crypto)?;
        decrypt_secret_from_report(self.report(), crypto, identity, selector)
    }
}

fn ensure_secret_decryptable(
    effective: &EffectiveState,
    selector: &SecretSelectorV1,
    user: &UserId,
    crypto: &impl CryptoProvider,
) -> Result<()> {
    match effective.classify_secret_for_user(selector, user, crypto) {
        SecretState::ActiveDecryptable => Ok(()),
        SecretState::Missing => Err(OpsError::SecretMissing),
        // A conflicted key has no current value: reads fail until an authorized resolver
        // picks a winner. Deliberately not a "missing" — the caller must learn why.
        SecretState::Conflicted => Err(OpsError::SecretConflicted),
        other => Err(OpsError::SecretNotDecryptable(other)),
    }
}

fn ensure_secret_writable(
    effective: &EffectiveState,
    selector: &SecretSelectorV1,
    user: &UserId,
) -> Result<()> {
    if !effective.users.contains_key(user) {
        return Err(OpsError::MissingWriterUser(user.clone()));
    }
    if effective.authority_unresolved {
        return Err(OpsError::SecretNotWritable);
    }
    if effective.authority_for_user(user).can_write(selector) {
        Ok(())
    } else {
        Err(OpsError::SecretNotWritable)
    }
}

pub(crate) fn ensure_can_write_secret(
    effective: &EffectiveState,
    user: &UserId,
    selector: &SecretSelectorV1,
) -> Result<()> {
    if !effective.users.contains_key(user) {
        return Err(OpsError::MissingUser(user.clone()));
    }
    if effective.authority_unresolved || !effective.authority_for_user(user).can_write(selector) {
        return Err(OpsError::SecretNotWritable);
    }
    Ok(())
}

pub(crate) fn decrypt_secret_from_report(
    report: &ValidationReport,
    crypto: &Crypto,
    identity: &Identity,
    selector: SecretSelectorV1,
) -> Result<SecretPlaintext> {
    let ActiveSecretV1 { signed, value } = report
        .effective
        .secret_record(&selector, crypto)?
        .ok_or(OpsError::SecretMissing)?;
    let trusted_root = effective_trusted_root(&report.effective)?.clone();
    decrypt_secret_record(identity, &signed, value, &trusted_root)
}

/// The trusted-root hash a validated state was selected under — present whenever a root
/// matched local trust, which every seal/decrypt path requires.
pub(crate) fn effective_trusted_root(effective: &EffectiveState) -> Result<&HashValue> {
    effective
        .root_signing_public_key_hash
        .as_ref()
        .ok_or(OpsError::MissingEffectiveRoot)
}

/// Decrypt one specific signed secret record for `identity`. Factored out of
/// [`decrypt_secret_from_report`] because merge-tie resolution must open the *chosen
/// candidate*, which is not necessarily the current LWW winner the report exposes.
pub(crate) fn decrypt_secret_record(
    identity: &Identity,
    signed: &VaultRecordV1,
    value: SecretRecordV1,
    trusted_root: &HashValue,
) -> Result<SecretPlaintext> {
    // The recipient is named by `UserId`, which commits to the HPKE key (id = H(signing‖hpke)),
    // so the slot need not carry the key hash separately. If a slot was wrapped to the wrong key,
    // the HPKE unwrap below fails — no separate pre-check is needed.
    let slot = value
        .sealed
        .recipient_slots
        .iter()
        .find(|slot| &slot.recipient_id == identity.user_id())
        .ok_or_else(|| OpsError::RecipientSlotMissing(identity.user_id().clone()))?;

    let slot_binding =
        recipient_slot_binding_bytes(trusted_root, &value.id, &value.selector, &slot.recipient_id)?;
    let content_key = thorax_crypto::unwrap_content_key(
        &identity.keys().hpke,
        &slot.hpke_encapsulated_key,
        &slot_binding,
        &slot_binding,
        &slot.wrapped_content_key,
    )?;
    let nonce = thorax_crypto::ContentNonce::from_bytes(&value.sealed.nonce)?;
    let record_key = RecordKey::Secret {
        secret_id: value.id.clone(),
    };
    let aad = secret_content_aad_bytes(
        trusted_root,
        &SealContext {
            record_key: &record_key,
            signer_key: &signed.signing_public_key,
            counter: value.counter,
            secret_id: &value.id,
            selector: &value.selector,
        },
        &value.sealed.nonce,
        &value.sealed.recipient_slots,
    )?;
    let opened = thorax_crypto::open_content(&content_key, &nonce, &aad, &value.sealed.ciphertext)?;

    // New values carry an authenticated discriminator. Unknown/corrupt Thorax envelopes fail
    // closed instead of silently becoming a legacy raw value. Pre-discriminator structured
    // values and raw values remain readable and are upgraded on their next write.
    let decoded = if let Some(payload) = opened.strip_prefix(SEALED_VALUE_V1_MAGIC) {
        Some(
            cord::deserialize::<SecretValueV1>(payload)
                .map_err(|_| OpsError::InvalidSecretPlaintext)?,
        )
    } else if opened.starts_with(SEALED_VALUE_PREFIX) {
        return Err(OpsError::InvalidSecretPlaintext);
    } else {
        cord::deserialize::<SecretValueV1>(&opened).ok()
    };
    let (primary, fields) = match decoded {
        Some(envelope) => {
            let SecretValueV1 { primary, fields } = envelope;
            let mut fields: Vec<SecretField> = fields
                .into_iter()
                .map(|entry| SecretField {
                    key: entry.key,
                    value: Zeroizing::new(entry.value),
                })
                .collect();
            // Stable, key-sorted order for deterministic display across frontends.
            fields.sort_by(|a, b| a.key.cmp(&b.key));
            (Zeroizing::new(primary), fields)
        }
        None => (opened, Vec::new()),
    };

    Ok(SecretPlaintext {
        selector: value.selector,
        plaintext: primary,
        fields,
    })
}

/// The record-position identity a sealed secret payload is cryptographically bound to:
/// where the record lands (key, signer, counter) and which secret it is (id, selector).
/// Both the seal path and the AAD re-derivation on decrypt describe a payload through this
/// one bundle.
pub(crate) struct SealContext<'a> {
    pub(crate) record_key: &'a RecordKey,
    /// The writer's signing public key — the same key the record envelope carries.
    pub(crate) signer_key: &'a [u8],
    pub(crate) counter: u64,
    pub(crate) secret_id: &'a SecretId,
    pub(crate) selector: &'a SecretSelectorV1,
}

pub(crate) fn seal_secret_payload(
    effective: &EffectiveState,
    context: &SealContext<'_>,
    value: &SecretValueV1,
) -> Result<SealedPayloadV1> {
    let trusted_root = effective_trusted_root(effective)?.clone();
    // The sealed plaintext is the cord-encoded value envelope (primary + additional fields),
    // not the bare primary bytes. It lives only for this seal and is zeroized after.
    let encoded = cord::serialize(value)?;
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        SEALED_VALUE_V1_MAGIC.len() + encoded.len(),
    ));
    plaintext.extend_from_slice(SEALED_VALUE_V1_MAGIC);
    plaintext.extend_from_slice(&encoded);
    let content_key = thorax_crypto::ContentKey::generate();
    let nonce = thorax_crypto::ContentNonce::generate();
    let nonce_bytes = nonce.to_vec();
    let mut recipient_slots = Vec::new();

    for reader_id in effective.current_reader_entries(context.selector) {
        let user = effective
            .users
            .get(&reader_id)
            .ok_or_else(|| OpsError::MissingReaderUser(reader_id.clone()))?;
        let slot_binding = recipient_slot_binding_bytes(
            &trusted_root,
            context.secret_id,
            context.selector,
            &reader_id,
        )?;
        let wrapped = thorax_crypto::wrap_content_key(
            &user.hpke_public_key,
            &slot_binding,
            &slot_binding,
            &content_key,
        )?;
        recipient_slots.push(RecipientSlotV1 {
            recipient_id: reader_id,
            hpke_encapsulated_key: wrapped.encapsulated_key,
            wrapped_content_key: wrapped.ciphertext,
        });
    }

    let aad = secret_content_aad_bytes(&trusted_root, context, &nonce_bytes, &recipient_slots)?;
    let ciphertext = thorax_crypto::seal_content(&content_key, &nonce, &aad, &plaintext)?;

    Ok(SealedPayloadV1 {
        nonce: nonce_bytes,
        ciphertext,
        recipient_slots,
    })
}

fn secret_content_aad_bytes(
    trusted_root: &HashValue,
    context: &SealContext<'_>,
    nonce: &[u8],
    recipient_slots: &[RecipientSlotV1],
) -> Result<Bytes> {
    Ok(cord::serialize(&SecretContentAadV1 {
        trusted_root: trusted_root.clone(),
        record_key: context.record_key.clone(),
        signing_public_key: context.signer_key.to_vec(),
        counter: context.counter,
        secret_id: context.secret_id.clone(),
        selector: context.selector.clone(),
        nonce: nonce.to_vec(),
        recipient_slots: recipient_slots.to_vec(),
    })?)
}

fn recipient_slot_binding_bytes(
    trusted_root: &HashValue,
    secret: &SecretId,
    selector: &SecretSelectorV1,
    recipient: &UserId,
) -> Result<Bytes> {
    Ok(cord::serialize(&RecipientSlotBindingV1 {
        trusted_root: trusted_root.clone(),
        secret_id: secret.clone(),
        selector: selector.clone(),
        recipient_id: recipient.clone(),
    })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::*;

    #[test]
    fn production_root_sets_and_gets_secret() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "prod", "vault"]);

        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"postgres://example",
        )
        .unwrap();
        let opened = get_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
        )
        .unwrap();

        assert_eq!(opened.selector, selector);
        assert_eq!(&*opened.plaintext, b"postgres://example");
        assert!(opened.fields.is_empty());
    }

    fn value_with_fields(primary: &[u8], fields: &[(&str, &[u8])]) -> SecretValueV1 {
        SecretValueV1 {
            primary: primary.to_vec(),
            fields: fields
                .iter()
                .map(|(key, value)| SecretFieldEntryV1 {
                    key: key.to_string(),
                    value: value.to_vec(),
                })
                .collect::<Vec<_>>()
                .into(),
        }
    }

    fn field_pairs(opened: &SecretPlaintext) -> Vec<(String, Vec<u8>)> {
        opened
            .fields
            .iter()
            .map(|field| (field.key.clone(), field.value.to_vec()))
            .collect()
    }

    #[test]
    fn primary_and_fields_round_trip() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                value_with_fields(b"pw", &[("host", b"db.example"), ("port", b"5432")]),
            )
            .unwrap();

        let opened = get_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
        )
        .unwrap();
        assert_eq!(&*opened.plaintext, b"pw");
        // Fields come back sorted by key.
        assert_eq!(
            field_pairs(&opened),
            vec![
                ("host".to_string(), b"db.example".to_vec()),
                ("port".to_string(), b"5432".to_vec()),
            ]
        );
    }

    #[test]
    fn primary_update_preserves_fields() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                value_with_fields(b"pw", &[("host", b"db.example")]),
            )
            .unwrap();

        // Update only the primary, carrying the fields across (the CLI `set` path).
        let opened = get_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
        )
        .unwrap();
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                opened.to_value_with_primary(b"pw2".to_vec()),
            )
            .unwrap();

        let again = get_secret(&fixture.paths, &fixture.crypto, &fixture.root, selector).unwrap();
        assert_eq!(&*again.plaintext, b"pw2");
        assert_eq!(
            field_pairs(&again),
            vec![("host".to_string(), b"db.example".to_vec())]
        );
    }

    #[test]
    fn with_field_and_without_field_mutate_only_their_key() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                value_with_fields(b"pw", &[("host", b"db.example")]),
            )
            .unwrap();

        // Add a second field.
        let opened = get_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
        )
        .unwrap();
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                opened.with_field("port", b"5432".to_vec()),
            )
            .unwrap();

        // Remove the first; the second and the primary survive.
        let opened = get_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
        )
        .unwrap();
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                opened.without_field("host"),
            )
            .unwrap();

        let opened = get_secret(&fixture.paths, &fixture.crypto, &fixture.root, selector).unwrap();
        assert_eq!(&*opened.plaintext, b"pw");
        assert_eq!(
            field_pairs(&opened),
            vec![("port".to_string(), b"5432".to_vec())]
        );
    }

    #[test]
    fn relabel_preserves_fields() {
        let fixture = ProductionFixture::initialized();
        let from = SecretSelectorV1::tuple(["app", "db"]);
        let to = SecretSelectorV1::tuple(["app", "db", "moved"]);
        LockedSession::load(&fixture.paths, &fixture.crypto)
            .unwrap()
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                from.clone(),
                value_with_fields(b"pw", &[("host", b"db.example")]),
            )
            .unwrap();

        let locked = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let mut unlocked =
            UnlockedSession::with_identity(locked, &fixture.crypto, fixture.root.clone()).unwrap();
        unlocked
            .relabel_secret(&fixture.crypto, from.clone(), to.clone())
            .unwrap();

        let opened = get_secret(&fixture.paths, &fixture.crypto, &fixture.root, to).unwrap();
        assert_eq!(&*opened.plaintext, b"pw");
        assert_eq!(
            field_pairs(&opened),
            vec![("host".to_string(), b"db.example".to_vec())]
        );
    }

    #[test]
    fn legacy_raw_value_falls_back_to_primary_only() {
        // The envelope round-trips; a bare value sealed before the envelope existed will not
        // decode as `SecretValueV1`, which is exactly the condition `decrypt_secret_record`
        // falls back on to treat the whole plaintext as the primary with no fields.
        let value = value_with_fields(b"pw", &[("host", b"db.example")]);
        let encoded = cord::serialize(&value).unwrap();
        assert_eq!(cord::deserialize::<SecretValueV1>(&encoded).unwrap(), value);
        assert!(cord::deserialize::<SecretValueV1>(b"raw-legacy-secret").is_err());
    }

    #[test]
    fn production_root_gets_secret_through_keychain() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "prod", "vault"]);
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
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"postgres://example",
        )
        .unwrap();
        let opened = get_secret_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            selector.clone(),
            OutputSink::Stdout,
        )
        .unwrap();

        assert_eq!(opened.selector, selector);
        assert_eq!(&*opened.plaintext, b"postgres://example");
    }

    #[test]
    fn production_root_sets_and_deletes_secret_through_keychain() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "prod", "keychain-write"]);
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

        set_secret_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            selector.clone(),
            b"keychain-mediated",
        )
        .unwrap();
        let opened = get_secret_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            selector.clone(),
            OutputSink::Stdout,
        )
        .unwrap();
        assert_eq!(&*opened.plaintext, b"keychain-mediated");

        delete_secret_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            selector.clone(),
        )
        .unwrap();
        // A deleted secret is indistinguishable from one that never existed: it reads as missing.
        assert!(matches!(
            get_secret(&fixture.paths, &fixture.crypto, &fixture.root, selector),
            Err(OpsError::SecretMissing)
        ));
    }

    #[test]
    fn production_reader_with_grant_can_get_secret() {
        let fixture = ProductionFixture::initialized();
        let alice = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.user_id().clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(["app"])),
            IdSeed::from_bytes(b"alice-production-read".to_vec()),
        )
        .unwrap();
        let selector = SecretSelectorV1::tuple(["app", "prod"]);

        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"secret bytes",
        )
        .unwrap();
        let opened = get_secret(&fixture.paths, &fixture.crypto, &alice, selector).unwrap();

        assert_eq!(&*opened.plaintext, b"secret bytes");
    }

    #[test]
    fn production_user_without_read_cannot_get_secret() {
        let fixture = ProductionFixture::initialized();
        let alice = Identity::generate(&fixture.crypto).unwrap();
        let bob = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &bob).unwrap();
        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.user_id().clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(["app"])),
            IdSeed::from_bytes(b"alice-only-read".to_vec()),
        )
        .unwrap();
        let selector = SecretSelectorV1::tuple(["app", "prod"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"not for bob",
        )
        .unwrap();

        assert!(matches!(
            get_secret(&fixture.paths, &fixture.crypto, &bob, selector),
            Err(OpsError::SecretNotDecryptable(SecretState::Unauthorized))
        ));
    }

    #[test]
    fn production_unauthorized_keychain_get_fails_closed_after_unlock() {
        // Unlock-first posture: the session anchors (bob is a member, so the funnel
        // succeeds), and the read itself fails closed on authority — no plaintext, no
        // recipient-slot probing.
        let fixture = ProductionFixture::initialized();
        let bob = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &bob).unwrap();
        let bob_keychain = ManualIdentityKeychain::new(
            FixedIdentityProvider::from_master_seed(&fixture.crypto, bob.master_seed()).unwrap(),
        );
        let selector = SecretSelectorV1::tuple(["app", "prod"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"not for bob",
        )
        .unwrap();

        let error = match get_secret_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &bob_keychain,
            bob.user_id(),
            selector,
            OutputSink::Stdout,
        ) {
            Ok(_) => panic!("unauthorized keychain get unexpectedly succeeded"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            OpsError::SecretNotDecryptable(SecretState::Unauthorized)
        ));
    }

    #[test]
    fn production_delete_secret_makes_get_return_deleted() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "deleted"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"short lived",
        )
        .unwrap();

        delete_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
        )
        .unwrap();

        // A deleted secret is indistinguishable from one that never existed: it reads as missing.
        assert!(matches!(
            get_secret(&fixture.paths, &fixture.crypto, &fixture.root, selector),
            Err(OpsError::SecretMissing)
        ));
    }

    #[test]
    fn production_commits_proceed_with_unknown_records_present() {
        let fixture = ProductionFixture::initialized();
        // A newer thorax's record lands in the vault (as it would via a git pull).
        let mut vault = thorax_store::read_vault(&fixture.paths).unwrap();
        let VaultStore::V1(ref mut v1) = vault;
        v1.records
            .insert(thorax_core::test_support::future_record_kind(3));
        thorax_store::write_vault_atomic(&fixture.paths, &vault).unwrap();

        // The advisory contract end to end: this build still reads and writes, surfaces
        // the unknown record as a warning, and carries it through the commit untouched.
        let selector = SecretSelectorV1::tuple(["app", "prod", "alongside-future"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"written next to a future record",
        )
        .unwrap();
        let opened = get_secret(&fixture.paths, &fixture.crypto, &fixture.root, selector).unwrap();
        assert_eq!(&*opened.plaintext, b"written next to a future record");

        let session = load_session(&fixture.paths, &fixture.crypto);
        assert!(session.report().issues.is_empty());
        assert_eq!(
            session.report().warnings,
            vec![ValidationWarning::UnknownRecords { count: 1 }]
        );
        let VaultStore::V1(v1) = session.vault();
        assert!(v1.records.iter().any(|record| record.body.is_unknown()));
    }

    #[test]
    fn production_secret_aad_binds_the_trusted_root() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "prod", "rooted"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"bound to this vault",
        )
        .unwrap();

        let session = load_session(&fixture.paths, &fixture.crypto);
        let ActiveSecretV1 { signed, value } = session
            .effective()
            .secret_record(&selector, &fixture.crypto)
            .unwrap()
            .unwrap();
        let trusted_root = effective_trusted_root(session.effective()).unwrap().clone();

        let opened =
            decrypt_secret_record(&fixture.root, &signed, value.clone(), &trusted_root).unwrap();
        assert_eq!(&*opened.plaintext, b"bound to this vault");

        // The same record presented under any other trust anchor must not open: the AAD
        // commits to the root the payload was sealed for.
        let foreign_root = HashValue(vec![0_u8; trusted_root.0.len()]);
        assert!(decrypt_secret_record(&fixture.root, &signed, value, &foreign_root).is_err());
    }

    #[test]
    fn non_admin_insider_cannot_brick_the_vault_by_forging_a_pairing() {
        // The signing-key collision DoS, under real crypto. A non-admin member appends a
        // `User` record pairing a *victim's* real signing key (and, separately, the root's)
        // with their own HPKE key, minting a second UserId over that key. Before the
        // attestation gate this forced a blocking AmbiguousSigningKey and bricked the whole
        // vault for everyone. Now the forged pairing is unattested — only the key's holder
        // can sign the matching self-signed entry point, which the attacker cannot — so it
        // is ignored: the vault stays valid and the victim keeps reading. This is the
        // possession-grade counterpart of the core `unattested_pairing_claim` test (where
        // deterministic crypto cannot model "cannot sign as the victim").
        let fixture = ProductionFixture::initialized();
        let alice = Identity::generate(&fixture.crypto).unwrap(); // victim: a reader
        let bob = Identity::generate(&fixture.crypto).unwrap(); // attacker: a non-admin member
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &bob).unwrap();
        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.user_id().clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(["app"])),
            IdSeed::from_bytes(b"alice-read".to_vec()),
        )
        .unwrap();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        // Sealed after the grant, so alice gets a recipient slot.
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"top secret",
        )
        .unwrap();
        assert_eq!(
            &*get_secret(&fixture.paths, &fixture.crypto, &alice, selector.clone())
                .unwrap()
                .plaintext,
            b"top secret"
        );

        // Bob holds only his own key. He forges two `User` records — one over alice's
        // signing key, one over the root's — both signed by himself, both pairing the
        // stolen signing key with his own HPKE key. He cannot produce the matching entry
        // point for either (that needs the victim's / root's private key).
        let mut vault = thorax_store::read_vault(&fixture.paths).unwrap();
        let trusted_root =
            thorax_core::crypto::key_hash(&fixture.crypto, fixture.root.signing_public_key())
                .unwrap();
        let ratchet = thorax_store::read_ratchet_for_root(&fixture.paths, &trusted_root)
            .unwrap()
            .unwrap();
        let report = thorax_core::validate_vault(&vault, &ratchet, &fixture.crypto).unwrap();
        let counter = thorax_core::next_counter(&report.effective);
        let forge_victim = thorax_core::hazmat::user_record(
            &fixture.crypto,
            &bob,
            alice.signing_public_key().to_vec(),
            bob.hpke_public_key().to_vec(),
            counter,
        )
        .unwrap();
        let forge_root = thorax_core::hazmat::user_record(
            &fixture.crypto,
            &bob,
            fixture.root.signing_public_key().to_vec(),
            bob.hpke_public_key().to_vec(),
            counter + 1,
        )
        .unwrap();
        {
            let VaultStore::V1(v1) = &mut vault;
            v1.records.insert(forge_victim);
            v1.records.insert(forge_root);
        }
        thorax_store::write_vault_atomic(&fixture.paths, &vault).unwrap();

        // The vault still validates — no blocking issue, no AmbiguousSigningKey warning
        // (the forged pairings are unattested, so they neither collide nor contest)...
        let session = load_session(&fixture.paths, &fixture.crypto);
        assert!(
            session.report().issues.is_empty(),
            "{:?}",
            session.report().issues
        );
        assert!(
            !session
                .report()
                .warnings
                .iter()
                .any(|warning| matches!(warning, ValidationWarning::AmbiguousSigningKey(_))),
            "{:?}",
            session.report().warnings
        );
        // ...and both the victim and the root still read the secret: their keys resolve to
        // them, unpoisoned.
        assert_eq!(
            &*get_secret(&fixture.paths, &fixture.crypto, &alice, selector.clone())
                .unwrap()
                .plaintext,
            b"top secret"
        );
        assert_eq!(
            &*get_secret(&fixture.paths, &fixture.crypto, &fixture.root, selector)
                .unwrap()
                .plaintext,
            b"top secret"
        );
    }
}
