use thorax_core::hazmat::{record_payload, secret_record, signed_payload};
use thorax_core::ids::derive_secret_id;
use thorax_core::{
    record_hash, record_key_for, ConflictKind, ConflictReport, CryptoProvider, EffectiveState,
    HashValue, RecordBodyV1, RecordKey, SecretRecordV1, SecretState, UserId, VaultRecordV1,
};
use thorax_crypto::{Crypto, Identity};

use crate::principals::{ensure_administer, ensure_can_confer_group, ensure_can_create_permission};
use crate::secrets::{
    decrypt_secret_record, effective_trusted_root, ensure_can_write_secret, seal_secret_payload,
    SealContext,
};
use crate::{
    AcceptRollbackOutput, LockedSession, OpsError, ResolveConflictOutput, Result, SecretPlaintext,
    UnlockedSession,
};

/// The conflict-resolution family of operations, acting as the session's unlocked
/// identity. A conflict is a key with no effective winner — a same-counter tie of
/// diverging bodies, or a suspected rollback — and the session's validation report is its
/// source of truth (`EffectiveState::conflicted`).
impl UnlockedSession {
    /// Resolve a conflict by ratifying one of its candidates: re-sign the chosen
    /// candidate's body, as the resolver, at a counter above both the global maximum and
    /// any rollback conflict's remembered watermark. Until this happens the conflicted key
    /// is inert — nothing at it is effective and reads of it fail; there is deliberately no
    /// implicit tie-break. An ordinary authorized mutation — the resolver needs the same
    /// authority the record class requires, and the commit is verified to have made the
    /// chosen content the effective record at the conflict's key.
    ///
    /// A rollback conflict whose records were dropped entirely has no candidates to pick;
    /// it is resolved by writing fresh content at the key (e.g. `set`), or by
    /// [`LockedSession::accept_rollback`] (this machine adapts its memory instead).
    pub fn resolve_conflict(
        &mut self,
        crypto: &Crypto,
        pick: &HashValue,
    ) -> Result<ResolveConflictOutput> {
        let (conflict, candidate) = find_conflict_candidate(self.effective(), crypto, pick)?;
        let body = candidate
            .body
            .known()
            .cloned()
            .ok_or(OpsError::ConflictNotResolvable(
                "candidate body is not readable by this build",
            ))?;
        ensure_can_resolve_conflict(self.effective(), self.user_id(), &conflict, &body)?;

        let (session, identity) = self.parts();

        // A secret *value* cannot be re-signed verbatim: its AEAD binds the record key,
        // signer, and counter into the associated data, so a counter bump would break
        // decryption. Resolving a secret conflict therefore re-seals: decrypt the chosen
        // candidate (the resolver needs a recipient slot on it) and write it like any
        // `set` — fresh content key, fresh slots for the *current* readers, the resolver
        // as writer.
        if let RecordBodyV1::Secret(value) = body {
            return session.resolve_secret_conflict(crypto, identity, &candidate, value);
        }

        let conflict_key = conflict.key.clone();
        let chosen = body.clone();
        session.commit_record(
            crypto,
            |_pre_report, counter| {
                let bumped =
                    body.with_lww_counter(counter)
                        .ok_or(OpsError::ConflictNotResolvable(
                            "the root record is not LWW-resolved",
                        ))?;
                let signed = signed_payload(crypto, identity, record_payload(bumped))?;
                let hash = record_hash(crypto, &signed)?;
                Ok((
                    signed,
                    ResolveConflictOutput {
                        key: conflict_key.clone(),
                        counter,
                        record_hash: hash,
                    },
                ))
            },
            |output, _hash, report| ensure_resolution_effective(&report.effective, &chosen, output),
        )
    }

    /// [`LockedSession::accept_rollback`], reachable from the anchored session too — the
    /// gating is intentionally identical (machine-local trust memory, fail-open; the
    /// identity plays no part).
    pub fn accept_rollback(
        &mut self,
        crypto: &Crypto,
        key: &RecordKey,
    ) -> Result<AcceptRollbackOutput> {
        let (session, _) = self.parts();
        session.accept_rollback(crypto, key)
    }

    /// Decrypt *candidates* of secret-value conflicts, so a resolver can inspect the
    /// competing (or rolled-back-to) values before picking a winner. Same gates as an
    /// ordinary `get`, per candidate: current read authority on the selector and a
    /// recipient slot keyed to the caller on that specific record — being a conflict
    /// candidate grants nothing. The keychain release scoped to the inspection happened
    /// when this session was opened.
    pub fn reveal_conflict_candidates(
        &self,
        crypto: &Crypto,
        picks: &[HashValue],
    ) -> Result<Vec<(HashValue, SecretPlaintext)>> {
        let mut candidates = Vec::new();
        for pick in picks {
            let (_, candidate) = find_conflict_candidate(self.effective(), crypto, pick)?;
            let Some(RecordBodyV1::Secret(value)) = candidate.body.known().cloned() else {
                return Err(OpsError::ConflictNotResolvable(
                    "only secret-value candidates can be revealed",
                ));
            };
            if self.effective().authority_unresolved
                || !self
                    .effective()
                    .authority_for_user(self.user_id())
                    .can_read(&value.selector)
            {
                return Err(OpsError::SecretNotDecryptable(SecretState::Unauthorized));
            }
            candidates.push((pick.clone(), candidate, value));
        }
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let trusted_root = effective_trusted_root(self.effective())?.clone();
        candidates
            .into_iter()
            .map(|(pick, candidate, value)| {
                decrypt_secret_record(self.identity(), &candidate, value, &trusted_root)
                    .map(|plaintext| (pick, plaintext))
            })
            .collect()
    }
}

/// The signer-direct inner half of secret-conflict resolution, plus the machine-local
/// rollback acceptance (deliberately *not* unlock-gated — see below).
impl LockedSession {
    fn resolve_secret_conflict(
        &mut self,
        crypto: &Crypto,
        identity: &Identity,
        candidate: &VaultRecordV1,
        value: SecretRecordV1,
    ) -> Result<ResolveConflictOutput> {
        let trusted_root = effective_trusted_root(self.effective())?.clone();
        let opened = decrypt_secret_record(identity, candidate, value, &trusted_root)?;
        let selector = opened.selector.clone();
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
                        signer_key: identity.signing_public_key(),
                        counter,
                        secret_id: &secret,
                        selector: &selector,
                    },
                    // Re-seal the whole value so resolving a conflict preserves any fields.
                    &opened.to_value(),
                )?;
                let signed = secret_record(crypto, identity, selector.clone(), sealed, counter)?;
                let hash = record_hash(crypto, &signed)?;
                Ok((
                    signed,
                    ResolveConflictOutput {
                        key: record_key.clone(),
                        counter,
                        record_hash: hash,
                    },
                ))
            },
            |output, _hash, report| {
                if report
                    .effective
                    .secret_record_is_current(&output.record_hash)
                {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective(
                        "conflict resolution did not become the effective record",
                    ))
                }
            },
        )
    }

    /// Accept a rollback: this machine deliberately forgets that it ever verified the
    /// remembered counter at `key`, lowering its watermark to whatever the vault currently
    /// shows, so the visible state becomes trusted as-is. The per-key counterpart of
    /// `reset_ratchet` — and like it, a **fail-open recovery flow**: it gives up the
    /// tamper alarm for exactly this key, so call sites must require explicit user intent.
    ///
    /// Purely machine-local — no record is written and no identity is unlocked (any local
    /// user may adjust their own machine's memory). Only rollback conflicts can be
    /// accepted; a tie is a real ambiguity in the vault itself and must be resolved.
    ///
    /// This is the deliberate exception to "mutations live on [`UnlockedSession`]": like
    /// `reset_ratchet`, a rollback may have conflicted the very entry point that makes
    /// the actor an effective member, so routing recovery through the membership-pinned
    /// session would deadlock it. It touches only this machine's trust memory — never the
    /// vault, never key material.
    pub fn accept_rollback(
        &mut self,
        crypto: &Crypto,
        key: &RecordKey,
    ) -> Result<AcceptRollbackOutput> {
        let conflict =
            self.effective()
                .conflicted
                .get(key)
                .ok_or(OpsError::ConflictNotResolvable(
                    "no conflict exists at this key",
                ))?;
        let ConflictKind::Rollback { remembered_counter } = conflict.kind else {
            return Err(OpsError::ConflictNotResolvable(
                "only rollback conflicts can be accepted — a tie needs an explicit winner",
            ));
        };
        let accepted_counter = conflict.counter;

        self.rewrite_ratchet(crypto, |trust| {
            if accepted_counter == 0 {
                // Nothing survives at the key: forget it entirely. The origin rides on the
                // watermark fact, so it goes too (re-learned if the key ever returns).
                trust.watermarks.remove(key);
                trust.origins.remove(key);
            } else {
                trust.watermarks.insert(key.clone(), accepted_counter);
            }
        })?;

        if self.effective().conflicted.contains_key(key) {
            return Err(OpsError::OperationNotEffective(
                "accepting the rollback did not clear the conflict",
            ));
        }
        Ok(AcceptRollbackOutput {
            key: key.clone(),
            remembered_counter,
            accepted_counter,
        })
    }
}

/// Whether `resolver` holds the authority to resolve `conflict` to `candidate_body` — the
/// same bar the record class requires to be written at all. Frontends use this to disable
/// resolution affordances the user cannot exercise; [`UnlockedSession::resolve_conflict`]
/// enforces it before signing anything, and the post-commit effectiveness check
/// remains the final arbiter (validation, not this pre-flight, decides what is admitted).
pub fn ensure_can_resolve_conflict(
    effective: &EffectiveState,
    resolver: &UserId,
    conflict: &ConflictReport,
    candidate_body: &RecordBodyV1,
) -> Result<()> {
    // The bumped record must land at the conflict's own key. The one kind that can't
    // always: an entry point, whose key is its signer — only the pinning user can re-sign
    // their own.
    let resolved_key = record_key_for(candidate_body, resolver)?;
    if resolved_key != conflict.key {
        return Err(OpsError::ConflictNotResolvable(
            "this record can only be re-signed by its own user",
        ));
    }
    match candidate_body {
        RecordBodyV1::Secret(record) => {
            ensure_can_write_secret(effective, resolver, &record.selector)
        }
        RecordBodyV1::SecretDeleted(record) => {
            ensure_can_write_secret(effective, resolver, &record.selector)
        }
        RecordBodyV1::Grant(record) => {
            ensure_can_create_permission(effective, resolver, &record.permission)
        }
        RecordBodyV1::GrantDeleted(record) => {
            ensure_can_create_permission(effective, resolver, &record.permission)
        }
        RecordBodyV1::GroupMember(record) => {
            ensure_administer(effective, resolver)?;
            ensure_can_confer_group(effective, resolver, &record.group_id)
        }
        RecordBodyV1::GroupMemberDeleted(_)
        | RecordBodyV1::User(_)
        | RecordBodyV1::UserDeleted(_)
        | RecordBodyV1::Group(_)
        | RecordBodyV1::GroupDeleted(_)
        | RecordBodyV1::UserHandle(_)
        | RecordBodyV1::VaultHandle(_) => ensure_administer(effective, resolver),
        // Ownership was pinned by the key check above; pinning a root needs no grant.
        RecordBodyV1::EntryPoint(_) => Ok(()),
        RecordBodyV1::VaultRoot(_) => Err(OpsError::ConflictNotResolvable(
            "the root record cannot conflict",
        )),
    }
}

/// Find the conflict candidate with record hash `pick` in the session's authoritative
/// conflict set — same-counter ties and rollback survivors alike.
fn find_conflict_candidate(
    effective: &EffectiveState,
    crypto: &impl CryptoProvider,
    pick: &HashValue,
) -> Result<(ConflictReport, VaultRecordV1)> {
    for conflict in effective.conflicted.values() {
        for candidate in &conflict.candidates {
            if &record_hash(crypto, candidate)? == pick {
                return Ok((conflict.clone(), candidate.clone()));
            }
        }
    }
    Err(OpsError::ConflictCandidateNotFound(pick.clone()))
}

/// Did the resolution's bump become the effective record at its key? Checked on outcome
/// content, which distinguishes the candidates because tie candidates diverge by
/// definition: an add's content must be the effective record, a deletion's object must be
/// effectively absent. Secrets get the exact-hash check (`secret_record_is_current`).
fn ensure_resolution_effective(
    effective: &EffectiveState,
    chosen: &RecordBodyV1,
    output: &ResolveConflictOutput,
) -> Result<()> {
    let won = match chosen {
        RecordBodyV1::Secret(_) | RecordBodyV1::SecretDeleted(_) => {
            effective.secret_record_is_current(&output.record_hash)
        }
        RecordBodyV1::User(record) => effective.users.get(&record.id).is_some_and(|user| {
            user.signing_public_key == record.signing_public_key
                && user.hpke_public_key == record.hpke_public_key
        }),
        RecordBodyV1::UserDeleted(record) => {
            !effective.users.contains_key(&record.id)
                && effective.deleted_users.contains(&record.id)
        }
        RecordBodyV1::Group(record) => effective
            .groups
            .get(&record.id)
            .is_some_and(|group| group.handle == record.handle && group.seed == record.seed),
        RecordBodyV1::GroupDeleted(record) => {
            !effective.groups.contains_key(&record.id)
                && effective.deleted_groups.contains(&record.id)
        }
        RecordBodyV1::GroupMember(record) => {
            effective.memberships.get(&record.id).is_some_and(|member| {
                member.group_id == record.group_id && member.member_id == record.member_id
            })
        }
        RecordBodyV1::GroupMemberDeleted(record) => !effective.memberships.contains_key(&record.id),
        RecordBodyV1::Grant(record) => effective.grants.get(&record.id).is_some_and(|grant| {
            grant.subject_id == record.subject_id && grant.permission == record.permission
        }),
        RecordBodyV1::GrantDeleted(record) => {
            !effective.grants.contains_key(&record.id)
                && effective.deleted_grants.contains(&record.id)
        }
        RecordBodyV1::UserHandle(record) => {
            effective.handles.get(&record.id).is_some_and(|handle| {
                handle.handle == record.handle && handle.user_id == record.user_id
            })
        }
        RecordBodyV1::VaultHandle(record) => effective
            .vault_handles
            .get(&record.id)
            .is_some_and(|handle| handle.handle == record.handle),
        RecordBodyV1::EntryPoint(record) => match &output.key {
            RecordKey::EntryPoint { user_id } => {
                effective.entry_points.get(user_id).is_some_and(|entry| {
                    entry.trusted_root_user_id == record.trusted_root_user_id
                        && entry.counter == output.counter
                })
            }
            _ => false,
        },
        RecordBodyV1::VaultRoot(_) => false,
    };
    if won {
        Ok(())
    } else {
        Err(OpsError::OperationNotEffective(
            "conflict resolution did not become the effective record",
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::*;
    use crate::*;
    use std::fs;

    /// End-to-end (c): rolling the vault file back past a verified write surfaces a
    /// rollback *conflict* on the secret's key — the session loads, reads of that key fail
    /// closed — and ratifying the surviving candidate re-signs it above the remembered
    /// watermark, clearing the conflict for good.
    #[test]
    fn rollback_is_a_conflict_and_ratifying_the_survivor_clears_it() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        let keychain = PassphraseKeychain::new(
            fixture._temp.path().join("keychain"),
            StaticPassphraseProvider::new("pw"),
        );
        let root_hash = key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap();
        save_identity_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            &root_hash,
            &fixture.root,
        )
        .unwrap();

        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v1",
        )
        .unwrap();
        let v1_vault = fs::read(&fixture.paths.vault_path).unwrap();
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v2",
        )
        .unwrap();

        // The vault file rolls back to the v1 state; the local ratchet still remembers v2.
        fs::write(&fixture.paths.vault_path, &v1_vault).unwrap();
        let session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();

        let conflict = session
            .effective()
            .secret_conflict(&selector, &fixture.crypto)
            .unwrap()
            .expect("the rolled-back secret key is a conflict")
            .clone();
        let ConflictKind::Rollback { remembered_counter } = conflict.kind else {
            panic!("expected a rollback conflict, got {:?}", conflict.kind);
        };
        assert_eq!(conflict.candidates.len(), 1, "the v1 record survives");
        assert!(conflict.counter < remembered_counter);

        // Reads of the conflicted key fail closed; the secret is absent from the live list.
        assert!(matches!(
            session.get_secret(&fixture.crypto, &fixture.root, selector.clone()),
            Err(OpsError::SecretConflicted)
        ));
        assert!(session.effective().secret_records().is_empty());

        // Ratify the survivor: it is re-sealed above the remembered watermark, so the
        // ratchet is satisfied and the conflict is gone.
        let pick = record_hash(&fixture.crypto, &conflict.candidates[0]).unwrap();
        let mut unlocked = UnlockedSession::promote(
            session,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            KeyUsePurpose::SignSecretWrite {
                selector: selector.clone(),
            },
        )
        .unwrap();
        let resolved = unlocked.resolve_conflict(&fixture.crypto, &pick).unwrap();
        assert!(resolved.counter > remembered_counter);
        assert!(unlocked.effective().conflicted.is_empty());
        let opened = unlocked.get_secret(&fixture.crypto, selector).unwrap();
        assert_eq!(&*opened.plaintext, b"v1");
    }

    /// A fresh `set` at a rolled-back key also clears the conflict: ordinary writes are
    /// floored above every rollback conflict's remembered watermark.
    #[test]
    fn a_fresh_set_at_a_rolled_back_key_clears_the_conflict() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v1",
        )
        .unwrap();
        let v1_vault = fs::read(&fixture.paths.vault_path).unwrap();
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v2",
        )
        .unwrap();
        fs::write(&fixture.paths.vault_path, &v1_vault).unwrap();

        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let conflict = session
            .effective()
            .secret_conflict(&selector, &fixture.crypto)
            .unwrap()
            .expect("rollback conflict")
            .clone();
        let ConflictKind::Rollback { remembered_counter } = conflict.kind else {
            panic!("expected a rollback conflict");
        };

        let output = session
            .set_secret_value(
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                SecretValueV1::from_primary(b"v3".to_vec()),
            )
            .unwrap();
        assert!(session.effective().conflicted.is_empty());
        let _ = output;
        let opened = session
            .get_secret(&fixture.crypto, &fixture.root, selector)
            .unwrap();
        assert_eq!(&*opened.plaintext, b"v3");
        // The write landed above the remembered watermark, or the conflict would persist.
        let report_counter = session
            .effective()
            .secret_records()
            .first()
            .map(|record| record.value.counter)
            .unwrap();
        assert!(report_counter > remembered_counter);
    }
}

#[cfg(test)]
mod accept_tests {
    use crate::test_util::*;
    use crate::*;
    use std::fs;

    /// Accepting a rollback is the no-signing alternative to ratifying: the machine lowers
    /// its own memory to what the vault shows, the conflict clears, and the surviving old
    /// value reads again *without* any new record being written.
    #[test]
    fn accepting_a_rollback_lowers_the_watermark_and_clears_the_conflict() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v1",
        )
        .unwrap();
        let v1_vault = fs::read(&fixture.paths.vault_path).unwrap();
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"v2",
        )
        .unwrap();
        fs::write(&fixture.paths.vault_path, &v1_vault).unwrap();

        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let record_count_before = match session.vault() {
            VaultStore::V1(v1) => v1.records.len(),
        };
        let key = session
            .effective()
            .secret_conflict(&selector, &fixture.crypto)
            .unwrap()
            .expect("rollback conflict")
            .key
            .clone();

        let accepted = session.accept_rollback(&fixture.crypto, &key).unwrap();
        assert!(accepted.remembered_counter > accepted.accepted_counter);
        assert!(session.effective().conflicted.is_empty());
        // No record was written — the machine adapted, not the vault.
        let record_count_after = match session.vault() {
            VaultStore::V1(v1) => v1.records.len(),
        };
        assert_eq!(record_count_before, record_count_after);
        let opened = session
            .get_secret(&fixture.crypto, &fixture.root, selector)
            .unwrap();
        assert_eq!(&*opened.plaintext, b"v1");

        // The acceptance persisted: a fresh load is clean too.
        let reloaded = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        assert!(reloaded.effective().conflicted.is_empty());
    }

    /// An erased key (nothing survives) accepts by forgetting the watermark entirely; the
    /// secret then reads as missing, exactly like one that never existed.
    #[test]
    fn accepting_an_erased_key_forgets_it() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "ghost"]);
        let before = fs::read(&fixture.paths.vault_path).unwrap();
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"short-lived",
        )
        .unwrap();
        fs::write(&fixture.paths.vault_path, &before).unwrap();

        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let conflict = session
            .effective()
            .secret_conflict(&selector, &fixture.crypto)
            .unwrap()
            .expect("rollback conflict")
            .clone();
        assert!(conflict.candidates.is_empty());

        let accepted = session
            .accept_rollback(&fixture.crypto, &conflict.key)
            .unwrap();
        assert_eq!(accepted.accepted_counter, 0);
        assert!(session.effective().conflicted.is_empty());
        assert!(!session.ratchet().watermarks.contains_key(&conflict.key));
        assert!(matches!(
            session.get_secret(&fixture.crypto, &fixture.root, selector),
            Err(OpsError::SecretMissing)
        ));
    }

    /// Ties cannot be accepted — they are real ambiguities in the vault, not memories.
    #[test]
    fn a_tie_cannot_be_accepted() {
        let fixture = ProductionFixture::initialized();
        let selector = SecretSelectorV1::tuple(["app", "db"]);
        let state_snapshot: Vec<u8> = {
            set_secret(
                &fixture.paths,
                &fixture.crypto,
                &fixture.root,
                selector.clone(),
                b"base",
            )
            .unwrap();
            fs::read(&fixture.paths.vault_path).unwrap()
        };
        let trust_path = ratchet_path(
            &fixture.paths,
            &key_hash(&fixture.crypto, fixture.root.signing_public_key()).unwrap(),
        );
        let trust_snapshot = fs::read(&trust_path).unwrap();
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"value-a",
        )
        .unwrap();
        let ours = fs::read(&fixture.paths.vault_path).unwrap();
        fs::write(&fixture.paths.vault_path, &state_snapshot).unwrap();
        fs::write(&trust_path, &trust_snapshot).unwrap();
        set_secret(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            selector.clone(),
            b"value-b",
        )
        .unwrap();
        let theirs = fs::read(&fixture.paths.vault_path).unwrap();
        let MergeOutcome::Merged { merged } = merge_vaults(
            Some(&decode_vault(&state_snapshot).unwrap()),
            &decode_vault(&ours).unwrap(),
            &decode_vault(&theirs).unwrap(),
        )
        .unwrap() else {
            panic!("union merge must not be refused");
        };
        fs::write(&fixture.paths.vault_path, encode_vault(&merged).unwrap()).unwrap();

        let mut session = LockedSession::load(&fixture.paths, &fixture.crypto).unwrap();
        let conflict = session
            .effective()
            .secret_conflict(&selector, &fixture.crypto)
            .unwrap()
            .expect("tie conflict")
            .clone();
        assert_eq!(conflict.kind, ConflictKind::Tie);
        assert!(matches!(
            session.accept_rollback(&fixture.crypto, &conflict.key),
            Err(OpsError::ConflictNotResolvable(_))
        ));
    }
}
