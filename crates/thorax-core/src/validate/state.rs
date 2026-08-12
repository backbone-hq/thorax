use super::effective::compare_lww;
use super::{ActiveSecretV1, EffectiveState, SecretSlot, SecretState, VerifiedRecord};
use crate::authz::AuthoritySet;
use crate::crypto::CryptoProvider;
use crate::format::*;
use crate::ids::derive_secret_id;
use crate::merge::ConflictReport;
use crate::Result;
use std::collections::{BTreeMap, BTreeSet};

impl EffectiveState {
    /// Attach the verified record set and build the per-secret winner index over it. The
    /// pipeline calls this once, *after* the authority fixpoint has settled: the index
    /// bakes in the same per-record gate the scans it replaced applied — the record's
    /// signer must hold write authority over the selector the record itself claims — so it
    /// must not be built against interim authorities. Conflict exclusion stays at the
    /// query layer (a conflicted key's winner is disputed; rollback-conflicted keys may
    /// have no records at all).
    pub(super) fn attach_verified_records(
        &mut self,
        verified_records: Vec<VerifiedRecord>,
        admitted_counter_max: Option<u64>,
    ) {
        self.admitted_counter_max = admitted_counter_max;
        self.verified_records = verified_records;
        let mut index: BTreeMap<SecretId, SecretSlot> = BTreeMap::new();
        for (position, record) in self.verified_records.iter().enumerate() {
            let Some((secret, selector)) = secret_record_identity(&record.body) else {
                continue;
            };
            // Authority is judged against the selector the record itself claims. Labels are
            // part of identity, so every record at one key carries the same selector; the
            // id is pinned to it by structural validation.
            if !self.authority_for_user(&record.signer).can_write(selector) {
                continue;
            }
            match index.get_mut(secret) {
                Some(slot) => {
                    // `compare_lww` is total over distinct records (record-hash tie-break,
                    // and byte-identical duplicates collapse before validation), so
                    // keep-the-greater picks the same winner the scans did.
                    if compare_lww(record, &self.verified_records[slot.winner]).is_gt() {
                        slot.winner = position;
                    }
                }
                None => {
                    index.insert(
                        secret.clone(),
                        SecretSlot {
                            winner: position,
                            first_seen: position,
                        },
                    );
                }
            }
        }
        self.secret_index = index;
    }

    pub fn authority_for_user(&self, user: &UserId) -> AuthoritySet {
        self.authorities
            .get(&PrincipalRefV1::User(user.clone()))
            .cloned()
            .unwrap_or_default()
    }

    pub fn authority_for_group(&self, group: &GroupId) -> AuthoritySet {
        self.authorities
            .get(&PrincipalRefV1::Group(group.clone()))
            .cloned()
            .unwrap_or_default()
    }

    /// The effective user a record's envelope signing key resolves to — the display-side
    /// counterpart of validation's key-uniqueness resolution (the envelope names a key,
    /// never a user). `None` when no effective user holds the key (e.g. a conflict
    /// candidate whose signer has since been deleted).
    pub fn user_for_signing_key(&self, signing_public_key: &[u8]) -> Option<&UserId> {
        self.users
            .iter()
            .find_map(|(id, user)| (user.signing_public_key == signing_public_key).then_some(id))
    }

    pub fn classify_secret_for_user(
        &self,
        selector: &SecretSelectorV1,
        user: &UserId,
        crypto: &impl CryptoProvider,
    ) -> SecretState {
        if self.authority_unresolved {
            return SecretState::Invalid;
        }

        // A conflicted key has no value to expose: fail closed before any winner lookup.
        match self.secret_conflict(selector, crypto) {
            Ok(Some(_)) => return SecretState::Conflicted,
            Ok(None) => {}
            Err(_) => return SecretState::Invalid,
        }

        let record = match self.live_secret_winner(selector, crypto) {
            Ok(Some(record)) => record,
            // No live value: never existed, or the latest record is a deletion — the two are
            // indistinguishable. (The deletion is still a signed fact in the log — see
            // `secret_record_is_current` — but it is never surfaced as a retrievable secret.)
            Ok(None) => return SecretState::Missing,
            Err(_) => return SecretState::Invalid,
        };

        match &record.body {
            RecordBodyV1::Secret(value) => {
                // A deleted user is absent from `users` and holds no authority, so the
                // checks below already exclude them.
                let current_user_auth = self.authority_for_user(user);
                if !current_user_auth.can_read(&value.selector) {
                    return SecretState::Unauthorized;
                }

                // Duplicate recipient slots are a structural integrity error.
                let mut seen = BTreeSet::new();
                for slot in &value.sealed.recipient_slots {
                    if !seen.insert(slot.recipient_id.clone()) {
                        return SecretState::Invalid;
                    }
                }

                // A value is exposed per-reader, not on exact-set match. The caller can read
                // iff the record carries a slot for them keyed to their current HPKE key.
                // Extra slots for *former* readers are harmless — they already had the value,
                // and confidentiality from them is restored only when the value next changes
                // (a fresh content key), not by stripping their slot from the current record.
                // A missing slot for some *other* current reader is that reader's concern.
                if !self.users.contains_key(user) {
                    return SecretState::Unauthorized;
                }
                // A slot's `recipient_id` (a `UserId`) commits to the reader's HPKE key, so a
                // slot bearing the reader's id is wrapped to their key; no separate hash compare.
                let can_decrypt = value
                    .sealed
                    .recipient_slots
                    .iter()
                    .any(|slot| slot.recipient_id == *user);
                if can_decrypt {
                    SecretState::ActiveDecryptable
                } else {
                    // Authorized, but the value has not been wrapped to this caller yet.
                    SecretState::NotEncryptedForReader
                }
            }
            _ => SecretState::Invalid,
        }
    }

    /// True if some current reader of `selector` lacks a recipient slot keyed to their
    /// current HPKE key — i.e. the value needs (re)wrapping so every authorized reader can
    /// decrypt it. Extra slots for former readers do not count; only missing readers do.
    /// This is what an access *addition* must fix; access *removals* leave it false.
    /// A conflicted secret reads as `false`: there is no value to wrap until resolution,
    /// and resolution itself re-seals to the current readers.
    pub fn secret_missing_reader(
        &self,
        selector: &SecretSelectorV1,
        crypto: &impl CryptoProvider,
    ) -> Result<bool> {
        let Some(active) = self.secret_record(selector, crypto)? else {
            return Ok(false);
        };
        let value = active.value;
        let readers = self.current_reader_entries(&value.selector);
        Ok(readers.iter().any(|reader_id| {
            !value
                .sealed
                .recipient_slots
                .iter()
                .any(|slot| slot.recipient_id == *reader_id)
        }))
    }

    /// The live value of a single secret, or `None` if it has no value — whether because it never
    /// existed or because its latest record is a deletion. The two are deliberately
    /// indistinguishable: a deleted secret is gone, and nothing retrieves deletions. (The deletion
    /// is still a signed fact in the log; ops verifies it landed via [`Self::secret_record_is_current`].)
    ///
    /// A *conflicted* secret also returns `None` — there is no value until resolution. Callers
    /// that must distinguish (anything user-facing) check [`Self::secret_conflict`] or
    /// [`Self::classify_secret_for_user`] first; plaintext paths are guarded by the latter.
    pub fn secret_record(
        &self,
        selector: &SecretSelectorV1,
        crypto: &impl CryptoProvider,
    ) -> Result<Option<ActiveSecretV1>> {
        if self.secret_conflict(selector, crypto)?.is_some() {
            return Ok(None);
        }
        let Some(record) = self.live_secret_winner(selector, crypto)? else {
            return Ok(None);
        };

        match &record.body {
            RecordBodyV1::Secret(value) => Ok(Some(ActiveSecretV1 {
                signed: record.signed.clone(),
                value: value.clone(),
            })),
            _ => Ok(None),
        }
    }

    /// The conflict at `selector`'s key, if any — a same-counter tie or a suspected
    /// rollback. Addressed by the whole selector (tuple + labels) like every secret lookup.
    pub fn secret_conflict(
        &self,
        selector: &SecretSelectorV1,
        crypto: &impl CryptoProvider,
    ) -> Result<Option<&ConflictReport>> {
        let secret = derive_secret_id(crypto, selector)?;
        Ok(self
            .conflicted
            .get(&RecordKey::Secret { secret_id: secret }))
    }

    /// Every conflict sitting on a secret key, for listings: these tuples have no current
    /// value, and reads of them fail until resolution.
    pub fn secret_conflicts(&self) -> Vec<&ConflictReport> {
        self.conflicted
            .values()
            .filter(|conflict| matches!(conflict.key, RecordKey::Secret { .. }))
            .collect()
    }

    /// The resolved, browsable secrets: one LWW-winning value per secret. Secrets whose latest
    /// record is a deletion are absent, and so are conflicted secrets (those are listed
    /// separately via [`Self::secret_conflicts`] — a listing that wants both shows this set
    /// as active rows and that one as conflict rows). This is the only list view — there is
    /// no notion of "listing deletions"; the signed log is the place to audit what was removed.
    pub fn secret_records(&self) -> Vec<ActiveSecretV1> {
        let mut slots: Vec<&SecretSlot> = self
            .secret_index
            .values()
            // Conflicted keys contribute nothing (every record at a key shares its
            // `RecordKey`, so the winner's key names the secret's key).
            .filter(|slot| {
                !self
                    .conflicted
                    .contains_key(&self.verified_records[slot.winner].key)
            })
            .collect();
        // Listing order is each key's first appearance in the record log — exactly what
        // the pre-index linear scan produced.
        slots.sort_unstable_by_key(|slot| slot.first_seen);
        slots
            .into_iter()
            // Keep only secrets whose winning record is a value; deletions drop out here.
            .filter_map(|slot| match &self.verified_records[slot.winner].body {
                RecordBodyV1::Secret(value) => Some(ActiveSecretV1 {
                    signed: self.verified_records[slot.winner].signed.clone(),
                    value: value.clone(),
                }),
                _ => None,
            })
            .collect()
    }

    /// Whether the record identified by `record_hash` is the current LWW winner for its secret.
    /// Deletion-agnostic: the winner may be a value or a deletion. Ops uses this after committing a
    /// mutation to confirm its own just-appended record actually took effect (mutate→reconcile→
    /// verify), without any public means of *retrieving* a deletion. An unauthorized, superseded,
    /// or conflicted record returns `false`.
    pub fn secret_record_is_current(&self, record_hash: &HashValue) -> bool {
        let Some(target) = self
            .verified_records
            .iter()
            .find(|record| &record.record_hash == record_hash)
        else {
            return false;
        };
        let Some((secret, _)) = secret_record_identity(&target.body) else {
            return false;
        };
        if self.conflicted.contains_key(&RecordKey::Secret {
            secret_id: secret.clone(),
        }) {
            return false;
        }
        match self.latest_authorized_secret_record(secret) {
            Some(winner) => &winner.record_hash == record_hash,
            None => false,
        }
    }

    /// Whether the current authorized LWW winner for this exact selector is a signed
    /// deletion. This is intentionally narrower than a history API: callers can
    /// distinguish authenticated removal from a selector that never existed, but cannot
    /// retrieve deleted plaintext or superseded records.
    pub fn secret_is_deleted(
        &self,
        selector: &SecretSelectorV1,
        crypto: &impl CryptoProvider,
    ) -> Result<bool> {
        let secret = derive_secret_id(crypto, selector)?;
        if self.conflicted.contains_key(&RecordKey::Secret {
            secret_id: secret.clone(),
        }) {
            return Ok(false);
        }
        Ok(self
            .latest_authorized_secret_record(&secret)
            .is_some_and(|record| matches!(record.body, RecordBodyV1::SecretDeleted(_))))
    }

    /// The `UserId`s of every current reader authorized for `selector`. A `UserId` commits to
    /// the reader's HPKE key, so the id is all a caller needs to wrap to (look up the key) or to
    /// check slot coverage against.
    pub fn current_reader_entries(&self, selector: &SecretSelectorV1) -> Vec<UserId> {
        let mut readers: Vec<UserId> = self
            .users
            .keys()
            .filter(|user| self.authority_for_user(user).can_read(selector))
            .cloned()
            .collect();
        readers.sort();
        readers
    }

    /// The LWW-winning *value* record for `selector`, if any: derives the secret id from the
    /// whole selector (tuple + labels), resolves the latest authorized record at it, and
    /// collapses a deletion winner (or no record at all) to `None`. Labels are part of the
    /// address, not a filter: `get app/db@env=prod` and `get app/db@env=staging` derive
    /// different ids and address different secrets. The shared core of every selector-keyed
    /// live view — `classify_secret_for_user`, `secret_record`, and (through it)
    /// `secret_missing_reader`. The deletion-agnostic path stays on
    /// [`Self::latest_authorized_secret_record`] (see `secret_record_is_current`).
    fn live_secret_winner(
        &self,
        selector: &SecretSelectorV1,
        crypto: &impl CryptoProvider,
    ) -> Result<Option<&VerifiedRecord>> {
        let secret = derive_secret_id(crypto, selector)?;
        Ok(self
            .latest_authorized_secret_record(&secret)
            // The latest record is a deletion (or some other body): no live value.
            .filter(|record| matches!(&record.body, RecordBodyV1::Secret(_))))
    }

    fn latest_authorized_secret_record(&self, secret: &SecretId) -> Option<&VerifiedRecord> {
        // The per-record authority gate (against each record's own claimed selector) is
        // baked into the index at attach time — see `attach_verified_records`.
        self.secret_index
            .get(secret)
            .map(|slot| &self.verified_records[slot.winner])
    }
}

fn secret_record_identity(body: &RecordBodyV1) -> Option<(&SecretId, &SecretSelectorV1)> {
    match body {
        RecordBodyV1::Secret(value) => Some((&value.id, &value.selector)),
        RecordBodyV1::SecretDeleted(deleted) => Some((&deleted.id, &deleted.selector)),
        _ => None,
    }
}
