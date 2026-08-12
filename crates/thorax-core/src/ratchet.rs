use crate::format::{
    FormatVersionRatchetRecordV1, GroupId, HashValue, PrincipalRefV1, RatchetRecordV1, RecordKey,
    SecretSelectorV1, TrustedRootRatchetRecordV1,
};
use std::collections::BTreeMap;

/// What gave rise to a content-derived record key — the preimage of its id, remembered so
/// a key can be *named* to the user even after every record at it is gone (a rollback that
/// erased the key entirely). Purely advisory display data: never enforcement, never part
/// of the ratchet comparison. Only kinds whose preimage is human-meaningful carry one;
/// seed-derived ids (groups, grants) and key-derived ids (users) have opaque preimages and
/// fall back to their short id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyOrigin {
    /// A secret's identity-bearing selector (tuple + labels — labels are scope axes folded
    /// into the id, so the whole selector is the preimage).
    Secret(SecretSelectorV1),
    /// The normalized handle string a user-handle id hashes from.
    UserHandle(String),
    /// The normalized handle string a vault-handle id hashes from.
    VaultHandle(String),
    /// The (group, member) pair a membership id is content-addressed by.
    GroupMember {
        group_id: GroupId,
        member_id: PrincipalRefV1,
    },
}

/// The local rollback ratchet for one trusted root. Unlike the vault it is unsigned and
/// recomputable, and it is exactly the per-object watermark set: the highest verified
/// Lamport counter seen at each record key. Counters only move forward in an honest,
/// append-only vault, so a lower effective counter at a remembered key is a rollback.
///
/// Every removal is an LWW deletion that advances its key's counter, so the watermark
/// protects deletions too — resurrecting a deleted object would lower the counter — without
/// burning the key: re-creating the object at a higher counter is fine. (On disk the map is
/// persisted as typed per-object facts; see `RatchetRecordV1` and the ratchet store.)
///
/// `origins` remembers each key's [`KeyOrigin`] alongside the counter, so a rollback that
/// dropped a key's records entirely can still be presented by name ("secret app/db", not
/// a hash). An origin is immutable per key (it is the id's preimage), advisory only, and
/// may be absent for keys without a meaningful preimage or remembered by older state.
///
/// This is the one ratchet type: the in-memory form and the on-disk form (`RatchetStore`,
/// in `thorax-store`) are the same data. `unknown_records` carries through `RatchetRecordV1`
/// variants a newer binary wrote that this build cannot parse, so a rewrite re-emits them
/// byte-for-byte instead of silently dropping rollback memory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ratchet {
    pub trusted_root: HashValue,
    pub watermarks: BTreeMap<RecordKey, u64>,
    pub origins: BTreeMap<RecordKey, KeyOrigin>,
    /// The highest vault *format version* (top-level `VaultStore` variant) verified under this
    /// root — the envelope's own ratchet, `0` when nothing is remembered yet. A vault
    /// presenting a lower version is the downgrade analogue of a rollback: someone
    /// re-wrapped a newer vault's records in an older envelope, shedding semantics this
    /// machine has already relied on. Validation fails it closed
    /// (`ValidationIssue::FormatVersionRegression`).
    pub format_version: u64,
    /// `RatchetRecordV1` variants written by a newer binary that this build cannot parse,
    /// carried opaquely so a rewrite re-emits them byte-for-byte. Always empty when this
    /// version produced the ratchet.
    pub unknown_records: Vec<UnknownRatchetRecord>,
}

/// A `RatchetRecordV1` variant this build does not understand — the raw variant payload,
/// carried opaquely. By construction it never holds a known record kind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownRatchetRecord(pub Vec<u8>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RatchetUpdate {
    /// Keys whose verified counter rose above the remembered watermark, with the new value.
    pub raised_watermarks: BTreeMap<RecordKey, u64>,
    /// Origins for keys this validation could name (the id preimage from the records
    /// themselves). Advisory; merged alongside the raises.
    pub origins: BTreeMap<RecordKey, KeyOrigin>,
    /// Set when the vault's format version exceeds the remembered one.
    pub raised_format_version: Option<u64>,
}

impl Ratchet {
    pub fn new(trusted_root: HashValue) -> Self {
        Self {
            trusted_root,
            watermarks: BTreeMap::new(),
            origins: BTreeMap::new(),
            format_version: 0,
            unknown_records: Vec::new(),
        }
    }

    /// Fold a validation's raised watermarks into the ratchet. Watermarks are
    /// monotonic: keep the larger of the remembered and the newly raised value. Origins
    /// are immutable per key, so the first one remembered sticks.
    pub fn apply_update(&mut self, update: &RatchetUpdate) {
        for (key, counter) in &update.raised_watermarks {
            let entry = self.watermarks.entry(key.clone()).or_insert(0);
            *entry = (*entry).max(*counter);
        }
        for (key, origin) in &update.origins {
            self.origins
                .entry(key.clone())
                .or_insert_with(|| origin.clone());
        }
        if let Some(version) = update.raised_format_version {
            self.format_version = self.format_version.max(version);
        }
    }

    /// The ratchet as a flat set of typed [`RatchetRecordV1`]s: one watermark record per
    /// keyed counter, the format-version record when one is remembered, and the trusted-root
    /// scope record. This is the on-disk / on-the-wire encoding shared by the ratchet store
    /// and the invite baseline (the inverse of [`Self::absorb_record`]). `unknown_records`
    /// are carried opaquely as `cord::Evolving::Unknown` by the store and are not re-emitted
    /// here.
    pub fn to_records(&self) -> Vec<RatchetRecordV1> {
        let mut records = Vec::new();
        for (key, counter) in &self.watermarks {
            // `for_key` is `None` only for `VaultRoot`, which never carries a counter and so
            // never enters the map.
            if let Some(record) = RatchetRecordV1::for_key(key, *counter, self.origins.get(key)) {
                records.push(record);
            }
        }
        if self.format_version > 0 {
            records.push(RatchetRecordV1::FormatVersion(
                FormatVersionRatchetRecordV1 {
                    version: self.format_version,
                },
            ));
        }
        records.push(RatchetRecordV1::TrustedRoot(TrustedRootRatchetRecordV1 {
            trusted_root: self.trusted_root.clone(),
        }));
        records
    }

    /// Fold one typed [`RatchetRecordV1`] into the ratchet (the inverse of
    /// [`Self::to_records`]): raise the watermark and remember the origin for a keyed record,
    /// raise `format_version` for the envelope record. The trusted-root record is ignored —
    /// the root is the ratchet's fixed scope, set at construction, not folded in here.
    pub fn absorb_record(&mut self, record: &RatchetRecordV1) {
        match record {
            RatchetRecordV1::TrustedRoot(_) => {}
            RatchetRecordV1::FormatVersion(fact) => {
                self.format_version = self.format_version.max(fact.version);
            }
            keyed => {
                // Every remaining variant is keyed; `key()` is `None` only for the un-keyed
                // facts handled above.
                if let Some(key) = keyed.key() {
                    let entry = self.watermarks.entry(key.clone()).or_insert(0);
                    *entry = (*entry).max(keyed.counter());
                    if let Some(origin) = keyed.origin() {
                        self.origins.entry(key).or_insert(origin);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{SecretId, UserId};

    fn hash(byte: u8) -> HashValue {
        HashValue(vec![byte; 32])
    }

    #[test]
    fn apply_update_raises_watermarks_monotonically() {
        let mut trust = Ratchet::new(hash(0));
        let low_key = RecordKey::Secret {
            secret_id: SecretId(hash(1)),
        };
        let new_key = RecordKey::User {
            user_id: UserId(hash(2)),
        };
        trust.watermarks.insert(low_key.clone(), 7);

        let mut update = RatchetUpdate::default();
        update.raised_watermarks.insert(low_key.clone(), 3);
        update.raised_watermarks.insert(new_key.clone(), 5);
        update.origins.insert(
            low_key.clone(),
            KeyOrigin::Secret(SecretSelectorV1::tuple(["app"])),
        );
        trust.apply_update(&update);

        // An already-higher watermark never regresses; new keys are adopted; origins stick.
        assert_eq!(trust.watermarks.get(&low_key), Some(&7));
        assert_eq!(trust.watermarks.get(&new_key), Some(&5));
        assert_eq!(
            trust.origins.get(&low_key),
            Some(&KeyOrigin::Secret(SecretSelectorV1::tuple(["app"])))
        );
    }
}
