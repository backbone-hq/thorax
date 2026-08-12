//! Three-way merge of vault record sets.
//!
//! A vault is a set of individually signed records resolved by Lamport LWW at validation
//! time, so a git-style three-way merge is the union of the distinct records on all sides:
//! the union of valid same-root vaults is itself a valid vault, deletion tombstones are
//! ordinary records that survive the union, and the effective counter at a key can never
//! drop below either side's. The merge is therefore not a trust boundary — every reader
//! re-validates the result against signatures, authority, and the watermark ratchet — but
//! it must fail closed on structural ambiguity and surface same-counter ties for explicit
//! resolution.

use crate::format::*;
#[cfg(test)]
use crate::validate::record_key_for;
use crate::Result;
#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Why a merge was refused outright. The caller leaves "ours" in place and reports a
/// conflict; there is no partial result to write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeRefusal {
    /// Ours or theirs carries no `VaultRoot` record at all; there is no trust anchor to
    /// merge under.
    MissingRoot,
    /// The sides do not carry the same `VaultRoot` records. That is vault substitution or
    /// root tampering, not a merge — v1 has no root rotation.
    RootMismatch,
}

/// Why a record key is in conflict: nothing at the key is effective, reads of it fail, and
/// listings flag it, until an authorized resolver re-signs a winner at a fresh counter.
/// There is deliberately **no** deterministic tie-break — silently picking a winner would
/// let an attacker (or an accident) choose an outcome no one authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Distinct records tied at the key's winning (maximum) Lamport counter with diverging
    /// bodies — concurrent writes no order exists for.
    Tie,
    /// The verified counter at this key fell below the locally remembered watermark: a
    /// higher-counter record this machine once verified (a newer value, or a deletion) is
    /// missing — a suspected rollback. Resolution re-signs above the remembered counter.
    Rollback { remembered_counter: u64 },
}

/// One conflicted record key: the disputed counter, why it is disputed, and the candidate
/// records currently present at that counter. `candidates` may be empty for a
/// [`ConflictKind::Rollback`] whose records were dropped entirely; such a conflict can only
/// be resolved by writing fresh content at the key (or an explicit local-trust reset).
/// Candidates are in canonical byte order — no order means preference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictReport {
    pub key: RecordKey,
    pub counter: u64,
    pub kind: ConflictKind,
    pub candidates: Vec<VaultRecordV1>,
    /// The key's remembered id preimage from local trust, so a rollback whose records were
    /// all erased can still be named ("secret app/db", "@alice"). Advisory display data;
    /// ties leave it `None` — their candidates carry the identity.
    pub origin: Option<crate::ratchet::KeyOrigin>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// The union vault. It is a loadable vault even when same-counter ties exist — both
    /// candidates coexist in the record set, the tied key is simply conflicted (nothing at
    /// it effective, reads of it failing) — so callers write it to the working tree either
    /// way. Whether anything needs resolution is the *validator's* answer, not the
    /// merge's: callers validate the union and read the authority-aware conflict set
    /// (`EffectiveState::conflicted`), so the merge surface can never disagree with what
    /// `thorax conflicts` shows.
    Merged {
        merged: VaultStore,
    },
    Refused(MergeRefusal),
}

/// Merge `ours` and `theirs` against their common ancestor `base` (`None` for an add/add
/// merge with no ancestor).
///
/// The union includes `base`: a record present in the ancestor but absent from a side was
/// *removed*, and removing records is never a legitimate v1 operation — deletion is a
/// tombstone record, and compaction is a separate design. Restoring the record is exactly
/// what keeps a merge from lowering the effective counter at any key.
///
/// Output ordering is canonical (counter, then record bytes), so the merged vault's bytes
/// are identical no matter which side runs the merge or how the inputs were ordered.
pub fn merge_vaults(
    base: Option<&VaultStore>,
    ours: &VaultStore,
    theirs: &VaultStore,
) -> Result<MergeOutcome> {
    let VaultStore::V1(ours_v1) = ours;
    let VaultStore::V1(theirs_v1) = theirs;
    let base_records = base.map(|vault| {
        let VaultStore::V1(v1) = vault;
        &v1.records
    });

    let ours_roots = root_records(&ours_v1.records)?;
    let theirs_roots = root_records(&theirs_v1.records)?;
    if ours_roots.is_empty() || theirs_roots.is_empty() {
        return Ok(MergeOutcome::Refused(MergeRefusal::MissingRoot));
    }
    if ours_roots != theirs_roots {
        return Ok(MergeOutcome::Refused(MergeRefusal::RootMismatch));
    }
    if let Some(base_records) = base_records {
        let base_roots = root_records(base_records)?;
        if !base_roots.is_empty() && base_roots != ours_roots {
            return Ok(MergeOutcome::Refused(MergeRefusal::RootMismatch));
        }
    }

    // The merge is a set-union: collect the distinct records from every side into a
    // `cord::Set`. Dedup (by record identity, equivalently canonical bytes) and the
    // canonical on-disk ordering are the Set's job — unknown future bodies dedup and
    // carry through like any other record. LWW ordering is by counter at validation, not
    // file position, so no in-memory sort is needed here.
    let records: cord::Set<VaultRecordV1> = base_records
        .into_iter()
        .flatten()
        .chain(&ours_v1.records)
        .chain(&theirs_v1.records)
        .cloned()
        .collect();

    let merged = VaultStore::V1(VaultStoreV1 { records });
    Ok(MergeOutcome::Merged { merged })
}

/// The same-counter, diverging-body ties in a vault, at each key's winning counter only —
/// a tie below the maximum cannot change the LWW outcome. Authority-blind, so it is **not**
/// a consumer surface: a tie between records no one is authorized to write is not a real
/// ambiguity, and surfacing it would let a merge claim conflicts that `thorax conflicts`
/// (the authority-aware `EffectiveState::conflicted`) rightly doesn't show. Kept private as
/// the test oracle that the conflict state is representable in-format.
#[cfg(test)]
fn detect_ties(vault: &VaultStore) -> Result<Vec<ConflictReport>> {
    let VaultStore::V1(v1) = vault;
    let mut groups: BTreeMap<RecordKey, Vec<&VaultRecordV1>> = BTreeMap::new();
    for record in &v1.records {
        // Unknown future bodies have no derivable key (validation leaves them inert),
        // and the root is the non-LWW singleton — neither can tie. Entry points key on
        // the *resolved* signer identity, which this authority-blind oracle does not
        // compute — validation owns their (self-keyed, rarely contested) resolution.
        let Some(body) = record.body.known() else {
            continue;
        };
        if matches!(
            body,
            RecordBodyV1::VaultRoot(_) | RecordBodyV1::EntryPoint(_)
        ) {
            continue;
        }
        // The placeholder signer is never consulted: every remaining body kind carries
        // its identifying id and ignores the signer in `record_key_for`.
        let placeholder = UserId(HashValue(Vec::new()));
        groups
            .entry(record_key_for(body, &placeholder)?)
            .or_default()
            .push(record);
    }

    let mut ties = Vec::new();
    for (key, candidates) in groups {
        let counter_of = |record: &VaultRecordV1| {
            record
                .body
                .known()
                .and_then(RecordBodyV1::lww_counter)
                .unwrap_or(0)
        };
        let Some(winning) = candidates.iter().map(|record| counter_of(record)).max() else {
            continue;
        };
        let tied: Vec<&VaultRecordV1> = candidates
            .into_iter()
            .filter(|record| counter_of(record) == winning)
            .collect();
        if tied.len() < 2 {
            continue;
        }
        // Identical bodies tied at the counter (e.g. two admins independently writing the
        // same record) resolve to the same outcome whichever wins; only diverging content
        // is a real ambiguity.
        if tied.iter().all(|record| record.body == tied[0].body) {
            continue;
        }
        // Records iterate in (randomized) set order, so sort the candidates canonically by
        // bytes — matching the production conflict path — for a deterministic report.
        let mut candidates: Vec<VaultRecordV1> = tied.into_iter().cloned().collect();
        candidates.sort_by_key(|signed| cord::serialize(signed).unwrap_or_default());
        ties.push(ConflictReport {
            key,
            counter: winning,
            kind: ConflictKind::Tie,
            candidates,
            origin: None,
        });
    }
    Ok(ties)
}

/// The canonical bytes of every `VaultRoot`-bodied record in `records`. Compared as sets
/// across merge sides: the trust anchor must be byte-identical, signature included.
fn root_records<'a>(
    records: impl IntoIterator<Item = &'a VaultRecordV1>,
) -> Result<BTreeSet<Vec<u8>>> {
    records
        .into_iter()
        .filter(|signed| matches!(signed.body.known(), Some(RecordBodyV1::VaultRoot(_))))
        .map(|signed| Ok(cord::serialize(signed)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use crate::validate::{decode_vault, encode_vault, VAULT_MAGIC};

    fn vault(records: Vec<VaultRecordV1>) -> VaultStore {
        VaultStore::V1(VaultStoreV1 {
            records: records.into(),
        })
    }

    /// Unwrap a non-refused union and pair it with the raw tie scan — the in-format
    /// conflict oracle these tests assert on (consumers get conflicts from validation).
    fn merged(outcome: MergeOutcome) -> (VaultStore, Vec<ConflictReport>) {
        match outcome {
            MergeOutcome::Merged { merged } => {
                let ties = detect_ties(&merged).unwrap();
                (merged, ties)
            }
            MergeOutcome::Refused(refusal) => panic!("unexpected refusal: {refusal:?}"),
        }
    }

    fn record_count(vault: &VaultStore) -> usize {
        let VaultStore::V1(v1) = vault;
        v1.records.len()
    }

    fn contains(vault: &VaultStore, record: &VaultRecordV1) -> bool {
        let VaultStore::V1(v1) = vault;
        v1.records.contains(record)
    }

    /// base: root introduces alice (with entry point); used by most merges below.
    fn shared_history(fixture: &Fixture, alice: &TestUser) -> Vec<VaultRecordV1> {
        vec![
            vault_root_record(fixture),
            user_record(fixture, alice, 1),
            trust_root(&fixture.crypto, alice, fixture, 1),
        ]
    }

    #[test]
    fn union_dedups_shared_history_and_is_symmetric() {
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let base = shared_history(&fixture, &alice);

        let grant = grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            2,
        );
        let secret = secret_record(
            &fixture.crypto,
            &fixture.root,
            &secret_selector(&["app", "prod"]),
            &[&fixture.root],
            2,
        );
        let ours = vault([base.clone(), vec![grant.clone()]].concat());
        let theirs = vault([base.clone(), vec![secret.clone()]].concat());
        let base = vault(base);

        let (forward, ties) = merged(merge_vaults(Some(&base), &ours, &theirs).unwrap());
        // Same counter at *different* keys is concurrency, not a tie.
        assert!(ties.is_empty());
        assert_eq!(record_count(&forward), 5);
        assert!(contains(&forward, &grant) && contains(&forward, &secret));

        // The merged bytes are identical no matter which side runs the merge.
        let (reverse, _) = merged(merge_vaults(Some(&base), &theirs, &ours).unwrap());
        assert_eq!(
            encode_vault(&forward).unwrap(),
            encode_vault(&reverse).unwrap()
        );
    }

    #[test]
    fn tombstone_dropped_from_one_side_is_restored_from_the_union() {
        // An attacker (or bad tool) hands us a "theirs" with the grant deletion stripped.
        // The union restores it from base/ours, so the merge cannot lower the effective
        // counter at the grant's key — the deletion still wins LWW after the merge.
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let grant = grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            2,
        );
        let tombstone = grant_deleted_record(
            &fixture.crypto,
            &fixture.root,
            grant_id(&fixture.crypto, "alice-read"),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            3,
        );
        let base_records = [
            shared_history(&fixture, &alice),
            vec![grant.clone(), tombstone.clone()],
        ]
        .concat();
        let theirs_records: Vec<VaultRecordV1> = base_records
            .iter()
            .filter(|record| *record != &tombstone)
            .cloned()
            .collect();
        let base = vault(base_records.clone());
        let ours = vault(base_records.clone());
        let theirs = vault(theirs_records);

        let (union, ties) = merged(merge_vaults(Some(&base), &ours, &theirs).unwrap());
        assert!(ties.is_empty());
        assert!(contains(&union, &tombstone));

        let VaultStore::V1(v1) = &union;
        let report = fixture.validate(Vec::from(&v1.records));
        assert!(!report
            .effective
            .grants
            .contains_key(&grant_id(&fixture.crypto, "alice-read")));
        assert!(report
            .effective
            .deleted_grants
            .contains(&grant_id(&fixture.crypto, "alice-read")));
    }

    #[test]
    fn delete_vs_update_across_branches_resolves_by_counter_without_a_tie() {
        // Branch A deletes the grant at counter 2; branch B re-issues it at counter 3.
        // Different counters at the same key are ordinary LWW, not a tie.
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let permission = GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all());
        let tombstone = grant_deleted_record(
            &fixture.crypto,
            &fixture.root,
            grant_id(&fixture.crypto, "alice-read"),
            permission.clone(),
            2,
        );
        let regrant = grant_record(
            &fixture.crypto,
            "alice-read",
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            permission,
            3,
        );
        let base = shared_history(&fixture, &alice);
        let ours = vault([base.clone(), vec![tombstone.clone()]].concat());
        let theirs = vault([base.clone(), vec![regrant.clone()]].concat());

        let (union, ties) = merged(merge_vaults(Some(&vault(base)), &ours, &theirs).unwrap());
        assert!(ties.is_empty());
        assert!(contains(&union, &tombstone) && contains(&union, &regrant));
    }

    #[test]
    fn same_counter_diverging_writes_at_one_key_report_a_tie() {
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let selector = secret_selector(&["app", "prod"]);
        let base = shared_history(&fixture, &alice);
        let ours_write = secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"ours-ciphertext",
            2,
        );
        let theirs_write = secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"theirs-ciphertext",
            2,
        );
        let ours = vault([base.clone(), vec![ours_write.clone()]].concat());
        let theirs = vault([base.clone(), vec![theirs_write.clone()]].concat());

        let (union, ties) = merged(merge_vaults(Some(&vault(base)), &ours, &theirs).unwrap());
        assert_eq!(ties.len(), 1);
        let tie = &ties[0];
        assert!(matches!(tie.key, RecordKey::Secret { .. }));
        assert_eq!(tie.counter, 2);
        assert_eq!(tie.candidates.len(), 2);
        assert!(tie.candidates.contains(&ours_write));
        assert!(tie.candidates.contains(&theirs_write));

        // The conflict state is representable in-format: encode the union, decode it cold,
        // and the same tie is still detectable from the bytes alone.
        let reloaded = decode_vault(&encode_vault(&union).unwrap()).unwrap();
        assert_eq!(detect_ties(&reloaded).unwrap(), ties);
    }

    #[test]
    fn identical_bodies_tied_at_a_counter_are_not_a_tie() {
        // Root and alice independently introduce the same user record body at the same
        // counter. Whichever record wins, the outcome is identical — no ambiguity.
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let bob = test_user(&fixture.crypto, "bob");
        let base = shared_history(&fixture, &alice);
        let by_root = user_record_signed_by(&fixture, &fixture.root, &bob, 2);
        let by_alice = user_record_signed_by(&fixture, &alice, &bob, 2);
        assert_eq!(by_root.body, by_alice.body);
        let ours = vault([base.clone(), vec![by_root]].concat());
        let theirs = vault([base.clone(), vec![by_alice]].concat());

        let (_, ties) = merged(merge_vaults(Some(&vault(base)), &ours, &theirs).unwrap());
        assert!(ties.is_empty());
    }

    #[test]
    fn tie_below_the_winning_counter_is_not_reported() {
        // The diverging counter-2 writes are superseded by ours' counter-3 write; the LWW
        // winner is unambiguous, so there is nothing to resolve.
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let selector = secret_selector(&["app", "prod"]);
        let base = shared_history(&fixture, &alice);
        let ours_write = secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"ours-ciphertext",
            2,
        );
        let theirs_write = secret_record_with_payload(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            b"theirs-ciphertext",
            2,
        );
        let newer_write = secret_record(
            &fixture.crypto,
            &fixture.root,
            &selector,
            &[&fixture.root],
            3,
        );
        let ours = vault([base.clone(), vec![ours_write, newer_write]].concat());
        let theirs = vault([base.clone(), vec![theirs_write]].concat());

        let (_, ties) = merged(merge_vaults(Some(&vault(base)), &ours, &theirs).unwrap());
        assert!(ties.is_empty());
    }

    #[test]
    fn add_add_merge_with_no_ancestor_unions_both_sides() {
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let bob = test_user(&fixture.crypto, "bob");
        let ours = vault(vec![
            vault_root_record(&fixture),
            user_record(&fixture, &alice, 1),
        ]);
        let theirs = vault(vec![
            vault_root_record(&fixture),
            user_record(&fixture, &bob, 1),
        ]);

        let (union, ties) = merged(merge_vaults(None, &ours, &theirs).unwrap());
        assert!(ties.is_empty());
        // The shared root dedups; both user introductions survive.
        assert_eq!(record_count(&union), 3);
    }

    #[test]
    fn different_roots_are_refused_as_substitution() {
        let fixture = Fixture::new();
        let other_root = test_user(&fixture.crypto, "other-root");
        let ours = vault(vec![vault_root_record(&fixture)]);
        let theirs = vault(vec![vault_root_record_for(&fixture.crypto, &other_root)]);

        assert_eq!(
            merge_vaults(None, &ours, &theirs).unwrap(),
            MergeOutcome::Refused(MergeRefusal::RootMismatch)
        );
    }

    #[test]
    fn base_with_a_different_root_is_refused() {
        let fixture = Fixture::new();
        let other_root = test_user(&fixture.crypto, "other-root");
        let base = vault(vec![vault_root_record_for(&fixture.crypto, &other_root)]);
        let ours = vault(vec![vault_root_record(&fixture)]);
        let theirs = vault(vec![vault_root_record(&fixture)]);

        assert_eq!(
            merge_vaults(Some(&base), &ours, &theirs).unwrap(),
            MergeOutcome::Refused(MergeRefusal::RootMismatch)
        );
    }

    #[test]
    fn side_without_a_root_is_refused() {
        let fixture = Fixture::new();
        let alice = test_user(&fixture.crypto, "alice");
        let ours = vault(vec![vault_root_record(&fixture)]);
        let theirs = vault(vec![user_record(&fixture, &alice, 1)]);

        assert_eq!(
            merge_vaults(None, &ours, &theirs).unwrap(),
            MergeOutcome::Refused(MergeRefusal::MissingRoot)
        );
    }

    #[test]
    fn unknown_future_records_pass_through_the_union() {
        // Simulate a newer binary's vault: a record kind at an index this build's
        // `RecordBodyV1` does not define, alongside the known root.
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
        enum RecordBodyFuture {
            #[cord(index = 0)]
            VaultRoot(VaultRootRecordV1),
            #[cord(index = 14)]
            Quota { limit: u64, counter: u64 },
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq, Hash)]
        struct SignedFuture {
            #[cord(evolving = 32)]
            body: cord::Evolving<RecordBodyFuture>,
            signing_public_key: Bytes,
            signature: Bytes,
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        struct VaultFutureV1 {
            records: cord::Set<SignedFuture>,
        }
        #[derive(cord::Cord, Clone, Debug, PartialEq, Eq)]
        enum VaultFuture {
            #[cord(index = 0)]
            V1(VaultFutureV1),
        }

        let fixture = Fixture::new();
        let root_record = vault_root_record(&fixture);
        let Some(RecordBodyV1::VaultRoot(root_body)) = root_record.body.known().cloned() else {
            panic!("fixture root record must carry a known VaultRoot body");
        };
        let future_bytes = cord::serialize(&VaultFuture::V1(VaultFutureV1 {
            records: vec![
                SignedFuture {
                    body: cord::Evolving::new(RecordBodyFuture::VaultRoot(root_body)),
                    signing_public_key: root_record.signing_public_key.clone(),
                    signature: root_record.signature.clone(),
                },
                SignedFuture {
                    body: cord::Evolving::new(RecordBodyFuture::Quota {
                        limit: 7,
                        counter: 9,
                    }),
                    signing_public_key: root_record.signing_public_key.clone(),
                    signature: b"future-signature".to_vec(),
                },
            ]
            .into(),
        }))
        .unwrap();
        // A vault *file* leads with the magic prefix, exactly as `encode_vault` writes it.
        let mut future_file = VAULT_MAGIC.to_vec();
        future_file.extend(future_bytes);
        let theirs = decode_vault(&future_file).unwrap();
        let ours = vault(vec![root_record]);

        let (union, ties) = merged(merge_vaults(None, &ours, &theirs).unwrap());
        assert!(ties.is_empty());
        let VaultStore::V1(v1) = &union;
        assert_eq!(v1.records.len(), 2);
        assert_eq!(
            v1.records
                .iter()
                .filter(|record| record.body.known().is_none())
                .count(),
            1
        );
        // The opaque record survives a re-encode byte-for-byte.
        let reloaded = decode_vault(&encode_vault(&union).unwrap()).unwrap();
        assert_eq!(&union, &reloaded);
    }
}
