use super::{EffectiveState, VerifiedRecord};
use crate::authz::AuthoritySet;
use crate::format::*;
use crate::merge::{ConflictKind, ConflictReport};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn compute_effective_state(
    root_user_record: UserRecordV1,
    root_signing_public_key_hash: HashValue,
    records: &[VerifiedRecord],
    admitted_deletions: &BTreeSet<HashValue>,
    rollback_keys: &BTreeMap<RecordKey, u64>,
) -> EffectiveState {
    let root_user = root_user_record.id.clone();

    // A non-root user is effective only if their own key vouches for this root via a valid
    // EntryPointRecord. Such records are self-signed and already structurally validated
    // against the actual root, so any verified one here is genuine. The root itself is
    // anchored by the self-signed RootRecord and needs no entry-point record. A rollback-
    // conflicted entry-point key is inert like any other conflicted key — the user drops
    // out of the effective set until the conflict is resolved.
    let entry_point_users: BTreeSet<UserId> = records
        .iter()
        .filter(|record| !rollback_keys.contains_key(&record.key))
        .filter_map(|record| match &record.key {
            RecordKey::EntryPoint { user_id }
                if matches!(record.body, RecordBodyV1::EntryPoint(_)) =>
            {
                Some(user_id.clone())
            }
            _ => None,
        })
        .collect();

    let mut selected = SelectedAuthorizedRecords::default();
    let mut authorities = root_authorities(&root_user);
    let mut authority_converged = false;

    for _ in 0..64 {
        let next = select_authorized_records(
            records,
            &root_user_record,
            &entry_point_users,
            admitted_deletions,
            rollback_keys,
            &authorities,
        );
        let new_authorities =
            compute_authorities_from_selected(&root_user, &next.memberships, &next.grants);

        if next == selected && new_authorities == authorities {
            authority_converged = true;
            break;
        }

        selected = next;
        authorities = new_authorities;
    }
    let SelectedAuthorizedRecords {
        users,
        groups,
        memberships,
        grants,
        deleted_users,
        deleted_groups,
        deleted_grants,
        mut conflicted,
    } = selected;

    let handle_resolution = lww_resolution(records, rollback_keys, |record| {
        match (&record.body, &record.key) {
            (RecordBodyV1::UserHandle(handle), RecordKey::UserHandle { handle_id })
                if signer_auth(&authorities, &record.signer).administer
                    && users.contains_key(&handle.user_id) =>
            {
                Some(handle_id.clone())
            }
            _ => None,
        }
    });
    conflicted.extend(handle_resolution.conflicted);
    let (handles, _) = partition_lww(handle_resolution.winners, |body| match body {
        RecordBodyV1::UserHandle(handle) => Some(handle.clone()),
        _ => None,
    });

    let vault_handle_resolution = lww_resolution(records, rollback_keys, |record| {
        match (&record.body, &record.key) {
            (RecordBodyV1::VaultHandle(_handle), RecordKey::VaultHandle { handle_id })
                if signer_auth(&authorities, &record.signer).administer =>
            {
                Some(handle_id.clone())
            }
            _ => None,
        }
    });
    conflicted.extend(vault_handle_resolution.conflicted);
    let (vault_handles, _) = partition_lww(vault_handle_resolution.winners, |body| match body {
        RecordBodyV1::VaultHandle(handle) => Some(handle.clone()),
        _ => None,
    });

    // Entry-point records are self-signed (a user vouches for the root with their own key),
    // already structurally validated against the actual root. Collect the latest one per
    // effective user; a deleted user's statement does not count.
    let entry_point_resolution = lww_resolution(records, rollback_keys, |record| {
        match (&record.body, &record.key) {
            (RecordBodyV1::EntryPoint(_), RecordKey::EntryPoint { user_id })
                if users.contains_key(user_id) =>
            {
                Some(user_id.clone())
            }
            _ => None,
        }
    });
    conflicted.extend(entry_point_resolution.conflicted);
    let (entry_points, _) = partition_lww(entry_point_resolution.winners, |body| match body {
        RecordBodyV1::EntryPoint(entry_point) => Some(entry_point.clone()),
        _ => None,
    });

    EffectiveState {
        root_user_id: Some(root_user),
        root_signing_public_key_hash: Some(root_signing_public_key_hash),
        users,
        handles,
        vault_handles,
        groups,
        memberships,
        grants,
        entry_points,
        deleted_users,
        deleted_groups,
        deleted_grants,
        authorities,
        authority_unresolved: !authority_converged,
        conflicted: materialize_conflicts(records, conflicted),
        admitted_counter_max: None,
        verified_records: Vec::new(),
        secret_index: BTreeMap::new(),
    }
}

/// Turn the fixpoint's hash-keyed conflict slots into the report form frontends consume.
pub(super) fn materialize_conflicts(
    records: &[VerifiedRecord],
    conflicted: BTreeMap<RecordKey, ConflictSlot>,
) -> BTreeMap<RecordKey, ConflictReport> {
    conflicted
        .into_iter()
        .map(|(key, slot)| {
            let mut candidates: Vec<VaultRecordV1> = records
                .iter()
                .filter(|record| slot.candidate_hashes.contains(&record.record_hash))
                .map(|record| record.signed.clone())
                .collect();
            candidates.sort_by_key(|signed| cord::serialize(signed).unwrap_or_default());
            candidates.dedup();
            let report = ConflictReport {
                key: key.clone(),
                counter: slot.counter,
                kind: ConflictKind::Tie,
                candidates,
                origin: None,
            };
            (key, report)
        })
        .collect()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SelectedAuthorizedRecords {
    users: BTreeMap<UserId, UserRecordV1>,
    groups: BTreeMap<GroupId, GroupRecordV1>,
    memberships: BTreeMap<GroupMemberId, GroupMemberRecordV1>,
    grants: BTreeMap<GrantId, GrantRecordV1>,
    deleted_users: BTreeSet<UserId>,
    deleted_groups: BTreeSet<GroupId>,
    deleted_grants: BTreeSet<GrantId>,
    /// Keys whose winning counter is contested (diverging bodies tied at the maximum):
    /// nothing at the key is selected — fail closed — and the dispute is reported.
    conflicted: BTreeMap<RecordKey, ConflictSlot>,
}

fn select_authorized_records(
    records: &[VerifiedRecord],
    root_user_record: &UserRecordV1,
    entry_point_users: &BTreeSet<UserId>,
    admitted_deletions: &BTreeSet<HashValue>,
    rollback_keys: &BTreeMap<RecordKey, u64>,
    authorities: &BTreeMap<PrincipalRefV1, AuthoritySet>,
) -> SelectedAuthorizedRecords {
    let mut conflicted = BTreeMap::new();

    // Users: the root is intrinsic (synthesized from the root record, never deletable);
    // every other user resolves by LWW between admin-signed User (add/restore) records and
    // admitted UserDeleted tombstones at the same key. A winning add still needs the user's
    // own self-signed entry point to count.
    let root_user = &root_user_record.id;
    let user_resolution = lww_resolution(records, rollback_keys, |record| match &record.body {
        RecordBodyV1::User(user) => {
            if user.id == *root_user || !signer_auth(authorities, &record.signer).administer {
                return None;
            }
            Some(user.id.clone())
        }
        RecordBodyV1::UserDeleted(deleted) => {
            if deleted.id == *root_user || !admitted_deletions.contains(&record.record_hash) {
                return None;
            }
            Some(deleted.id.clone())
        }
        _ => None,
    });
    conflicted.extend(user_resolution.conflicted);
    // Unwrapped by hand rather than via `partition_lww`: a winning add whose user never
    // vouched for the root is neither live nor deleted, and the root user is synthesized.
    let mut users = BTreeMap::new();
    let mut deleted_users = BTreeSet::new();
    users.insert(root_user.clone(), root_user_record.clone());
    for (user_id, record) in user_resolution.winners {
        match &record.body {
            RecordBodyV1::User(user) => {
                if entry_point_users.contains(&user_id) {
                    users.insert(user_id, user.clone());
                }
            }
            // A UserDeleted won the LWW at this key → the user is deleted.
            _ => {
                deleted_users.insert(user_id);
            }
        }
    }

    let group_resolution = lww_resolution(records, rollback_keys, |record| match &record.body {
        RecordBodyV1::Group(group) => {
            if !signer_auth(authorities, &record.signer).administer {
                return None;
            }
            Some(group.id.clone())
        }
        RecordBodyV1::GroupDeleted(deleted) => {
            if !admitted_deletions.contains(&record.record_hash) {
                return None;
            }
            Some(deleted.id.clone())
        }
        _ => None,
    });
    conflicted.extend(group_resolution.conflicted);
    // A GroupDeleted winner at a key → the group is deleted.
    let (groups, deleted_groups) = partition_lww(group_resolution.winners, |body| match body {
        RecordBodyV1::Group(value) => Some(value.clone()),
        _ => None,
    });

    // Membership is content-addressed by (group, member) and resolved by LWW: a GroupMember (add)
    // and GroupMemberDeleted (remove) at the same key compete by counter, like a secret value vs
    // its deletion. The latest authorized record wins; if it is a deletion, the member is absent.
    let membership_resolution =
        lww_resolution(records, rollback_keys, |record| match &record.body {
            RecordBodyV1::GroupMember(member) => {
                if !signer_auth(authorities, &record.signer).administer
                    || !groups.contains_key(&member.group_id)
                    || !principal_exists(&member.member_id, &users, &groups)
                {
                    return None;
                }
                Some(member.id.clone())
            }
            RecordBodyV1::GroupMemberDeleted(deleted) => {
                if !signer_auth(authorities, &record.signer).administer {
                    return None;
                }
                Some(deleted.id.clone())
            }
            _ => None,
        });
    conflicted.extend(membership_resolution.conflicted);
    // A GroupMemberDeleted winner at a key → no membership (tombstoned keys are not tracked).
    let (memberships, _) = partition_lww(membership_resolution.winners, |body| match body {
        RecordBodyV1::GroupMember(value) => Some(value.clone()),
        _ => None,
    });

    let grant_resolution = lww_resolution(records, rollback_keys, |record| match &record.body {
        RecordBodyV1::Grant(grant) => {
            if !principal_exists(&grant.subject_id, &users, &groups)
                || !signer_auth(authorities, &record.signer)
                    .can_create_permission(&grant.permission)
            {
                return None;
            }
            Some(grant.id.clone())
        }
        RecordBodyV1::GrantDeleted(deleted) => {
            if !admitted_deletions.contains(&record.record_hash) {
                return None;
            }
            Some(deleted.id.clone())
        }
        _ => None,
    });
    conflicted.extend(grant_resolution.conflicted);
    // A GrantDeleted winner at a key → the grant is deleted.
    let (grants, deleted_grants) = partition_lww(grant_resolution.winners, |body| match body {
        RecordBodyV1::Grant(value) => Some(value.clone()),
        _ => None,
    });

    SelectedAuthorizedRecords {
        users,
        groups,
        memberships,
        grants,
        deleted_users,
        deleted_groups,
        deleted_grants,
        conflicted,
    }
}

fn compute_authorities_from_selected(
    root_user: &UserId,
    memberships: &BTreeMap<GroupMemberId, GroupMemberRecordV1>,
    grants: &BTreeMap<GrantId, GrantRecordV1>,
) -> BTreeMap<PrincipalRefV1, AuthoritySet> {
    let mut authorities = root_authorities(root_user);
    for grant in grants.values() {
        authorities
            .entry(grant.subject_id.clone())
            .or_default()
            .add_permission(&grant.permission);
    }

    loop {
        let mut changed = false;
        for membership in memberships.values() {
            let group_ref = PrincipalRefV1::Group(membership.group_id.clone());
            let Some(group_auth) = authorities.get(&group_ref).cloned() else {
                continue;
            };
            let member_auth = authorities.entry(membership.member_id.clone()).or_default();
            changed |= member_auth.merge_from(&group_auth);
        }
        if !changed {
            break;
        }
    }
    authorities
}

fn root_authorities(root_user: &UserId) -> BTreeMap<PrincipalRefV1, AuthoritySet> {
    let mut authorities = BTreeMap::new();
    authorities.insert(
        PrincipalRefV1::User(root_user.clone()),
        AuthoritySet::root(),
    );
    authorities
}

/// One key's contested winning counter: the disputed counter and the candidate records
/// (by hash) tied at it with diverging bodies. Hash-keyed so the fixpoint can compare
/// selections cheaply; materialized into [`ConflictReport`]s once selection settles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ConflictSlot {
    pub(super) counter: u64,
    pub(super) candidate_hashes: Vec<HashValue>,
}

pub(super) struct LwwResolution<'a, K: Ord> {
    pub(super) winners: BTreeMap<K, &'a VerifiedRecord>,
    pub(super) conflicted: BTreeMap<RecordKey, ConflictSlot>,
}

/// LWW resolution per key, considering only records `classify` admits — `classify` carries
/// each call site's authority/admission gating and key extraction. Records at a
/// rollback-suspected key are inert (the key is already conflicted; nothing at it may take
/// effect). A key whose maximum counter carries diverging bodies has **no winner** — it is
/// returned as conflicted instead. There is no signer/hash tie-break: equal counters with
/// equal bodies pick the lowest record hash (the outcome is identical either way); equal
/// counters with diverging bodies are a conflict for an authorized resolver to settle.
pub(super) fn lww_resolution<'a, K: Ord>(
    records: &'a [VerifiedRecord],
    rollback_keys: &BTreeMap<RecordKey, u64>,
    classify: impl Fn(&'a VerifiedRecord) -> Option<K>,
) -> LwwResolution<'a, K> {
    let mut slots: BTreeMap<K, Vec<&'a VerifiedRecord>> = BTreeMap::new();
    for record in records {
        if rollback_keys.contains_key(&record.key) {
            continue;
        }
        let Some(key) = classify(record) else {
            continue;
        };
        let counter = record.body.lww_counter().unwrap_or(0);
        let slot = slots.entry(key).or_default();
        match slot.first() {
            Some(leader) => {
                let leading = leader.body.lww_counter().unwrap_or(0);
                if counter > leading {
                    slot.clear();
                    slot.push(record);
                } else if counter == leading {
                    slot.push(record);
                }
            }
            None => slot.push(record),
        }
    }

    let mut winners = BTreeMap::new();
    let mut conflicted = BTreeMap::new();
    for (key, candidates) in slots {
        let diverging = candidates
            .iter()
            .any(|record| record.body != candidates[0].body);
        if diverging {
            let leader = candidates[0];
            let mut candidate_hashes: Vec<HashValue> = candidates
                .iter()
                .map(|record| record.record_hash.clone())
                .collect();
            candidate_hashes.sort();
            candidate_hashes.dedup();
            conflicted.insert(
                leader.key.clone(),
                ConflictSlot {
                    counter: leader.body.lww_counter().unwrap_or(0),
                    candidate_hashes,
                },
            );
        } else if let Some(winner) = candidates
            .into_iter()
            .min_by(|a, b| a.record_hash.cmp(&b.record_hash))
        {
            winners.insert(key, winner);
        }
    }
    LwwResolution {
        winners,
        conflicted,
    }
}

/// Split LWW winners into live values (`value` extracts a body) and tombstoned keys (the
/// winner at the key is some other body — a deletion).
fn partition_lww<K: Ord, V>(
    winners: BTreeMap<K, &VerifiedRecord>,
    value: impl Fn(&RecordBodyV1) -> Option<V>,
) -> (BTreeMap<K, V>, BTreeSet<K>) {
    let mut live = BTreeMap::new();
    let mut deleted = BTreeSet::new();
    for (key, record) in winners {
        match value(&record.body) {
            Some(body) => {
                live.insert(key, body);
            }
            None => {
                deleted.insert(key);
            }
        }
    }
    (live, deleted)
}

fn signer_auth(
    authorities: &BTreeMap<PrincipalRefV1, AuthoritySet>,
    signer: &UserId,
) -> AuthoritySet {
    authorities
        .get(&PrincipalRefV1::User(signer.clone()))
        .cloned()
        .unwrap_or_default()
}

fn principal_exists(
    principal: &PrincipalRefV1,
    users: &BTreeMap<UserId, UserRecordV1>,
    groups: &BTreeMap<GroupId, GroupRecordV1>,
) -> bool {
    match principal {
        PrincipalRefV1::User(user) => users.contains_key(user),
        PrincipalRefV1::Group(group) => groups.contains_key(group),
    }
}

/// Lamport-order comparison used for deterministic *iteration order* (e.g. scanning
/// deletion candidates for admission). It is **not** a winner picker between diverging
/// bodies — same-counter divergence is a conflict, never broken by signer or hash (see
/// [`lww_resolution`]); the signer/hash components below only stabilize the ordering.
pub(super) fn compare_lww(a: &VerifiedRecord, b: &VerifiedRecord) -> std::cmp::Ordering {
    a.body
        .lww_counter()
        .unwrap_or(0)
        .cmp(&b.body.lww_counter().unwrap_or(0))
        .then_with(|| a.signer.cmp(&b.signer))
        .then_with(|| a.record_hash.cmp(&b.record_hash))
}
