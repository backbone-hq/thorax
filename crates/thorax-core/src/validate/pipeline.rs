use super::effective::{compare_lww, compute_effective_state, lww_resolution};
use super::structure::{structurally_valid_user, structurally_validate_record};
use super::{record_key_for, EffectiveState, ValidationIssue, ValidationReport, VerifiedRecord};
use crate::authz::AuthoritySet;
use crate::crypto::{derive_hash, derive_user_id, key_hash, signed_record_message, CryptoProvider};
use crate::format::*;
use crate::merge::{ConflictKind, ConflictReport};
use crate::ratchet::{KeyOrigin, Ratchet, RatchetUpdate};
use crate::Result;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn validate_v1(
    vault: &VaultStoreV1,
    ratchet: &Ratchet,
    crypto: &impl CryptoProvider,
    verified: &BTreeSet<HashValue>,
) -> Result<ValidationReport> {
    let mut issues = Vec::new();
    // Records whose *kind* this build cannot read. Advisory format additions never change
    // what this build computes, stay in the vault byte-for-byte through merges and rewrites,
    // and surface as a warning, not an issue.
    let mut unknown_records: usize = 0;

    // Byte-identical duplicates collapse to one record before anything counts or scans
    // them. The merge union never produces duplicates (it is a record-*set* union), so
    // they only appear in hand-crafted files — where an attacker with git write could
    // otherwise replay one validly-signed record thousands of times to multiply
    // validation cost, or duplicate the root record to manufacture an `AmbiguousRoot`.
    let mut seen_hashes: BTreeSet<HashValue> = BTreeSet::new();
    let mut records: Vec<(&VaultRecordV1, HashValue)> = Vec::with_capacity(vault.records.len());
    for signed in &vault.records {
        let record_hash = derive_hash(crypto, "thorax.record-hash.v1", signed)?;
        if seen_hashes.insert(record_hash.clone()) {
            records.push((signed, record_hash));
        }
    }

    let selected_root = select_root(&records, ratchet, crypto, verified, &mut issues)?;
    let Some(root) = selected_root else {
        return Ok(ValidationReport {
            effective: EffectiveState {
                authority_unresolved: true,
                ..Default::default()
            },
            ratchet_update: RatchetUpdate::default(),
            issues,
            warnings: warnings_for(unknown_records),
        });
    };

    // Signing-key resolution: bind each signing public key to the one identity that holds
    // it. A record signature only attests to the signing key, whereas a `UserId` commits to
    // *both* the signing and HPKE keys (see `derive_user_id`); the envelope names only the
    // verification key, so resolution is what turns a signature into a complete identity.
    //
    // The hazard is that a `User` record is admin-*asserted*: an admin vouches for a
    // member's `(signing, hpke)` pairing, but the member's possession of that pairing is
    // proven only by their own *self-signed* entry point (signed under the signing key).
    // Without tying resolution to that proof, any member could append a `User` record
    // pairing a *victim's* real signing key with a different HPKE key, minting a second
    // `UserId` over that key and forcing a collision — a vault-wide denial of service
    // against a key they do not even hold.
    //
    // So a claimed pairing only counts once it is *attested*: a verified self-signed entry
    // point declares it (computed below). A forged pairing names an identity no one can
    // attest — only the signing key's holder can sign its entry point — so it is ignored,
    // never allowed to contest the real owner. A genuine collision then requires two
    // *attested* pairings on one key, i.e. the key holder self-colliding (corruption), and
    // even that is contained: the contested key's records drop, the rest of the vault
    // stays valid. (Whether an introducing signer holds administer is still enforced later
    // in the authority fixpoint; this phase only resolves signatures to identities.)
    let root_signing_key = &root.signing_public_key;
    let mut user_bodies: Vec<(&VaultRecordV1, &HashValue, &UserRecordV1)> = Vec::new();
    for (signed, record_hash) in &records {
        if let Some(RecordBodyV1::User(user)) = signed.body.known() {
            if structurally_valid_user(user, crypto).is_ok() {
                user_bodies.push((signed, record_hash, user));
            }
        }
    }
    let mut claims: BTreeMap<Bytes, BTreeSet<UserId>> = BTreeMap::new();
    let mut introduced: BTreeMap<UserId, Bytes> = BTreeMap::new();
    let mut introduced_keys: BTreeSet<Bytes> = BTreeSet::new();
    introduced.insert(root.root.id.clone(), root_signing_key.clone());
    introduced_keys.insert(root_signing_key.clone());
    loop {
        let mut changed = false;
        for (signed, record_hash, user) in &user_bodies {
            if introduced.contains_key(&user.id) {
                continue;
            }
            // The envelope's key must already be introduced for the signature to count;
            // which identity holds it is settled by the uniqueness check below.
            if !introduced_keys.contains(&signed.signing_public_key) {
                continue;
            }
            if !verified.contains(record_hash) {
                let Ok(message) = signed_record_message(signed) else {
                    continue;
                };
                if !crypto.verify_signature(
                    "thorax.signed.v1",
                    &signed.signing_public_key,
                    &message,
                    &signed.signature,
                ) {
                    continue;
                }
            }
            claims
                .entry(user.signing_public_key.clone())
                .or_default()
                .insert(user.id.clone());
            introduced.insert(user.id.clone(), user.signing_public_key.clone());
            introduced_keys.insert(user.signing_public_key.clone());
            changed = true;
        }
        if !changed {
            break;
        }
    }
    // Attestation set: identities that have proven possession of their *full* pairing via
    // a self-signed entry point. An entry point is signed under the very signing key it
    // declares (the self-signed constraint, enforced structurally), so only the holder of a
    // signing key can attest a `(signing, hpke)` pairing for it. This is the proof a forged
    // claim cannot fabricate — an attacker can assert a victim's signing key in a `User`
    // record, but cannot sign the matching entry point.
    let mut attested: BTreeSet<UserId> = BTreeSet::new();
    for (signed, record_hash) in &records {
        let Some(RecordBodyV1::EntryPoint(entry_point)) = signed.body.known() else {
            continue;
        };
        if entry_point.trusted_root_user_id != root.root.id {
            continue;
        }
        if !verified.contains(record_hash) {
            let Ok(message) = signed_record_message(signed) else {
                continue;
            };
            if !crypto.verify_signature(
                "thorax.signed.v1",
                &signed.signing_public_key,
                &message,
                &signed.signature,
            ) {
                continue;
            }
        }
        // The pairing is `(envelope signing key, body HPKE key)`: the signature above proves
        // the signer holds the envelope's signing key, and the entry point declares the HPKE
        // key paired with it.
        attested.insert(derive_user_id(
            crypto,
            &signed.signing_public_key,
            &entry_point.hpke_public_key,
        )?);
    }

    // Resolution map: verification key -> the one identity holding it. The root key is
    // reserved (only the root can sign under it). For every other claimed key:
    //  - a sole claimant resolves it (the ordinary case, attested or not — a member who has
    //    not yet posted an entry point holds no authority anyway);
    //  - several claimants resolve to the unique *attested* one — the rest are unattested
    //    impostors (a `User` record asserts a pairing, but only the key's holder can attest
    //    it), so they neither win nor collide;
    //  - two or more *attested* pairings on one key (the holder self-colliding), or several
    //    unattested claims with no attested owner, leave the key *contested*: its records
    //    are dropped as inert and a localized warning names it, while the rest of the vault
    //    stays valid. A contested key can therefore only deny its own holder, never brick
    //    the vault for everyone.
    let mut signer_for_key: BTreeMap<Bytes, UserId> = BTreeMap::new();
    signer_for_key.insert(root_signing_key.clone(), root.root.id.clone());
    let mut contested_keys: BTreeSet<Bytes> = BTreeSet::new();
    let mut ambiguous_keys: Vec<HashValue> = Vec::new();
    for (signing_key, claimants) in &claims {
        // The root key is never forfeited: only the holder of the root private key can sign
        // under it, so any `User` record asserting it (signed by someone else) names a
        // phantom no record can be attributed to. Keep the root's own resolution; ignore
        // the impostor claim entirely (no collision, no contest).
        if signing_key == root_signing_key {
            continue;
        }
        let attested_claimants: Vec<&UserId> = claimants
            .iter()
            .filter(|id| attested.contains(id))
            .collect();
        let resolved = if claimants.len() == 1 {
            claimants.iter().next()
        } else if attested_claimants.len() == 1 {
            Some(attested_claimants[0])
        } else {
            None
        };
        match resolved {
            Some(signer) => {
                signer_for_key.insert(signing_key.clone(), signer.clone());
            }
            None => {
                contested_keys.insert(signing_key.clone());
                ambiguous_keys.push(key_hash(crypto, signing_key)?);
            }
        }
    }

    let mut verified_records = Vec::new();
    for (signed, record_hash) in &records {
        let Some(body) = signed.body.known().cloned() else {
            unknown_records += 1;
            continue;
        };

        if let Err(issue) = structurally_validate_record(signed, &body, &root.root, crypto) {
            issues.push(issue);
            continue;
        }

        // A contested key resolves to no single identity: its records are inert (dropped),
        // the localized `AmbiguousSigningKey` warning above already named the key. This is
        // the blast-radius containment — only the contested key's own records vanish, the
        // rest of the vault validates.
        if contested_keys.contains(&signed.signing_public_key) {
            continue;
        }
        // Resolve the envelope's verification key to its one introduced identity first —
        // a key no identity holds leaves the signature attesting to no one.
        let Some(signer) = signer_for_key.get(&signed.signing_public_key) else {
            issues.push(ValidationIssue::UnknownSignerKey(key_hash(
                crypto,
                &signed.signing_public_key,
            )?));
            continue;
        };
        let key = record_key_for(&body, signer)?;
        // A hash hit attests this exact envelope (the hash commits to body, key, and
        // signature together) already verified — skip only the curve math.
        if !verified.contains(record_hash) {
            let message = signed_record_message(signed)?;
            if !crypto.verify_signature(
                "thorax.signed.v1",
                &signed.signing_public_key,
                &message,
                &signed.signature,
            ) {
                issues.push(ValidationIssue::InvalidSignature(key));
                continue;
            }
        }
        verified_records.push(VerifiedRecord {
            record_hash: record_hash.clone(),
            signed: (*signed).clone(),
            body,
            key,
            signer: signer.clone(),
        });
    }

    // Resolve authority once without rollback exclusions. Signature validity alone is not
    // admission: only records their signer was authorized to issue may influence rollback
    // memory or the Lamport clock. This distinction prevents a read-only member from signing
    // an inert MAX-counter record and globally wedging every later writer.
    let no_rollbacks = BTreeMap::new();
    let (provisional, provisional_deletions) =
        resolve_effective_with_deletions(&root, &verified_records, &no_rollbacks);
    let (current_watermarks, observed_origins) =
        admitted_watermarks(&verified_records, &provisional, &provisional_deletions);

    // Rollback detection — has the highest authority-admitted counter at a remembered key
    // gone backward? A rollback-suspected key becomes a conflict until an authorized writer
    // re-signs above the remembered counter.
    let mut rollback_keys: BTreeMap<RecordKey, u64> = BTreeMap::new();
    for (key, remembered) in &ratchet.watermarks {
        let current = current_watermarks.get(key).copied().unwrap_or(0);
        if current < *remembered {
            rollback_keys.insert(key.clone(), *remembered);
        }
    }

    let (mut effective, _admitted_deletions) =
        resolve_effective_with_deletions(&root, &verified_records, &rollback_keys);
    if effective.authority_unresolved {
        issues.push(ValidationIssue::AuthorityDidNotConverge);
    }

    // Secret ties join the conflict set here (selection above only resolves the principal
    // graph; secrets resolve per-key like everything else but are queried on demand).
    // Same gate as every secret query: only records whose signer can write the selector
    // they claim compete at the key.
    let secret_resolution = lww_resolution(&verified_records, &rollback_keys, |record| {
        let (secret, selector) = match &record.body {
            RecordBodyV1::Secret(value) => (&value.id, &value.selector),
            RecordBodyV1::SecretDeleted(deleted) => (&deleted.id, &deleted.selector),
            _ => return None,
        };
        effective
            .authority_for_user(&record.signer)
            .can_write(selector)
            .then(|| secret.clone())
    });
    let secret_conflicts =
        super::effective::materialize_conflicts(&verified_records, secret_resolution.conflicted);
    effective.conflicted.extend(secret_conflicts);

    // Rollback conflicts carry whatever still exists at the regressed key (possibly
    // nothing) as candidates, so a resolver can ratify a survivor explicitly — plus the
    // key's remembered origin, so even a fully-erased key can be named.
    for (key, remembered) in &rollback_keys {
        let current = current_watermarks.get(key).copied().unwrap_or(0);
        let mut candidates: Vec<VaultRecordV1> = verified_records
            .iter()
            .filter(|record| {
                &record.key == key && record.body.lww_counter().unwrap_or(0) == current
            })
            .map(|record| record.signed.clone())
            .collect();
        candidates.sort_by_key(|signed| cord::serialize(signed).unwrap_or_default());
        candidates.dedup();
        effective.conflicted.insert(
            key.clone(),
            ConflictReport {
                key: key.clone(),
                counter: current,
                kind: ConflictKind::Rollback {
                    remembered_counter: *remembered,
                },
                candidates,
                origin: observed_origins
                    .get(key)
                    .or_else(|| ratchet.origins.get(key))
                    .cloned(),
            },
        );
    }

    let admitted_counter_max = current_watermarks.values().copied().max();
    effective.attach_verified_records(verified_records, admitted_counter_max);

    let mut ratchet_update = RatchetUpdate::default();

    // The verified high-water mark per key from *this* vault. Counters only grow in an
    // honest append-only vault, so this is the reference for both remembering and rollback.
    // Deletions raise the watermark like any other write, which is what protects them: a
    // vault that drops a deletion shows a lower counter at its key.
    for (key, current) in &current_watermarks {
        let remembered = ratchet.watermarks.get(key).copied().unwrap_or(0);
        if *current > remembered {
            ratchet_update
                .raised_watermarks
                .insert(key.clone(), *current);
        }
    }
    // Origins ride along for every key this validation could name; `apply_update` keeps
    // the first remembered one (preimages are immutable per key).
    for (key, origin) in observed_origins {
        if !ratchet.origins.contains_key(&key) {
            ratchet_update.origins.insert(key, origin);
        }
    }

    let mut warnings = warnings_for(unknown_records);
    for key in ambiguous_keys {
        warnings.push(super::ValidationWarning::AmbiguousSigningKey(key));
    }

    Ok(ValidationReport {
        effective,
        ratchet_update,
        issues,
        warnings,
    })
}

fn warnings_for(unknown_records: usize) -> Vec<super::ValidationWarning> {
    if unknown_records > 0 {
        vec![super::ValidationWarning::UnknownRecords {
            count: unknown_records,
        }]
    } else {
        Vec::new()
    }
}

/// The id preimage a record's body names, where one is human-meaningful — what
/// [`KeyOrigin`] remembers for its key.
fn record_origin(body: &RecordBodyV1) -> Option<KeyOrigin> {
    match body {
        RecordBodyV1::Secret(record) => Some(KeyOrigin::Secret(record.selector.clone())),
        RecordBodyV1::SecretDeleted(record) => Some(KeyOrigin::Secret(record.selector.clone())),
        RecordBodyV1::UserHandle(record) => Some(KeyOrigin::UserHandle(record.handle.clone())),
        RecordBodyV1::VaultHandle(record) => Some(KeyOrigin::VaultHandle(record.handle.clone())),
        RecordBodyV1::GroupMember(record) => Some(KeyOrigin::GroupMember {
            group_id: record.group_id.clone(),
            member_id: record.member_id.clone(),
        }),
        RecordBodyV1::GroupMemberDeleted(record) => Some(KeyOrigin::GroupMember {
            group_id: record.group_id.clone(),
            member_id: record.member_id.clone(),
        }),
        _ => None,
    }
}

#[derive(Clone)]
struct SelectedRoot {
    root: VaultRootRecordV1,
    /// The root's signing key, taken from the (self-signed) envelope — the body no longer
    /// stores it. Cached here so the rest of validation doesn't re-reach the envelope.
    signing_public_key: Bytes,
    root_signing_public_key_hash: HashValue,
}

fn select_root(
    records: &[(&VaultRecordV1, HashValue)],
    ratchet: &Ratchet,
    crypto: &impl CryptoProvider,
    verified: &BTreeSet<HashValue>,
    issues: &mut Vec<ValidationIssue>,
) -> Result<Option<SelectedRoot>> {
    let mut matches = Vec::new();
    for (signed, record_hash) in records {
        let Some(RecordBodyV1::VaultRoot(root)) = signed.body.known() else {
            continue;
        };
        // The root is self-signed, so its signing key is the envelope's. The id commits to
        // (envelope signing, body hpke).
        if root.id != derive_user_id(crypto, &signed.signing_public_key, &root.hpke_public_key)? {
            continue;
        }
        if !verified.contains(record_hash) {
            let message = signed_record_message(signed)?;
            if !crypto.verify_signature(
                "thorax.signed.v1",
                &signed.signing_public_key,
                &message,
                &signed.signature,
            ) {
                continue;
            }
        }
        let root_signing_public_key_hash = key_hash(crypto, &signed.signing_public_key)?;
        if root_signing_public_key_hash == ratchet.trusted_root {
            matches.push(SelectedRoot {
                root: root.clone(),
                signing_public_key: signed.signing_public_key.clone(),
                root_signing_public_key_hash,
            });
        }
    }

    match matches.len() {
        0 => {
            issues.push(ValidationIssue::RootNotTrusted);
            Ok(None)
        }
        1 => Ok(matches.pop()),
        _ => {
            issues.push(ValidationIssue::AmbiguousRoot);
            Ok(None)
        }
    }
}

fn user_from_root(root: &VaultRootRecordV1, signing_public_key: &[u8]) -> UserRecordV1 {
    UserRecordV1 {
        id: root.id.clone(),
        signing_public_key: signing_public_key.to_vec(),
        hpke_public_key: root.hpke_public_key.clone(),
        // The root user is synthesized from the trust anchor, not LWW-resolved; the counter
        // never competes (root records are excluded from the user-key pools).
        counter: 0,
    }
}

/// Resolve the principal graph and monotonically admit authority-gated deletions. Kept as one
/// helper because validation first needs an authority view with no rollback exclusions to decide
/// which counters are legitimate, then recomputes the final view with rollback keys made inert.
fn resolve_effective_with_deletions(
    root: &SelectedRoot,
    records: &[VerifiedRecord],
    rollback_keys: &BTreeMap<RecordKey, u64>,
) -> (EffectiveState, BTreeSet<HashValue>) {
    let mut deletion_candidates: Vec<&VerifiedRecord> = records
        .iter()
        .filter(|record| {
            matches!(
                record.body,
                RecordBodyV1::UserDeleted(_)
                    | RecordBodyV1::GroupDeleted(_)
                    | RecordBodyV1::GrantDeleted(_)
            )
        })
        .collect();
    deletion_candidates.sort_by(|a, b| compare_lww(a, b));
    let mut admitted_deletions = BTreeSet::new();
    let effective = loop {
        let state = compute_effective_state(
            user_from_root(&root.root, &root.signing_public_key),
            root.root_signing_public_key_hash.clone(),
            records,
            &admitted_deletions,
            rollback_keys,
        );
        let newly_admitted = deletion_candidates.iter().find_map(|record| {
            if admitted_deletions.contains(&record.record_hash) {
                return None;
            }
            let signer_auth = state.authority_for_user(&record.signer);
            let authorized = match &record.body {
                RecordBodyV1::UserDeleted(_) | RecordBodyV1::GroupDeleted(_) => {
                    signer_auth.administer
                }
                RecordBodyV1::GrantDeleted(deleted) => {
                    grant_deleted_authorized(&signer_auth, deleted, &state)
                }
                _ => false,
            };
            authorized.then(|| record.record_hash.clone())
        });
        match newly_admitted {
            Some(hash) => {
                admitted_deletions.insert(hash);
            }
            None => break state,
        }
    };
    (effective, admitted_deletions)
}

fn admitted_watermarks(
    records: &[VerifiedRecord],
    effective: &EffectiveState,
    admitted_deletions: &BTreeSet<HashValue>,
) -> (BTreeMap<RecordKey, u64>, BTreeMap<RecordKey, KeyOrigin>) {
    let attested_users: BTreeSet<UserId> = records
        .iter()
        .filter_map(|record| match &record.body {
            RecordBodyV1::EntryPoint(_) => Some(record.signer.clone()),
            _ => None,
        })
        .collect();
    let mut watermarks = BTreeMap::new();
    let mut origins = BTreeMap::new();
    for record in records {
        let auth = effective.authority_for_user(&record.signer);
        let admitted = match &record.body {
            RecordBodyV1::VaultRoot(_) => true,
            RecordBodyV1::EntryPoint(_) => attested_users.contains(&record.signer),
            RecordBodyV1::User(user) => auth.administer && attested_users.contains(&user.id),
            RecordBodyV1::UserDeleted(_)
            | RecordBodyV1::GroupDeleted(_)
            | RecordBodyV1::GrantDeleted(_) => admitted_deletions.contains(&record.record_hash),
            RecordBodyV1::UserHandle(_)
            | RecordBodyV1::VaultHandle(_)
            | RecordBodyV1::Group(_)
            | RecordBodyV1::GroupMember(_)
            | RecordBodyV1::GroupMemberDeleted(_) => auth.administer,
            RecordBodyV1::Grant(grant) => auth.can_create_permission(&grant.permission),
            RecordBodyV1::Secret(secret) => auth.can_write(&secret.selector),
            RecordBodyV1::SecretDeleted(secret) => auth.can_write(&secret.selector),
        };
        if !admitted {
            continue;
        }
        if let Some(counter) = record.body.lww_counter() {
            let entry = watermarks.entry(record.key.clone()).or_insert(0);
            *entry = (*entry).max(counter);
        }
        if let Some(origin) = record_origin(&record.body) {
            origins.entry(record.key.clone()).or_insert(origin);
        }
    }
    (watermarks, origins)
}

/// Whether a grant deletion's signer holds the authority the deletion requires.
fn grant_deleted_authorized(
    signer_auth: &AuthoritySet,
    deleted: &GrantDeletedRecordV1,
    state: &EffectiveState,
) -> bool {
    match state.grants.get(&deleted.id) {
        // A live grant can only be deleted by someone who could have created both the
        // tombstone's stated permission and the live grant's actual permission — a weaker
        // manager cannot delete a stronger grant.
        Some(active) => {
            signer_auth.can_create_permission(&deleted.permission)
                && signer_auth.can_create_permission(&active.permission)
        }
        // No live grant at this key: it never became effective, was superseded, or is
        // dangling because its subject was deleted. Admins may tombstone freely here — this
        // is how user/group deletion cascades clean up keyspace authority an admin holds no
        // manage grant over, so that restoring the principal does not silently resurrect
        // its old grants.
        None => signer_auth.administer || signer_auth.can_create_permission(&deleted.permission),
    }
}
