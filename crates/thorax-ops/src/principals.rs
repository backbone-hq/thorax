use thorax_core::hazmat::{
    append_record, ensure_identity_consistent, entry_point_record, grant_deleted_record,
    grant_record, group_deleted_record, group_member_deleted_record, group_member_record,
    group_record, user_deleted_record, user_handle_record, user_record, vault_handle_record,
};
use thorax_core::ids::{
    derive_grant_id, derive_group_id, derive_group_member_id, derive_user_handle_id,
    derive_vault_handle_id, is_valid_handle, normalize_handle,
};
use thorax_core::{
    next_counter, CryptoProvider, EffectiveState, GrantId, GrantPermissionV1, GroupId,
    GroupMemberId, IdSeed, PrincipalRefV1, RecordSigner, UserHandleId, UserHandleRecordV1, UserId,
    ValidationReport, VaultHandleId, VaultHandleRecordV1,
};
use thorax_crypto::Crypto;

use crate::{
    AccessChange, LockedSession, OpsError, ResolvedUserRef, Result, UnlockedSession, UserRef,
};

pub fn resolve_user_ref(
    report: &ValidationReport,
    crypto: &impl CryptoProvider,
    reference: UserRef,
) -> Result<ResolvedUserRef> {
    match reference {
        UserRef::Id(user) => {
            if !report.effective.users.contains_key(&user) {
                return Err(OpsError::MissingUser(user));
            }
            let handle = primary_handle_for_user(report, &user);
            Ok(ResolvedUserRef {
                user_id: user,
                handle: handle
                    .as_ref()
                    .map(|record| normalize_handle(&record.handle)),
            })
        }
        UserRef::Handle(handle) => {
            let handle = normalize_user_handle(handle)?;
            let handle_id = derive_user_handle_id(crypto, &handle)?;
            let record = report
                .effective
                .handles
                .get(&handle_id)
                .ok_or_else(|| OpsError::UserHandleNotFound(handle.clone()))?;
            if !report.effective.users.contains_key(&record.user_id) {
                return Err(OpsError::UserHandleTargetMissing {
                    handle,
                    user: record.user_id.clone(),
                });
            }
            Ok(ResolvedUserRef {
                user_id: record.user_id.clone(),
                handle: Some(normalize_handle(&record.handle)),
            })
        }
    }
}

/// The users-and-handles family of operations, acting as the session's unlocked identity.
impl UnlockedSession {
    pub fn set_user_handle(
        &mut self,
        crypto: &Crypto,
        handle: impl Into<String>,
        target: UserId,
    ) -> Result<UserHandleId> {
        let (session, identity) = self.parts();
        let handle = normalize_user_handle(handle)?;
        ensure_administer(session.effective(), identity.user_id())?;
        if !session.effective().users.contains_key(&target) {
            return Err(OpsError::MissingUser(target));
        }
        session.set_user_handle(crypto, identity, handle, target)
    }

    pub fn set_vault_handle(
        &mut self,
        crypto: &Crypto,
        handle: impl Into<String>,
    ) -> Result<VaultHandleId> {
        let (session, identity) = self.parts();
        let handle = normalize_vault_handle(handle)?;
        ensure_administer(session.effective(), identity.user_id())?;
        session.set_vault_handle(crypto, identity, handle)
    }

    /// Delete a user and cascade over everything hanging off them (memberships, grants
    /// naming them as subject) — see `LockedSession::delete_user` for the cascade's
    /// rationale.
    pub fn delete_user(
        &mut self,
        crypto: &Crypto,
        target: UserId,
        reason: Option<String>,
    ) -> Result<UserId> {
        let (session, identity) = self.parts();
        ensure_administer(session.effective(), identity.user_id())?;
        if !session.effective().users.contains_key(&target) {
            return Err(OpsError::MissingUser(target));
        }
        session.delete_user(crypto, identity, target, reason)
    }
}

/// The groups-and-grants family of operations, acting as the session's unlocked identity.
/// Access *additions* (grants, member adds) converge readers internally in the same op —
/// see [`AccessChange`].
impl UnlockedSession {
    /// Grant a permission *and* make it cryptographically effective in one operation: the
    /// grant record is appended, then existing secrets the issuer can decrypt are
    /// re-encrypted so the new reader has a slot. Convergence the issuer cannot perform
    /// (secrets it cannot decrypt) is surfaced in `reconcile.needs_rotation`. Frontends
    /// render the returned [`AccessChange`]; they never sequence a separate reconcile and
    /// so cannot forget to.
    pub fn grant_permission(
        &mut self,
        crypto: &Crypto,
        subject: PrincipalRefV1,
        permission: GrantPermissionV1,
    ) -> Result<AccessChange<GrantId>> {
        ensure_can_create_permission(self.effective(), self.user_id(), &permission)?;
        ensure_principal_exists(self.effective(), &subject)?;
        self.access_addition(crypto, |session, identity| {
            session.grant_permission(
                crypto,
                identity,
                subject,
                permission,
                thorax_crypto::random_seed(),
            )
        })
    }

    pub fn delete_grant(&mut self, crypto: &Crypto, grant: GrantId) -> Result<GrantId> {
        let permission = self
            .effective()
            .grants
            .get(&grant)
            .ok_or(OpsError::OperationNotEffective("grant is not active"))?
            .permission
            .clone();
        ensure_can_create_permission(self.effective(), self.user_id(), &permission)?;
        let (session, identity) = self.parts();
        session.delete_grant(crypto, identity, grant, permission)
    }

    pub fn create_group(&mut self, crypto: &Crypto, handle: impl Into<String>) -> Result<GroupId> {
        ensure_administer(self.effective(), self.user_id())?;
        let (session, identity) = self.parts();
        session.create_group(crypto, identity, thorax_crypto::random_seed(), handle)
    }

    pub fn delete_group(&mut self, crypto: &Crypto, group: GroupId) -> Result<GroupId> {
        ensure_administer(self.effective(), self.user_id())?;
        if !self.effective().groups.contains_key(&group) {
            return Err(OpsError::OperationNotEffective("group is not active"));
        }
        let (session, identity) = self.parts();
        session.delete_group(crypto, identity, group)
    }

    pub fn add_group_member(
        &mut self,
        crypto: &Crypto,
        group: GroupId,
        member: PrincipalRefV1,
    ) -> Result<AccessChange<GroupMemberId>> {
        ensure_administer(self.effective(), self.user_id())?;
        ensure_principal_exists(self.effective(), &PrincipalRefV1::Group(group.clone()))?;
        ensure_principal_exists(self.effective(), &member)?;
        ensure_can_confer_group(self.effective(), self.user_id(), &group)?;
        // Membership must be idempotent: adding a principal already in the group would
        // otherwise write a second, redundant membership record. Reject up front, like the
        // other delete guards.
        if self
            .effective()
            .memberships
            .values()
            .any(|m| m.group_id == group && m.member_id == member)
        {
            return Err(OpsError::OperationNotEffective(
                "principal is already a member of this group",
            ));
        }
        // Conferring group membership confers the group's read access, so it is an access
        // *addition* exactly like a direct grant — converge the new member's secrets in
        // the same op.
        self.access_addition(crypto, |session, identity| {
            session.add_group_member(crypto, identity, group, member)
        })
    }

    pub fn delete_group_member(
        &mut self,
        crypto: &Crypto,
        group: GroupId,
        member: PrincipalRefV1,
    ) -> Result<GroupMemberId> {
        ensure_administer(self.effective(), self.user_id())?;
        let membership = derive_group_member_id(crypto, &group, &member)?;
        if !self.effective().memberships.contains_key(&membership) {
            return Err(OpsError::OperationNotEffective(
                "group membership is not active",
            ));
        }
        let (session, identity) = self.parts();
        session.delete_group_member(crypto, identity, group, member)
    }
}

/// The signer-direct inner halves of the users-and-handles family: crate-internal, so the
/// untrusted session type carries no mutation vocabulary outside this crate.
impl LockedSession {
    /// Add (or restore) a member. The user record naming the new member's public keys is
    /// signed by `admin`; the entry point pinning the root is self-signed by the new
    /// member, which is possible here because the inviter holds the invitee's seed at
    /// invite time. Re-adding a previously deleted user is the same operation: the fresh
    /// counter out-votes the deletion and the identity (same keys → same id) is restored.
    pub(crate) fn add_user(
        &mut self,
        crypto: &impl CryptoProvider,
        admin: &impl RecordSigner,
        user: &impl RecordSigner,
    ) -> Result<UserId> {
        ensure_identity_consistent(crypto, admin)?;
        let user_id = ensure_identity_consistent(crypto, user)?;
        self.commit(
            crypto,
            |vault, report| {
                let counter = next_counter(&report.effective);
                append_record(
                    vault,
                    user_record(
                        crypto,
                        admin,
                        user.signing_public_key().to_vec(),
                        user.hpke_public_key().to_vec(),
                        counter,
                    )?,
                );
                // Record the new user's self-signed trust in the current root. The root's
                // `user_id` commits to both root keys, so pinning it is the whole
                // substitution defense — no need to look up the root's key material here.
                let root_user = report
                    .effective
                    .root_user_id
                    .clone()
                    .ok_or(OpsError::MissingEffectiveRoot)?;
                append_record(
                    vault,
                    // Same Lamport counter as the user record: they live at different keys,
                    // so they never compete; ties across keys are meaningless to LWW.
                    entry_point_record(crypto, user, root_user, counter)?,
                );
                Ok(user_id.clone())
            },
            |user_id, report| {
                // Content match suffices; the winning LWW counter is irrelevant to
                // effectiveness.
                if report.effective.users.get(user_id).is_some_and(|record| {
                    record.id == *user_id
                        && record.signing_public_key == user.signing_public_key()
                        && record.hpke_public_key == user.hpke_public_key()
                }) {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective("user is not active"))
                }
            },
        )
    }

    pub(crate) fn set_user_handle(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        handle: impl Into<String>,
        user: UserId,
    ) -> Result<UserHandleId> {
        let handle = normalize_user_handle(handle)?;
        let handle_id = derive_user_handle_id(crypto, &handle)?;
        self.commit_record(
            crypto,
            |_pre_report, counter| {
                let signed =
                    user_handle_record(crypto, signer, handle.clone(), user.clone(), counter)?;
                Ok((signed, handle_id.clone()))
            },
            // The effective handle is "ours" if its content matches; the LWW counter that
            // won is irrelevant to whether the intent took effect (a concurrent identical
            // write is benign).
            |handle_id, _hash, report| {
                if report
                    .effective
                    .handles
                    .get(handle_id)
                    .is_some_and(|record| record.handle == handle && record.user_id == user)
                {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective("user handle is not active"))
                }
            },
        )
    }

    pub(crate) fn set_vault_handle(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        handle: impl Into<String>,
    ) -> Result<VaultHandleId> {
        let _signer_id = ensure_identity_consistent(crypto, signer)?;
        let handle = normalize_vault_handle(handle)?;
        let handle_id = derive_vault_handle_id(crypto, &handle)?;
        self.commit_record(
            crypto,
            |_pre_report, counter| {
                let signed = vault_handle_record(crypto, signer, handle.clone(), counter)?;
                Ok((signed, handle_id.clone()))
            },
            // Content match suffices; the winning LWW counter does not affect whether the
            // intent is effective.
            |handle_id, _hash, report| {
                if report
                    .effective
                    .vault_handles
                    .get(handle_id)
                    .is_some_and(|record| record.handle == handle)
                {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective(
                        "vault handle is not active",
                    ))
                }
            },
        )
    }

    /// Delete a user and cascade over everything hanging off them: their group memberships
    /// and the grants naming them as subject. The cascade keeps deletion and restoration
    /// symmetric — re-inviting the user (same seed → same id, fresh counter) restores the
    /// identity but none of its old access; that must be re-granted explicitly.
    pub(crate) fn delete_user(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        user: UserId,
        reason: Option<String>,
    ) -> Result<UserId> {
        self.commit(
            crypto,
            |vault, pre_report| {
                if pre_report.effective.deleted_users.contains(&user) {
                    return Err(OpsError::OperationNotEffective("user is already deleted"));
                }
                if !pre_report.effective.users.contains_key(&user) {
                    return Err(OpsError::MissingUser(user.clone()));
                }
                let user_principal = PrincipalRefV1::User(user.clone());
                let mut counter = next_counter(&pre_report.effective);
                // The user tombstone goes first (lowest counter): once it is admitted, the
                // user's grants are dangling, which is what authorizes an admin to
                // tombstone them even without a covering manage grant.
                append_record(
                    vault,
                    user_deleted_record(crypto, signer, user.clone(), reason.clone(), counter)?,
                );
                for membership in pre_report.effective.memberships.values() {
                    if membership.member_id != user_principal {
                        continue;
                    }
                    counter = counter.saturating_add(1);
                    append_record(
                        vault,
                        group_member_deleted_record(
                            crypto,
                            signer,
                            membership.group_id.clone(),
                            membership.member_id.clone(),
                            counter,
                        )?,
                    );
                }
                for grant in pre_report.effective.grants.values() {
                    if grant.subject_id != user_principal {
                        continue;
                    }
                    counter = counter.saturating_add(1);
                    append_record(
                        vault,
                        grant_deleted_record(
                            crypto,
                            signer,
                            grant.id.clone(),
                            grant.permission.clone(),
                            counter,
                        )?,
                    );
                }
                Ok(user.clone())
            },
            |user, report| {
                if report.effective.users.contains_key(user) {
                    Err(OpsError::OperationNotEffective("user is still active"))
                } else {
                    Ok(())
                }
            },
        )
    }

    pub fn resolve_user_ref(
        &self,
        crypto: &impl CryptoProvider,
        reference: UserRef,
    ) -> Result<ResolvedUserRef> {
        resolve_user_ref(self.report(), crypto, reference)
    }
}

/// The RecordSigner-based inner halves of the groups-and-grants family.
impl LockedSession {
    /// Append a grant record only — the *authorization* half. This does NOT make the grant
    /// cryptographically effective; on its own it leaves newly-authorized readers without a
    /// recipient slot. It is crate-internal precisely so no frontend can perform that
    /// half-operation: callers outside `thorax-ops` must go through
    /// [`UnlockedSession::grant_permission`], which converges too.
    pub(crate) fn grant_permission(
        &mut self,
        crypto: &impl CryptoProvider,
        issuer: &impl RecordSigner,
        subject: PrincipalRefV1,
        permission: GrantPermissionV1,
        seed: IdSeed,
    ) -> Result<GrantId> {
        ensure_identity_consistent(crypto, issuer)?;
        let grant = derive_grant_id(crypto, &seed)?;
        self.commit_record(
            crypto,
            |_pre_report, counter| {
                let signed = grant_record(
                    crypto,
                    issuer,
                    subject.clone(),
                    permission.clone(),
                    seed.clone(),
                    counter,
                )?;
                Ok((signed, grant.clone()))
            },
            // Content match suffices; the winning LWW counter is irrelevant to
            // effectiveness.
            |grant, _hash, report| {
                if report.effective.grants.get(grant).is_some_and(|record| {
                    record.seed == seed
                        && record.subject_id == subject
                        && record.permission == permission
                }) {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective("grant is not active"))
                }
            },
        )
    }

    pub(crate) fn delete_grant(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        grant: GrantId,
        permission: GrantPermissionV1,
    ) -> Result<GrantId> {
        self.commit_record(
            crypto,
            |pre_report, counter| {
                if !pre_report.effective.grants.contains_key(&grant) {
                    return Err(OpsError::OperationNotEffective("grant is not active"));
                }
                let signed = grant_deleted_record(
                    crypto,
                    signer,
                    grant.clone(),
                    permission.clone(),
                    counter,
                )?;
                Ok((signed, grant.clone()))
            },
            // The deletion won iff the grant is no longer effective.
            |grant, _hash, report| {
                if report.effective.grants.contains_key(grant) {
                    Err(OpsError::OperationNotEffective("grant is still active"))
                } else {
                    Ok(())
                }
            },
        )
    }

    pub(crate) fn create_group(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        seed: IdSeed,
        handle: impl Into<String>,
    ) -> Result<GroupId> {
        let handle = normalize_group_handle(handle)?;
        let group = derive_group_id(crypto, &seed)?;
        self.commit_record(
            crypto,
            |_pre_report, counter| {
                let signed = group_record(crypto, signer, seed.clone(), handle.clone(), counter)?;
                Ok((signed, group.clone()))
            },
            // Content match suffices; the winning LWW counter is irrelevant to
            // effectiveness.
            |group, _hash, report| {
                if report
                    .effective
                    .groups
                    .get(group)
                    .is_some_and(|record| record.seed == seed && record.handle == handle)
                {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective("group is not active"))
                }
            },
        )
    }

    /// Delete a group and cascade over everything hanging off it: memberships *in* the
    /// group, memberships *of* the group in other groups, and grants whose subject is the
    /// group. The cascade keeps deletion and restoration symmetric — a later re-add of the
    /// group restores nothing implicitly, because every dependent fact was explicitly
    /// tombstoned with it.
    pub(crate) fn delete_group(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        group: GroupId,
    ) -> Result<GroupId> {
        self.commit(
            crypto,
            |vault, pre_report| {
                if !pre_report.effective.groups.contains_key(&group) {
                    return Err(OpsError::OperationNotEffective("group is not active"));
                }
                let group_principal = PrincipalRefV1::Group(group.clone());
                let mut counter = next_counter(&pre_report.effective);
                // The group tombstone goes first (lowest counter): once it is admitted, the
                // group's grants are dangling, which is what authorizes an admin to
                // tombstone them even without a covering manage grant.
                append_record(
                    vault,
                    group_deleted_record(crypto, signer, group.clone(), counter)?,
                );
                for membership in pre_report.effective.memberships.values() {
                    if membership.group_id != group && membership.member_id != group_principal {
                        continue;
                    }
                    counter = counter.saturating_add(1);
                    append_record(
                        vault,
                        group_member_deleted_record(
                            crypto,
                            signer,
                            membership.group_id.clone(),
                            membership.member_id.clone(),
                            counter,
                        )?,
                    );
                }
                for grant in pre_report.effective.grants.values() {
                    if grant.subject_id != group_principal {
                        continue;
                    }
                    counter = counter.saturating_add(1);
                    append_record(
                        vault,
                        grant_deleted_record(
                            crypto,
                            signer,
                            grant.id.clone(),
                            grant.permission.clone(),
                            counter,
                        )?,
                    );
                }
                Ok(group.clone())
            },
            // The deletion won iff the group is no longer effective.
            |group, report| {
                if report.effective.groups.contains_key(group) {
                    Err(OpsError::OperationNotEffective("group is still active"))
                } else {
                    Ok(())
                }
            },
        )
    }

    /// Append a group-membership record only — the *authorization* half. Like
    /// [`LockedSession::grant_permission`], this confers read access without converging the
    /// new member's secrets, so it is crate-internal; frontends go through
    /// [`UnlockedSession::add_group_member`], which converges in the same op.
    pub(crate) fn add_group_member(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        group: GroupId,
        member: PrincipalRefV1,
    ) -> Result<GroupMemberId> {
        let membership = derive_group_member_id(crypto, &group, &member)?;
        self.commit_record(
            crypto,
            |_pre_report, counter| {
                let signed =
                    group_member_record(crypto, signer, group.clone(), member.clone(), counter)?;
                Ok((signed, membership.clone()))
            },
            // Membership is content-addressed + LWW: it is effective iff the latest
            // authorized record at this (group, member) key is the add (not a deletion).
            |membership, _hash, report| {
                if report.effective.memberships.contains_key(membership) {
                    Ok(())
                } else {
                    Err(OpsError::OperationNotEffective(
                        "group membership is not active",
                    ))
                }
            },
        )
    }

    pub(crate) fn delete_group_member(
        &mut self,
        crypto: &impl CryptoProvider,
        signer: &impl RecordSigner,
        group: GroupId,
        member: PrincipalRefV1,
    ) -> Result<GroupMemberId> {
        let membership = derive_group_member_id(crypto, &group, &member)?;
        self.commit_record(
            crypto,
            |pre_report, counter| {
                if !pre_report.effective.memberships.contains_key(&membership) {
                    return Err(OpsError::OperationNotEffective(
                        "group membership is not active",
                    ));
                }
                let signed = group_member_deleted_record(
                    crypto,
                    signer,
                    group.clone(),
                    member.clone(),
                    counter,
                )?;
                Ok((signed, membership.clone()))
            },
            // The removal won iff the membership is no longer effective.
            |membership, _hash, report| {
                if report.effective.memberships.contains_key(membership) {
                    Err(OpsError::OperationNotEffective(
                        "group membership is still active",
                    ))
                } else {
                    Ok(())
                }
            },
        )
    }
}

pub(crate) fn ensure_administer(effective: &EffectiveState, user: &UserId) -> Result<()> {
    if !effective.users.contains_key(user) {
        return Err(OpsError::MissingUser(user.clone()));
    }
    if effective.authority_unresolved || !effective.authority_for_user(user).administer {
        return Err(OpsError::AdministerRequired(user.clone()));
    }
    Ok(())
}

/// Adding a member to a group confers all of that group's authority on the new member. A member
/// add is therefore only allowed if the actor could have granted each of those permissions
/// directly (`can_create_permission`). Because the effective hierarchy is administer > manage >
/// write > read, this also keeps the actor able to decrypt any keyspace access they confer.
pub(crate) fn ensure_can_confer_group(
    effective: &EffectiveState,
    actor: &UserId,
    group: &GroupId,
) -> Result<()> {
    let actor_auth = effective.authority_for_user(actor);
    for permission in effective.authority_for_group(group).as_grant_permissions() {
        if !actor_auth.can_create_permission(&permission) {
            return Err(OpsError::CannotConferGroupAuthority(actor.clone()));
        }
    }
    Ok(())
}

pub(crate) fn ensure_can_create_permission(
    effective: &EffectiveState,
    user: &UserId,
    permission: &GrantPermissionV1,
) -> Result<()> {
    if !effective.users.contains_key(user) {
        return Err(OpsError::MissingUser(user.clone()));
    }
    if effective.authority_unresolved
        || !effective
            .authority_for_user(user)
            .can_create_permission(permission)
    {
        return Err(OpsError::OperationNotEffective(
            "user cannot grant this permission",
        ));
    }
    Ok(())
}

fn ensure_principal_exists(effective: &EffectiveState, principal: &PrincipalRefV1) -> Result<()> {
    match principal {
        PrincipalRefV1::User(user) => {
            // A deleted user is already absent from `users`.
            if effective.users.contains_key(user) {
                Ok(())
            } else {
                Err(OpsError::MissingUser(user.clone()))
            }
        }
        PrincipalRefV1::Group(group) => {
            if effective.groups.contains_key(group) {
                Ok(())
            } else {
                Err(OpsError::OperationNotEffective("group is not active"))
            }
        }
    }
}

pub(crate) fn normalize_user_handle(handle: impl Into<String>) -> Result<String> {
    let original = handle.into();
    let normalized = normalize_handle(&original);
    if !is_valid_handle(&normalized) {
        return Err(OpsError::InvalidUserHandle {
            handle: original,
            reason: HANDLE_CHARSET_REASON,
        });
    }
    Ok(normalized)
}

fn normalize_vault_handle(handle: impl Into<String>) -> Result<String> {
    let original = handle.into();
    let normalized = normalize_handle(&original);
    if !is_valid_handle(&normalized) {
        return Err(OpsError::InvalidVaultHandle {
            handle: original,
            reason: HANDLE_CHARSET_REASON,
        });
    }
    Ok(normalized)
}

fn normalize_group_handle(handle: impl Into<String>) -> Result<String> {
    let original = handle.into();
    let normalized = normalize_handle(&original);
    if !is_valid_handle(&normalized) {
        return Err(OpsError::InvalidGroupHandle {
            handle: original,
            reason: HANDLE_CHARSET_REASON,
        });
    }
    Ok(normalized)
}

const HANDLE_CHARSET_REASON: &str =
    "handle must be 1–64 chars of a–z, 0–9, '-', '_', starting and ending with a letter or digit";

pub(crate) fn primary_handle_for_user<'a>(
    report: &'a ValidationReport,
    user: &UserId,
) -> Option<&'a UserHandleRecordV1> {
    report
        .effective
        .handles
        .values()
        .filter(|record| &record.user_id == user)
        .min_by(|left, right| normalize_handle(&left.handle).cmp(&normalize_handle(&right.handle)))
}

pub(crate) fn primary_vault_handle(report: &ValidationReport) -> Option<&VaultHandleRecordV1> {
    report
        .effective
        .vault_handles
        .values()
        .min_by(|left, right| normalize_handle(&left.handle).cmp(&normalize_handle(&right.handle)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use crate::*;
    use thorax_core::test_support::test_user;

    #[test]
    fn add_user_self_signed_record_becomes_active() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");

        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert!(loaded.effective().users.contains_key(&alice.id));
    }

    #[test]
    fn root_can_grant_permission_and_it_becomes_effective() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();

        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(["app"])),
            IdSeed::from_bytes(b"alice-read".to_vec()),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert!(loaded
            .effective()
            .authority_for_user(&alice.id)
            .can_read(&SecretSelectorV1::tuple(["app", "prod"])));
        assert!(!loaded
            .effective()
            .authority_for_user(&alice.id)
            .can_read(&SecretSelectorV1::tuple(["other"])));
    }

    #[test]
    fn unauthorized_grant_is_rejected_before_write() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let before = record_count(&fixture.paths, &fixture.crypto);

        let error = grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &alice,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::Administer,
            IdSeed::from_bytes(b"bad-admin".to_vec()),
        )
        .unwrap_err();
        let after = record_count(&fixture.paths, &fixture.crypto);

        assert!(matches!(error, OpsError::OperationNotEffective(_)));
        assert_eq!(before, after);
    }

    #[test]
    fn unauthorized_same_key_grant_update_is_rejected_before_write() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            IdSeed::from_bytes(b"shared-grant".to_vec()),
        )
        .unwrap();
        let before = record_count(&fixture.paths, &fixture.crypto);

        let error = grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &alice,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::Administer,
            IdSeed::from_bytes(b"shared-grant".to_vec()),
        )
        .unwrap_err();
        let after = record_count(&fixture.paths, &fixture.crypto);

        assert!(matches!(error, OpsError::OperationNotEffective(_)));
        assert_eq!(before, after);
        let loaded = valid_session(&fixture.paths, &fixture.crypto);
        assert!(!loaded.effective().authority_for_user(&alice.id).administer);
    }

    #[test]
    fn root_can_set_user_handle() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();

        let handle = set_user_handle(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            " Alice ",
            alice.id.clone(),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert_eq!(
            handle,
            derive_user_handle_id(&fixture.crypto, "alice").unwrap()
        );
        assert_eq!(
            loaded
                .effective()
                .handles
                .get(&handle)
                .map(|record| &record.user_id),
            Some(&alice.id)
        );
    }

    #[test]
    fn user_ref_handle_resolves_latest_effective_handle() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        let bob = test_user(&fixture.crypto, "bob");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &bob).unwrap();
        set_user_handle(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            "owner",
            alice.id.clone(),
        )
        .unwrap();
        set_user_handle(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            "owner",
            bob.id.clone(),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        let resolved = resolve_user_ref(
            loaded.report(),
            &fixture.crypto,
            UserRef::Handle("OWNER".into()),
        )
        .unwrap();

        assert_eq!(resolved.user_id, bob.id);
        assert_eq!(resolved.handle.as_deref(), Some("owner"));
    }

    #[test]
    fn moving_handle_does_not_move_user_grants() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        let bob = test_user(&fixture.crypto, "bob");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &bob).unwrap();
        set_user_handle(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            "deploy",
            alice.id.clone(),
        )
        .unwrap();
        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::prefix(["app"])),
            IdSeed::from_bytes(b"alice-app-read".to_vec()),
        )
        .unwrap();
        set_user_handle(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            "deploy",
            bob.id.clone(),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);
        let selector = SecretSelectorV1::tuple(["app", "prod"]);
        let resolved = resolve_user_ref(
            loaded.report(),
            &fixture.crypto,
            UserRef::Handle("deploy".into()),
        )
        .unwrap();

        assert_eq!(resolved.user_id, bob.id);
        assert!(loaded
            .effective()
            .authority_for_user(&alice.id)
            .can_read(&selector));
        assert!(!loaded
            .effective()
            .authority_for_user(&bob.id)
            .can_read(&selector));
    }

    #[test]
    fn root_can_set_vault_handle() {
        let fixture = Fixture::initialized();

        let handle =
            set_vault_handle(&fixture.paths, &fixture.crypto, &fixture.root, " Project ").unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert_eq!(
            handle,
            derive_vault_handle_id(&fixture.crypto, "project").unwrap()
        );
        assert_eq!(
            loaded
                .effective()
                .vault_handles
                .get(&handle)
                .map(|record| &record.handle),
            Some(&"project".to_string())
        );
    }

    #[test]
    fn user_deletion_updates_effective_state_and_raises_the_watermark() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();

        let committed = delete_user(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            alice.id.clone(),
            Some("leaving".to_string()),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert!(committed.effective().deleted_users.contains(&alice.id));
        assert!(!committed.effective().users.contains_key(&alice.id));
        // The deletion raised the watermark at alice's user key, which is what protects it
        // from rollback.
        let alice_key = RecordKey::User {
            user_id: alice.id.clone(),
        };
        assert!(
            loaded
                .ratchet()
                .watermarks
                .get(&alice_key)
                .copied()
                .unwrap_or(0)
                > 0
        );
    }

    #[test]
    fn deleting_a_user_cascades_over_their_grants_and_memberships() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let group = create_group(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            IdSeed::from_bytes(b"ops".to_vec()),
            "Ops",
        )
        .unwrap();
        add_group_member(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            group.clone(),
            PrincipalRefV1::User(alice.id.clone()),
        )
        .unwrap();
        let grant = grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::User(alice.id.clone()),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            IdSeed::from_bytes(b"alice-read".to_vec()),
        )
        .unwrap();

        delete_user(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            alice.id.clone(),
            None,
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);
        assert!(loaded.effective().deleted_users.contains(&alice.id));
        assert!(loaded.effective().deleted_grants.contains(&grant));
        assert!(loaded.effective().memberships.is_empty());

        // Restoring the identity (same keys, fresh counter) brings back the user but none
        // of the cascaded access: the grant and membership were explicitly tombstoned.
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);
        assert!(loaded.effective().users.contains_key(&alice.id));
        assert!(loaded.effective().deleted_grants.contains(&grant));
        assert!(loaded.effective().memberships.is_empty());
        assert!(!loaded
            .effective()
            .authority_for_user(&alice.id)
            .can_read(&SecretSelectorV1::tuple(["app"])));
    }

    #[test]
    fn group_membership_and_group_grant_flow_works() {
        let fixture = Fixture::initialized();
        let alice = test_user(&fixture.crypto, "alice");
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let group = create_group(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            IdSeed::from_bytes(b"ops".to_vec()),
            "Ops",
        )
        .unwrap();
        add_group_member(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            group.clone(),
            PrincipalRefV1::User(alice.id.clone()),
        )
        .unwrap();
        grant_permission(
            &fixture.paths,
            &fixture.crypto,
            &fixture.root,
            PrincipalRefV1::Group(group),
            GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()),
            IdSeed::from_bytes(b"ops-read".to_vec()),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert!(loaded
            .effective()
            .authority_for_user(&alice.id)
            .can_read(&SecretSelectorV1::tuple(["anything"])));
    }

    #[test]
    fn production_root_sets_user_handle_through_keychain() {
        let fixture = ProductionFixture::initialized();
        let alice = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
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

        let handle = set_user_handle_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            " Alice ",
            alice.user_id().clone(),
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);
        let resolved = resolve_user_ref(
            loaded.report(),
            &fixture.crypto,
            UserRef::Handle("alice".into()),
        )
        .unwrap();

        assert_eq!(
            handle,
            derive_user_handle_id(&fixture.crypto, "alice").unwrap()
        );
        assert_eq!(&resolved.user_id, alice.user_id());
    }

    #[test]
    fn non_admin_handle_set_fails_closed_after_unlock() {
        // Unlock-first posture: alice (a member without administer) anchors fine; the
        // operation itself is what fails, before any record is signed.
        let fixture = ProductionFixture::initialized();
        let alice = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let alice_keychain = ManualIdentityKeychain::new(
            FixedIdentityProvider::from_master_seed(&fixture.crypto, alice.master_seed()).unwrap(),
        );

        let error = set_user_handle_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &alice_keychain,
            alice.user_id(),
            "root",
            fixture.root.user_id().clone(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OpsError::AdministerRequired(user) if user == alice.user_id().clone()
        ));
    }

    #[test]
    fn production_root_sets_vault_handle_through_keychain() {
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

        let handle = set_vault_handle_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &keychain,
            fixture.root.user_id(),
            " Project ",
        )
        .unwrap();
        let loaded = valid_session(&fixture.paths, &fixture.crypto);

        assert_eq!(
            handle,
            derive_vault_handle_id(&fixture.crypto, "project").unwrap()
        );
        assert_eq!(
            loaded
                .effective()
                .vault_handles
                .get(&handle)
                .map(|record| &record.handle),
            Some(&"project".to_string())
        );
    }

    #[test]
    fn non_admin_vault_handle_set_fails_closed_after_unlock() {
        let fixture = ProductionFixture::initialized();
        let alice = Identity::generate(&fixture.crypto).unwrap();
        add_user(&fixture.paths, &fixture.crypto, &fixture.root, &alice).unwrap();
        let alice_keychain = ManualIdentityKeychain::new(
            FixedIdentityProvider::from_master_seed(&fixture.crypto, alice.master_seed()).unwrap(),
        );

        let error = set_vault_handle_with_keychain(
            &fixture.paths,
            &fixture.crypto,
            &alice_keychain,
            alice.user_id(),
            "project",
        )
        .unwrap_err();

        assert!(matches!(
            error,
            OpsError::AdministerRequired(user) if user == alice.user_id().clone()
        ));
    }
}
