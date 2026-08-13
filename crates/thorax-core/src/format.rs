use cord::{Cord, Evolving};

pub type Bytes = Vec<u8>;

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HashValue(pub Bytes);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserHandleId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultHandleId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupMemberId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretId(pub HashValue);

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdSeed(pub Bytes);

/// Canonical preimage for a `UserId`: a user's identity commits to *both* of its public
/// keys (signing and HPKE), which both derive deterministically from the master seed. So
/// the id binds the full public keypair — pinning a `UserId` pins both keys, and an HPKE
/// key cannot be swapped without changing the identity. See `derive_user_id`.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct UserIdInputV1 {
    pub signing_public_key: Bytes,
    pub hpke_public_key: Bytes,
}

/// Canonical preimage for a `GroupMemberId`: a membership is content-addressed by the
/// `(group, member)` pair it represents, so "member ∈ group" has one stable id (adding is
/// idempotent and removal resolves against the same key). See `derive_group_member_id`.
/// Also carried in `GroupMemberRatchetRecordV1` as the key's remembered origin.
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupMemberIdInputV1 {
    pub group_id: GroupId,
    pub member_id: PrincipalRefV1,
}

impl IdSeed {
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }
}

/// Versioned envelope for the invite an inviter transfers to a new user out-of-band.
/// Unknown future versions fail closed at decode time.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub enum Invite {
    #[cord(index = 0)]
    V1(InviteV1),
    #[cord(index = 1)]
    V2(InviteV2),
}

/// A self-contained invitation: the recipient identity seed, intended vault root, and the
/// issuer's pre-invite rollback baseline. The user id and public keys derive from the seed.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct InviteV1 {
    pub master_seed: Bytes,
    pub trusted_root: HashValue,
    pub rollback_baseline: RatchetBaselineV1,
}

/// V2 makes the first-sync rollback baseline optional. Compact invitations still pin the vault
/// root and recipient identity, but begin rollback protection from the state observed at claim.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct InviteV2 {
    pub master_seed: Bytes,
    pub trusted_root: HashValue,
    pub rollback_baseline: Option<RatchetBaselineV1>,
}

/// Version-independent invitation data consumed by operations and frontends after decoding.
/// Wire-version branching stops at the codec boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationMaterial {
    pub master_seed: Bytes,
    pub trusted_root: HashValue,
    pub rollback_baseline: Option<RatchetBaselineV1>,
}

impl Invite {
    pub fn into_material(self) -> InvitationMaterial {
        match self {
            Invite::V1(invite) => InvitationMaterial {
                master_seed: invite.master_seed,
                trusted_root: invite.trusted_root,
                rollback_baseline: Some(invite.rollback_baseline),
            },
            Invite::V2(invite) => InvitationMaterial {
                master_seed: invite.master_seed,
                trusted_root: invite.trusted_root,
                rollback_baseline: invite.rollback_baseline,
            },
        }
    }
}

impl InvitationMaterial {
    /// Project normalized material into the current wire format with the requested first-sync
    /// protection. `include_baseline` cannot invent a baseline omitted by an older input.
    pub fn to_v2(&self, include_baseline: bool) -> InviteV2 {
        InviteV2 {
            master_seed: self.master_seed.clone(),
            trusted_root: self.trusted_root.clone(),
            rollback_baseline: include_baseline
                .then(|| self.rollback_baseline.clone())
                .flatten(),
        }
    }

    pub fn has_rollback_baseline(&self) -> bool {
        self.rollback_baseline.is_some()
    }
}

pub const INVITE_MAGIC: &[u8] = b"thorax-invite\0";
pub const MAX_INVITE_BYTES: usize = 257 * 1024 * 1024;

/// A snapshot of the issuer's rollback ratchet when the invite was issued — the first-sync
/// seed of the recipient's own ratchet (mirrors `Ratchet`). When supplied to `claim`,
/// the recipient's first sync starts from this instead of empty, so a vault rolled back past
/// the issuer's view — a lowered Lamport counter at any remembered object — is rejected
/// (`ClaimRolledBack`).
///
/// Unsigned: it is trusted because it is embedded in the invitation that already carries the
/// recipient's `master_seed` and intended root.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct RatchetBaselineV1 {
    pub records: Vec<RatchetRecordV1>,
}

// One watermark-bearing ratchet record per object kind: it carries the highest verified
// Lamport counter (the *watermark*) observed for the object named by `id`. Ids are
// content-derived (a secret id derives from its whole selector, a membership id from its
// (group, member) pair, a user id from its keys, …), so the id alone names the object; the
// only extra scope is the trusted root, which scopes the state file that holds these records.
// Every deletion is LWW, so the watermark is the entire rollback defense: a deletion (or any
// newer write) raises the counter, and a vault later showing a lower effective counter at a
// remembered id has been rolled back.
//
// Kinds whose id preimage is human-meaningful also carry it (the secret's selector, a handle's
// string, a membership's (group, member) pair), so a key whose records were erased entirely
// can still be *named* to the user. The preimage is advisory display data — never part of
// the ratchet comparison — and an empty value means "not remembered" (older state); display
// falls back to the short id. Seed-derived ids (groups, grants) and key-derived ids (users)
// have opaque preimages and carry none.
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserRatchetRecordV1 {
    pub id: UserId,
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UserHandleRatchetRecordV1 {
    pub id: UserHandleId,
    pub counter: u64,
    pub handle: String,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultHandleRatchetRecordV1 {
    pub id: VaultHandleId,
    pub counter: u64,
    pub handle: String,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupRatchetRecordV1 {
    pub id: GroupId,
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GroupMemberRatchetRecordV1 {
    pub id: GroupMemberId,
    pub counter: u64,
    pub membership: Option<GroupMemberIdInputV1>,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantRatchetRecordV1 {
    pub id: GrantId,
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretRatchetRecordV1 {
    pub id: SecretId,
    pub counter: u64,
    /// The secret's selector (tuple + labels) — the id's preimage, remembered so a key can
    /// be named even after a rollback erases every record at it. An empty-tuple selector
    /// means "not remembered". Labels are part of identity, so they belong here too.
    pub selector: SecretSelectorV1,
}

/// The entry-point watermark is keyed by the pinning user: an entry point's identity is its
/// signer (the record body carries no id), and within one trusted root — the scope of the
/// state file — the pinned root is constant.
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryPointRatchetRecordV1 {
    pub id: UserId,
    pub counter: u64,
}

/// The typed ratchet records persisted in a state file. The first eight variants are
/// *watermark* records — one per LWW-resolved object kind, each carrying the highest verified
/// Lamport counter for the object its `id` names. The last two (`FormatVersion`, `TrustedRoot`)
/// are not watermarks: they bind the envelope version and the file's scope respectively, and
/// carry no per-object counter. The signed `VaultRoot` record has no ratchet record of any
/// kind — it is the trust anchor itself and cannot be deleted.
#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RatchetRecordV1 {
    #[cord(index = 0)]
    User(UserRatchetRecordV1),
    #[cord(index = 1)]
    UserHandle(UserHandleRatchetRecordV1),
    #[cord(index = 2)]
    VaultHandle(VaultHandleRatchetRecordV1),
    #[cord(index = 3)]
    Group(GroupRatchetRecordV1),
    #[cord(index = 4)]
    GroupMember(GroupMemberRatchetRecordV1),
    #[cord(index = 5)]
    Grant(GrantRatchetRecordV1),
    #[cord(index = 6)]
    Secret(SecretRatchetRecordV1),
    #[cord(index = 7)]
    EntryPoint(EntryPointRatchetRecordV1),
    /// The highest vault *format version* (top-level `VaultStore` variant) this machine has
    /// verified under this trusted root. Not keyed by a record: it guards the envelope
    /// itself. A vault presenting a lower version than remembered is a regression — the
    /// downgrade analogue of a rollback (someone re-wrapped a newer vault's records in an
    /// older envelope, shedding the newer semantics) — and fails validation closed.
    #[cord(index = 8)]
    FormatVersion(FormatVersionRatchetRecordV1),
    /// The trusted root this state file is scoped to. Not keyed by a record and not a
    /// ratchet: it is the file's self-describing scope, the one fact every state file must
    /// carry exactly once. It lives in the record set (rather than as a sibling struct
    /// field) so the state file's shape matches the vault and keychain — a version enum over
    /// a single `records` set. Read-back checks it equals the root the path was resolved
    /// under (`TrustRootMismatch`), catching a misplaced/restored file.
    #[cord(index = 9)]
    TrustedRoot(TrustedRootRatchetRecordV1),
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FormatVersionRatchetRecordV1 {
    pub version: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustedRootRatchetRecordV1 {
    pub trusted_root: HashValue,
}

impl RatchetRecordV1 {
    /// The typed watermark fact for a counter observed at `key`, or `None` for the one
    /// non-watermarked key (`VaultRoot`). `origin` is the key's remembered id preimage
    /// where one is meaningful (see [`crate::ratchet::KeyOrigin`]); a missing or mismatched
    /// origin encodes as the empty sentinel, and display falls back to the short id.
    pub fn for_key(
        key: &RecordKey,
        counter: u64,
        origin: Option<&crate::ratchet::KeyOrigin>,
    ) -> Option<Self> {
        use crate::ratchet::KeyOrigin;
        Some(match key {
            RecordKey::VaultRoot => return None,
            RecordKey::EntryPoint { user_id } => {
                RatchetRecordV1::EntryPoint(EntryPointRatchetRecordV1 {
                    id: user_id.clone(),
                    counter,
                })
            }
            RecordKey::User { user_id } => RatchetRecordV1::User(UserRatchetRecordV1 {
                id: user_id.clone(),
                counter,
            }),
            RecordKey::UserHandle { handle_id } => {
                RatchetRecordV1::UserHandle(UserHandleRatchetRecordV1 {
                    id: handle_id.clone(),
                    counter,
                    handle: match origin {
                        Some(KeyOrigin::UserHandle(handle)) => handle.clone(),
                        _ => String::new(),
                    },
                })
            }
            RecordKey::VaultHandle { handle_id } => {
                RatchetRecordV1::VaultHandle(VaultHandleRatchetRecordV1 {
                    id: handle_id.clone(),
                    counter,
                    handle: match origin {
                        Some(KeyOrigin::VaultHandle(handle)) => handle.clone(),
                        _ => String::new(),
                    },
                })
            }
            RecordKey::Group { group_id } => RatchetRecordV1::Group(GroupRatchetRecordV1 {
                id: group_id.clone(),
                counter,
            }),
            RecordKey::GroupMember { group_member_id } => {
                RatchetRecordV1::GroupMember(GroupMemberRatchetRecordV1 {
                    id: group_member_id.clone(),
                    counter,
                    membership: match origin {
                        Some(KeyOrigin::GroupMember {
                            group_id,
                            member_id,
                        }) => Some(GroupMemberIdInputV1 {
                            group_id: group_id.clone(),
                            member_id: member_id.clone(),
                        }),
                        _ => None,
                    },
                })
            }
            RecordKey::Grant { grant_id } => RatchetRecordV1::Grant(GrantRatchetRecordV1 {
                id: grant_id.clone(),
                counter,
            }),
            RecordKey::Secret { secret_id } => RatchetRecordV1::Secret(SecretRatchetRecordV1 {
                id: secret_id.clone(),
                counter,
                selector: match origin {
                    Some(KeyOrigin::Secret(selector)) => selector.clone(),
                    _ => SecretSelectorV1::tuple(Vec::<String>::new()),
                },
            }),
        })
    }

    /// The remembered id preimage carried by this fact, if any — `None` for kinds without
    /// one and for the empty "not remembered" sentinel.
    pub fn origin(&self) -> Option<crate::ratchet::KeyOrigin> {
        use crate::ratchet::KeyOrigin;
        match self {
            RatchetRecordV1::UserHandle(w) if !w.handle.is_empty() => {
                Some(KeyOrigin::UserHandle(w.handle.clone()))
            }
            RatchetRecordV1::VaultHandle(w) if !w.handle.is_empty() => {
                Some(KeyOrigin::VaultHandle(w.handle.clone()))
            }
            RatchetRecordV1::GroupMember(w) => {
                w.membership
                    .as_ref()
                    .map(|membership| KeyOrigin::GroupMember {
                        group_id: membership.group_id.clone(),
                        member_id: membership.member_id.clone(),
                    })
            }
            RatchetRecordV1::Secret(w) if !w.selector.tuple.is_empty() => {
                Some(KeyOrigin::Secret(w.selector.clone()))
            }
            _ => None,
        }
    }

    /// The record key this watermark guards — the inverse of [`RatchetRecordV1::for_key`].
    /// `None` for the one un-keyed fact ([`RatchetRecordV1::FormatVersion`], which guards the
    /// vault envelope rather than a record).
    pub fn key(&self) -> Option<RecordKey> {
        Some(match self {
            RatchetRecordV1::FormatVersion(_) | RatchetRecordV1::TrustedRoot(_) => return None,
            RatchetRecordV1::User(w) => RecordKey::User {
                user_id: w.id.clone(),
            },
            RatchetRecordV1::UserHandle(w) => RecordKey::UserHandle {
                handle_id: w.id.clone(),
            },
            RatchetRecordV1::VaultHandle(w) => RecordKey::VaultHandle {
                handle_id: w.id.clone(),
            },
            RatchetRecordV1::Group(w) => RecordKey::Group {
                group_id: w.id.clone(),
            },
            RatchetRecordV1::GroupMember(w) => RecordKey::GroupMember {
                group_member_id: w.id.clone(),
            },
            RatchetRecordV1::Grant(w) => RecordKey::Grant {
                grant_id: w.id.clone(),
            },
            RatchetRecordV1::Secret(w) => RecordKey::Secret {
                secret_id: w.id.clone(),
            },
            RatchetRecordV1::EntryPoint(w) => RecordKey::EntryPoint {
                user_id: w.id.clone(),
            },
        })
    }

    /// The monotone value this fact ratchets: the Lamport counter for keyed facts, the
    /// envelope version for [`RatchetRecordV1::FormatVersion`].
    pub fn counter(&self) -> u64 {
        match self {
            RatchetRecordV1::User(w) => w.counter,
            RatchetRecordV1::UserHandle(w) => w.counter,
            RatchetRecordV1::VaultHandle(w) => w.counter,
            RatchetRecordV1::Group(w) => w.counter,
            RatchetRecordV1::GroupMember(w) => w.counter,
            RatchetRecordV1::Grant(w) => w.counter,
            RatchetRecordV1::Secret(w) => w.counter,
            RatchetRecordV1::EntryPoint(w) => w.counter,
            RatchetRecordV1::FormatVersion(w) => w.version,
            // Not a ratchet — the trusted root is a fixed scope, not a monotone counter.
            RatchetRecordV1::TrustedRoot(_) => 0,
        }
    }
}

/// The vault's versioned envelope. The variant index **is** the format's criticality
/// scheme: anything that would change what an older reader should compute — authority,
/// admission, confidentiality semantics — must be a new top-level variant (a deliberate
/// flag-day for every member), while additions *within* a variant must be advisory and are
/// carried through inert by older readers. Old binaries fail closed on an unknown variant
/// at decode, which is exactly the intended brick. Each machine ratchets the highest version
/// it has verified per trusted root
/// (`Ratchet::format_version`), so re-wrapping a newer vault's records in an older
/// envelope is a detected regression, not a silent downgrade.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub enum VaultStore {
    #[cord(index = 0)]
    V1(VaultStoreV1),
}

impl VaultStore {
    /// The envelope's format version (variant index + 1) — the value the per-root
    /// `Ratchet::format_version` ratchet remembers and checks.
    pub fn format_version(&self) -> u64 {
        match self {
            VaultStore::V1(_) => 1,
        }
    }
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct VaultStoreV1 {
    /// A `cord::Set`, not a `Vec`: the vault is a *set* of distinct signed records, and the
    /// merge is a set-union over its branches. cord canonicalizes on write (sorts strictly
    /// ascending by record bytes, rejects duplicates) and rejects non-canonical input on
    /// read, so the file's bytes are deterministic regardless of write order — two machines
    /// that wrote the same records in any order produce byte-identical vaults. LWW ordering
    /// is by each record's Lamport counter, derived at validation, never by file position.
    pub records: cord::Set<VaultRecordV1>,
}

/// The record envelope is deliberately *variant-free*: beyond the `Evolving`-wrapped body
/// it carries only raw bytes — the public key the signature verifies under, and the
/// signature itself — so no future addition can make a V1 record envelope undecodable.
/// The signature scheme is fixed per major version (V1 = Ed25519); a new scheme is a
/// `VaultStore::V2` event, because a record old readers cannot verify is a record they cannot
/// see (an unverifiable tombstone is an invisible tombstone).
///
/// The key is a *lookup hint*, not an identity claim: it counts only once the
/// introduction fixpoint binds it to exactly one effective user (the signing-key-
/// uniqueness invariant), so a record can never attest its own signer.
#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct VaultRecordV1 {
    #[cord(evolving = 32)]
    pub body: Evolving<RecordBodyV1>,
    pub signing_public_key: Bytes,
    pub signature: Bytes,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RecordBodyV1 {
    #[cord(index = 0)]
    VaultRoot(VaultRootRecordV1),
    #[cord(index = 1)]
    EntryPoint(EntryPointRecordV1),
    #[cord(index = 2)]
    User(UserRecordV1),
    #[cord(index = 3)]
    UserHandle(UserHandleRecordV1),
    #[cord(index = 4)]
    Group(GroupRecordV1),
    #[cord(index = 5)]
    GroupDeleted(GroupDeletedRecordV1),
    #[cord(index = 6)]
    GroupMember(GroupMemberRecordV1),
    #[cord(index = 7)]
    GroupMemberDeleted(GroupMemberDeletedRecordV1),
    #[cord(index = 8)]
    Grant(GrantRecordV1),
    #[cord(index = 9)]
    GrantDeleted(GrantDeletedRecordV1),
    #[cord(index = 10)]
    UserDeleted(UserDeletedRecordV1),
    #[cord(index = 11)]
    Secret(SecretRecordV1),
    #[cord(index = 12)]
    SecretDeleted(SecretDeletedRecordV1),
    #[cord(index = 13)]
    VaultHandle(VaultHandleRecordV1),
}

impl RecordBodyV1 {
    /// The last-writer-wins ordering counter, or `None` for the one record kind that is
    /// never resolved by counter (`VaultRoot`, the singleton trust anchor). This is the
    /// single, exhaustive decision point: every removal is an LWW tombstone that competes
    /// with the add/update records at the same key, and every counter feeds the per-object
    /// watermark ratchet.
    pub fn lww_counter(&self) -> Option<u64> {
        match self {
            RecordBodyV1::EntryPoint(r) => Some(r.counter),
            RecordBodyV1::User(r) => Some(r.counter),
            RecordBodyV1::UserDeleted(r) => Some(r.counter),
            RecordBodyV1::UserHandle(r) => Some(r.counter),
            RecordBodyV1::VaultHandle(r) => Some(r.counter),
            RecordBodyV1::Group(r) => Some(r.counter),
            RecordBodyV1::GroupDeleted(r) => Some(r.counter),
            RecordBodyV1::GroupMember(r) => Some(r.counter),
            RecordBodyV1::GroupMemberDeleted(r) => Some(r.counter),
            RecordBodyV1::Grant(r) => Some(r.counter),
            RecordBodyV1::GrantDeleted(r) => Some(r.counter),
            RecordBodyV1::Secret(r) => Some(r.counter),
            RecordBodyV1::SecretDeleted(r) => Some(r.counter),
            RecordBodyV1::VaultRoot(_) => None,
        }
    }

    /// The same body re-stamped with a fresh LWW counter, or `None` for the one counterless
    /// kind (`VaultRoot`). This is the conflict-resolution bump: re-signing a tied record's
    /// body at one above the global counter maximum makes the chosen winner explicit.
    pub fn with_lww_counter(&self, counter: u64) -> Option<Self> {
        let mut body = self.clone();
        match &mut body {
            RecordBodyV1::EntryPoint(r) => r.counter = counter,
            RecordBodyV1::User(r) => r.counter = counter,
            RecordBodyV1::UserDeleted(r) => r.counter = counter,
            RecordBodyV1::UserHandle(r) => r.counter = counter,
            RecordBodyV1::VaultHandle(r) => r.counter = counter,
            RecordBodyV1::Group(r) => r.counter = counter,
            RecordBodyV1::GroupDeleted(r) => r.counter = counter,
            RecordBodyV1::GroupMember(r) => r.counter = counter,
            RecordBodyV1::GroupMemberDeleted(r) => r.counter = counter,
            RecordBodyV1::Grant(r) => r.counter = counter,
            RecordBodyV1::GrantDeleted(r) => r.counter = counter,
            RecordBodyV1::Secret(r) => r.counter = counter,
            RecordBodyV1::SecretDeleted(r) => r.counter = counter,
            RecordBodyV1::VaultRoot(_) => return None,
        }
        Some(body)
    }

    /// Whether this body is one of the deletion tombstones — the LWW competitor that, when
    /// it wins at its key, makes the object absent.
    pub fn is_deletion(&self) -> bool {
        matches!(
            self,
            RecordBodyV1::UserDeleted(_)
                | RecordBodyV1::GroupDeleted(_)
                | RecordBodyV1::GroupMemberDeleted(_)
                | RecordBodyV1::GrantDeleted(_)
                | RecordBodyV1::SecretDeleted(_)
        )
    }
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrincipalRefV1 {
    #[cord(index = 0)]
    User(UserId),
    #[cord(index = 1)]
    Group(GroupId),
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordKey {
    #[cord(index = 0)]
    VaultRoot,
    /// An entry point's identity is its signer; the pinned root needs no spot in the key
    /// because validation only admits entry points pinning the selected root.
    #[cord(index = 1)]
    EntryPoint { user_id: UserId },
    #[cord(index = 2)]
    User { user_id: UserId },
    #[cord(index = 3)]
    UserHandle { handle_id: UserHandleId },
    #[cord(index = 4)]
    Group { group_id: GroupId },
    #[cord(index = 5)]
    GroupMember { group_member_id: GroupMemberId },
    #[cord(index = 6)]
    Grant { grant_id: GrantId },
    #[cord(index = 7)]
    Secret { secret_id: SecretId },
    #[cord(index = 8)]
    VaultHandle { handle_id: VaultHandleId },
}

// Each record carries its own identity in an `id` field (its kind is given by the enclosing
// `RecordBodyV1` variant). For derived ids (`Group`/`GroupMember`/`Grant` from `seed`, `Secret`
// from `selector`, the handle records from `handle`, `User`/`VaultRoot` from their keys) the `id`
// is stored *and* re-verified at validation. `EntryPoint` is the sole exception: it has no `id`
// because its identity is the envelope signer (`VaultRecordV1.signer_id`).
#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct VaultRootRecordV1 {
    // Self-signed: the root's signing key is the envelope's `signing_public_key`, so it is not
    // duplicated here; the body carries only the HPKE half. id = H(envelope.signing ‖ hpke).
    pub id: UserId,
    pub hpke_public_key: Bytes,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct EntryPointRecordV1 {
    /// The root this user pins. A `UserId` commits to *both* root public keys (see
    /// `derive_user_id`), so this single field is the complete substitution-defense pin.
    /// The pinning user is the record's signer (`VaultRecordV1.signing_public_key`).
    pub trusted_root_user_id: UserId,
    /// The pinning user's HPKE public key — the second half of the identity this self-signed
    /// record vouches for. The signing half is the envelope's `signing_public_key` (the entry
    /// point is signed under it), so it is not duplicated here. Together they prove possession
    /// of the *full* identity `UserId = hash(signing, hpke)`: only the signing key's holder can
    /// sign an entry point, and it declares the HPKE key paired with it — which is what lets
    /// signer resolution refuse a `User` record asserting a real signing key paired with a
    /// forged HPKE key (no attacker can sign the matching entry point). See
    /// `validate::pipeline`'s attestation gate.
    pub hpke_public_key: Bytes,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

/// Introduces (or restores) a member: admin-signed, and resolved by LWW against
/// `UserDeleted` at the same key. The id still commits to both public keys, so a deleted
/// user re-added with the same keys is the same identity, restored.
#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserRecordV1 {
    pub id: UserId,
    pub signing_public_key: Bytes,
    pub hpke_public_key: Bytes,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserHandleRecordV1 {
    pub id: UserHandleId,
    pub handle: String,
    pub user_id: UserId,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct VaultHandleRecordV1 {
    // The vault handle names *this* vault; there is one vault (one root) per validation
    // context, so unlike a user handle it needs no subject pointer — the root is implicit.
    pub id: VaultHandleId,
    pub handle: String,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupRecordV1 {
    pub id: GroupId,
    pub seed: IdSeed,
    pub handle: String,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupDeletedRecordV1 {
    pub id: GroupId,
    /// Lamport ordering counter — LWW against the `Group` record at the same key.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupMemberRecordV1 {
    /// Content-addressed: `id = derive_group_member_id(group_id, member_id)`, so the membership
    /// "member ∈ group" has one stable id. Adding is idempotent; removal (`GroupMemberDeleted`)
    /// resolves against this same key by LWW counter.
    pub id: GroupMemberId,
    pub group_id: GroupId,
    pub member_id: PrincipalRefV1,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GroupMemberDeletedRecordV1 {
    pub id: GroupMemberId,
    pub group_id: GroupId,
    pub member_id: PrincipalRefV1,
    /// Lamport ordering counter — LWW against the `GroupMember` add at the same key.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantRecordV1 {
    pub id: GrantId,
    pub seed: IdSeed,
    pub subject_id: PrincipalRefV1,
    pub permission: GrantPermissionV1,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

/// Deletes a grant. Carries the deleted grant's `permission` so authority gating can hold
/// the deleter to the same bar as the granter: the signer must be able to create both the
/// stated permission and the live grant's permission (a weaker manager cannot delete a
/// stronger grant).
#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GrantDeletedRecordV1 {
    pub id: GrantId,
    pub permission: GrantPermissionV1,
    /// Lamport ordering counter — LWW against the `Grant` record at the same key.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserDeletedRecordV1 {
    pub id: UserId,
    pub reason: Option<String>,
    /// Lamport ordering counter — LWW against the `User` record at the same key.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretRecordV1 {
    pub id: SecretId,
    pub selector: SecretSelectorV1,
    pub sealed: SealedPayloadV1,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretDeletedRecordV1 {
    pub id: SecretId,
    pub selector: SecretSelectorV1,
    /// Lamport ordering counter for LWW resolution.
    pub counter: u64,
}

/// The sealed bytes of a secret value. V1 commits the whole vault to a single ciphersuite
/// (ChaCha20-Poly1305 content AEAD + X25519-HKDF-SHA256 HPKE for content-key wrapping) and
/// to opaque-bytes plaintext: there is no per-record scheme tag or content-type. Crypto
/// agility is a top-level `VaultStore` format-version flag-day, not a per-secret choice; how
/// an opened value is rendered (text vs hex) is decided by the reader from the bytes, not
/// recorded here.
#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SealedPayloadV1 {
    pub nonce: Bytes,
    pub ciphertext: Bytes,
    pub recipient_slots: Vec<RecipientSlotV1>,
}

/// The plaintext sealed inside a secret's ciphertext. `primary` is the secret's value, byte
/// for byte what it has always been; `fields` carries zero or more *additional* key→value
/// pairs. This is **not** a stored record — it is the structure of the bytes inside
/// [`SealedPayloadV1::ciphertext`], so the additional pairs share the secret's content key,
/// nonce, recipient slots, counter, and AAD binding: they are encrypted to exactly the
/// secret's current readers, and both their names and values are confidential. A legacy value
/// sealed before this envelope existed decodes as `{ primary = all bytes, fields = empty }`,
/// so no migration is required.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
pub struct SecretValueV1 {
    pub primary: Bytes,
    /// Additional pairs as a canonical `Set` (cord sorts and de-duplicates on encode). Keys are
    /// unique by construction at the write boundary; the set is the on-wire backstop.
    pub fields: cord::Set<SecretFieldEntryV1>,
}

/// One additional key→value pair inside a [`SecretValueV1`].
#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretFieldEntryV1 {
    pub key: String,
    pub value: Bytes,
}

impl SecretValueV1 {
    /// A value with just a primary and no additional fields — the common write.
    pub fn from_primary(primary: impl Into<Bytes>) -> Self {
        Self {
            primary: primary.into(),
            fields: Vec::new().into(),
        }
    }
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecipientSlotV1 {
    /// The reader this slot wraps the content key for. A `UserId` is `H(signing‖hpke)`, so it
    /// already commits to the recipient's HPKE key — there is no separate key hash. A slot
    /// wrapped to the wrong key simply fails to open (HPKE unwrap), and `classify_secret_for_user`
    /// reports decryptability by matching this id against the reader set.
    pub recipient_id: UserId,
    pub hpke_encapsulated_key: Bytes,
    pub wrapped_content_key: Bytes,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretSelectorV1 {
    pub tuple: Vec<String>,
    pub labels: Vec<SecretLabelV1>,
}

impl SecretSelectorV1 {
    pub fn tuple(parts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tuple: parts.into_iter().map(Into::into).collect(),
            labels: Vec::new(),
        }
    }
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyspaceSelectorV1 {
    pub tuple: TupleMatcherV1,
    pub labels: Vec<KeyspaceLabelMatcherV1>,
}

impl KeyspaceSelectorV1 {
    pub fn all() -> Self {
        Self {
            tuple: TupleMatcherV1::Any,
            labels: Vec::new(),
        }
    }

    pub fn exact(parts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            tuple: TupleMatcherV1::Exact(parts.into_iter().map(Into::into).collect()),
            labels: Vec::new(),
        }
    }

    pub fn prefix(parts: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let parts = parts.into_iter().map(Into::into).collect::<Vec<_>>();
        if parts.is_empty() {
            Self::all()
        } else {
            Self {
                tuple: TupleMatcherV1::Prefix(parts),
                labels: Vec::new(),
            }
        }
    }
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretLabelV1 {
    pub key: String,
    pub value: String,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyspaceLabelMatcherV1 {
    pub key: String,
    pub matcher: LabelMatcherV1,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TupleMatcherV1 {
    #[cord(index = 0)]
    Any,
    #[cord(index = 1)]
    Exact(Vec<String>),
    #[cord(index = 2)]
    Prefix(Vec<String>),
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LabelMatcherV1 {
    #[cord(index = 0)]
    Any,
    #[cord(index = 1)]
    Equals(String),
    #[cord(index = 2)]
    In(Vec<String>),
    #[cord(index = 3)]
    Absent,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub enum GrantPermissionV1 {
    #[cord(index = 0)]
    ReadKeyspace(KeyspaceSelectorV1),
    #[cord(index = 1)]
    WriteKeyspace(KeyspaceSelectorV1),
    #[cord(index = 2)]
    ManageKeyspace(ManageKeyspaceGrantV1),
    #[cord(index = 3)]
    Administer,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, Hash)]
pub struct ManageKeyspaceGrantV1 {
    pub selector: KeyspaceSelectorV1,
    pub grantable: Vec<KeyspaceGrantClassV1>,
}

#[derive(Cord, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyspaceGrantClassV1 {
    #[cord(index = 0)]
    Read,
    #[cord(index = 1)]
    Write,
    #[cord(index = 2)]
    Manage,
}
