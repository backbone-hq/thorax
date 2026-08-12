//! `thorax vault cat` — decode a vault.cord and render a semantic, LWW-aware,
//! deterministic text representation suitable for git's `textconv` diff driver.
//!
//! The output resolves user IDs to `@handle` and group IDs to `%groupname` where
//! the vault contains handle records, falling back to truncated hex. Secrets that
//! have been rotated (multiple records at the same key) are surfaced by their
//! version counter. Tombstoned (deleted / revoked) entities are omitted.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::path::Path;

use thorax_frontend::FrontendError;
use thorax_ops::*;

// ── Group key ──

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum GroupKey {
    VaultRoot,
    EntryPoint(UserId),
    User(UserId),
    UserHandle(UserHandleId),
    VaultHandle(VaultHandleId),
    Group(GroupId),
    GroupMember(GroupMemberId),
    Grant(GrantId),
    Secret(SecretId),
}

// ── Effective record ──

#[allow(dead_code)]
enum EffectiveRecord {
    Active(RecordBodyV1),
    Deleted(RecordBodyV1),
}

// ── Lookup maps ──

struct VaultContext {
    handle_of_user: HashMap<Vec<u8>, String>,
    name_of_group: HashMap<Vec<u8>, String>,
    deleted_users: HashSet<Vec<u8>>,
}

// ── Record classification ──

fn classify_record(body: &RecordBodyV1) -> Option<(GroupKey, u64)> {
    match body {
        RecordBodyV1::VaultRoot(_) => Some((GroupKey::VaultRoot, 0)),
        RecordBodyV1::EntryPoint(r) => Some((
            GroupKey::EntryPoint(r.trusted_root_user_id.clone()),
            r.counter,
        )),
        RecordBodyV1::User(r) => Some((GroupKey::User(r.id.clone()), r.counter)),
        RecordBodyV1::UserDeleted(r) => Some((GroupKey::User(r.id.clone()), r.counter)),
        RecordBodyV1::UserHandle(r) => Some((GroupKey::UserHandle(r.id.clone()), r.counter)),
        RecordBodyV1::VaultHandle(r) => Some((GroupKey::VaultHandle(r.id.clone()), r.counter)),
        RecordBodyV1::Group(r) => Some((GroupKey::Group(r.id.clone()), r.counter)),
        RecordBodyV1::GroupDeleted(r) => Some((GroupKey::Group(r.id.clone()), r.counter)),
        RecordBodyV1::GroupMember(r) => Some((GroupKey::GroupMember(r.id.clone()), r.counter)),
        RecordBodyV1::GroupMemberDeleted(r) => {
            Some((GroupKey::GroupMember(r.id.clone()), r.counter))
        }
        RecordBodyV1::Grant(r) => Some((GroupKey::Grant(r.id.clone()), r.counter)),
        RecordBodyV1::GrantDeleted(r) => Some((GroupKey::Grant(r.id.clone()), r.counter)),
        RecordBodyV1::Secret(r) => Some((GroupKey::Secret(r.id.clone()), r.counter)),
        RecordBodyV1::SecretDeleted(r) => Some((GroupKey::Secret(r.id.clone()), r.counter)),
    }
}

fn is_deletion(body: &RecordBodyV1) -> bool {
    matches!(
        body,
        RecordBodyV1::UserDeleted(_)
            | RecordBodyV1::GroupDeleted(_)
            | RecordBodyV1::GroupMemberDeleted(_)
            | RecordBodyV1::GrantDeleted(_)
            | RecordBodyV1::SecretDeleted(_)
    )
}

fn record_type_priority(body: &RecordBodyV1) -> u8 {
    match body {
        RecordBodyV1::VaultRoot(_) => 0,
        RecordBodyV1::EntryPoint(_) => 1,
        RecordBodyV1::User(_) | RecordBodyV1::UserDeleted(_) => 2,
        RecordBodyV1::UserHandle(_) => 3,
        RecordBodyV1::VaultHandle(_) => 4,
        RecordBodyV1::Secret(_) | RecordBodyV1::SecretDeleted(_) => 5,
        RecordBodyV1::Grant(_) | RecordBodyV1::GrantDeleted(_) => 6,
        RecordBodyV1::Group(_) | RecordBodyV1::GroupDeleted(_) => 7,
        RecordBodyV1::GroupMember(_) | RecordBodyV1::GroupMemberDeleted(_) => 8,
    }
}

// ── Display helpers ──

fn hex_prefix(bytes: &[u8], len: usize) -> String {
    let len = len.min(bytes.len());
    bytes[..len].iter().map(|x| format!("{x:02x}")).collect()
}

fn userid_hex(id: &UserId) -> String {
    hex_prefix(&id.0 .0, 16)
}

fn userid_display(id: &UserId, ctx: &VaultContext) -> String {
    let key = id.0 .0.to_vec();
    match ctx.handle_of_user.get(&key) {
        Some(handle) => format!("@{handle}"),
        None => userid_hex(id),
    }
}

fn principal_display(p: &PrincipalRefV1, ctx: &VaultContext) -> String {
    match p {
        PrincipalRefV1::User(id) => userid_display(id, ctx),
        PrincipalRefV1::Group(id) => {
            let key = id.0 .0.to_vec();
            match ctx.name_of_group.get(&key) {
                Some(name) => format!("%{name}"),
                None => format!("%{}", hex_prefix(&id.0 .0, 8)),
            }
        }
    }
}

fn format_recipients(slots: &[RecipientSlotV1], ctx: &VaultContext) -> String {
    if slots.is_empty() {
        return "[]".to_string();
    }
    let labels: Vec<String> = slots
        .iter()
        .map(|s| userid_display(&s.recipient_id, ctx))
        .collect();
    format!("[{}]", labels.join(" "))
}

fn format_permission(p: &GrantPermissionV1) -> &'static str {
    match p {
        GrantPermissionV1::ReadKeyspace(_) => "read",
        GrantPermissionV1::WriteKeyspace(_) => "write",
        GrantPermissionV1::ManageKeyspace(_) => "manage",
        GrantPermissionV1::Administer => "administer",
    }
}

// ── Build VaultContext from grouped records ──

fn build_vault_context(groups: &BTreeMap<GroupKey, Vec<&RecordBodyV1>>) -> VaultContext {
    let mut per_user: HashMap<Vec<u8>, (String, u64)> = HashMap::new();
    let mut name_of_group: HashMap<Vec<u8>, String> = HashMap::new();
    let mut deleted_users: HashSet<Vec<u8>> = HashSet::new();

    for (key, records) in groups {
        match key {
            GroupKey::User(_) => {
                // The LWW winner tells us whether the user is currently active or deleted.
                let winner = *records
                    .iter()
                    .max_by_key(|b| classify_record(b).map(|(_, c)| c))
                    .unwrap();
                if is_deletion(winner) {
                    if let RecordBodyV1::UserDeleted(r) = winner {
                        deleted_users.insert(r.id.0 .0.to_vec());
                    }
                }
            }
            GroupKey::UserHandle(_) => {
                for body in records {
                    if let RecordBodyV1::UserHandle(r) = body {
                        if deleted_users.contains(&r.user_id.0 .0.to_vec()) {
                            continue;
                        }
                        let uk = r.user_id.0 .0.to_vec();
                        let e = per_user.entry(uk);
                        match e {
                            std::collections::hash_map::Entry::Occupied(mut o) => {
                                if r.counter > o.get().1 {
                                    o.insert((r.handle.clone(), r.counter));
                                }
                            }
                            std::collections::hash_map::Entry::Vacant(v) => {
                                v.insert((r.handle.clone(), r.counter));
                            }
                        }
                    }
                }
            }
            GroupKey::Group(gid) => {
                for body in records {
                    if let RecordBodyV1::Group(r) = body {
                        name_of_group
                            .entry(gid.0 .0.to_vec())
                            .or_insert_with(|| r.handle.clone());
                    }
                }
            }
            _ => {}
        }
    }

    VaultContext {
        handle_of_user: per_user.into_iter().map(|(k, (h, _))| (k, h)).collect(),
        name_of_group,
        deleted_users,
    }
}

// ── Decrypt map ──

fn build_decrypt_map(
    crypto: &Crypto,
    session: &UnlockedSession,
) -> HashMap<SecretId, SecretPlaintext> {
    let mut map = HashMap::new();
    for active in session.effective().secret_records() {
        let sel = active.value.selector.clone();
        if let Ok(pt) = session.get_secret(crypto, sel) {
            map.insert(active.value.id.clone(), pt);
        }
    }
    map
}

// ── Rendering ──

fn render_effective(
    effective: &EffectiveRecord,
    ctx: &VaultContext,
    plaintext: Option<&SecretPlaintext>,
) -> String {
    let (body, tombstone) = match effective {
        EffectiveRecord::Active(b) => (b, false),
        EffectiveRecord::Deleted(b) => (b, true),
    };

    let mut out = String::new();
    match body {
        RecordBodyV1::VaultRoot(r) => {
            writeln!(out, "vault-root").ok();
            writeln!(out, "  root: {}", userid_display(&r.id, ctx)).ok();
            writeln!(out, "  hpke: {}", hex_prefix(&r.hpke_public_key, 16)).ok();
        }
        RecordBodyV1::EntryPoint(r) => {
            writeln!(
                out,
                "entry-point {}",
                userid_display(&r.trusted_root_user_id, ctx)
            )
            .ok();
            writeln!(out, "  hpke: {}", hex_prefix(&r.hpke_public_key, 16)).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::User(r) => {
            write!(out, "user {}", userid_display(&r.id, ctx)).ok();
            if tombstone {
                write!(out, " (deleted)").ok();
            }
            writeln!(out).ok();
            writeln!(out, "  signing: {}", hex_prefix(&r.signing_public_key, 8)).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::UserDeleted(r) => {
            writeln!(out, "user {} (deleted)", userid_display(&r.id, ctx)).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::UserHandle(r) => {
            writeln!(
                out,
                "user-handle {}: {} -> \"{}\"",
                hex_prefix(&r.id.0 .0, 8),
                userid_display(&r.user_id, ctx),
                r.handle
            )
            .ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::VaultHandle(r) => {
            writeln!(
                out,
                "vault-handle {}: \"{}\"",
                hex_prefix(&r.id.0 .0, 8),
                r.handle
            )
            .ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::Group(r) => {
            write!(out, "group {}: \"{}\"", hex_prefix(&r.id.0 .0, 8), r.handle).ok();
            if tombstone {
                write!(out, " (deleted)").ok();
            }
            writeln!(out).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::GroupDeleted(r) => {
            writeln!(out, "group {} (deleted)", hex_prefix(&r.id.0 .0, 8)).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::GroupMember(r) => {
            write!(
                out,
                "group-member {}: group={} member={}",
                hex_prefix(&r.id.0 .0, 8),
                hex_prefix(&r.group_id.0 .0, 8),
                principal_display(&r.member_id, ctx)
            )
            .ok();
            if tombstone {
                write!(out, " (deleted)").ok();
            }
            writeln!(out).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::GroupMemberDeleted(r) => {
            writeln!(
                out,
                "group-member {}: group={} member={} (deleted)",
                hex_prefix(&r.id.0 .0, 8),
                hex_prefix(&r.group_id.0 .0, 8),
                principal_display(&r.member_id, ctx)
            )
            .ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::Grant(r) => {
            write!(out, "grant {}:", hex_prefix(&r.id.0 .0, 8)).ok();
            if tombstone {
                write!(out, " (revoked)").ok();
            }
            writeln!(out).ok();
            writeln!(out, "  subject: {}", principal_display(&r.subject_id, ctx)).ok();
            writeln!(out, "  permission: {}", format_permission(&r.permission)).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::GrantDeleted(r) => {
            writeln!(out, "grant {} (revoked)", hex_prefix(&r.id.0 .0, 8)).ok();
            writeln!(out, "  permission: {}", format_permission(&r.permission)).ok();
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::Secret(r) => {
            let ss = r.selector.tuple.join("/");
            if tombstone {
                writeln!(out, "secret \"{}\" (deleted)", ss).ok();
            } else {
                writeln!(out, "secret \"{}\"", ss).ok();
                if !r.selector.labels.is_empty() {
                    let ls: Vec<&str> = r.selector.labels.iter().map(|l| l.key.as_str()).collect();
                    writeln!(out, "  labels: [{}]", ls.join(", ")).ok();
                }
                writeln!(
                    out,
                    "  recipients: {}",
                    format_recipients(&r.sealed.recipient_slots, ctx)
                )
                .ok();
                writeln!(out, "  ciphertext: {} bytes", r.sealed.ciphertext.len()).ok();
                if let Some(pt) = plaintext {
                    let ph: String = pt.plaintext.iter().map(|b| format!("{b:02x}")).collect();
                    writeln!(out, "  primary: {ph}").ok();
                    if !pt.fields.is_empty() {
                        writeln!(out, "  fields:").ok();
                        for f in &pt.fields {
                            let vh: String = f.value.iter().map(|b| format!("{b:02x}")).collect();
                            writeln!(out, "    {} = {vh}", f.key).ok();
                        }
                    }
                }
            }
            writeln!(out, "  version: {}", r.counter).ok();
        }
        RecordBodyV1::SecretDeleted(r) => {
            let ss = r.selector.tuple.join("/");
            writeln!(out, "secret \"{}\" (deleted)", ss).ok();
            if !r.selector.labels.is_empty() {
                let ls: Vec<&str> = r.selector.labels.iter().map(|l| l.key.as_str()).collect();
                writeln!(out, "  labels: [{}]", ls.join(", ")).ok();
            }
            writeln!(out, "  version: {}", r.counter).ok();
        }
    }
    out
}

// ── Public API ──

pub fn cat_vault_with_decrypt(
    path: &Path,
    session: Option<&UnlockedSession>,
) -> std::result::Result<String, FrontendError> {
    let (base, ctx) = load_and_resolve(path)?;
    let dm = session.map(|s| {
        let crypto = Crypto;
        build_decrypt_map(&crypto, s)
    });
    Ok(render_vault(&base, &ctx, dm.as_ref()))
}

#[allow(dead_code)]
pub(crate) fn cat_vault(path: &Path) -> std::result::Result<String, FrontendError> {
    let (base, ctx) = load_and_resolve(path)?;
    Ok(render_vault(&base, &ctx, None))
}

// ── Internal pipeline ──

struct ResolvedVault {
    records_total: usize,
    resolved: Vec<(RecordBodyV1, bool)>,
    root_hex: String,
}

fn load_and_resolve(
    path: &Path,
) -> std::result::Result<(ResolvedVault, VaultContext), FrontendError> {
    let bytes = std::fs::read(path).map_err(|e| FrontendError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    let vault = decode_vault(&bytes).map_err(|e| FrontendError::Ops(OpsError::Core(e)))?;
    let VaultStore::V1(v1) = &vault;

    let mut groups: BTreeMap<GroupKey, Vec<&RecordBodyV1>> = BTreeMap::new();
    for rec in &v1.records {
        let Some(body) = rec.body.known() else {
            continue;
        };
        if let Some((key, _)) = classify_record(body) {
            groups.entry(key).or_default().push(body);
        }
    }

    let ctx = build_vault_context(&groups);

    let mut resolved: Vec<(RecordBodyV1, bool)> = Vec::new();
    for rs in groups.values() {
        if rs.len() == 1 {
            resolved.push(((*rs[0]).clone(), is_deletion(rs[0])));
        } else {
            let w = *rs
                .iter()
                .max_by_key(|b| classify_record(b).map(|(_, c)| c))
                .unwrap();
            resolved.push((w.clone(), is_deletion(w)));
        }
    }
    resolved.sort_by_key(|(a, _)| record_type_priority(a));

    let root_hex = v1
        .records
        .iter()
        .find_map(|r| {
            let body = r.body.known()?;
            if let RecordBodyV1::VaultRoot(vr) = body {
                Some(userid_hex(&vr.id))
            } else {
                None
            }
        })
        .unwrap_or_default();

    Ok((
        ResolvedVault {
            records_total: v1.records.len(),
            resolved,
            root_hex,
        },
        ctx,
    ))
}

fn plural(n: usize, singular: &str, p: &str) -> String {
    if n == 1 {
        format!("{n} {singular}")
    } else {
        format!("{n} {p}")
    }
}

fn plural_active(n: usize) -> String {
    if n == 1 {
        "1 logical entity".into()
    } else {
        format!("{n} logical entities")
    }
}

fn render_vault(
    base: &ResolvedVault,
    ctx: &VaultContext,
    dm: Option<&HashMap<SecretId, SecretPlaintext>>,
) -> String {
    let mut out = String::new();
    writeln!(out, "# thorax vault — format v1").ok();
    writeln!(out, "# root: {}", base.root_hex).ok();

    let active_count = base.resolved.iter().filter(|(_, t)| !t).count();
    writeln!(
        out,
        "# {}, {}",
        plural(base.records_total, "record", "records"),
        plural_active(active_count),
    )
    .ok();

    for (body, tombstone) in &base.resolved {
        if *tombstone {
            continue;
        }
        // Skip handle records for deleted users — the user is gone.
        if let RecordBodyV1::UserHandle(r) = body {
            if ctx.deleted_users.contains(&r.user_id.0 .0.to_vec()) {
                continue;
            }
        }
        let eff = EffectiveRecord::Active(body.clone());
        let pt = dm.and_then(|m| {
            if let RecordBodyV1::Secret(r) = body {
                m.get(&r.id)
            } else {
                None
            }
        });
        write!(out, "\n{}", render_effective(&eff, ctx, pt)).ok();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    fn empty_ctx() -> VaultContext {
        VaultContext {
            handle_of_user: HashMap::new(),
            name_of_group: HashMap::new(),
            deleted_users: HashSet::new(),
        }
    }

    // ── hex_prefix ──

    #[test]
    fn test_hex_prefix_normal() {
        assert_eq!(hex_prefix(&[0xde, 0xad, 0xbe, 0xef], 2), "dead");
    }
    #[test]
    fn test_hex_prefix_short() {
        assert_eq!(hex_prefix(&[0x01, 0x02], 8), "0102");
    }
    #[test]
    fn test_hex_prefix_empty() {
        assert_eq!(hex_prefix(&[], 4), "");
    }

    // ── is_deletion ──

    #[test]
    fn test_is_deletion_true() {
        assert!(is_deletion(&RecordBodyV1::SecretDeleted(
            SecretDeletedRecordV1 {
                id: sid(1),
                selector: sel("x"),
                counter: 0
            }
        )));
    }
    #[test]
    fn test_is_deletion_false() {
        assert!(!is_deletion(&RecordBodyV1::Secret(SecretRecordV1 {
            id: sid(1),
            selector: sel("x"),
            sealed: empty_sealed(),
            counter: 0
        })));
    }

    // ── classify_record ──

    #[test]
    fn test_classify_share_key() {
        let id = sid(42);
        let sk = classify_record(&RecordBodyV1::Secret(SecretRecordV1 {
            id: id.clone(),
            selector: sel("t"),
            sealed: empty_sealed(),
            counter: 1,
        }))
        .unwrap()
        .0;
        let dk = classify_record(&RecordBodyV1::SecretDeleted(SecretDeletedRecordV1 {
            id: id.clone(),
            selector: sel("t"),
            counter: 2,
        }))
        .unwrap()
        .0;
        assert_eq!(sk, dk);
    }

    // ── userid_display ──

    #[test]
    fn test_userid_with_handle() {
        let id = uid(&[0xbb; 32]);
        let mut h = HashMap::new();
        h.insert(id.0 .0.to_vec(), "root".into());
        let ctx = VaultContext {
            handle_of_user: h,
            name_of_group: HashMap::new(),
            deleted_users: HashSet::new(),
        };
        assert_eq!(userid_display(&id, &ctx), "@root");
    }
    #[test]
    fn test_userid_hex_fallback() {
        assert_eq!(
            userid_display(&uid(&[0xcc; 32]), &empty_ctx()),
            userid_hex(&uid(&[0xcc; 32]))
        );
    }

    // ── principal_display ──

    #[test]
    fn test_principal_user_handle() {
        let id = uid(&[0xdd; 32]);
        let mut h = HashMap::new();
        h.insert(id.0 .0.to_vec(), "alice".into());
        let ctx = VaultContext {
            handle_of_user: h,
            name_of_group: HashMap::new(),
            deleted_users: HashSet::new(),
        };
        assert_eq!(principal_display(&PrincipalRefV1::User(id), &ctx), "@alice");
    }
    #[test]
    fn test_principal_group_name() {
        let gid = GroupId(HashValue(bts(&[0xee; 32])));
        let mut n = HashMap::new();
        n.insert(gid.0 .0.to_vec(), "devs".into());
        let ctx = VaultContext {
            handle_of_user: HashMap::new(),
            name_of_group: n,
            deleted_users: HashSet::new(),
        };
        assert_eq!(
            principal_display(&PrincipalRefV1::Group(gid), &ctx),
            "%devs"
        );
    }

    // ── format_recipients ──

    #[test]
    fn test_recipients_empty() {
        assert_eq!(format_recipients(&[], &empty_ctx()), "[]");
    }
    #[test]
    fn test_recipients_hex() {
        let s = RecipientSlotV1 {
            recipient_id: uid(&[0xca; 32]),
            hpke_encapsulated_key: bts(&[0; 32]),
            wrapped_content_key: bts(&[0; 32]),
        };
        assert_eq!(
            format_recipients(&[s], &empty_ctx()),
            "[cacacacacacacacacacacacacacacaca]"
        );
    }
    #[test]
    fn test_recipients_handle() {
        let id = uid(&[0xaa; 32]);
        let mut h = HashMap::new();
        h.insert(id.0 .0.to_vec(), "alice".into());
        let ctx = VaultContext {
            handle_of_user: h,
            name_of_group: HashMap::new(),
            deleted_users: HashSet::new(),
        };
        let s = RecipientSlotV1 {
            recipient_id: id,
            hpke_encapsulated_key: bts(&[0; 32]),
            wrapped_content_key: bts(&[0; 32]),
        };
        assert_eq!(format_recipients(&[s], &ctx), "[@alice]");
    }

    // ── format_permission ──

    #[test]
    fn test_perm_read() {
        assert_eq!(
            format_permission(&GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all())),
            "read"
        );
    }
    #[test]
    fn test_perm_write() {
        assert_eq!(
            format_permission(&GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all())),
            "write"
        );
    }
    #[test]
    fn test_perm_admin() {
        assert_eq!(
            format_permission(&GrantPermissionV1::Administer),
            "administer"
        );
    }

    // ── render_effective ──

    #[test]
    fn test_render_root() {
        let eff = EffectiveRecord::Active(RecordBodyV1::VaultRoot(VaultRootRecordV1 {
            id: uid(&[0xab; 32]),
            hpke_public_key: bts(&[0xcd; 32]),
        }));
        let o = render_effective(&eff, &empty_ctx(), None);
        assert!(o.contains("vault-root") && o.contains("root: abababababababab"));
    }
    #[test]
    fn test_render_secret_decrypt() {
        let pt = SecretPlaintext {
            selector: sel("k"),
            plaintext: Zeroizing::new(bts(&[0xde, 0xad])),
            fields: vec![SecretField {
                key: "who".into(),
                value: Zeroizing::new(bts(b"me")),
            }],
        };
        let eff = EffectiveRecord::Active(RecordBodyV1::Secret(SecretRecordV1 {
            id: sid(1),
            selector: sel("k"),
            sealed: empty_sealed(),
            counter: 5,
        }));
        let o = render_effective(&eff, &empty_ctx(), Some(&pt));
        assert!(o.contains("primary: dead"));
        assert!(o.contains("who = 6d65"));
    }
    #[test]
    fn test_render_deleted_with_labels() {
        let eff = EffectiveRecord::Deleted(RecordBodyV1::SecretDeleted(SecretDeletedRecordV1 {
            id: sid(2),
            selector: SecretSelectorV1 {
                tuple: vec!["old".into()],
                labels: vec![SecretLabelV1 {
                    key: "d".into(),
                    value: "y".into(),
                }],
            },
            counter: 10,
        }));
        let o = render_effective(&eff, &empty_ctx(), None);
        assert!(o.contains(r#"secret "old" (deleted)"#) && o.contains("labels: [d]"));
    }
    #[test]
    fn test_render_grant_revoked() {
        let eff = EffectiveRecord::Deleted(RecordBodyV1::GrantDeleted(GrantDeletedRecordV1 {
            id: GrantId(HashValue(bts(&[0x33; 32]))),
            permission: GrantPermissionV1::Administer,
            counter: 7,
        }));
        assert!(render_effective(&eff, &empty_ctx(), None).contains("(revoked)"));
    }

    // ── build_vault_context ──

    #[test]
    fn test_context_handle_wins() {
        let u = uid(&[0xaa; 32]);
        let lo = RecordBodyV1::UserHandle(UserHandleRecordV1 {
            id: UserHandleId(HashValue(bts(&[1; 32]))),
            handle: "old".into(),
            user_id: u.clone(),
            counter: 1,
        });
        let hi = RecordBodyV1::UserHandle(UserHandleRecordV1 {
            id: UserHandleId(HashValue(bts(&[2; 32]))),
            handle: "alice".into(),
            user_id: u.clone(),
            counter: 5,
        });
        let mut g: BTreeMap<GroupKey, Vec<&RecordBodyV1>> = BTreeMap::new();
        g.entry(GroupKey::UserHandle(UserHandleId(HashValue(bts(&[1; 32])))))
            .or_default()
            .push(&lo);
        g.entry(GroupKey::UserHandle(UserHandleId(HashValue(bts(&[2; 32])))))
            .or_default()
            .push(&hi);
        let ctx = build_vault_context(&g);
        assert_eq!(
            ctx.handle_of_user.get(&u.0 .0.to_vec()).map(|s| s.as_str()),
            Some("alice")
        );
    }

    // ── LWW helpers ──

    #[test]
    fn test_lww_high_wins() {
        let id = sid(99);
        let lo = RecordBodyV1::Secret(SecretRecordV1 {
            id: id.clone(),
            selector: sel("k"),
            sealed: empty_sealed(),
            counter: 1,
        });
        let hi = RecordBodyV1::Secret(SecretRecordV1 {
            id: id.clone(),
            selector: sel("k"),
            sealed: empty_sealed(),
            counter: 10,
        });
        let w = *[&lo, &hi]
            .iter()
            .max_by_key(|b| classify_record(b).map(|(_, c)| c))
            .unwrap();
        assert_eq!(classify_record(w).unwrap().1, 10);
    }
    #[test]
    fn test_lww_tombstone_wins() {
        let id = sid(88);
        let a = RecordBodyV1::Secret(SecretRecordV1 {
            id: id.clone(),
            selector: sel("k"),
            sealed: empty_sealed(),
            counter: 1,
        });
        let t = RecordBodyV1::SecretDeleted(SecretDeletedRecordV1 {
            id: id.clone(),
            selector: sel("k"),
            counter: 5,
        });
        let w = *[&a, &t]
            .iter()
            .max_by_key(|b| classify_record(b).map(|(_, c)| c))
            .unwrap();
        assert!(is_deletion(w) && classify_record(w).unwrap().1 == 5);
    }

    // ── helpers ──

    fn bts(d: &[u8]) -> Bytes {
        Bytes::from(d.to_vec())
    }
    fn uid(d: &[u8; 32]) -> UserId {
        UserId(HashValue(bts(d)))
    }
    fn sid(n: u8) -> SecretId {
        SecretId(HashValue(bts(&[n; 32])))
    }
    fn sel(s: &str) -> SecretSelectorV1 {
        SecretSelectorV1 {
            tuple: vec![s.into()],
            labels: vec![],
        }
    }
    fn empty_sealed() -> SealedPayloadV1 {
        SealedPayloadV1 {
            nonce: Bytes::new(),
            ciphertext: Bytes::new(),
            recipient_slots: vec![],
        }
    }
}
