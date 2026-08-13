//! Pure projections from the verified [`EffectiveState`] (+ validation report and local trust)
//! into the shapes the views render. No I/O, no crypto decisions of our own — classification and
//! reader sets are delegated to `EffectiveState` so the TUI stays on the one shared path.

use std::collections::BTreeMap;

use thorax_frontend::{escape_segment, escape_tuple};
use thorax_ops::{
    ActiveSecretV1, Crypto, EffectiveState, GrantId, GrantPermissionV1, GrantRecordV1, GroupId,
    KeyspaceGrantClassV1, KeyspaceSelectorV1, LabelMatcherV1, PrincipalRefV1, Ratchet, RecordKey,
    SecretSelectorV1, SecretState, TupleMatcherV1, UserId, ValidationIssue, ValidationReport,
};

// ── Secret selector rendering ────────────────────────────────────────────────

/// `app/api/stripe` — the tuple joined by `/`, each segment in its canonical (quoted when it
/// carries a structural character) spelling, so the result round-trips through [`parse_selector`].
pub fn selector_path(selector: &SecretSelectorV1) -> String {
    escape_tuple(&selector.tuple)
}

/// `{env=prod, region=us-east-1}` or empty string when there are no labels.
pub fn selector_labels(selector: &SecretSelectorV1) -> String {
    if selector.labels.is_empty() {
        return String::new();
    }
    let inner = selector
        .labels
        .iter()
        .map(|l| format!("{}={}", l.key, l.value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{{{inner}}}")
}

/// `app/api/stripe {env=prod}` — full human selector.
pub fn selector_display(selector: &SecretSelectorV1) -> String {
    let labels = selector_labels(selector);
    if labels.is_empty() {
        selector_path(selector)
    } else {
        format!("{} {}", selector_path(selector), labels)
    }
}

/// The selector's labels as the `&`-separated `key=value` form a Labels field accepts:
/// `env=prod&region=us` (empty string when there are no labels). Keys and values are rendered
/// canonically (quoted when they carry a structural character) so the field round-trips through
/// [`parse_selector`].
pub fn selector_label_pairs(selector: &SecretSelectorV1) -> String {
    selector
        .labels
        .iter()
        .map(|l| format!("{}={}", escape_segment(&l.key), escape_segment(&l.value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Selectors of all live secrets.
pub fn value_selectors(state: &EffectiveState) -> Vec<SecretSelectorV1> {
    state
        .secret_records()
        .into_iter()
        .map(|r| r.value.selector)
        .collect()
}

/// The selector carried by a live secret record.
pub fn record_selector(record: &ActiveSecretV1) -> &SecretSelectorV1 {
    &record.value.selector
}

/// Parse a typed selector spec into a [`SecretSelectorV1`] using the one shared selector grammar
/// (`thorax_frontend::parse_secret_selector`): a `/`-separated tuple, an optional `@`-introduced
/// label section of `&`-separated `key=value` pairs, with shell-style quoting (`\x`, `"…"`) so any
/// segment, key, or value can carry a structural character. The TUI form combines its Path and
/// Labels fields into this spelling before calling here, so the editor, CLI, and SDKs all accept
/// and print selectors identically.
pub fn parse_selector(input: &str) -> Result<SecretSelectorV1, String> {
    thorax_frontend::parse_secret_selector(input.trim()).map_err(|error| error.to_string())
}

// ── Secret tree ──────────────────────────────────────────────────────────────

/// A leaf: one concrete secret (tuple + labels), with the viewer-relative state. Live and
/// conflicted secrets reach the browse tree; deletions are filtered out at [`build_tree`].
#[derive(Clone, Debug)]
pub struct SecretLeaf {
    pub selector: SecretSelectorV1,
    pub state: SecretState,
}

/// A tree node keyed by one tuple segment. `path` is the full tuple prefix to this node, used as a
/// stable identity for expansion state and selection.
#[derive(Clone, Debug, Default)]
pub struct TreeNode {
    pub segment: String,
    pub path: Vec<String>,
    pub children: Vec<TreeNode>,
    pub leaves: Vec<SecretLeaf>,
}

#[derive(Clone, Debug, Default)]
pub struct SecretTree {
    pub roots: Vec<TreeNode>,
    /// Count of secret leaves in the tree (live + conflicted). No longer shown in the UI;
    /// kept for tests/diagnostics.
    #[cfg_attr(not(test), allow(dead_code))]
    pub total: usize,
}

/// Build the tuple tree from all active secret records, classifying each leaf for `viewer` when
/// one is known. Records are filtered through `facets` (label AND-equality) and the fuzzy `search`
/// query (over the `/`-joined key path) before they reach the tree.
pub fn build_tree(
    state: &EffectiveState,
    crypto: &Crypto,
    viewer: Option<&UserId>,
    facets: &FacetFilter,
    search: &str,
) -> SecretTree {
    let mut root = TreeNode::default();
    let mut total = 0usize;
    let mut query = PathQuery::new(search);
    // Only live secrets are browsable. Deletions (including the old selector left behind by a
    // relabel) are a safety-dominant part of the signed log, but they are not browsable secrets;
    // `secret_records` drops them so the policy lives in core, not here.
    for record in state.secret_records() {
        let selector = record_selector(&record).clone();
        if !facets.matches(&selector) || !query.matches(&selector) {
            continue;
        }
        total += 1;
        let state_for_viewer = match viewer {
            Some(user) => state.classify_secret_for_user(&selector, user, crypto),
            None => SecretState::Unauthorized,
        };
        let leaf = SecretLeaf {
            selector: selector.clone(),
            state: state_for_viewer,
        };
        insert_leaf(&mut root, &selector.tuple, leaf);
    }
    // Conflicted secrets are absent from `secret_records` (no candidate is the value), but
    // they must stay visible: each renders as a leaf flagged Conflicted at its selector. A
    // rollback conflict whose records were dropped entirely carries no selector to place
    // here — it is reachable via the Conflicts tab only.
    for conflict in state.secret_conflicts() {
        let Some(selector) = conflict_selector(conflict) else {
            continue;
        };
        if !facets.matches(&selector) || !query.matches(&selector) {
            continue;
        }
        total += 1;
        let leaf = SecretLeaf {
            selector: selector.clone(),
            state: SecretState::Conflicted,
        };
        insert_leaf(&mut root, &selector.tuple, leaf);
    }
    sort_node(&mut root);
    SecretTree {
        roots: root.children,
        total,
    }
}

/// The selector a secret conflict is about, recovered from its first candidate body (all
/// candidates at one key share the secret's identity). `None` when no candidate survived.
fn conflict_selector(conflict: &thorax_ops::ConflictReport) -> Option<SecretSelectorV1> {
    conflict
        .candidates
        .first()
        .and_then(|signed| signed.body.known())
        .and_then(|body| match body {
            thorax_ops::RecordBodyV1::Secret(record) => Some(record.selector.clone()),
            thorax_ops::RecordBodyV1::SecretDeleted(record) => Some(record.selector.clone()),
            _ => None,
        })
}

/// The selector to prefill an in-place fresh `set` with when resolving a rollback: the
/// claimed selector of a surviving candidate, else the full selector local trust remembered
/// for the key (the origin is the id's preimage, so it carries the labels too — they are
/// part of identity).
pub fn rollback_set_selector(conflict: &thorax_ops::ConflictReport) -> Option<SecretSelectorV1> {
    conflict_selector(conflict).or_else(|| match &conflict.origin {
        Some(thorax_ops::KeyOrigin::Secret(selector)) => Some(selector.clone()),
        _ => None,
    })
}

fn insert_leaf(node: &mut TreeNode, tuple: &[String], leaf: SecretLeaf) {
    let Some((head, rest)) = tuple.split_first() else {
        node.leaves.push(leaf);
        return;
    };
    let mut next_path = node.path.clone();
    next_path.push(head.clone());
    let child = match node.children.iter_mut().find(|c| &c.segment == head) {
        Some(existing) => existing,
        None => {
            node.children.push(TreeNode {
                segment: head.clone(),
                path: next_path,
                children: Vec::new(),
                leaves: Vec::new(),
            });
            node.children.last_mut().expect("just pushed")
        }
    };
    insert_leaf(child, rest, leaf);
}

fn sort_node(node: &mut TreeNode) {
    node.children.sort_by(|a, b| a.segment.cmp(&b.segment));
    node.leaves
        .sort_by_key(|leaf| selector_labels(&leaf.selector));
    for child in &mut node.children {
        sort_node(child);
    }
}

// ── Facets ─────────────────────────────────────────────────────────────────

/// All label keys present in the namespace and the values seen for each, for the facet bar.
#[derive(Clone, Debug, Default)]
pub struct FacetIndex {
    pub keys: Vec<String>,
    pub values: BTreeMap<String, Vec<String>>,
}

pub fn facet_index(state: &EffectiveState) -> FacetIndex {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // Live secrets only — a deleted/relabeled-away secret's labels are not live facet values.
    for record in state.secret_records() {
        for label in &record_selector(&record).labels {
            let entry = values.entry(label.key.clone()).or_default();
            if !entry.contains(&label.value) {
                entry.push(label.value.clone());
            }
        }
    }
    for vals in values.values_mut() {
        vals.sort();
    }
    let keys = values.keys().cloned().collect();
    FacetIndex { keys, values }
}

/// Active label=value constraints, AND-combined. A selector matches when it carries every
/// constrained key with the chosen value.
#[derive(Clone, Debug, Default)]
pub struct FacetFilter {
    pub constraints: BTreeMap<String, String>,
}

impl FacetFilter {
    pub fn matches(&self, selector: &SecretSelectorV1) -> bool {
        self.constraints.iter().all(|(key, value)| {
            selector
                .labels
                .iter()
                .any(|l| &l.key == key && &l.value == value)
        })
    }
}

/// A compiled fuzzy query over a secret's `/`-joined key path. An empty query matches every
/// secret, so the tree is unfiltered when the search bar is closed/blank. The match is
/// path-aware (segment boundaries score higher) and case-insensitive. Holds a `nucleo` matcher,
/// which scores one needle at a time and needs `&mut`, so `matches` does too.
struct PathQuery {
    matcher: nucleo_matcher::Matcher,
    pattern: Option<nucleo_matcher::pattern::Pattern>,
    buf: Vec<char>,
}

impl PathQuery {
    fn new(query: &str) -> Self {
        let pattern = (!query.is_empty()).then(|| {
            nucleo_matcher::pattern::Pattern::parse(
                query,
                nucleo_matcher::pattern::CaseMatching::Ignore,
                nucleo_matcher::pattern::Normalization::Smart,
            )
        });
        PathQuery {
            matcher: nucleo_matcher::Matcher::new(nucleo_matcher::Config::DEFAULT.match_paths()),
            pattern,
            buf: Vec::new(),
        }
    }

    fn matches(&mut self, selector: &SecretSelectorV1) -> bool {
        let Some(pattern) = &self.pattern else {
            return true;
        };
        let haystack = selector.tuple.join("/");
        let utf32 = nucleo_matcher::Utf32Str::new(&haystack, &mut self.buf);
        pattern.score(utf32, &mut self.matcher).is_some()
    }
}

// ── Access model (hierarchical: grants nested under each principal) ───────────

/// One grant a principal holds, split into two columns (access class + keyspace) for display.
#[derive(Clone, Debug)]
pub struct AccessGrant {
    /// `None` = the root user's built-in initial authority (not a deletable grant).
    pub grant_id: Option<GrantId>,
    pub class: String,
    pub keyspace: String,
}

#[derive(Clone, Debug)]
pub struct AccessUser {
    pub user_id: UserId,
    pub handle: Option<String>,
    pub is_root: bool,
    pub grants: Vec<AccessGrant>,
    pub group_memberships: Vec<String>,
}

impl AccessUser {
    pub fn label(&self) -> String {
        match &self.handle {
            Some(h) => format!("@{h}"),
            None => short_user(&self.user_id),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AccessGroup {
    pub group_id: GroupId,
    pub handle: String,
    pub members: Vec<String>,
    pub grants: Vec<AccessGrant>,
}

#[derive(Clone, Debug, Default)]
pub struct AccessModel {
    pub users: Vec<AccessUser>,
    pub groups: Vec<AccessGroup>,
}

/// Short hex of a user id (helper used for labels).
pub fn short_user(user: &UserId) -> String {
    thorax_frontend::short_user_hex(user)
}

/// Split a permission into (access class, keyspace) columns for the two-column display.
pub fn permission_columns(permission: &GrantPermissionV1) -> (String, String) {
    match permission {
        GrantPermissionV1::ReadKeyspace(s) => ("read".to_string(), keyspace_display(s)),
        GrantPermissionV1::WriteKeyspace(s) => ("write".to_string(), keyspace_display(s)),
        GrantPermissionV1::ManageKeyspace(m) => {
            let classes = m
                .grantable
                .iter()
                .map(grant_class_name)
                .collect::<Vec<_>>()
                .join(", ");
            (
                "manage".to_string(),
                format!("{} (can grant: {})", keyspace_display(&m.selector), classes),
            )
        }
        GrantPermissionV1::Administer => ("administer".to_string(), "entire vault".to_string()),
    }
}

pub fn build_access(state: &EffectiveState) -> AccessModel {
    let mut handle_for: BTreeMap<UserId, String> = BTreeMap::new();
    for record in state.handles.values() {
        handle_for.insert(record.user_id.clone(), record.handle.clone());
    }
    let group_name = |g: &GroupId| -> String {
        state
            .groups
            .get(g)
            .map(|r| format!("%{}", r.handle))
            .unwrap_or_else(|| format!("%{}", thorax_frontend::short_hash(&g.0)))
    };
    let principal_label = |p: &PrincipalRefV1| -> String {
        match p {
            PrincipalRefV1::User(u) => handle_for
                .get(u)
                .map(|h| format!("@{h}"))
                .unwrap_or_else(|| short_user(u)),
            PrincipalRefV1::Group(g) => group_name(g),
        }
    };

    let grants_for = |subject_is: &dyn Fn(&PrincipalRefV1) -> bool| -> Vec<AccessGrant> {
        let mut grants: Vec<_> = state
            .grants
            .values()
            .filter(|g: &&GrantRecordV1| subject_is(&g.subject_id))
            .map(|g| {
                let (class, keyspace) = permission_columns(&g.permission);
                AccessGrant {
                    grant_id: Some(g.id.clone()),
                    class,
                    keyspace,
                }
            })
            .collect();
        grants.sort_by(|a, b| {
            a.class
                .cmp(&b.class)
                .then_with(|| a.keyspace.cmp(&b.keyspace))
        });
        grants
    };

    let mut users = Vec::new();
    for user in state.users.keys() {
        let is_root = state.root_user_id.as_ref() == Some(user);
        let mut grants = Vec::new();
        if is_root {
            grants.push(AccessGrant {
                grant_id: None,
                class: "administer".to_string(),
                keyspace: "entire vault (initial authority; cannot be deleted)".to_string(),
            });
        }
        let u = user.clone();
        grants.extend(grants_for(
            &|p| matches!(p, PrincipalRefV1::User(x) if *x == u),
        ));
        let mut group_memberships: Vec<_> = state
            .memberships
            .values()
            .filter(|m| matches!(&m.member_id, PrincipalRefV1::User(x) if x == user))
            .map(|m| group_name(&m.group_id))
            .collect();
        group_memberships.sort();
        users.push(AccessUser {
            user_id: user.clone(),
            handle: handle_for.get(user).cloned(),
            is_root,
            grants,
            group_memberships,
        });
    }
    users.sort_by(|a, b| b.is_root.cmp(&a.is_root).then(a.label().cmp(&b.label())));

    let mut groups = Vec::new();
    for (group_id, record) in &state.groups {
        let gid = group_id.clone();
        let grants = grants_for(&|p| matches!(p, PrincipalRefV1::Group(x) if *x == gid));
        let mut members: Vec<_> = state
            .memberships
            .values()
            .filter(|m| &m.group_id == group_id)
            .map(|m| principal_label(&m.member_id))
            .collect();
        members.sort();
        groups.push(AccessGroup {
            group_id: group_id.clone(),
            handle: record.handle.clone(),
            members,
            grants,
        });
    }
    groups.sort_by(|a, b| a.handle.cmp(&b.handle));

    AccessModel { users, groups }
}

// ── Health ─────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct Health {
    pub issues: Vec<String>,
    /// Non-blocking advisories (e.g. records from a newer thorax: inert and preserved), already
    /// rendered via `thorax_frontend::describe_warning` — never `{:?}`.
    pub warnings: Vec<String>,
    pub stale: Vec<SecretSelectorV1>,
    pub secret_count: usize,
    pub user_count: usize,
    /// Short form of the trusted-root fingerprint this machine pinned — the same first-8-hex form
    /// the CLI and the header show.
    pub trusted_root: String,
    /// Size of the rollback ratchet: how many record keys carry a remembered high-water counter.
    pub watermark_count: usize,
    /// The highest vault format version verified under this root; `0` when nothing is remembered
    /// yet (the envelope's own downgrade ratchet).
    pub format_version: u64,
}

pub fn build_health(
    state: &EffectiveState,
    report: &ValidationReport,
    ratchet: &Ratchet,
    crypto: &Crypto,
) -> Health {
    let issues = report
        .issues
        .iter()
        .map(thorax_frontend::describe_issue)
        .collect();
    let warnings = report
        .warnings
        .iter()
        .map(thorax_frontend::describe_warning)
        .collect();
    let mut stale = Vec::new();
    let mut secret_count = 0usize;
    for record in state.secret_records() {
        secret_count += 1;
        let selector = record_selector(&record);
        if state
            .secret_missing_reader(selector, crypto)
            .unwrap_or(false)
        {
            stale.push(selector.clone());
        }
    }
    Health {
        issues,
        warnings,
        stale,
        secret_count,
        user_count: state.users.len(),
        trusted_root: thorax_frontend::short_hash(&ratchet.trusted_root),
        watermark_count: ratchet.watermarks.len(),
        format_version: ratchet.format_version,
    }
}

// ── Fail-closed gate ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockReason {
    BadSignature(RecordKey),
    UnknownSignerKey,
    RootNotTrusted,
    AmbiguousRoot,
    AuthorityDidNotConverge,
    FormatVersionRegression { remembered: u64, current: u64 },
    Structure(String),
}

/// If validation found any issue, the TUI must show the locked view rather than any namespace —
/// every `ValidationIssue` is treated as blocking. Returns the first issue as a block reason.
/// A suspected rollback is not an issue: it surfaces as a
/// conflict in the Conflicts tab while the rest of the app stays usable. Likewise, records from
/// a newer thorax are a warning (inert and preserved), never a block.
pub fn block_reason(report: &ValidationReport) -> Option<BlockReason> {
    report.issues.first().map(|issue| match issue {
        ValidationIssue::InvalidSignature(key) => BlockReason::BadSignature(key.clone()),
        ValidationIssue::UnknownSignerKey(_) => BlockReason::UnknownSignerKey,
        ValidationIssue::RootNotTrusted => BlockReason::RootNotTrusted,
        ValidationIssue::AmbiguousRoot => BlockReason::AmbiguousRoot,
        ValidationIssue::AuthorityDidNotConverge => BlockReason::AuthorityDidNotConverge,
        ValidationIssue::FormatVersionRegression {
            remembered,
            current,
        } => BlockReason::FormatVersionRegression {
            remembered: *remembered,
            current: *current,
        },
        ValidationIssue::InvalidStructure(msg) => BlockReason::Structure(msg.clone()),
    })
}

// ── Permission rendering ───────────────────────────────────────────────────

pub fn grant_class_name(class: &KeyspaceGrantClassV1) -> &'static str {
    match class {
        KeyspaceGrantClassV1::Read => "read",
        KeyspaceGrantClassV1::Write => "write",
        KeyspaceGrantClassV1::Manage => "manage",
    }
}

pub fn keyspace_display(selector: &KeyspaceSelectorV1) -> String {
    let tuple = match &selector.tuple {
        TupleMatcherV1::Any => "* (entire vault)".to_string(),
        TupleMatcherV1::Exact(t) => format!("{} (exact)", escape_tuple(t)),
        TupleMatcherV1::Prefix(t) => format!("{}/*", escape_tuple(t)),
    };
    if selector.labels.is_empty() {
        return tuple;
    }
    let labels = selector
        .labels
        .iter()
        .map(|m| format!("{}{}", m.key, label_matcher_display(&m.matcher)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{tuple} {{{labels}}}")
}

fn label_matcher_display(matcher: &LabelMatcherV1) -> String {
    match matcher {
        LabelMatcherV1::Any => "=*".to_string(),
        LabelMatcherV1::Equals(v) => format!("={v}"),
        LabelMatcherV1::In(vs) => format!(" in [{}]", vs.join(",")),
        LabelMatcherV1::Absent => " absent".to_string(),
    }
}

// ── Merge conflicts ──────────────────────────────────────────────────────────

/// One candidate of a conflict, ready to render.
#[derive(Clone, Debug)]
pub struct ConflictCandidateView {
    /// Record hash — the pick handle `resolve_conflict_with_keychain` takes.
    pub pick: thorax_ops::HashValue,
    pub summary: String,
    pub signer: String,
    /// Kind-specific `(label, value)` rows for the detail pane's metadata section.
    pub details: Vec<(String, String)>,
    /// For secret-value candidates: the selector, which drives the access table and the
    /// reveal affordance in the detail pane.
    pub selector: Option<SecretSelectorV1>,
    /// Whether the acting user can decrypt *this candidate*: current read authority plus a
    /// recipient slot keyed to their current key on this specific record.
    pub decryptable: bool,
}

/// One unresolved conflict (a same-counter tie or a suspected rollback), ready to render in
/// the Merge view. Until resolved the key has no effective value and reads of it fail.
#[derive(Clone, Debug)]
pub struct ConflictView {
    pub kind: &'static str,
    /// "tie" or "rollback" (see `thorax_frontend::conflict_kind_name`).
    pub conflict_kind: &'static str,
    pub label: String,
    pub counter: u64,
    /// One-line human explanation of what this conflict means and how it resolves.
    pub summary: String,
    /// Why the acting user cannot resolve this conflict here (missing authority, or a
    /// rollback with no surviving candidates), if they can't.
    pub blocked: Option<String>,
    /// Whether `a` (accept in place) applies: rollbacks are machine-local memory, so any
    /// local user may accept one; a tie is a real ambiguity in the vault itself and must
    /// pick a winner instead.
    pub acceptable: bool,
    /// Whether `s` (set a fresh value in place) applies: a rollback on a secret key — an
    /// ordinary set lands above the remembered watermark and clears the conflict.
    pub settable: bool,
    pub candidates: Vec<ConflictCandidateView>,
}

/// Project the session's conflicts for the Merge view: labels, candidate summaries + full
/// details, per-candidate decryptability for the acting user, and whether they hold the
/// authority to resolve each conflict.
pub fn build_merge(
    conflicts: &[thorax_ops::ConflictReport],
    state: &EffectiveState,
    crypto: &Crypto,
    acting: Option<&UserId>,
) -> Vec<ConflictView> {
    let user_label = |user: &UserId| {
        state
            .handles
            .values()
            .find(|handle| &handle.user_id == user)
            .map(|handle| format!("@{}", handle.handle))
            .unwrap_or_else(|| thorax_frontend::short_user_hex(user))
    };
    let principal_label = |principal: &PrincipalRefV1| match principal {
        PrincipalRefV1::User(user) => user_label(user),
        PrincipalRefV1::Group(group) => state
            .groups
            .get(group)
            .map(|record| format!("%{}", record.handle))
            .unwrap_or_else(|| format!("%{}", thorax_frontend::short_hash(&group.0))),
    };
    let group_label = |group: &thorax_ops::GroupId| {
        state
            .groups
            .get(group)
            .map(|record| format!("%{}", record.handle))
            .unwrap_or_else(|| format!("%{}", thorax_frontend::short_hash(&group.0)))
    };
    let candidate_view = |conflict: &thorax_ops::ConflictReport,
                          candidate: &thorax_ops::VaultRecordV1| {
        use thorax_ops::RecordBodyV1;
        let signer = state
            .user_for_signing_key(&candidate.signing_public_key)
            .map(user_label)
            .unwrap_or_else(|| "unknown signer".to_string());
        let mut details: Vec<(String, String)> = Vec::new();
        let mut selector = None;
        let mut decryptable = false;
        match candidate.body.known() {
            Some(RecordBodyV1::Secret(record)) => {
                let labels = selector_labels(&record.selector);
                details.push(("selector".into(), selector_path(&record.selector)));
                details.push((
                    "labels".into(),
                    if labels.is_empty() {
                        "—".into()
                    } else {
                        labels
                    },
                ));
                details.push((
                    "content".into(),
                    format!("{} bytes (sealed)", record.sealed.ciphertext.len()),
                ));
                details.push(("sealed to".into(), {
                    let mut recipients: Vec<_> = record
                        .sealed
                        .recipient_slots
                        .iter()
                        .map(|slot| user_label(&slot.recipient_id))
                        .collect();
                    recipients.sort();
                    recipients.join(" ╱ ")
                }));
                decryptable = match acting {
                    Some(user) => {
                        state.authority_for_user(user).can_read(&record.selector)
                            && record
                                .sealed
                                .recipient_slots
                                .iter()
                                .any(|slot| &slot.recipient_id == user)
                    }
                    None => false,
                };
                selector = Some(record.selector.clone());
            }
            Some(RecordBodyV1::SecretDeleted(record)) => {
                details.push(("deletes".into(), selector_path(&record.selector)));
                selector = Some(record.selector.clone());
            }
            Some(RecordBodyV1::Grant(record)) => {
                let (class, keyspace) = permission_columns(&record.permission);
                details.push(("subject".into(), principal_label(&record.subject_id)));
                details.push(("access".into(), class));
                details.push(("keyspace".into(), keyspace));
            }
            Some(RecordBodyV1::GrantDeleted(record)) => {
                let (class, keyspace) = permission_columns(&record.permission);
                details.push(("deletes grant".into(), format!("{class} on {keyspace}")));
            }
            Some(RecordBodyV1::User(record)) => {
                details.push(("user".into(), user_label(&record.id)));
                details.push(("id".into(), thorax_frontend::user_hex(&record.id)));
            }
            Some(RecordBodyV1::UserDeleted(record)) => {
                details.push(("deletes user".into(), user_label(&record.id)));
                if let Some(reason) = &record.reason {
                    details.push(("reason".into(), reason.clone()));
                }
            }
            Some(RecordBodyV1::UserHandle(record)) => {
                details.push(("handle".into(), format!("@{}", record.handle)));
                details.push(("assigned to".into(), user_label(&record.user_id)));
            }
            Some(RecordBodyV1::VaultHandle(record)) => {
                details.push(("vault name".into(), record.handle.clone()));
            }
            Some(RecordBodyV1::Group(record)) => {
                details.push(("group".into(), format!("%{}", record.handle)));
            }
            Some(RecordBodyV1::GroupDeleted(record)) => {
                details.push(("deletes group".into(), group_label(&record.id)));
            }
            Some(RecordBodyV1::GroupMember(record)) => {
                details.push(("group".into(), group_label(&record.group_id)));
                details.push(("adds member".into(), principal_label(&record.member_id)));
            }
            Some(RecordBodyV1::GroupMemberDeleted(record)) => {
                details.push(("group".into(), group_label(&record.group_id)));
                details.push(("removes member".into(), principal_label(&record.member_id)));
            }
            Some(RecordBodyV1::EntryPoint(record)) => {
                details.push(("pins root".into(), user_label(&record.trusted_root_user_id)));
            }
            Some(RecordBodyV1::VaultRoot(_)) | None => {}
        }
        details.push(("signed by".into(), signer.clone()));
        details.push(("counter".into(), conflict.counter.to_string()));
        details.push((
            "record".into(),
            thorax_frontend::short_hash(
                &thorax_ops::record_hash(crypto, candidate)
                    .unwrap_or(thorax_ops::HashValue(Vec::new())),
            ),
        ));
        ConflictCandidateView {
            pick: thorax_ops::record_hash(crypto, candidate)
                .unwrap_or(thorax_ops::HashValue(Vec::new())),
            summary: candidate
                .body
                .known()
                .map(thorax_frontend::candidate_summary)
                .unwrap_or_else(|| "unknown record".to_string()),
            signer,
            details,
            selector,
            decryptable,
        }
    };

    conflicts
        .iter()
        .map(|conflict| {
            let candidates = conflict
                .candidates
                .iter()
                .map(|candidate| candidate_view(conflict, candidate))
                .collect();
            let acceptable = matches!(conflict.kind, thorax_ops::ConflictKind::Rollback { .. });
            let settable = acceptable && matches!(conflict.key, RecordKey::Secret { .. });
            let blocked = if conflict.candidates.is_empty() {
                // A rollback whose records were dropped entirely: nothing here to ratify —
                // the in-place ways out are a fresh write (secret keys) and accepting it.
                Some(if settable {
                    "no surviving candidates ╱ [s] set a fresh value ╱ [a] accept the rollback"
                        .to_string()
                } else {
                    "no surviving candidates ╱ [a] accept the rollback".to_string()
                })
            } else {
                match acting {
                    None => Some("no identity selected".to_string()),
                    Some(acting) => conflict
                        .candidates
                        .first()
                        .and_then(|candidate| candidate.body.known())
                        .and_then(|body| {
                            // Human diagnostic, not `Display` — some OpsError variants embed
                            // debug-formatted ids that must never reach the screen.
                            thorax_ops::ensure_can_resolve_conflict(state, acting, conflict, body)
                                .err()
                                .map(|error| {
                                    thorax_frontend::diagnose(&thorax_frontend::FrontendError::Ops(
                                        error,
                                    ))
                                    .message
                                })
                        }),
                }
            };
            ConflictView {
                kind: thorax_frontend::record_key_kind(&conflict.key),
                conflict_kind: thorax_frontend::conflict_kind_name(&conflict.kind),
                label: thorax_frontend::conflict_label(conflict),
                counter: conflict.counter,
                summary: thorax_frontend::conflict_kind_summary(conflict),
                blocked,
                acceptable,
                settable,
                candidates,
            }
        })
        .collect()
}
