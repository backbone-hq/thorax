use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use ratatui::layout::Rect;

use thorax_frontend::{stored_default_user, FrontendError};
use thorax_ops::{
    resolve_user_ref, Crypto, EffectiveState, GrantId, GrantPermissionV1, GroupId, HashValue,
    KeyspaceSelectorV1, LockedSession, PrincipalRefV1, SecretSelectorV1, SecretState,
    TupleMatcherV1, UnlockedSession, UserId, UserRef, ValidationReport, WorkspacePaths,
};
use zeroize::Zeroizing;

use crate::project::{
    self, AccessModel, BlockReason, FacetFilter, FacetIndex, Health, SecretLeaf, SecretTree,
};
use crate::session::UnlockSession;

use super::msg::{ButtonAction, Effect, GetPurpose, GrantSubject, Modal, View};

pub(super) const REVEAL_SECS: u64 = 30;
pub(super) const CLIPBOARD_CLEAR_SECS: u64 = 20;
/// Auto-relock the session after this much inactivity.
pub(super) const IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// How long a transient status line lingers before auto-dismissing — errors stay longer so they
/// stay readable, but neither pins to the footer indefinitely.
pub(super) const STATUS_INFO_SECS: u64 = 4;
pub(super) const STATUS_ERROR_SECS: u64 = 9;
/// How often (at most) a `Tick` stats the vault file to notice external changes (a git pull,
/// another process). Cheap (len + mtime); a change triggers a full reload.
pub(super) const FRESHNESS_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTab {
    Users,
    Groups,
}

/// One row of the flattened, hierarchical access list (principals with their grants nested below).
#[derive(Clone, Debug)]
pub enum AccessRow {
    /// A user principal header. `idx` indexes `access.users`.
    User { idx: usize, expanded: bool },
    /// A group principal header. `idx` indexes `access.groups`.
    Group { idx: usize, expanded: bool },
    /// A grant held by the principal above (two columns: class + keyspace).
    Grant {
        class: String,
        keyspace: String,
        grant: Option<GrantId>,
    },
    /// A group membership line.
    Member { label: String },
    /// An informational "no grants yet" line under a principal.
    Note(String),
}

/// Keyboard focus within a view: either the list/tree, or one of the action-bar buttons (so arrows
/// and Tab can move onto the buttons, and Enter activates the focused one).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    List,
    Button(usize),
}

/// One row of the principal × read/write/manage access table.
#[derive(Clone, Debug)]
pub struct AccessMatrixRow {
    pub label: String,
    pub read: bool,
    pub write: bool,
    pub manage: bool,
}

/// A recorded clickable region.
#[derive(Clone, Copy, Debug)]
pub struct Button {
    pub rect: Rect,
    pub action: ButtonAction,
}

/// Which scrollable list a recorded [`ListRegion`] belongs to, so a click can select the right row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListKind {
    Secrets,
    Access,
    Merge,
}

/// The on-screen rect + scroll offset of a list, so a mouse click maps to a row index.
#[derive(Clone, Copy, Debug)]
pub struct ListRegion {
    pub kind: ListKind,
    pub rect: Rect,
    pub offset: usize,
}

/// One row of the flattened, currently-visible secret tree.
#[derive(Clone, Debug)]
pub enum Row {
    Branch {
        path: Vec<String>,
        label: String,
        depth: usize,
        expanded: bool,
        has_children: bool,
    },
    Leaf {
        depth: usize,
        /// Display name in the tree (the tuple's last segment, or labels when disambiguating).
        name: String,
        leaf: SecretLeaf,
    },
}

/// A currently-revealed secret value with its auto-remask deadline.
pub struct Reveal {
    pub selector: SecretSelectorV1,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub is_utf8: bool,
    pub expires_at: Instant,
}

/// One additional field's decrypted value. Unlike the primary, fields are shown in plaintext
/// without a reveal step (they carry data/metadata, not the headline secret), so there is no
/// per-field countdown.
pub struct RevealedField {
    pub key: String,
    pub value: Zeroizing<Vec<u8>>,
    pub is_utf8: bool,
}

/// The decrypted additional fields of the selected secret, eagerly loaded so the detail pane can
/// render them in plaintext. Keyed by selector so a stale load for another secret is ignored.
pub struct SecretFields {
    pub selector: SecretSelectorV1,
    pub fields: Vec<RevealedField>,
}

/// One revealed conflict-candidate value, keyed by record hash (several candidates share
/// one selector — that's what a conflict is).
pub struct MergeRevealValue {
    pub pick: HashValue,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub is_utf8: bool,
}

/// The revealed values of one conflict's candidates — revealing any candidate reveals every
/// one the user can decrypt, so the competing values can be compared directly, under a
/// single shared auto-remask deadline. Same discipline as [`Reveal`].
pub struct MergeReveal {
    pub values: Vec<MergeRevealValue>,
    pub expires_at: Instant,
}

impl MergeReveal {
    pub fn value_for(&self, pick: &HashValue) -> Option<&MergeRevealValue> {
        self.values.iter().find(|value| &value.pick == pick)
    }
}

/// One row of the Merge view's tree: a conflict header, or one of its candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergeRow {
    Conflict { conflict: usize },
    Candidate { conflict: usize, candidate: usize },
}

/// The model's vault session at its current trust tier. `Locked` is the pre-anchor
/// snapshot — it renders only behind the unlock gate and the block/join screens, and the
/// only mutation it offers is the machine-local rollback acceptance (recovery must stay
/// reachable without a membership pin). `Unlocked` is the promoted session every workspace
/// surface and every vault mutation runs on: possession-checked verifications plus the
/// membership pin, with the whole operation vocabulary as methods.
#[derive(Default)]
pub enum SessionState {
    /// No usable workspace (no vault, or no local trust yet).
    #[default]
    None,
    /// Loaded and validated, but not anchored to an unlocked identity.
    Locked(Box<LockedSession>),
    /// Anchored: the session type the rich ops API lives on.
    Unlocked(Box<UnlockedSession>),
}

impl SessionState {
    /// The underlying read snapshot at either tier.
    pub fn session(&self) -> Option<&LockedSession> {
        match self {
            SessionState::None => None,
            SessionState::Locked(session) => Some(session.as_ref()),
            SessionState::Unlocked(unlocked) => Some(unlocked.session()),
        }
    }

    pub fn exists(&self) -> bool {
        !matches!(self, SessionState::None)
    }

    pub fn unlocked_mut(&mut self) -> Option<&mut UnlockedSession> {
        match self {
            SessionState::Unlocked(unlocked) => Some(unlocked),
            _ => None,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        matches!(self, SessionState::Unlocked(_))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Status {
    pub text: String,
    pub is_error: bool,
}

impl Status {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: false,
        }
    }
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

pub struct Model {
    pub paths: WorkspacePaths,
    pub crypto: Crypto,

    // workspace
    /// The resolved vault snapshot at its trust tier: loaded once, read via `&self`,
    /// mutated through the `Unlocked` variant's operation methods.
    pub session: SessionState,
    pub block: Option<BlockReason>,
    pub workspace_error: Option<String>,
    pub vault_name: String,
    /// `(len, modified)` of the vault file as of the last load/commit — the cheap external-change
    /// probe `Tick` compares against. Correctness never depends on it (commits byte-compare under
    /// the workspace lock); it only keeps the view fresh after a git pull or another process.
    pub(super) vault_fingerprint: Option<(u64, std::time::SystemTime)>,
    pub(super) last_freshness_check: Instant,

    // projections (rebuilt by reproject)
    pub tree: SecretTree,
    pub facets: FacetIndex,
    pub facet_filter: FacetFilter,
    pub access: AccessModel,
    pub health: Health,
    /// Unresolved conflicts in the loaded vault — same-counter ties and suspected rollbacks
    /// alike, from the report's authority-aware set (raw + projected). Non-empty conflicts
    /// are what summon the alert-colored Merge tab.
    pub conflicts: Vec<thorax_ops::ConflictReport>,
    pub merge: Vec<project::ConflictView>,

    // ui
    pub view: View,
    pub access_tab: AccessTab,
    pub expanded: BTreeSet<Vec<String>>,
    /// Live fuzzy search over secret key paths (Secrets view). `search` is the query text, applied
    /// to the tree whether or not the bar is focused — so it survives Enter and keeps filtering
    /// while you navigate; empty means no filter. `searching` is true only while the one-line input
    /// bar captures keystrokes. While a query is active the tree shows every matching branch
    /// expanded (see [`Model::visible_rows`]) so scattered hits are immediately visible.
    pub search: String,
    pub searching: bool,
    /// Expanded principals in the access list, keyed by `u:<hex>` / `g:<hex>`.
    pub access_expanded: BTreeSet<String>,
    pub selected_row: usize,
    pub access_selected: usize,
    /// Selected row in the Merge view's conflict→candidate tree (indexes `merge_rows()`).
    pub merge_selected: usize,
    /// Revealed conflict-candidate values (Merge view), with their auto-remask deadline.
    pub merge_reveal: Option<MergeReveal>,
    /// After the next reload, select (and reveal in the tree) this secret — e.g. the one just
    /// created or edited, so the user lands on it instead of staying put.
    pub select_target: Option<SecretSelectorV1>,
    pub modal: Option<Modal>,
    pub status: Status,
    /// Auto-dismiss bookkeeping for the transient footer status: when the visible text was last
    /// seen, and when it should clear. Driven by `Tick` so any `status` assignment is covered
    /// without threading a timer through every call site.
    pub(super) status_seen: String,
    pub(super) status_expires: Option<Instant>,

    // identity / session
    pub acting: Option<UserId>,
    pub acting_label: Option<String>,
    /// A vault exists but this machine has no local identity for it (never joined): show the
    /// full-screen join screen instead of the unlock gate.
    pub needs_join: bool,
    pub unlock_session: UnlockSession,
    pub reveal: Option<Reveal>,
    /// Eagerly-loaded additional fields of the selected secret (shown in plaintext).
    pub secret_fields: Option<SecretFields>,
    pub clipboard_clear_at: Option<Instant>,
    /// Buffer + error for the full-screen unlock gate (shown whenever the session is locked).
    pub unlock_input: String,
    pub unlock_error: Option<String>,
    /// Last user activity, for idle auto-relock.
    pub last_active: Instant,

    // Keyboard focus (list vs. an action button) within the current view.
    pub focus: Focus,
    // Hit-test regions recorded by the renderer each frame, for mouse clicks.
    pub buttons: Vec<Button>,
    pub list_region: Option<ListRegion>,

    pub should_quit: bool,
    pub now: Instant,
    /// True only while the (synchronous, ~1–2s) unlock KDF is about to run: the event loop sets it,
    /// paints one "deriving key" frame of the jack-in gate, then runs the blocking unlock. Pure
    /// visual state — the unlock itself is unchanged, so the headless `update` tests never see it.
    pub deriving: bool,
}

impl Model {
    /// Load the workspace, validate, resolve the acting identity, and build projections.
    pub fn load(paths: WorkspacePaths) -> Self {
        let crypto = Crypto;
        let mut model = Model {
            paths,
            crypto,
            session: SessionState::None,
            block: None,
            workspace_error: None,
            vault_name: String::new(),
            vault_fingerprint: None,
            last_freshness_check: Instant::now(),
            tree: SecretTree::default(),
            facets: FacetIndex::default(),
            facet_filter: FacetFilter::default(),
            access: AccessModel::default(),
            health: Health::default(),
            conflicts: Vec::new(),
            merge: Vec::new(),
            view: View::Secrets,
            access_tab: AccessTab::Users,
            expanded: BTreeSet::new(),
            search: String::new(),
            searching: false,
            access_expanded: BTreeSet::new(),
            selected_row: 0,
            access_selected: 0,
            merge_selected: 0,
            merge_reveal: None,
            select_target: None,
            modal: None,
            status: Status::default(),
            status_seen: String::new(),
            status_expires: None,
            acting: None,
            acting_label: None,
            needs_join: false,
            unlock_session: UnlockSession::new(),
            reveal: None,
            secret_fields: None,
            clipboard_clear_at: None,
            unlock_input: String::new(),
            unlock_error: None,
            last_active: Instant::now(),
            focus: Focus::List,
            buttons: Vec::new(),
            list_region: None,
            should_quit: false,
            now: Instant::now(),
            deriving: false,
        };
        model.reload();
        // Expand top-level branches by default so the namespace is visible at a glance.
        let top: Vec<Vec<String>> = model.tree.roots.iter().map(|n| n.path.clone()).collect();
        model.expanded.extend(top);
        // A usable but locked workspace shows the full-screen unlock gate (see `is_unlock_gate`);
        // no further setup is needed — the gate renders whenever the session is locked.
        model
    }

    /// Whether the full-screen unlock gate should take over the screen: a usable workspace whose
    /// session is locked. Blocks all other actions until the passphrase is entered.
    pub fn is_unlock_gate(&self) -> bool {
        self.session.exists()
            && self.block.is_none()
            && self.workspace_error.is_none()
            && self.acting.is_some()
            && self.unlock_session.is_locked()
    }

    /// Whether the full-screen join screen should take over: a usable workspace exists but this
    /// machine has no local identity for it yet (you haven't joined). Offers claiming an invite.
    pub fn is_join_gate(&self) -> bool {
        self.needs_join && self.block.is_none() && self.workspace_error.is_none()
    }

    /// Whether the terminal's native text selection should be available. Mouse capture is useful
    /// for clicks, but it prevents drag-selecting sensitive material the user explicitly exposed.
    pub fn terminal_selection_enabled(&self) -> bool {
        self.reveal.is_some()
            || self.merge_reveal.is_some()
            || matches!(self.modal, Some(Modal::InviteBundle { .. }))
    }

    /// Promote a locked session to the cached unlocked identity, if both exist:
    /// possession-check the verifications and pin vault membership
    /// ([`UnlockedSession::with_identity`]). On failure the gate relocks with the error
    /// surfaced and the session reloads as `Locked` — the workspace must never render
    /// from a state the unlocked identity does not vouch for.
    ///
    /// A vault with blocking issues deliberately stays `Locked`: the block screens render
    /// the breakage, and the recovery actions they offer must not require a membership
    /// pin a broken vault cannot grant.
    pub fn promote_session_if_unlocked(&mut self) {
        if !matches!(&self.session, SessionState::Locked(session) if session.report().issues.is_empty())
        {
            return;
        }
        let Some(identity) = self.unlock_session.identity().cloned() else {
            return;
        };
        let SessionState::Locked(session) = std::mem::take(&mut self.session) else {
            unreachable!("checked above");
        };
        match UnlockedSession::with_identity(*session, &self.crypto, identity) {
            Ok(unlocked) => self.session = SessionState::Unlocked(Box::new(unlocked)),
            Err(error) => {
                // The failed promotion consumed the session; reload a fresh locked
                // snapshot so the gate and block screens still have state to render.
                self.unlock_session.lock();
                self.unlock_error = Some(thorax_frontend::diagnose(&error.into()).message);
                match LockedSession::load(&self.paths, &self.crypto) {
                    Ok(session) => self.session = SessionState::Locked(Box::new(session)),
                    Err(error) => self.workspace_error = Some(op_error(error)),
                }
            }
        }
    }

    /// Lock the session and drop anything sensitive on screen (revealed value, open editor). The
    /// next render shows the unlock gate.
    pub fn relock(&mut self) {
        if let SessionState::Unlocked(unlocked) = std::mem::take(&mut self.session) {
            self.session = SessionState::Locked(Box::new(unlocked.lock()));
        }
        self.unlock_session.lock();
        self.reveal = None;
        self.secret_fields = None;
        self.merge_reveal = None;
        self.modal = None;
        self.unlock_input.clear();
        self.unlock_error = None;
    }

    /// If a decryptable secret is selected under an unlocked session and its additional fields
    /// are not already loaded, the effect that loads them so the detail pane can show them in
    /// plaintext. Cheap (a local decrypt, no keychain prompt) and a no-op once loaded, so the
    /// dispatch loop can call it after every message.
    pub fn fields_sync_effect(&self) -> Option<Effect> {
        if !self.session.is_unlocked() {
            return None;
        }
        let leaf = self.selected_leaf()?;
        if leaf.state != thorax_ops::SecretState::ActiveDecryptable {
            return None;
        }
        if self
            .secret_fields
            .as_ref()
            .is_some_and(|loaded| loaded.selector == leaf.selector)
        {
            return None;
        }
        Some(Effect::GetSecret {
            selector: leaf.selector,
            purpose: GetPurpose::Fields,
        })
    }

    /// Re-read the vault from disk into a fresh [`LockedSession`] (one validation), resolve
    /// identity, and reproject. Used on start, when joining/initializing, and when the external
    /// freshness probe notices the vault file changed. Mutations do NOT come through here — a
    /// committed session is already post-state, so they run [`Model::refresh_from_session`] only.
    pub fn reload(&mut self) {
        match LockedSession::load(&self.paths, &self.crypto) {
            Ok(session) => {
                self.session = SessionState::Locked(Box::new(session));
                // While unlocked, every fresh load is re-promoted before anything renders
                // from it; locked loads sit behind the unlock gate anyway.
                self.promote_session_if_unlocked();
                self.refresh_from_session();
            }
            Err(error) => {
                self.session = SessionState::None;
                self.vault_fingerprint = None;
                self.conflicts.clear();
                self.merge.clear();
                // A vault exists on disk but this machine has no local trust for its root yet
                // (a fresh clone / never joined): that's the join screen, not "no vault".
                if matches!(error, thorax_ops::OpsError::MissingRatchet(_)) {
                    self.needs_join = true;
                    self.workspace_error = None;
                    self.acting = None;
                    self.acting_label = None;
                    self.vault_name = self
                        .paths
                        .root
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("thorax")
                        .to_string();
                } else {
                    self.needs_join = false;
                    self.workspace_error = Some(op_error(error));
                }
            }
        }
    }

    /// Re-derive everything the model holds besides the session itself — vault name, block
    /// reason, acting identity, conflicts, projections, selection — from the current session. Runs
    /// after a fresh load and after every successful commit (the session is already at the
    /// post-commit state, so no re-read or re-validation happens here).
    pub fn refresh_from_session(&mut self) {
        // Take the session state out so its report can be read while `self` is mutated.
        let state = std::mem::take(&mut self.session);
        let Some(session) = state.session() else {
            self.session = state;
            return;
        };
        self.vault_name = vault_name(session.effective(), &self.paths);
        self.block = project::block_reason(session.report());
        self.resolve_acting(session.report());
        // The report's `conflicted` set is the authority-aware source of truth — same-counter
        // ties and rollback conflicts alike — so the Conflicts tab agrees with the read path
        // (not the raw merge-driver scan). They summon the Merge tab; resolving the last one
        // (or an external fix) dismisses it.
        self.conflicts = session
            .report()
            .effective
            .conflicted
            .values()
            .cloned()
            .collect();
        self.session = state;
        self.workspace_error = None;
        self.vault_fingerprint = vault_file_fingerprint(&self.paths);
        self.reproject();
        self.merge_reveal = None;
        // The value (and thus its fields) may have changed; drop the eager load so the next
        // dispatch refetches for whatever is now selected.
        self.secret_fields = None;
        let rows = self.merge_rows().len();
        if self.merge_selected >= rows {
            self.merge_selected = rows.saturating_sub(1);
        }
        if self.view == View::Merge && self.merge.is_empty() {
            self.view = View::Secrets;
        }
        // Land on a just-created/edited secret if one was queued.
        if let Some(target) = self.select_target.take() {
            self.navigate_to(&target);
        }
    }

    fn resolve_acting(&mut self, report: &ValidationReport) {
        self.acting = None;
        self.acting_label = None;
        self.needs_join = false;
        // The acting identity is whatever this machine last established for this root (via init or
        // a prior claim). There is deliberately no "act as root by default" fallback: if there is
        // no local identity, you are not a member here yet → the join screen, not a borrowed root.
        let root = report.effective.root_signing_public_key_hash.clone();
        let stored = root
            .as_ref()
            .and_then(|root| stored_default_user(&self.paths, root).ok().flatten());
        if let Some(stored) = &stored {
            // Try as a handle, then as a raw 64-hex user id.
            let label = &stored.user_ref;
            let resolved = resolve_user_ref(report, &self.crypto, UserRef::Handle(label.clone()))
                .ok()
                .or_else(|| {
                    parse_user_id(label)
                        .and_then(|id| resolve_user_ref(report, &self.crypto, UserRef::Id(id)).ok())
                });
            if let Some(r) = resolved {
                self.acting = Some(r.user_id);
                self.acting_label = r.handle.or_else(|| Some(stored.display.clone()));
                return;
            }
        }
        // No usable local identity for this vault → onboarding via the join screen.
        self.needs_join = true;
    }

    /// Rebuild all view projections from the current session + facets + viewer.
    pub fn reproject(&mut self) {
        let Some(session) = self.session.session() else {
            return;
        };
        let report = session.report();
        let state = &report.effective;
        self.facets = project::facet_index(state);
        self.tree = project::build_tree(
            state,
            &self.crypto,
            self.acting.as_ref(),
            &self.facet_filter,
            &self.search,
        );
        self.access = project::build_access(state);
        self.health = project::build_health(state, report, session.ratchet(), &self.crypto);
        self.merge =
            project::build_merge(&self.conflicts, state, &self.crypto, self.acting.as_ref());
        let rows = self.visible_rows().len();
        if self.selected_row >= rows && rows > 0 {
            self.selected_row = rows - 1;
        }
    }

    /// Switch to the Secrets view, expand the secret's ancestor branches, and select its row — used
    /// to land on a secret just created or edited.
    fn navigate_to(&mut self, selector: &SecretSelectorV1) {
        self.view = View::Secrets;
        for i in 1..=selector.tuple.len() {
            self.expanded.insert(selector.tuple[..i].to_vec());
        }
        if let Some(idx) = self
            .visible_rows()
            .into_iter()
            .position(|row| matches!(row, Row::Leaf { leaf, .. } if leaf.selector == *selector))
        {
            self.selected_row = idx;
        }
    }

    pub fn verified(&self) -> bool {
        self.block.is_none()
            && self
                .session
                .session()
                .map(|s| s.report().issues.is_empty())
                .unwrap_or(false)
    }

    pub fn effective(&self) -> Option<&EffectiveState> {
        self.session.session().map(|s| s.effective())
    }

    // ── tree navigation ────────────────────────────────────────────────────

    /// Flatten the tree into the rows currently visible given the expansion set.
    pub fn visible_rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        // An active search prunes the tree to matching leaves only, so every remaining branch
        // leads to a hit: expand them all so scattered matches show without disturbing (or
        // requiring) the user's saved expansion set, which is restored verbatim once search clears.
        let expand_all = !self.search.is_empty();
        for node in &self.tree.roots {
            push_rows(node, 0, &self.expanded, expand_all, &mut rows);
        }
        rows
    }

    /// Put the selection on the first secret leaf of the current (filtered) tree, falling back to
    /// the top row when none is visible. Called as a search query changes so a typed filter lands
    /// on an actual hit rather than the auto-expanded parent branch above it — then Enter hands the
    /// list a selection that `r`/`y`/`e`/`d` can act on.
    pub(super) fn select_first_leaf(&mut self) {
        self.selected_row = self
            .visible_rows()
            .iter()
            .position(|row| matches!(row, Row::Leaf { .. }))
            .unwrap_or(0);
    }

    pub fn selected_leaf(&self) -> Option<SecretLeaf> {
        match self.visible_rows().into_iter().nth(self.selected_row) {
            Some(Row::Leaf { leaf, .. }) => Some(leaf),
            _ => None,
        }
    }

    /// Who can read/write/manage a given target (a secret selector, or a namespace represented as a
    /// selector with the prefix tuple). Includes any principal with at least one of the three.
    pub fn access_matrix(&self, selector: &SecretSelectorV1) -> Vec<AccessMatrixRow> {
        let Some(state) = self.effective() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for u in &self.access.users {
            let a = state.authority_for_user(&u.user_id);
            let (read, write, manage) = (
                a.can_read(selector),
                a.can_write(selector),
                a.can_manage(selector),
            );
            if read || write || manage {
                out.push(AccessMatrixRow {
                    label: u.label(),
                    read,
                    write,
                    manage,
                });
            }
        }
        for g in &self.access.groups {
            let a = state.authority_for_group(&g.group_id);
            let (read, write, manage) = (
                a.can_read(selector),
                a.can_write(selector),
                a.can_manage(selector),
            );
            if read || write || manage {
                out.push(AccessMatrixRow {
                    label: format!("%{}", g.handle),
                    read,
                    write,
                    manage,
                });
            }
        }
        out
    }

    /// For a namespace prefix: (number of secrets under it, sorted labels of who can read them).
    pub fn namespace_summary(&self, prefix: &[String]) -> (usize, Vec<String>) {
        let Some(state) = self.effective() else {
            return (0, Vec::new());
        };
        let mut count = 0usize;
        let mut readers = std::collections::BTreeSet::new();
        for selector in project::value_selectors(state) {
            if selector.tuple.starts_with(prefix) {
                count += 1;
                for r in state.current_reader_entries(&selector) {
                    readers.insert(self.user_label(&r));
                }
            }
        }
        (count, readers.into_iter().collect())
    }

    /// Whether the currently-selected secret is the one being revealed.
    pub fn is_selected_revealed(&self) -> bool {
        match (self.selected_leaf(), self.reveal.as_ref()) {
            (Some(leaf), Some(r)) => r.selector == leaf.selector,
            _ => false,
        }
    }

    /// The ordered action-bar buttons for the current view/tab (drawn, click-mapped, and focusable).
    pub fn view_buttons(&self) -> Vec<ButtonAction> {
        match self.view {
            View::Secrets => {
                let mut b = vec![ButtonAction::NewSecret];
                if let Some(leaf) = self.selected_leaf() {
                    // Reveal/Edit only for secrets you can actually decrypt; when already revealed,
                    // offer Hide instead of Reveal.
                    if leaf.state == SecretState::ActiveDecryptable {
                        if self.is_selected_revealed() {
                            b.push(ButtonAction::HideSecret);
                        } else {
                            b.push(ButtonAction::RevealSecret);
                        }
                        b.push(ButtonAction::EditSecret);
                        // Moving re-keys the secret (its labels/tuple are its identity), so it
                        // needs the plaintext to re-seal — only offered when you can decrypt it.
                        b.push(ButtonAction::Relabel);
                    }
                    b.push(ButtonAction::DeleteSecret);
                    // Delegate on this specific secret, if you hold delegable authority over it.
                    if self.can_grant_on(&leaf.selector.tuple) {
                        b.push(ButtonAction::GrantHere);
                    }
                } else if let Some(path) = self.selected_branch_path() {
                    // On a namespace: offer to grant access here, if you can.
                    if self.can_grant_on(&path) {
                        b.push(ButtonAction::GrantHere);
                    }
                }
                b
            }
            View::Access => match self.access_tab {
                AccessTab::Users => {
                    // Note: no Claim here — joining/establishing your own identity is a startup
                    // action (the join screen), not a mid-session management action on others.
                    let mut b = vec![ButtonAction::InviteUser];
                    match self.selected_access_row() {
                        // A grant child is selected → it can be deleted.
                        Some(AccessRow::Grant { grant: Some(_), .. }) => {
                            b.push(ButtonAction::DeleteGrant)
                        }
                        // A user header is selected → grant to them / delete them.
                        Some(AccessRow::User { .. }) => {
                            b.push(ButtonAction::NewGrant);
                            b.push(ButtonAction::DeleteUser);
                        }
                        _ => {}
                    }
                    b
                }
                AccessTab::Groups => {
                    let mut b = vec![ButtonAction::NewGroup];
                    match self.selected_access_row() {
                        Some(AccessRow::Grant { grant: Some(_), .. }) => {
                            b.push(ButtonAction::DeleteGrant)
                        }
                        Some(AccessRow::Group { .. }) => {
                            b.push(ButtonAction::NewGrant);
                            b.push(ButtonAction::AddMember);
                            b.push(ButtonAction::DeleteAccess);
                        }
                        _ => {}
                    }
                    b
                }
            },
            // Buttons act on the selected *candidate*: reveal its value (secret candidates
            // the user can decrypt), and resolve — offered only when the acting user holds
            // the authority for the conflict; blocked conflicts show the reason in the
            // detail pane.
            View::Merge => match self.selected_merge_candidate() {
                Some((conflict, candidate)) => {
                    let mut b = Vec::new();
                    if candidate.decryptable {
                        if self.is_selected_merge_revealed() {
                            b.push(ButtonAction::HideSecret);
                        } else {
                            b.push(ButtonAction::RevealSecret);
                        }
                    }
                    if conflict.blocked.is_none() {
                        b.push(ButtonAction::ResolveConflict);
                    }
                    b
                }
                None => Vec::new(),
            },
        }
    }

    /// The flattened conflict→candidate tree of the Merge view (conflicts always expanded —
    /// the candidates *are* the decision, hiding them would only add a step).
    pub fn merge_rows(&self) -> Vec<MergeRow> {
        let mut rows = Vec::new();
        for (conflict, view) in self.merge.iter().enumerate() {
            rows.push(MergeRow::Conflict { conflict });
            for candidate in 0..view.candidates.len() {
                rows.push(MergeRow::Candidate {
                    conflict,
                    candidate,
                });
            }
        }
        rows
    }

    pub fn selected_merge_row(&self) -> Option<MergeRow> {
        if self.view != View::Merge {
            return None;
        }
        self.merge_rows().into_iter().nth(self.merge_selected)
    }

    /// The selected candidate (conflict view + candidate view), when a candidate row is selected.
    pub fn selected_merge_candidate(
        &self,
    ) -> Option<(&project::ConflictView, &project::ConflictCandidateView)> {
        match self.selected_merge_row()? {
            MergeRow::Candidate {
                conflict,
                candidate,
            } => {
                let view = self.merge.get(conflict)?;
                Some((view, view.candidates.get(candidate)?))
            }
            MergeRow::Conflict { .. } => None,
        }
    }

    /// The raw conflict report behind a selected conflict *header* row — what the in-place
    /// actions (accept, set fresh) act on. `conflicts` and `merge` are index-aligned
    /// (`build_merge` maps the reports one to one).
    pub fn selected_conflict_header(&self) -> Option<&thorax_ops::ConflictReport> {
        match self.selected_merge_row()? {
            MergeRow::Conflict { conflict } => self.conflicts.get(conflict),
            MergeRow::Candidate { .. } => None,
        }
    }

    /// The projected view of the selected conflict header row, for contextual action hints.
    pub fn selected_conflict_view(&self) -> Option<&project::ConflictView> {
        match self.selected_merge_row()? {
            MergeRow::Conflict { conflict } => self.merge.get(conflict),
            MergeRow::Candidate { .. } => None,
        }
    }

    /// Whether the selected merge candidate is among the currently revealed values.
    pub fn is_selected_merge_revealed(&self) -> bool {
        match (self.selected_merge_candidate(), self.merge_reveal.as_ref()) {
            (Some((_, candidate)), Some(reveal)) => reveal.value_for(&candidate.pick).is_some(),
            _ => false,
        }
    }

    /// Stable key for a principal's expansion state.
    fn user_key(user: &UserId) -> String {
        format!("u:{}", thorax_frontend::user_hex(user))
    }
    fn group_key(group: &GroupId) -> String {
        format!("g:{}", thorax_frontend::short_hash(&group.0))
    }

    /// The flattened, hierarchical rows for the current Access tab.
    pub fn access_rows(&self) -> Vec<AccessRow> {
        let mut rows = Vec::new();
        match self.access_tab {
            AccessTab::Users => {
                for (idx, u) in self.access.users.iter().enumerate() {
                    let expanded = self.access_expanded.contains(&Self::user_key(&u.user_id));
                    rows.push(AccessRow::User { idx, expanded });
                    if expanded {
                        for g in &u.grants {
                            rows.push(AccessRow::Grant {
                                class: g.class.clone(),
                                keyspace: g.keyspace.clone(),
                                grant: g.grant_id.clone(),
                            });
                        }
                        for m in &u.group_memberships {
                            rows.push(AccessRow::Member {
                                label: format!("in group {m}"),
                            });
                        }
                        if u.grants.is_empty() && u.group_memberships.is_empty() {
                            rows.push(AccessRow::Note("no grants".to_string()));
                        }
                    }
                }
            }
            AccessTab::Groups => {
                for (idx, g) in self.access.groups.iter().enumerate() {
                    let expanded = self.access_expanded.contains(&Self::group_key(&g.group_id));
                    rows.push(AccessRow::Group { idx, expanded });
                    if expanded {
                        for grant in &g.grants {
                            rows.push(AccessRow::Grant {
                                class: grant.class.clone(),
                                keyspace: grant.keyspace.clone(),
                                grant: grant.grant_id.clone(),
                            });
                        }
                        for m in &g.members {
                            rows.push(AccessRow::Member {
                                label: format!("member {m}"),
                            });
                        }
                        if g.grants.is_empty() && g.members.is_empty() {
                            rows.push(AccessRow::Note("no grants or members".to_string()));
                        }
                    }
                }
            }
        }
        rows
    }

    fn selected_access_row(&self) -> Option<AccessRow> {
        if self.view != View::Access {
            return None;
        }
        self.access_rows().into_iter().nth(self.access_selected)
    }

    /// The user principal selected (a User header row), if any.
    pub fn selected_user(&self) -> Option<UserId> {
        match self.selected_access_row()? {
            AccessRow::User { idx, .. } => self.access.users.get(idx).map(|u| u.user_id.clone()),
            _ => None,
        }
    }

    /// The group principal selected (a Group header row), if any.
    pub fn selected_group(&self) -> Option<GroupId> {
        match self.selected_access_row()? {
            AccessRow::Group { idx, .. } => self.access.groups.get(idx).map(|g| g.group_id.clone()),
            _ => None,
        }
    }

    /// The (deletable) grant selected — a Grant child row with a real grant id.
    pub fn selected_grant(&self) -> Option<GrantId> {
        match self.selected_access_row()? {
            AccessRow::Grant { grant, .. } => grant,
            _ => None,
        }
    }

    /// The principal (user or group) the selected row belongs to, for "grant to this principal".
    pub fn selected_principal(&self) -> Option<PrincipalRefV1> {
        if let Some(u) = self.selected_user() {
            return Some(PrincipalRefV1::User(u));
        }
        self.selected_group().map(PrincipalRefV1::Group)
    }

    /// Expansion key of the selected access principal (User/Group header), if any.
    fn selected_access_key(&self) -> Option<String> {
        match self.selected_access_row()? {
            AccessRow::User { idx, .. } => self
                .access
                .users
                .get(idx)
                .map(|u| Self::user_key(&u.user_id)),
            AccessRow::Group { idx, .. } => self
                .access
                .groups
                .get(idx)
                .map(|g| Self::group_key(&g.group_id)),
            _ => None,
        }
    }

    /// Toggle expansion of the selected access principal.
    pub(super) fn toggle_access(&mut self) {
        if let Some(key) = self.selected_access_key() {
            if !self.access_expanded.insert(key.clone()) {
                self.access_expanded.remove(&key);
            }
        }
    }

    /// Collapse the selected access principal.
    pub(super) fn collapse_access(&mut self) {
        if let Some(key) = self.selected_access_key() {
            self.access_expanded.remove(&key);
        }
    }

    /// The namespace (branch) path selected in the Secrets tree, if any.
    pub fn selected_branch_path(&self) -> Option<Vec<String>> {
        if self.view != View::Secrets {
            return None;
        }
        match self.visible_rows().into_iter().nth(self.selected_row) {
            Some(Row::Branch { path, .. }) => Some(path),
            _ => None,
        }
    }

    /// Whether the acting user can hand out access on `path` (so a "grant here" button is offered).
    pub fn can_grant_on(&self, path: &[String]) -> bool {
        let (Some(acting), Some(state)) = (self.acting.as_ref(), self.effective()) else {
            return false;
        };
        let auth = state.authority_for_user(acting);
        let ks = KeyspaceSelectorV1 {
            tuple: TupleMatcherV1::Prefix(path.to_vec()),
            labels: Vec::new(),
        };
        auth.can_create_permission(&GrantPermissionV1::ReadKeyspace(ks.clone()))
            || auth.can_create_permission(&GrantPermissionV1::WriteKeyspace(ks))
    }

    /// Candidate subjects (users + groups) for the grant form.
    pub fn grant_subjects(&self) -> Vec<GrantSubject> {
        let mut out = Vec::new();
        for u in &self.access.users {
            out.push(GrantSubject {
                label: u.label(),
                principal: PrincipalRefV1::User(u.user_id.clone()),
            });
        }
        for g in &self.access.groups {
            out.push(GrantSubject {
                label: format!("%{}", g.handle),
                principal: PrincipalRefV1::Group(g.group_id.clone()),
            });
        }
        out
    }

    /// Human label for a user (handle if known, else short hex).
    pub fn user_label(&self, user: &UserId) -> String {
        self.access
            .users
            .iter()
            .find(|u| &u.user_id == user)
            .map(|u| u.label())
            .unwrap_or_else(|| thorax_frontend::short_user_hex(user))
    }

    pub(super) fn move_selection(&mut self, delta: isize) {
        let len = match self.view {
            View::Secrets => self.visible_rows().len(),
            View::Access => self.access_len(),
            View::Merge => self.merge_rows().len(),
        };
        if len == 0 {
            return;
        }
        let cur = match self.view {
            View::Access => self.access_selected,
            View::Merge => self.merge_selected,
            _ => self.selected_row,
        } as isize;
        let next = (cur + delta).clamp(0, len as isize - 1) as usize;
        match self.view {
            View::Access => self.access_selected = next,
            View::Merge => self.merge_selected = next,
            _ => self.selected_row = next,
        }
    }

    fn access_len(&self) -> usize {
        self.access_rows().len()
    }

    pub(super) fn toggle_open(&mut self) {
        if self.view != View::Secrets {
            return;
        }
        if let Some(Row::Branch { path, expanded, .. }) =
            self.visible_rows().into_iter().nth(self.selected_row)
        {
            if expanded {
                self.expanded.remove(&path);
            } else {
                self.expanded.insert(path);
            }
        }
    }

    pub(super) fn collapse(&mut self) {
        if self.view != View::Secrets {
            return;
        }
        if let Some(Row::Branch {
            path,
            expanded: true,
            ..
        }) = self.visible_rows().into_iter().nth(self.selected_row)
        {
            self.expanded.remove(&path);
        }
    }

    // ── session ──────────────────────────────────────────────────────────────
}

fn push_rows(
    node: &project::TreeNode,
    depth: usize,
    expanded: &BTreeSet<Vec<String>>,
    expand_all: bool,
    out: &mut Vec<Row>,
) {
    let has_children = !node.children.is_empty();

    // The common case — a tuple holds exactly one secret and nothing deeper — renders the node
    // itself as the secret leaf (named by its segment), so there is no extra "(no labels)" level.
    // Its labels are shown in the detail pane.
    if !has_children && node.leaves.len() == 1 {
        out.push(Row::Leaf {
            depth,
            name: node.segment.clone(),
            leaf: node.leaves[0].clone(),
        });
        return;
    }

    let is_expanded = expand_all || expanded.contains(&node.path);
    out.push(Row::Branch {
        path: node.path.clone(),
        label: node.segment.clone(),
        depth,
        expanded: is_expanded,
        has_children: true,
    });
    if is_expanded {
        for child in &node.children {
            push_rows(child, depth + 1, expanded, expand_all, out);
        }
        // Multiple secrets share this tuple (or a secret sits at a tuple that also has children):
        // disambiguate them by their labels.
        for leaf in &node.leaves {
            let name = if leaf.selector.labels.is_empty() {
                "(default)".to_string()
            } else {
                project::selector_labels(&leaf.selector)
            };
            out.push(Row::Leaf {
                depth: depth + 1,
                name,
                leaf: leaf.clone(),
            });
        }
    }
}

/// The cheap external-change probe: `(len, modified)` of the vault file, `None` if unreadable.
pub(super) fn vault_file_fingerprint(
    paths: &WorkspacePaths,
) -> Option<(u64, std::time::SystemTime)> {
    let meta = std::fs::metadata(&paths.vault_path).ok()?;
    Some((meta.len(), meta.modified().ok()?))
}

fn vault_name(state: &EffectiveState, paths: &WorkspacePaths) -> String {
    if let Some(handle) = state.vault_handles.values().next() {
        return format!("@{}", handle.handle);
    }
    paths
        .root
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("thorax")
        .to_string()
}

fn parse_user_id(label: &str) -> Option<UserId> {
    if label.len() != 64 || !label.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(32);
    let raw = label.as_bytes();
    for pair in raw.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        bytes.push((hi * 16 + lo) as u8);
    }
    Some(UserId(HashValue(bytes)))
}

/// Render any error that converts into a [`FrontendError`] (ops/store/keychain/frontend) as a human
/// one-liner via the shared diagnostics layer.
pub(super) fn op_error(error: impl Into<FrontendError>) -> String {
    thorax_frontend::diagnose(&error.into()).message
}
