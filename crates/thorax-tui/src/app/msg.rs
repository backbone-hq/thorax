use thorax_ops::{
    GrantId, GrantPermissionV1, GroupId, HashValue, KeyspaceGrantClassV1, KeyspaceSelectorV1,
    ManageKeyspaceGrantV1, PrincipalRefV1, RecordKey, SecretSelectorV1, TupleMatcherV1, UserId,
};
use zeroize::Zeroizing;

use super::model::{AccessTab, MergeRevealValue, RevealedField};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum View {
    Secrets,
    Access,
    /// Merge-conflict resolution. The tab exists only while the loaded vault carries
    /// unresolved conflicts; resolving the last one removes it.
    Merge,
}

/// A clickable on-screen action, recorded by the renderer with its hit-rect (see [`Model::buttons`])
/// so mouse clicks can be routed to the same handlers as the keyboard shortcuts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ButtonAction {
    SwitchView(View),
    AccessTab(AccessTab),
    NewSecret,
    EditSecret,
    Relabel,
    DeleteSecret,
    RevealSecret,
    HideSecret,
    InviteUser,
    DeleteUser,
    NewGrant,
    GrantHere,
    DeleteGrant,
    NewGroup,
    AddMember,
    DeleteAccess,
    ResolveConflict,
}

impl ButtonAction {
    /// The label drawn inside the `[ … ]` button.
    pub fn label(self) -> &'static str {
        match self {
            ButtonAction::SwitchView(View::Secrets) => "Secrets",
            ButtonAction::SwitchView(View::Access) => "Access",
            ButtonAction::SwitchView(View::Merge) => "Conflicts",
            ButtonAction::AccessTab(AccessTab::Users) => "Users",
            ButtonAction::AccessTab(AccessTab::Groups) => "Groups",
            ButtonAction::NewSecret => "+ New",
            ButtonAction::EditSecret => "Edit",
            ButtonAction::Relabel => "Move",
            ButtonAction::DeleteSecret => "Delete",
            ButtonAction::RevealSecret => "Reveal",
            ButtonAction::HideSecret => "Hide",
            ButtonAction::InviteUser => "+ Invite",
            ButtonAction::DeleteUser => "Delete",
            ButtonAction::NewGrant => "+ Grant",
            ButtonAction::GrantHere => "+ Delegate",
            ButtonAction::DeleteGrant => "Delete",
            ButtonAction::NewGroup => "+ Group",
            ButtonAction::AddMember => "+ Member",
            ButtonAction::DeleteAccess => "Delete",
            ButtonAction::ResolveConflict => "Resolve",
        }
    }

    pub(super) fn into_message(self) -> Message {
        match self {
            ButtonAction::SwitchView(v) => Message::SwitchView(v),
            ButtonAction::AccessTab(t) => Message::SetAccessTab(t),
            ButtonAction::NewSecret => Message::StartNewSecret,
            ButtonAction::EditSecret => Message::StartEdit,
            ButtonAction::Relabel => Message::StartRelabel,
            ButtonAction::DeleteSecret => Message::RequestDeleteSecret,
            ButtonAction::RevealSecret => Message::Reveal,
            ButtonAction::HideSecret => Message::HideReveal,
            ButtonAction::InviteUser => Message::StartInvite,
            ButtonAction::DeleteUser => Message::RequestUserDelete,
            ButtonAction::NewGrant => Message::StartGrant,
            ButtonAction::GrantHere => Message::StartGrant,
            ButtonAction::DeleteGrant => Message::RequestAccessDelete,
            ButtonAction::NewGroup => Message::StartGroup,
            ButtonAction::AddMember => Message::StartAddMember,
            ButtonAction::DeleteAccess => Message::RequestAccessDelete,
            ButtonAction::ResolveConflict => Message::RequestResolveConflict,
        }
    }
}

/// Modal overlays. The active modal owns keyboard focus. (The unlock gate is not a modal — it is a
/// full-screen state driven by [`Model::is_unlock_gate`].)
pub enum Modal {
    Help,
    /// Workspace health/diagnostics (validation, inventory, stale secrets, session) — opened with
    /// `H`, not a top-level view.
    Health,
    /// A destructive confirmation with a consequence preview.
    Confirm {
        title: String,
        lines: Vec<String>,
        action: ConfirmAction,
    },
    /// A private invite bundle shown after creating a user. While visible, mouse capture is
    /// released so terminal text selection works, and `y` copies it through the clipboard effect.
    InviteBundle {
        encoded: String,
    },
    /// Multi-line in-memory value editor (never spills to disk).
    Editor {
        title: String,
        selector: SecretSelectorV1,
        textarea: Box<ratatui_textarea::TextArea<'static>>,
    },
    /// Guided multi-field form (new secret, move, claim, invite, group, init). Structured like
    /// the grant form: labeled fields, the focused one accented, ↑↓/Tab to move between them.
    Form(Box<Form>),
    /// Guided form for creating a grant (pick subject + access + keyspace).
    Grant(Box<GrantForm>),
    /// Pick a principal to add to a group.
    Member(Box<MemberForm>),
    /// Label filter picker: one row per label key, `←→` chooses a value (or "any"), AND-combined.
    /// `focus` is the selected key row. Reads `facets` / writes `facet_filter` live.
    Facet {
        focus: usize,
    },
}

/// State for the add-member-to-group form.
#[derive(Clone, Debug)]
pub struct MemberForm {
    pub group_id: GroupId,
    pub group_label: String,
    pub candidates: Vec<GrantSubject>,
    pub idx: usize,
    pub error: Option<String>,
}

/// A selectable grant subject (user or group) with a display label.
#[derive(Clone, Debug)]
pub struct GrantSubject {
    pub label: String,
    pub principal: PrincipalRefV1,
}

/// The four access classes a grant can confer.
pub const GRANT_CLASSES: [&str; 4] = ["read", "write", "manage", "administer"];

/// State for the grant-creation form.
#[derive(Clone, Debug)]
pub struct GrantForm {
    pub subjects: Vec<GrantSubject>,
    pub subject_idx: usize,
    pub class_idx: usize,
    pub keyspace: String,
    /// Focused field: 0 = subject, 1 = access, 2 = keyspace.
    pub field: usize,
    pub error: Option<String>,
}

impl GrantForm {
    pub fn is_admin(&self) -> bool {
        self.class_idx == 3
    }

    /// Build the (subject, permission) pair, or an error message.
    pub(super) fn build(&self) -> Result<(PrincipalRefV1, GrantPermissionV1), String> {
        let subject = self
            .subjects
            .get(self.subject_idx)
            .ok_or("pick a subject")?
            .principal
            .clone();
        let keyspace = || -> Result<KeyspaceSelectorV1, String> {
            let tuple: Vec<String> = self
                .keyspace
                .split('/')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if tuple.is_empty() {
                return Err("enter a keyspace path, e.g. app/prod".to_string());
            }
            Ok(KeyspaceSelectorV1 {
                tuple: TupleMatcherV1::Prefix(tuple),
                labels: Vec::new(),
            })
        };
        let permission = match self.class_idx {
            0 => GrantPermissionV1::ReadKeyspace(keyspace()?),
            1 => GrantPermissionV1::WriteKeyspace(keyspace()?),
            2 => GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: keyspace()?,
                grantable: vec![
                    KeyspaceGrantClassV1::Read,
                    KeyspaceGrantClassV1::Write,
                    KeyspaceGrantClassV1::Manage,
                ],
            }),
            _ => GrantPermissionV1::Administer,
        };
        Ok((subject, permission))
    }
}

/// One labeled field in a [`Form`]. A focused field shows a cursor; `masked` renders the value as
/// dots (passphrases); `placeholder` is shown dim when the field is empty.
#[derive(Clone, Debug)]
pub struct FormField {
    pub label: String,
    pub value: String,
    pub placeholder: String,
    pub masked: bool,
}

impl FormField {
    pub fn text(label: &str, placeholder: &str) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            placeholder: placeholder.into(),
            masked: false,
        }
    }
    pub fn prefilled(label: &str, value: String) -> Self {
        Self {
            label: label.into(),
            value,
            placeholder: String::new(),
            masked: false,
        }
    }
    pub fn secret(label: &str, placeholder: &str) -> Self {
        Self {
            label: label.into(),
            value: String::new(),
            placeholder: placeholder.into(),
            masked: true,
        }
    }
}

/// A guided multi-field form. The focused field accepts typing; ↑↓/Tab move between fields.
#[derive(Clone, Debug)]
pub struct Form {
    pub title: String,
    pub fields: Vec<FormField>,
    pub focus: usize,
    pub error: Option<String>,
    /// Non-error guidance shown beneath the fields (e.g. a move consequence warning).
    pub note: Option<String>,
    /// The footer verb, e.g. "create" / "next" — shown as "Enter <verb>".
    pub submit_verb: String,
    pub then: FormThen,
}

impl Form {
    /// The trimmed value of field `i`, or empty.
    pub(super) fn value(&self, i: usize) -> String {
        self.fields
            .get(i)
            .map(|f| f.value.trim().to_string())
            .unwrap_or_default()
    }
}

/// What a [`Form`] feeds into on submit.
#[derive(Clone, Debug)]
pub enum FormThen {
    /// New secret: fields [Path, Labels] → open the value editor next.
    NewSecret,
    /// Move: fields [Path, Labels] → re-key the secret currently at this selector.
    Relabel(SecretSelectorV1),
    /// Claim: field [Bundle] — the `thrx1…` string is claimed.
    Claim,
    /// Invite: field [Handle] — becomes a new user; the bundle is shown.
    Invite,
    /// New group: field [Name].
    Group,
}

/// Destructive actions gated behind [`Modal::Confirm`].
#[derive(Clone, Debug)]
pub enum ConfirmAction {
    DeleteSecret(SecretSelectorV1),
    DeleteGrant(GrantId),
    DeleteGroup(GroupId),
    DeleteUser(UserId),
    /// Resolve a conflict to the candidate with this record hash.
    ResolveConflict(HashValue),
    /// Accept a rollback at this key: machine-local watermark adjustment, no record written.
    AcceptRollback(RecordKey),
}

/// Why a secret is being decrypted, which decides the sink and the follow-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GetPurpose {
    Reveal,
    Copy,
    Edit,
    /// Eagerly load the secret's additional fields for plaintext display (no reveal gate).
    Fields,
}

/// Side effects the loop performs after `update`.
pub enum Effect {
    /// Full re-read + re-validation from disk. Only for flows with no live session to commit
    /// through (startup, join, init) and the external-change freshness probe —
    /// mutations leave the session already at the post-commit state and never reload.
    Reload,
    GetSecret {
        selector: SecretSelectorV1,
        purpose: GetPurpose,
    },
    SetSecret {
        selector: SecretSelectorV1,
        plaintext: Zeroizing<Vec<u8>>,
        label: String,
    },
    DeleteSecret(SecretSelectorV1),
    /// Re-key a secret to a new selector: re-seal its plaintext at `new`, then tombstone `old`,
    /// then reconcile readers (labels/tuple are part of identity, so this is the move op).
    Relabel {
        old: SecretSelectorV1,
        new: SecretSelectorV1,
    },
    DeleteGrant(GrantId),
    DeleteGroup(GroupId),
    Invite(String),
    DeleteUser(UserId),
    /// Join an existing vault with an invite, protecting the new identity under
    /// `passphrase`. Establishes this machine's identity (the startup join flow).
    Join {
        bundle: String,
        passphrase: String,
    },
    CreateGroup(String),
    GrantPermission {
        subject: PrincipalRefV1,
        permission: GrantPermissionV1,
    },
    AddMember {
        group: GroupId,
        member: PrincipalRefV1,
    },
    Init(String),
    /// Resolve a conflict to the candidate with this record hash (re-sign at a fresh counter).
    ResolveConflict(HashValue),
    /// Accept a rollback at this key: this machine forgets the higher counter it remembered,
    /// trusting the visible state as-is. Machine-local — no record, no keychain unlock.
    AcceptRollback(RecordKey),
    /// Decrypt a conflict's secret-value candidates for inspection (Merge view reveal).
    RevealConflictCandidates {
        picks: Vec<HashValue>,
    },
    CopyToClipboard(Zeroizing<Vec<u8>>),
    Quit,
}

/// Inputs and op results.
pub enum Message {
    // navigation / view
    MoveUp,
    MoveDown,
    MoveTop,
    MoveBottom,
    PageUp,
    PageDown,
    Open,  // expand / drill in
    Close, // collapse / up
    SwitchView(View),
    CycleAccessTab,
    SetAccessTab(AccessTab),
    // secret actions
    Reveal,
    HideReveal,
    Copy,
    StartEdit,
    StartRelabel,
    StartNewSecret,
    RequestDeleteSecret,
    RequestResolveConflict,
    RequestAcceptRollback,
    /// Open the set-secret flow prefilled with a rollback conflict's selector (Conflicts view).
    StartSetFresh,
    // workspace lifecycle
    /// Submit the inline init gate: create a new vault protected by the typed passphrase.
    InitSubmit,
    // access actions
    StartClaim,
    StartInvite,
    StartGrant,
    StartGroup,
    StartAddMember,
    MemberFormKey(crossterm::event::KeyEvent),
    RequestUserDelete,
    RequestAccessDelete,
    OpenFacetFilter,
    FacetFormKey(crossterm::event::KeyEvent),
    // fuzzy search (Secrets view)
    /// Open (or re-focus) the live search bar, keeping any existing query for editing.
    OpenSearch,
    SearchChar(char),
    SearchBackspace,
    /// Enter: keep the query applied and hand the keyboard back to the list.
    SearchApply,
    /// Esc: clear the query and close the bar.
    SearchCancel,
    ShowBundle(String),
    CopyInviteBundle,
    // focus / buttons
    FocusNext,
    FocusList,
    ButtonPrev,
    ButtonNext,
    ActivateButton,
    // mouse
    MouseClick(u16, u16),
    // unlock gate
    UnlockChar(char),
    UnlockBackspace,
    UnlockClear,
    UnlockSubmit,
    // modal
    OpenHelp,
    OpenHealth,
    CloseModal,
    ConfirmYes,
    EditorKey(crossterm::event::KeyEvent),
    EditorSubmit,
    FormKey(crossterm::event::KeyEvent),
    GrantFormKey(crossterm::event::KeyEvent),
    // op results
    SecretRevealed {
        selector: SecretSelectorV1,
        plaintext: Zeroizing<Vec<u8>>,
        is_utf8: bool,
        copy: bool,
    },
    SecretForEdit {
        selector: SecretSelectorV1,
        plaintext: Zeroizing<Vec<u8>>,
    },
    SecretFieldsLoaded {
        selector: SecretSelectorV1,
        fields: Vec<RevealedField>,
    },
    ConflictCandidatesRevealed {
        values: Vec<MergeRevealValue>,
    },
    OpFailed(String),
    OpOk(String),
    // lifecycle
    LockNow,
    Tick,
    Quit,
}
