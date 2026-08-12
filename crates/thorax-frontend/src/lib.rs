//! Shared presentation and runtime helpers for Thorax frontends.

use std::path::PathBuf;

use clap::Args;

pub mod bundle;
pub mod diagnostics;
mod error;
mod merge_driver;
mod merge_view;
mod render;
mod runtime;
mod selector;
mod user;

pub use diagnostics::{describe_issue, describe_warning, diagnose, emit, exit, Diagnostic};
pub use error::{map_secret_error, FrontendError};
pub use merge_driver::{
    install_merge_driver, merge_driver_status, MergeDriverInstall, MergeDriverStatus,
    GITATTRIBUTES_DIFF_LINE, GITATTRIBUTES_LINE, GITATTRIBUTES_MERGE_LINE,
};
pub use merge_view::{
    candidate_summary, conflict_kind_name, conflict_kind_summary, conflict_label, record_key_kind,
};
pub use render::{hash_hex, hex_bytes, short_hash, short_user_hex, user_hex};
pub use runtime::{
    build_keychain, build_keychain_with_passphrase, ci_identity_user, ci_invite,
    confirm_destructive, copy_to_clipboard, encode_invite, explicit_or_current_root, invite_bytes,
    maybe_bootstrap_ci_trust, open_session, open_valid_session, read_invite,
    recover_workspace_if_present, workspace_paths, INVITE_ENV, INVITE_FILE_ENV,
    UNSAFE_KEYCHAIN_PASSPHRASE_ENV,
};
pub use selector::{
    escape_segment, escape_tuple, parse_secret_query, parse_secret_selector, selector_string,
};
pub use user::{
    decode_hex, decode_hex_exact, normalize_hex_prefix, parse_handle_name, parse_user_id,
    parse_user_ref, remember_user_if_explicit, report_root_key_hash,
    resolve_cli_user_ref_in_report, resolve_cli_user_ref_with_report,
    resolve_optional_cli_user_ref_with_report, stored_default_user, user_config_ref,
    write_current_user_for_root, CliUser, StoredDefaultUser,
};

/// Flags shared by every Thorax frontend. Flattened into the top-level parser and marked global,
/// so they may appear before or after a subcommand and are handed to whichever frontend runs.
#[derive(Args, Clone, Debug, Default)]
pub struct GlobalArgs {
    /// Workspace root. Defaults to current directory for init and workspace discovery otherwise.
    #[arg(long, global = true)]
    pub path: Option<PathBuf>,
    /// Emit machine-readable JSON where supported.
    #[arg(long, global = true)]
    pub json: bool,
}
