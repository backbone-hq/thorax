//! The application model, message/effect types, and the update loop.
//!
//! Elm-shaped: [`Model`] holds all state, [`Message`] describes inputs and op results, `update`
//! transitions the model and returns [`Effect`]s the runner performs (ops calls, clipboard, quit).
//! Rendering lives in [`crate::ui`]; key→message mapping in [`crate::event`].

mod effects;
mod model;
mod msg;
mod update;

pub use self::effects::run_effect;
// Facade re-exports: every pre-split `crate::app::X` path keeps resolving. Some are reached only
// from `#[cfg(test)]` code (tests.rs) or within the submodules, which a plain `cargo check`
// (lib-only) would flag as unused.
#[allow(unused_imports)]
pub use self::model::{
    AccessMatrixRow, AccessRow, AccessTab, Button, Focus, ListKind, ListRegion, MergeReveal,
    MergeRevealValue, MergeRow, Model, Reveal, Row, Status,
};
#[allow(unused_imports)]
pub use self::msg::{
    ButtonAction, ConfirmAction, Effect, Form, FormField, FormThen, GetPurpose, GrantForm,
    GrantSubject, MemberForm, Message, Modal, View, GRANT_CLASSES,
};
pub use self::update::update;
