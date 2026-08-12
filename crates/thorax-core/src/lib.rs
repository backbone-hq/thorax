pub mod authz;
pub mod crypto;
pub mod format;
pub mod hazmat;
pub mod ids;
pub mod join;
pub mod merge;
pub mod ratchet;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod validate;

pub use authz::{selector_matches, selector_subsumes};
pub use crypto::{CryptoProvider, DeterministicCrypto, RecordSigner};
pub use format::*;
pub use ids::{
    derive_grant_id, derive_group_id, derive_group_member_id, derive_secret_id,
    derive_user_handle_id, derive_vault_handle_id, normalize_handle,
};
pub use join::*;
pub use merge::{merge_vaults, ConflictKind, ConflictReport, MergeOutcome, MergeRefusal};
pub use ratchet::{KeyOrigin, Ratchet, RatchetUpdate, UnknownRatchetRecord};
pub use validate::{
    decode_vault, encode_vault, next_counter, record_hash, record_key_for, validate_vault,
    validate_vault_with_verified, ActiveSecretV1, EffectiveState, SecretState, ValidationIssue,
    ValidationReport, ValidationWarning, MAX_LWW_COUNTER, MAX_VAULT_BYTES, MAX_VAULT_RECORDS,
};

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("cord error: {0}")]
    Cord(#[from] cord::CordError),
    #[error("validation failed: {0}")]
    Validation(String),
}
