//! Vedoy Shield Core v0.3.0 -- experimental, NOT a production E2EE implementation.
//! Rust authenticated hybrid AKE prototype and optional Signal SPQR adapter.
//! NOT PQXDH, NOT a complete Triple Ratchet, NOT independently audited.
//! Encrypted durable snapshots must be committed before packets leave the client.
pub mod chain;
pub mod hybrid;
pub mod identity;
pub mod json;
pub mod ratchet;
pub mod session;
pub mod storage;
pub mod vault;
pub mod wordforge;
use thiserror::Error;
#[derive(Debug, Error)]
pub enum ShieldError {
    #[error("peer identity is not trusted")]
    UntrustedIdentity,
    #[error("peer signature is invalid")]
    InvalidSignature,
    #[error("invalid key, input, or protocol version")]
    InvalidFormat,
    #[error("encryption or authentication failed")]
    AuthenticationFailed,
    #[error("length or counter limit exceeded")]
    LimitExceeded,
    #[error("sequence mismatch (out-of-order unsupported by demo chain)")]
    SequenceMismatch,
    #[error("no secure hardware key vault has been configured")]
    MissingKeyVault,
    #[error("post-quantum ratchet not enabled: do not fall back silently")]
    RatchetUnavailable,
    #[error("ratchet failed authentication, decoding, or state checks")]
    RatchetFailed,
    #[error("storage I/O error")]
    Storage,
    #[error("storage revision conflict")]
    StorageConflict,
    #[error("unsupported filesystem durability guarantees")]
    UnsupportedStorage,
    #[error("secondary password/PIN policy was not satisfied")]
    InvalidCredentials,
    #[error("identity-verification provider is not configured")]
    IdentityProviderUnavailable,
}
pub type ShieldResult<T> = Result<T, ShieldError>;
