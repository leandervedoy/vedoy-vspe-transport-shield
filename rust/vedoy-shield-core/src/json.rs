//! JSON wire schema. Public data only; NEVER encode private keys or PIN.
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use crate::{ShieldError, ShieldResult};
pub const PROTOCOL_VERSION: u8 = 3;
pub const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub core_version: String,
    pub wire_version: u8,
    pub authenticated_hybrid_kem: String,
    pub post_quantum_ratchet_available: bool,
    pub storage: String,
    pub production_ready: bool,
}
pub fn capabilities() -> Capabilities {
    Capabilities {
        core_version: PACKAGE_VERSION.to_owned(),
        wire_version: PROTOCOL_VERSION,
        authenticated_hybrid_kem: "experimental-ed25519-x25519-mlkem1024".to_owned(),
        post_quantum_ratchet_available: cfg!(feature = "signal-spqr"),
        storage: "unix-atomic-aes256gcmsiv-argon2id-password2-and-pin".to_owned(),
        production_ready: false,
    }
}
pub fn parse_bounded<T: DeserializeOwned>(input: &[u8]) -> ShieldResult<T> {
    if input.len() > 2 * 1024 * 1024 { return Err(ShieldError::LimitExceeded); }
    serde_json::from_slice(input).map_err(|_| ShieldError::InvalidFormat)
}
pub fn encode_bounded<T: Serialize>(value: &T) -> ShieldResult<Vec<u8>> {
    let output = serde_json::to_vec(value).map_err(|_| ShieldError::InvalidFormat)?;
    if output.len() > 2 * 1024 * 1024 { return Err(ShieldError::LimitExceeded); }
    Ok(output)
}
