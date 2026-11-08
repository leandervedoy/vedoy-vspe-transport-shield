//! Optional Signal SPQR adapter. This is not a full Triple Ratchet. NEVER
//! silently fall back to the research symmetric chain. SPQR is AGPL-3.0-only.
use crate::{chain::MessageKey, hybrid::HybridRoot, ShieldError, ShieldResult};
use zeroize::{Zeroize, ZeroizeOnDrop};
const MAX_STATE: usize = 16 * 1024 * 1024;
const MAX_CHUNK: usize = 1024 * 1024;
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PostQuantumRatchet { state: Vec<u8> }
pub struct PreparedSend {
    pub next_state: Vec<u8>,
    pub chunk: Vec<u8>,
    pub key: MessageKey,
}
pub struct PreparedReceive {
    pub next_state: Vec<u8>,
    pub key: MessageKey,
}
impl PostQuantumRatchet {
    /// Callers must seal these bytes inside an encrypted atomic snapshot.
    pub(crate) fn encrypted_snapshot_bytes(&self) -> Vec<u8> { self.state.clone() }
    pub fn from_encrypted_snapshot(state: Vec<u8>) -> ShieldResult<Self> {
        if state.is_empty() || state.len() > MAX_STATE { return Err(ShieldError::InvalidFormat); }
        #[cfg(not(feature = "signal-spqr"))]
        return Err(ShieldError::RatchetUnavailable);
        #[cfg(feature = "signal-spqr")]
        {
            spqr::current_version(&state).map_err(|_| ShieldError::RatchetFailed)?;
            Ok(Self { state })
        }
    }
    pub fn initialize(root: &HybridRoot, sender: bool) -> ShieldResult<Self> {
        #[cfg(not(feature = "signal-spqr"))]
        { let _ = (root, sender); Err(ShieldError::RatchetUnavailable) }
        #[cfg(feature = "signal-spqr")]
        {
            use spqr::{ChainParams, Direction, Params, Version};
            let key = root.derive_chain_seed(b"vedoy/shield/0.3/spqr-auth-key")?;
            let direction = if sender { Direction::A2B } else { Direction::B2A };
            let state = spqr::initial_state(Params {
                direction, version: Version::V1, min_version: Version::V1,
                auth_key: &key, chain_params: ChainParams::default(),
            }).map_err(|_| ShieldError::RatchetFailed)?;
            Ok(Self { state })
        }
    }
    pub fn prepare_send(&self) -> ShieldResult<PreparedSend> {
        #[cfg(not(feature = "signal-spqr"))]
        return Err(ShieldError::RatchetUnavailable);
        #[cfg(feature = "signal-spqr")]
        {
            let mut rng = rand::rng();
            let result = spqr::send(&self.state, &mut rng)
                .map_err(|_| ShieldError::RatchetFailed)?;
            if result.state.len() > MAX_STATE || result.msg.is_empty() || result.msg.len() > MAX_CHUNK {
                return Err(ShieldError::LimitExceeded);
            }
            let key = derived_message_key(result.key.ok_or(ShieldError::RatchetFailed)?)?;
            Ok(PreparedSend { next_state: result.state, chunk: result.msg, key })
        }
    }
    pub fn prepare_receive(&self, chunk: &[u8]) -> ShieldResult<PreparedReceive> {
        if chunk.is_empty() || chunk.len() > MAX_CHUNK { return Err(ShieldError::InvalidFormat); }
        #[cfg(not(feature = "signal-spqr"))]
        return Err(ShieldError::RatchetUnavailable);
        #[cfg(feature = "signal-spqr")]
        {
            let result = spqr::recv(&self.state, &chunk.to_vec())
                .map_err(|_| ShieldError::RatchetFailed)?;
            if result.state.len() > MAX_STATE { return Err(ShieldError::LimitExceeded); }
            let key = derived_message_key(result.key.ok_or(ShieldError::RatchetFailed)?)?;
            Ok(PreparedReceive { next_state: result.state, key })
        }
    }
}
#[cfg(feature = "signal-spqr")]
fn derived_message_key(mut upstream_key: Vec<u8>) -> ShieldResult<MessageKey> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    if upstream_key.len() != 32 {
        upstream_key.zeroize();
        return Err(ShieldError::RatchetFailed);
    }
    let mut key = [0u8; 32];
    let result = Hkdf::<Sha256>::new(None, &upstream_key)
        .expand(b"vedoy/shield/0.3/wordforge/from-spqr", &mut key);
    upstream_key.zeroize();
    result.map_err(|_| ShieldError::RatchetFailed)?;
    Ok(MessageKey(key))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(feature = "signal-spqr"))]
    #[test]
    fn no_fallback() {
        assert!(matches!(PostQuantumRatchet::from_encrypted_snapshot(vec![1]), Err(ShieldError::RatchetUnavailable)));
    }
}
