//! Research-only symmetric message key chain, NOT Double/Triple Ratchet.
//! Production sessions intentionally require SPQR and never fall back here.
use crate::{hybrid::HybridRoot, ShieldError, ShieldResult};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MessageKey(pub(crate) [u8; 32]);
pub struct MessageStep {
    pub sequence: u64,
    pub key: MessageKey,
    next_chain: [u8; 32],
}
impl Drop for MessageStep {
    fn drop(&mut self) { self.next_chain.zeroize(); }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SymmetricChain {
    key: [u8; 32],
    counter: u64,
}
impl SymmetricChain {
    pub fn from_seed(seed: [u8; 32]) -> Self { Self { key: seed, counter: 0 } }
    pub fn sequence(&self) -> u64 { self.counter }
    pub fn prepare(&self) -> ShieldResult<MessageStep> {
        if self.counter == u64::MAX { return Err(ShieldError::LimitExceeded); }
        let hkdf = Hkdf::<Sha256>::new(None, &self.key);
        let mut msg = [0u8; 32];
        let mut next = [0u8; 32];
        let mut ctx = b"vedoy/shield/0.3/msg".to_vec();
        ctx.extend_from_slice(&self.counter.to_be_bytes());
        hkdf.expand(&ctx, &mut msg).map_err(|_| ShieldError::InvalidFormat)?;
        let mut ctx = b"vedoy/shield/0.3/next".to_vec();
        ctx.extend_from_slice(&self.counter.to_be_bytes());
        hkdf.expand(&ctx, &mut next).map_err(|_| ShieldError::InvalidFormat)?;
        Ok(MessageStep { sequence: self.counter, key: MessageKey(msg), next_chain: next })
    }
    pub fn commit(&mut self, step: MessageStep) -> ShieldResult<()> {
        if self.counter != step.sequence { return Err(ShieldError::SequenceMismatch); }
        self.key.zeroize();
        self.key.copy_from_slice(&step.next_chain);
        self.counter += 1;
        Ok(())
    }
}
pub struct SessionChains {
    pub send: SymmetricChain,
    pub receive: SymmetricChain,
}
impl SessionChains {
    pub fn initiator(root: &HybridRoot) -> ShieldResult<Self> {
        Ok(Self {
            send: SymmetricChain::from_seed(root.derive_chain_seed(b"v0.3/init->resp")?),
            receive: SymmetricChain::from_seed(root.derive_chain_seed(b"v0.3/resp->init")?),
        })
    }
    pub fn responder(root: &HybridRoot) -> ShieldResult<Self> {
        Ok(Self {
            send: SymmetricChain::from_seed(root.derive_chain_seed(b"v0.3/resp->init")?),
            receive: SymmetricChain::from_seed(root.derive_chain_seed(b"v0.3/init->resp")?),
        })
    }
}
