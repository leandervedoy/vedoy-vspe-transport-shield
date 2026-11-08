//! Experimental authenticated hybrid (X25519 + ML-KEM-1024) handshake.
//! Both peers must externally pin identity keys. This is NOT PQXDH:
//! asynchronous signed/one-time prekeys, global replay ledger, key transparency,
//! formal proofs and postquantum *authentication* are still absent.
use crate::{ShieldError, ShieldResult};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem},
    ml_kem_1024::{DecapsulationKey, EncapsulationKey},
    Ciphertext, MlKem1024, TryKeyInit,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DOMAIN: &[u8] = b"VEDOY/SHIELD/WORD-FORGE/0.3/HYBRID-MLKEM1024-X25519";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientBundle {
    pub version: u8,
    pub mlkem1024_public: Vec<u8>,
    pub x25519_public: [u8; 32],
    pub identity_public: [u8; 32],
    pub signature: Vec<u8>,
}
impl RecipientBundle {
    fn signed_material(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 4 + self.mlkem1024_public.len() + 64);
        bytes.extend_from_slice(DOMAIN);
        bytes.push(self.version);
        bytes.extend_from_slice(&(self.mlkem1024_public.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.mlkem1024_public);
        bytes.extend_from_slice(&self.x25519_public);
        bytes.extend_from_slice(&self.identity_public);
        bytes
    }
    pub fn verify_pinned(&self, pinned_identity: &[u8; 32]) -> ShieldResult<()> {
        if self.version != 3 || &self.identity_public != pinned_identity {
            return Err(ShieldError::UntrustedIdentity);
        }
        let verify = VerifyingKey::from_bytes(pinned_identity)
            .map_err(|_| ShieldError::InvalidFormat)?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| ShieldError::InvalidFormat)?;
        verify.verify(&self.signed_material(), &signature)
            .map_err(|_| ShieldError::InvalidSignature)?;
        EncapsulationKey::new_from_slice(&self.mlkem1024_public)
            .map_err(|_| ShieldError::InvalidFormat)?;
        if self.x25519_public == [0u8; 32] {
            return Err(ShieldError::InvalidFormat);
        }
        Ok(())
    }
}
pub struct RecipientPrivate {
    mlkem: DecapsulationKey,
    x25519: StaticSecret,
    signing: SigningKey,
}
impl RecipientPrivate {
    pub fn generate() -> (Self, RecipientBundle) {
        let (mlkem, encaps) = MlKem1024::generate_keypair();
        let x25519 = StaticSecret::random_from_rng(OsRng);
        let xpub = PublicKey::from(&x25519);
        let mut identity_seed = [0u8; 32];
        OsRng.fill_bytes(&mut identity_seed);
        let signing = SigningKey::from_bytes(&identity_seed);
        identity_seed.zeroize();
        let mut bundle = RecipientBundle {
            version: 3,
            mlkem1024_public: ml_kem::KeyExport::to_bytes(&encaps).to_vec(),
            x25519_public: *xpub.as_bytes(),
            identity_public: signing.verifying_key().to_bytes(),
            signature: Vec::new(),
        };
        bundle.signature = signing.sign(&bundle.signed_material()).to_bytes().to_vec();
        (Self { mlkem, x25519, signing }, bundle)
    }
    pub fn identity_public(&self) -> [u8; 32] { self.signing.verifying_key().to_bytes() }

    /// Caller must verify the public sender key through a trusted channel and
    /// *durably consume* the invite_id to prevent replay (not included here).
    pub fn accept(&self, invite: &HybridInvite, bundle: &RecipientBundle,
                  pinned_sender_identity: &[u8; 32]) -> ShieldResult<HybridRoot> {
        bundle.verify_pinned(&self.identity_public())?;
        if &invite.sender_identity_public != pinned_sender_identity {
            return Err(ShieldError::UntrustedIdentity);
        }
        let verify = VerifyingKey::from_bytes(pinned_sender_identity)
            .map_err(|_| ShieldError::InvalidFormat)?;
        let signature = Signature::from_slice(&invite.sender_signature)
            .map_err(|_| ShieldError::InvalidSignature)?;
        verify.verify(&invite.transcript(bundle), &signature)
            .map_err(|_| ShieldError::InvalidSignature)?;
        if invite.version != 3 || invite.chat_id.is_empty() || invite.chat_id.len() > 256 {
            return Err(ShieldError::InvalidFormat);
        }
        let bundle_digest: [u8; 32] = Sha256::digest(bundle.signed_material()).into();
        if invite.recipient_bundle_sha256 != bundle_digest {
            return Err(ShieldError::AuthenticationFailed);
        }
        let ct: Ciphertext<MlKem1024> = invite.mlkem1024_ciphertext
            .as_slice().try_into().map_err(|_| ShieldError::InvalidFormat)?;
        let pq_shared = self.mlkem.decapsulate(&ct);
        let peer = PublicKey::from(invite.ephemeral_x25519_public);
        let x_shared = self.x25519.diffie_hellman(&peer);
        if x_shared.as_bytes() == &[0u8; 32] {
            return Err(ShieldError::AuthenticationFailed);
        }
        derive_root(pq_shared.as_slice(), x_shared.as_bytes(), &invite.transcript(bundle))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridInvite {
    pub version: u8,
    pub chat_id: String,
    pub recipient_bundle_sha256: [u8; 32],
    pub ephemeral_x25519_public: [u8; 32],
    pub mlkem1024_ciphertext: Vec<u8>,
    pub invite_id: [u8; 16],
    pub sender_identity_public: [u8; 32],
    pub sender_signature: Vec<u8>,
}
impl HybridInvite {
    fn transcript(&self, bundle: &RecipientBundle) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&self.recipient_bundle_sha256);
        bytes.extend_from_slice(&(self.chat_id.len() as u32).to_be_bytes());
        bytes.extend_from_slice(self.chat_id.as_bytes());
        bytes.extend_from_slice(&self.invite_id);
        bytes.extend_from_slice(&self.sender_identity_public);
        bytes.extend_from_slice(&self.ephemeral_x25519_public);
        bytes.extend_from_slice(&(self.mlkem1024_ciphertext.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.mlkem1024_ciphertext);
        bytes.extend_from_slice(&bundle.identity_public);
        bytes
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridRoot(pub(crate) [u8; 32]);
impl HybridRoot {
    pub fn derive_chain_seed(&self, purpose: &[u8]) -> ShieldResult<[u8; 32]> {
        let mut next = [0u8; 32];
        Hkdf::<Sha512>::new(None, &self.0).expand(purpose, &mut next)
            .map_err(|_| ShieldError::InvalidFormat)?;
        Ok(next)
    }
}
fn derive_root(pq_shared: &[u8], x_shared: &[u8; 32], transcript: &[u8]) -> ShieldResult<HybridRoot> {
    let mut combined = Zeroizing::new([0u8; 64]);
    if pq_shared.len() != 32 { return Err(ShieldError::InvalidFormat); }
    combined[..32].copy_from_slice(pq_shared);
    combined[32..].copy_from_slice(x_shared);
    let salt = Sha256::digest(transcript);
    let hkdf = Hkdf::<Sha512>::new(Some(&salt), combined.as_ref());
    let mut root = [0u8; 32];
    hkdf.expand(DOMAIN, &mut root).map_err(|_| ShieldError::InvalidFormat)?;
    Ok(HybridRoot(root))
}
pub fn initiate(bundle: &RecipientBundle, pinned_identity: &[u8; 32],
                sender: &SenderIdentity, chat_id: &str) -> ShieldResult<(HybridInvite, HybridRoot)> {
    if chat_id.is_empty() || chat_id.len() > 256 {
        return Err(ShieldError::InvalidFormat);
    }
    bundle.verify_pinned(pinned_identity)?;
    let encaps = EncapsulationKey::new_from_slice(&bundle.mlkem1024_public)
        .map_err(|_| ShieldError::InvalidFormat)?;
    let (ct, pq_shared) = encaps.encapsulate();
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let peer = PublicKey::from(bundle.x25519_public);
    let x_shared = ephemeral.diffie_hellman(&peer);
    if x_shared.as_bytes() == &[0u8; 32] {
        return Err(ShieldError::AuthenticationFailed);
    }
    let mut invite_id = [0u8; 16];
    OsRng.fill_bytes(&mut invite_id);
    let mut invite = HybridInvite {
        version: 3,
        chat_id: chat_id.to_owned(),
        recipient_bundle_sha256: Sha256::digest(bundle.signed_material()).into(),
        ephemeral_x25519_public: *ephemeral_public.as_bytes(),
        mlkem1024_ciphertext: ct.to_vec(),
        invite_id,
        sender_identity_public: sender.identity_public(),
        sender_signature: Vec::new(),
    };
    invite.sender_signature = sender.sign(&invite.transcript(bundle));
    let root = derive_root(pq_shared.as_slice(), x_shared.as_bytes(), &invite.transcript(bundle))?;
    Ok((invite, root))
}
pub struct SenderIdentity { signing: SigningKey }
impl SenderIdentity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let signing = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Self { signing }
    }
    pub fn identity_public(&self) -> [u8; 32] { self.signing.verifying_key().to_bytes() }
    fn sign(&self, transcript: &[u8]) -> Vec<u8> {
        self.signing.sign(transcript).to_bytes().to_vec()
    }
}
