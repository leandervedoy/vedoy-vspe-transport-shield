//! Identity proofing is separate from cryptographic identity keys.
//! Never send passport/NFC/selfie to chat transport or message servers.
use crate::{ShieldError, ShieldResult};
use serde::{Deserialize, Serialize};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDocument { Passport, NationalIdCard }
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofingRequest {
    pub account_pseudonym: String,
    pub document_type: IdentityDocument,
    pub request_nonce: String,
}
pub struct VerifiedProof {
    pub provider: String,
    pub account_pseudonym: String,
    pub verified_at_unix_seconds: u64,
    pub assurance: String,
}
pub trait IdentityProofing: Send + Sync {
    fn start(&self, request: &ProofingRequest) -> ShieldResult<String>;
    fn verify_server_attestation(&self, signed_attestation: &str,
        expected_nonce: &str, expected_account: &str) -> ShieldResult<VerifiedProof>;
}
pub struct UnconfiguredProofing;
impl IdentityProofing for UnconfiguredProofing {
    fn start(&self, _request: &ProofingRequest) -> ShieldResult<String> {
        Err(ShieldError::IdentityProviderUnavailable)
    }
    fn verify_server_attestation(&self, _signed_attestation: &str,
        _expected_nonce: &str, _expected_account: &str) -> ShieldResult<VerifiedProof> {
        Err(ShieldError::IdentityProviderUnavailable)
    }
}
