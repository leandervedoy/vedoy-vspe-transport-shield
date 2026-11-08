//! Fails closed until Android Keystore / iOS Keychain adapter is provided.
use crate::{ShieldError, ShieldResult};
use zeroize::Zeroizing;
pub trait SecureKeyVault: Send + Sync {
    fn store(&self, reference: &str, secret: &[u8]) -> ShieldResult<()>;
    fn load(&self, reference: &str) -> ShieldResult<Zeroizing<Vec<u8>>>;
    fn delete(&self, reference: &str) -> ShieldResult<()>;
}
pub struct UnavailableVault;
impl SecureKeyVault for UnavailableVault {
    fn store(&self, _reference: &str, _secret: &[u8]) -> ShieldResult<()> {
        Err(ShieldError::MissingKeyVault)
    }
    fn load(&self, _reference: &str) -> ShieldResult<Zeroizing<Vec<u8>>> {
        Err(ShieldError::MissingKeyVault)
    }
    fn delete(&self, _reference: &str) -> ShieldResult<()> {
        Err(ShieldError::MissingKeyVault)
    }
}
