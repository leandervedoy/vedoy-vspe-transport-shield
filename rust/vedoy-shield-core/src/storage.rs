//! Atomic encrypted snapshots for Unix-like clients. Password #2 AND PIN
//! unlock a local state file using Argon2id -> AES-256-GCM-SIV.
//! PIN is NOT hardware rate-limited! Production MUST wrap the key through
//! Android Keystore / iOS Secure Enclave, with attempts and rollback controls.
//! Atomicity != protection from malicious rollback or full device compromise.
use crate::{ShieldError, ShieldResult};
use aes_gcm_siv::{aead::{Aead, KeyInit, Payload}, Aes256GcmSiv};
use argon2::{Algorithm, Argon2, Params, Version};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
const FILE_VERSION: u8 = 3;
const MAX_SNAPSHOT: usize = 16 * 1024 * 1024;
const DOMAIN: &[u8] = b"vedoy/shield/0.3/sealed-state";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedSnapshot {
    version: u8,
    revision: u64,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}
pub struct LoadedSnapshot {
    pub revision: u64,
    pub plaintext: Zeroizing<Vec<u8>>,
}
pub struct EncryptedAtomicStore {
    folder: PathBuf,
    filename: String,
}
fn valid_credentials(password2: &str, pin: &str) -> ShieldResult<()> {
    if password2.len() < 12 || password2.len() > 256 || pin.len() < 6
       || pin.len() > 12 || !pin.bytes().all(|c| c.is_ascii_digit()) {
        return Err(ShieldError::InvalidCredentials);
    }
    Ok(())
}
fn derive(password2: &str, pin: &str, salt: &[u8; 16]) -> ShieldResult<Zeroizing<[u8; 32]>> {
    valid_credentials(password2, pin)?;
    let mut input = Zeroizing::new(Vec::with_capacity(password2.len() + pin.len() + 48));
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(&(password2.len() as u16).to_be_bytes());
    input.extend_from_slice(password2.as_bytes());
    input.push(pin.len() as u8);
    input.extend_from_slice(pin.as_bytes());
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|_| ShieldError::InvalidFormat)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(&input, salt, &mut *key)
        .map_err(|_| ShieldError::AuthenticationFailed)?;
    Ok(key)
}
fn aad(scope: &str, revision: u64) -> ShieldResult<Vec<u8>> {
    if scope.is_empty() || scope.len() > 256 {
        return Err(ShieldError::InvalidFormat);
    }
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(&(scope.len() as u32).to_be_bytes());
    out.extend_from_slice(scope.as_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    Ok(out)
}
impl EncryptedAtomicStore {
    /// Folder must be private and on a single local Unix filesystem.
    /// No shared /tmp, NFS or cloud-sync folders; no symlink directory.
    pub fn new(folder: &Path, filename: &str) -> ShieldResult<Self> {
        if filename.is_empty() || filename.len() > 100 || filename == "." || filename == ".."
           || !filename.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'
                                   || b == b'_' || b == b'.') {
            return Err(ShieldError::InvalidFormat);
        }
        #[cfg(not(unix))]
        { let _ = folder; Err(ShieldError::UnsupportedStorage) }
        #[cfg(unix)]
        {
            fs::create_dir_all(folder).map_err(|_| ShieldError::Storage)?;
            if fs::symlink_metadata(folder).map_err(|_| ShieldError::Storage)?.file_type().is_symlink() {
                return Err(ShieldError::UnsupportedStorage);
            }
            fs::set_permissions(folder, fs::Permissions::from_mode(0o700))
                .map_err(|_| ShieldError::Storage)?;
            let canonical = folder.canonicalize().map_err(|_| ShieldError::Storage)?;
            Ok(Self { folder: canonical, filename: filename.to_owned() })
        }
    }
    fn path(&self) -> PathBuf { self.folder.join(&self.filename) }
    fn lock(&self, exclusive: bool) -> ShieldResult<File> {
        let path = self.folder.join(format!(".{}.lock", self.filename));
        #[cfg(unix)]
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).mode(0o600)
            .open(path).map_err(|_| ShieldError::Storage)?;
        #[cfg(not(unix))]
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false)
            .open(path).map_err(|_| ShieldError::Storage)?;
        let r = if exclusive { FileExt::lock_exclusive(&file) }
                else { FileExt::lock_shared(&file) };
        r.map_err(|_| ShieldError::Storage)?;
        Ok(file)
    }
    fn read_envelope(&self) -> ShieldResult<Option<SealedSnapshot>> {
        let path = self.path();
        if !path.exists() { return Ok(None); }
        let meta = fs::symlink_metadata(&path).map_err(|_| ShieldError::Storage)?;
        if !meta.is_file() || meta.file_type().is_symlink()
           || meta.len() > (MAX_SNAPSHOT as u64) * 5 {
            return Err(ShieldError::UnsupportedStorage);
        }
        let bytes = fs::read(path).map_err(|_| ShieldError::Storage)?;
        let snapshot: SealedSnapshot = serde_json::from_slice(&bytes)
            .map_err(|_| ShieldError::InvalidFormat)?;
        if snapshot.version != FILE_VERSION || snapshot.ciphertext.len() > MAX_SNAPSHOT + 32 {
            return Err(ShieldError::InvalidFormat);
        }
        Ok(Some(snapshot))
    }
    pub fn load(&self, password2: &str, pin: &str, scope: &str) -> ShieldResult<LoadedSnapshot> {
        let _lock = self.lock(false)?;
        let snapshot = self.read_envelope()?.ok_or(ShieldError::Storage)?;
        let key = derive(password2, pin, &snapshot.salt)?;
        let cipher = Aes256GcmSiv::new_from_slice(&*key)
            .map_err(|_| ShieldError::InvalidFormat)?;
        let ad = aad(scope, snapshot.revision)?;
        let data = cipher.decrypt((&snapshot.nonce).into(),
                                  Payload { msg: &snapshot.ciphertext, aad: &ad })
            .map_err(|_| ShieldError::AuthenticationFailed)?;
        if data.len() > MAX_SNAPSHOT { return Err(ShieldError::LimitExceeded); }
        Ok(LoadedSnapshot { revision: snapshot.revision, plaintext: Zeroizing::new(data) })
    }
    /// Compare-and-swap write. Persist state + ciphertext *before* networking.
    pub fn save(&self, password2: &str, pin: &str, scope: &str,
                expected_revision: u64, plaintext: &[u8]) -> ShieldResult<u64> {
        #[cfg(not(unix))]
        return Err(ShieldError::UnsupportedStorage);
        #[cfg(unix)]
        {
            if plaintext.len() > MAX_SNAPSHOT { return Err(ShieldError::LimitExceeded); }
            let _lock = self.lock(true)?;
            let actual = self.read_envelope()?.map_or(0, |x| x.revision);
            if actual != expected_revision { return Err(ShieldError::StorageConflict); }
            let revision = actual.checked_add(1).ok_or(ShieldError::LimitExceeded)?;
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 12];
            OsRng.fill_bytes(&mut salt);
            OsRng.fill_bytes(&mut nonce);
            let key = derive(password2, pin, &salt)?;
            let cipher = Aes256GcmSiv::new_from_slice(&*key)
                .map_err(|_| ShieldError::InvalidFormat)?;
            let ad = aad(scope, revision)?;
            let ciphertext = cipher.encrypt((&nonce).into(),
                                            Payload { msg: plaintext, aad: &ad })
                .map_err(|_| ShieldError::AuthenticationFailed)?;
            let data = Zeroizing::new(serde_json::to_vec(&SealedSnapshot {
                version: FILE_VERSION, revision, salt, nonce, ciphertext,
            }).map_err(|_| ShieldError::Storage)?);
            let mut suffix = [0u8; 8];
            OsRng.fill_bytes(&mut suffix);
            let temp = self.folder.join(format!(".{}.{}.tmp", self.filename,
                                                u64::from_le_bytes(suffix)));
            let mut output = OpenOptions::new().write(true).create_new(true).mode(0o600)
                .open(&temp).map_err(|_| ShieldError::Storage)?;
            let result = (|| {
                output.write_all(&data).map_err(|_| ShieldError::Storage)?;
                output.sync_all().map_err(|_| ShieldError::Storage)?;
                fs::rename(&temp, self.path()).map_err(|_| ShieldError::Storage)?;
                File::open(&self.folder).and_then(|f| f.sync_all())
                    .map_err(|_| ShieldError::Storage)?;
                Ok(revision)
            })();
            if result.is_err() { let _ = fs::remove_file(&temp); }
            result
        }
    }
    pub fn load_json<T: DeserializeOwned>(&self, password2: &str, pin: &str,
                                           scope: &str) -> ShieldResult<(u64, T)> {
        let snap = self.load(password2, pin, scope)?;
        let value = serde_json::from_slice(&snap.plaintext).map_err(|_| ShieldError::InvalidFormat)?;
        Ok((snap.revision, value))
    }
    pub fn save_json<T: Serialize>(&self, password2: &str, pin: &str,
                                  scope: &str, expected_revision: u64, value: &T) -> ShieldResult<u64> {
        let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| ShieldError::InvalidFormat)?);
        self.save(password2, pin, scope, expected_revision, &bytes)
    }
}
