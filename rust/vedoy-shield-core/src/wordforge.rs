//! Experimental per-word AEAD, authenticated outer envelope, and padding.
//! No claim of cryptographic advantage over standard E2EE. The public_seed is
//! NON-secret and does not add entropy to the session/ratchet secret.
use aes_gcm_siv::{aead::{Aead as _, KeyInit as _, Payload as AesPayload}, Aes256GcmSiv};
use chacha20poly1305::{aead::{Aead as _, KeyInit as _, Payload as ChaPayload}, ChaCha20Poly1305};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_segmentation::UnicodeSegmentation;
use crate::{chain::MessageKey, ShieldError, ShieldResult};

const MAX_PLAINTEXT: usize = 64_000;
const MAX_TOKENS: usize = 12_288;
const MAX_ENVELOPE: usize = 512_000;
const MAX_RATCHET_CHUNK: usize = 1_048_576;
const BLOCK_SIZE: usize = 512;
const VERSION: u8 = 3;
const DOMAIN: &[u8] = b"vedoy/shield/wordforge/0.3/";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WordEnvelope {
    pub version: u8,
    pub sequence: u64,
    pub message_id: [u8; 16],
    pub public_seed: [u8; 32],
    pub nonce: [u8; 12],
    /// Never disclose or change without invalidating the outer AEAD.
    pub pq_ratchet_chunk: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum InnerToken {
    Word { alg: u8, nonce: [u8; 12], ciphertext: Vec<u8> },
    Separator { text: String },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inner { tokens: Vec<InnerToken>, word_count: usize }

fn derive(key: &MessageKey, seed: &[u8; 32], info: &[u8]) -> ShieldResult<[u8; 32]> {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(seed), &key.0)
        .expand(info, &mut out).map_err(|_| ShieldError::InvalidFormat)?;
    Ok(out)
}
fn word_context(chat_id: &str, sequence: u64, id: &[u8; 16],
                index: u32, count: u32, alg: u8) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(b"word-aad/");
    out.extend_from_slice(&(chat_id.len() as u32).to_be_bytes());
    out.extend_from_slice(chat_id.as_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&index.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    out.push(alg);
    out
}
fn outer_context(chat_id: &str, env: &WordEnvelope) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(b"outer-aad/");
    out.extend_from_slice(&(chat_id.len() as u32).to_be_bytes());
    out.extend_from_slice(chat_id.as_bytes());
    out.push(env.version);
    out.extend_from_slice(&env.sequence.to_be_bytes());
    out.extend_from_slice(&env.message_id);
    out.extend_from_slice(&env.public_seed);
    out.extend_from_slice(&(env.pq_ratchet_chunk.len() as u32).to_be_bytes());
    out.extend_from_slice(&Sha256::digest(&env.pq_ratchet_chunk));
    out
}
fn label_with_hash(label: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut info = DOMAIN.to_vec();
    info.extend_from_slice(label);
    info.extend_from_slice(&Sha256::digest(aad));
    info
}
fn algorithm(seed: &[u8; 32], id: &[u8; 16], index: u32) -> u8 {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(seed)
        .expect("32-byte HMAC key is valid");
    mac.update(b"vedoy/shield/wordforge/0.3/choose/");
    mac.update(id);
    mac.update(&index.to_be_bytes());
    mac.finalize().into_bytes()[0] & 1
}
fn encrypt_word(alg: u8, key: &[u8; 32], nonce: &[u8; 12],
                msg: &[u8], aad: &[u8]) -> ShieldResult<Vec<u8>> {
    match alg {
        0 => Aes256GcmSiv::new_from_slice(key).map_err(|_| ShieldError::InvalidFormat)?
            .encrypt(nonce.into(), AesPayload { msg, aad })
            .map_err(|_| ShieldError::AuthenticationFailed),
        1 => ChaCha20Poly1305::new_from_slice(key).map_err(|_| ShieldError::InvalidFormat)?
            .encrypt(nonce.into(), ChaPayload { msg, aad })
            .map_err(|_| ShieldError::AuthenticationFailed),
        _ => Err(ShieldError::InvalidFormat),
    }
}
fn decrypt_word(alg: u8, key: &[u8; 32], nonce: &[u8; 12],
                msg: &[u8], aad: &[u8]) -> ShieldResult<Vec<u8>> {
    match alg {
        0 => Aes256GcmSiv::new_from_slice(key).map_err(|_| ShieldError::InvalidFormat)?
            .decrypt(nonce.into(), AesPayload { msg, aad })
            .map_err(|_| ShieldError::AuthenticationFailed),
        1 => ChaCha20Poly1305::new_from_slice(key).map_err(|_| ShieldError::InvalidFormat)?
            .decrypt(nonce.into(), ChaPayload { msg, aad })
            .map_err(|_| ShieldError::AuthenticationFailed),
        _ => Err(ShieldError::InvalidFormat),
    }
}
/// LEGACY research-only helper. No SPQR chunk means it cannot be used by
/// production session orchestration. Prefer encrypt_ratchet_message.
pub fn encrypt_message(plaintext: &str, chat_id: &str, sequence: u64,
                       msg_key: &MessageKey) -> ShieldResult<WordEnvelope> {
    encrypt_ratchet_message(plaintext, chat_id, sequence, msg_key, &[])
}
pub fn encrypt_ratchet_message(plaintext: &str, chat_id: &str, sequence: u64,
                               msg_key: &MessageKey, pq_ratchet_chunk: &[u8]) -> ShieldResult<WordEnvelope> {
    if chat_id.is_empty() || chat_id.len() > 256 || plaintext.len() > MAX_PLAINTEXT
       || pq_ratchet_chunk.len() > MAX_RATCHET_CHUNK {
        return Err(ShieldError::LimitExceeded);
    }
    let mut env = WordEnvelope {
        version: VERSION, sequence, message_id: [0; 16], public_seed: [0; 32],
        nonce: [0; 12], pq_ratchet_chunk: pq_ratchet_chunk.to_vec(),
        ciphertext: Vec::new(),
    };
    OsRng.fill_bytes(&mut env.message_id);
    OsRng.fill_bytes(&mut env.public_seed);
    OsRng.fill_bytes(&mut env.nonce);
    let segments: Vec<&str> = UnicodeSegmentation::split_word_bounds(plaintext).collect();
    if segments.len() > MAX_TOKENS { return Err(ShieldError::LimitExceeded); }
    let count = segments.iter().filter(|s| s.chars().any(|c| c.is_alphanumeric())).count();
    if count > 4_096 { return Err(ShieldError::LimitExceeded); }
    let mut index = 0u32;
    let mut tokens = Vec::with_capacity(segments.len());
    for segment in segments {
        if !segment.chars().any(|c| c.is_alphanumeric()) {
            tokens.push(InnerToken::Separator { text: segment.to_owned() });
            continue;
        }
        let alg = algorithm(&env.public_seed, &env.message_id, index);
        let aad = word_context(chat_id, sequence, &env.message_id, index, count as u32, alg);
        let derived = derive(msg_key, &env.public_seed, &label_with_hash(b"word/", &aad))?;
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = encrypt_word(alg, &derived, &nonce, segment.as_bytes(), &aad)?;
        tokens.push(InnerToken::Word { alg, nonce, ciphertext });
        index += 1;
    }
    let inner = serde_json::to_vec(&Inner { tokens, word_count: count })
        .map_err(|_| ShieldError::InvalidFormat)?;
    if inner.len() > MAX_ENVELOPE - 512 { return Err(ShieldError::LimitExceeded); }
    let mut padded = Vec::with_capacity(inner.len() + BLOCK_SIZE + 4);
    padded.extend_from_slice(&(inner.len() as u32).to_be_bytes());
    padded.extend_from_slice(&inner);
    let padding = (BLOCK_SIZE - (padded.len() % BLOCK_SIZE)) % BLOCK_SIZE;
    let start = padded.len();
    padded.resize(start + padding, 0);
    OsRng.fill_bytes(&mut padded[start..]);
    let aad = outer_context(chat_id, &env);
    let derived = derive(msg_key, &env.public_seed, &label_with_hash(b"outer/", &aad))?;
    env.ciphertext = encrypt_word(0, &derived, &env.nonce, &padded, &aad)?;
    Ok(env)
}
pub fn decrypt_message(env: &WordEnvelope, chat_id: &str, expected_sequence: u64,
                       msg_key: &MessageKey) -> ShieldResult<String> {
    if env.version != VERSION || env.sequence != expected_sequence {
        return Err(ShieldError::SequenceMismatch);
    }
    if chat_id.is_empty() || chat_id.len() > 256 || env.ciphertext.len() > MAX_ENVELOPE + 512
       || env.pq_ratchet_chunk.len() > MAX_RATCHET_CHUNK {
        return Err(ShieldError::LimitExceeded);
    }
    let aad = outer_context(chat_id, env);
    let derived = derive(msg_key, &env.public_seed, &label_with_hash(b"outer/", &aad))?;
    let padded = decrypt_word(0, &derived, &env.nonce, &env.ciphertext, &aad)?;
    if padded.len() < 4 || padded.len() % BLOCK_SIZE != 0 {
        return Err(ShieldError::InvalidFormat);
    }
    let body_len = u32::from_be_bytes(padded[..4].try_into().map_err(|_| ShieldError::InvalidFormat)?) as usize;
    if body_len > MAX_ENVELOPE || body_len > padded.len() - 4 {
        return Err(ShieldError::InvalidFormat);
    }
    let inner: Inner = serde_json::from_slice(&padded[4..4 + body_len])
        .map_err(|_| ShieldError::InvalidFormat)?;
    if inner.tokens.len() > MAX_TOKENS || inner.word_count > 4_096 {
        return Err(ShieldError::LimitExceeded);
    }
    let mut out = String::new();
    let mut words = 0u32;
    for token in inner.tokens {
        match token {
            InnerToken::Separator { text } => {
                if text.chars().any(|c| c.is_alphanumeric()) {
                    return Err(ShieldError::InvalidFormat);
                }
                out.push_str(&text);
            }
            InnerToken::Word { alg, nonce, ciphertext } => {
                if words >= inner.word_count as u32 || ciphertext.len() > MAX_ENVELOPE {
                    return Err(ShieldError::InvalidFormat);
                }
                if alg != algorithm(&env.public_seed, &env.message_id, words) {
                    return Err(ShieldError::InvalidFormat);
                }
                let aad = word_context(chat_id, env.sequence, &env.message_id, words,
                                       inner.word_count as u32, alg);
                let derived = derive(msg_key, &env.public_seed, &label_with_hash(b"word/", &aad))?;
                let bytes = decrypt_word(alg, &derived, &nonce, &ciphertext, &aad)?;
                let part = String::from_utf8(bytes).map_err(|_| ShieldError::InvalidFormat)?;
                if !part.chars().any(|c| c.is_alphanumeric()) {
                    return Err(ShieldError::InvalidFormat);
                }
                out.push_str(&part);
                words += 1;
            }
        }
    }
    if words != inner.word_count as u32 || out.len() > MAX_PLAINTEXT {
        return Err(ShieldError::InvalidFormat);
    }
    Ok(out)
}
