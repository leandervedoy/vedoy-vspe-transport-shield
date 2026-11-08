//! Persist-before-send orchestration. Not a production Triple Ratchet; use a
//! complete reviewed PQXDH and Triple Ratchet implementation in real apps.
//! Network layer MUST NOT transmit before save_json has succeeded.
use crate::{
    hybrid::HybridRoot,
    ratchet::PostQuantumRatchet,
    storage::EncryptedAtomicStore,
    wordforge::{self, WordEnvelope},
    ShieldError, ShieldResult,
};
use serde::{Deserialize, Serialize};
const VERSION: u8 = 3;
const MAX_OUTBOX: usize = 1024;
const MAX_INBOX: usize = 4096;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentPacket {
    pub chat_id: String,
    pub envelope: WordEnvelope,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredMessage {
    pub message_id: [u8; 16],
    pub plaintext: String,
}
/// This structure is private plaintext; never upload or log it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateSession {
    pub version: u8,
    pub chat_id: String,
    pub next_send: u64,
    pub ratchet_state: Vec<u8>,
    pub outbox: Vec<SentPacket>,
    pub inbox: Vec<StoredMessage>,
}
fn check_state(s: &PrivateSession, expected_chat: &str) -> ShieldResult<()> {
    if s.version != VERSION || s.chat_id != expected_chat || s.chat_id.is_empty()
       || s.chat_id.len() > 256 || s.outbox.len() > MAX_OUTBOX
       || s.inbox.len() > MAX_INBOX || s.ratchet_state.len() > 16 * 1024 * 1024 {
        return Err(ShieldError::InvalidFormat);
    }
    Ok(())
}
pub fn create_session(store: &EncryptedAtomicStore, password2: &str, pin: &str,
                      scope: &str, chat_id: &str, root: &HybridRoot,
                      sender: bool) -> ShieldResult<()> {
    if chat_id.is_empty() || chat_id.len() > 256 { return Err(ShieldError::InvalidFormat); }
    let ratchet = PostQuantumRatchet::initialize(root, sender)?;
    let state = PrivateSession {
        version: VERSION, chat_id: chat_id.to_owned(), next_send: 0,
        ratchet_state: ratchet.encrypted_snapshot_bytes(),
        outbox: Vec::new(), inbox: Vec::new(),
    };
    store.save_json(password2, pin, scope, 0, &state)?;
    Ok(())
}
/// Return sendable packet ONLY after new state + outbox are durably committed.
pub fn queue_message(store: &EncryptedAtomicStore, password2: &str, pin: &str,
                     scope: &str, chat_id: &str, plaintext: &str) -> ShieldResult<SentPacket> {
    let (rev, mut state): (u64, PrivateSession) = store.load_json(password2, pin, scope)?;
    check_state(&state, chat_id)?;
    if state.outbox.len() >= MAX_OUTBOX { return Err(ShieldError::LimitExceeded); }
    let ratchet = PostQuantumRatchet::from_encrypted_snapshot(state.ratchet_state.clone())?;
    let prepared = ratchet.prepare_send()?;
    let envelope = wordforge::encrypt_ratchet_message(
        plaintext, chat_id, state.next_send, &prepared.key, &prepared.chunk,
    )?;
    let packet = SentPacket { chat_id: chat_id.to_owned(), envelope };
    state.next_send = state.next_send.checked_add(1).ok_or(ShieldError::LimitExceeded)?;
    state.ratchet_state = prepared.next_state;
    state.outbox.push(packet.clone());
    store.save_json(password2, pin, scope, rev, &state)?;
    Ok(packet)
}
/// Reveal decrypted text only after new ratchet state and inbox are saved.
pub fn receive_message(store: &EncryptedAtomicStore, password2: &str, pin: &str,
                       scope: &str, chat_id: &str, packet: &SentPacket) -> ShieldResult<String> {
    let (rev, mut state): (u64, PrivateSession) = store.load_json(password2, pin, scope)?;
    check_state(&state, chat_id)?;
    if packet.chat_id != chat_id || packet.envelope.pq_ratchet_chunk.is_empty()
       || state.inbox.len() >= MAX_INBOX {
        return Err(ShieldError::InvalidFormat);
    }
    if state.inbox.iter().any(|m| m.message_id == packet.envelope.message_id) {
        return Err(ShieldError::AuthenticationFailed);
    }
    let ratchet = PostQuantumRatchet::from_encrypted_snapshot(state.ratchet_state.clone())?;
    let prepared = ratchet.prepare_receive(&packet.envelope.pq_ratchet_chunk)?;
    let plaintext = wordforge::decrypt_message(
        &packet.envelope, chat_id, packet.envelope.sequence, &prepared.key)?;
    state.ratchet_state = prepared.next_state;
    state.inbox.push(StoredMessage {
        message_id: packet.envelope.message_id, plaintext: plaintext.clone(),
    });
    store.save_json(password2, pin, scope, rev, &state)?;
    Ok(plaintext)
}
/// Caller must validate an authenticated delivery receipt before invoking.
pub fn acknowledge_delivery(store: &EncryptedAtomicStore, password2: &str, pin: &str,
                            scope: &str, chat_id: &str, message_id: [u8; 16]) -> ShieldResult<()> {
    let (rev, mut state): (u64, PrivateSession) = store.load_json(password2, pin, scope)?;
    check_state(&state, chat_id)?;
    let before = state.outbox.len();
    state.outbox.retain(|p| p.envelope.message_id != message_id);
    if state.outbox.len() == before { return Err(ShieldError::InvalidFormat); }
    store.save_json(password2, pin, scope, rev, &state)?;
    Ok(())
}
