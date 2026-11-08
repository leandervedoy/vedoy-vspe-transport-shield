//! Transport boundary for public VSPE packets.
//!
//! This module deliberately owns encoding and input validation only. It does
//! not open sockets, select relays, authenticate a server, or claim that a
//! relay provides end-to-end security. Callers must authenticate their own
//! transport and only hand packets to `session::receive_message` after decode.

use crate::{
    json::{encode_bounded, parse_bounded, PROTOCOL_VERSION},
    session::SentPacket,
    ShieldError, ShieldResult,
};

pub const MAX_PACKET_BYTES: usize = 2 * 1024 * 1024;
const MAX_CHAT_ID_BYTES: usize = 256;
const MAX_CIPHERTEXT_BYTES: usize = 512 * 1024;
const MAX_RATCHET_CHUNK_BYTES: usize = 1024 * 1024;

/// Encode a public, encrypted packet for an authenticated transport.
///
/// Private session state, passwords, PINs and identity secrets are not part of
/// this format and must never be passed to this function.
pub fn encode_packet(packet: &SentPacket) -> ShieldResult<Vec<u8>> {
    validate_packet(packet)?;
    encode_bounded(packet)
}

/// Decode an untrusted transport payload. Decryption and ratchet advancement
/// remain the responsibility of `session::receive_message`.
pub fn decode_packet(input: &[u8]) -> ShieldResult<SentPacket> {
    if input.is_empty() || input.len() > MAX_PACKET_BYTES {
        return Err(ShieldError::LimitExceeded);
    }
    let packet: SentPacket = parse_bounded(input)?;
    validate_packet(&packet)?;
    Ok(packet)
}

fn validate_packet(packet: &SentPacket) -> ShieldResult<()> {
    let envelope = &packet.envelope;
    if packet.chat_id.is_empty()
        || packet.chat_id.len() > MAX_CHAT_ID_BYTES
        || envelope.version != PROTOCOL_VERSION
        || envelope.ciphertext.is_empty()
        || envelope.ciphertext.len() > MAX_CIPHERTEXT_BYTES
        || envelope.pq_ratchet_chunk.len() > MAX_RATCHET_CHUNK_BYTES
    {
        return Err(ShieldError::InvalidFormat);
    }
    Ok(())
}
