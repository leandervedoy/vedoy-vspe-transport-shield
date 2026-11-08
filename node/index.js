/**
 * Public VSPE packet validation for Node.js.
 *
 * This package does not create keys, encrypt, decrypt, establish sessions, or
 * authenticate a network peer. Use the reviewed Rust core for cryptographic
 * operations and treat decoded packets as untrusted until that core verifies
 * and durably commits them.
 */
export const PROTOCOL_VERSION = 3;
export const MAX_PACKET_BYTES = 2 * 1024 * 1024;

const MAX_CHAT_ID_BYTES = 256;
const MAX_CIPHERTEXT_BYTES = 512 * 1024;
const MAX_RATCHET_CHUNK_BYTES = 1024 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class VspeTransportError extends Error {
  constructor(message, code = "INVALID_PACKET") {
    super(message);
    this.name = "VspeTransportError";
    this.code = code;
  }
}

function fail(message, code) {
  throw new VspeTransportError(message, code);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function byteArray(value, name, expectedLength, maximumLength = expectedLength) {
  if (!Array.isArray(value) || value.length < expectedLength || value.length > maximumLength) {
    fail(`${name} has an invalid length`);
  }
  if (!value.every((byte) => Number.isInteger(byte) && byte >= 0 && byte <= 255)) {
    fail(`${name} must be an array of bytes`);
  }
}

function unsignedInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${name} must be a non-negative safe integer`);
}

/** Validate a public, encrypted VSPE packet and return it unchanged. */
export function validatePacket(packet) {
  if (!isRecord(packet) || Object.keys(packet).length !== 2) fail("packet must contain only chat_id and envelope");
  if (typeof packet.chat_id !== "string" || packet.chat_id.length === 0 || encoder.encode(packet.chat_id).length > MAX_CHAT_ID_BYTES) {
    fail("chat_id must be a non-empty UTF-8 string of at most 256 bytes");
  }
  const envelope = packet.envelope;
  if (!isRecord(envelope)) fail("envelope must be an object");
  const fields = ["version", "sequence", "message_id", "public_seed", "nonce", "pq_ratchet_chunk", "ciphertext"];
  if (Object.keys(envelope).length !== fields.length || !fields.every((field) => Object.hasOwn(envelope, field))) {
    fail("envelope fields do not match protocol version 3");
  }
  if (envelope.version !== PROTOCOL_VERSION) fail("unsupported protocol version", "UNSUPPORTED_VERSION");
  unsignedInteger(envelope.sequence, "sequence");
  byteArray(envelope.message_id, "message_id", 16);
  byteArray(envelope.public_seed, "public_seed", 32);
  byteArray(envelope.nonce, "nonce", 12);
  byteArray(envelope.pq_ratchet_chunk, "pq_ratchet_chunk", 0, MAX_RATCHET_CHUNK_BYTES);
  byteArray(envelope.ciphertext, "ciphertext", 1, MAX_CIPHERTEXT_BYTES);
  return packet;
}

/** Encode a previously validated public packet as bounded UTF-8 JSON. */
export function encodePacket(packet) {
  validatePacket(packet);
  const encoded = encoder.encode(JSON.stringify(packet));
  if (encoded.byteLength > MAX_PACKET_BYTES) fail("packet exceeds the wire-size limit", "LIMIT_EXCEEDED");
  return encoded;
}

/** Parse and validate untrusted UTF-8 JSON received from a transport. */
export function decodePacket(input) {
  if (!(typeof input === "string" || input instanceof Uint8Array)) fail("input must be a string or Uint8Array");
  const bytes = typeof input === "string" ? encoder.encode(input) : input;
  if (bytes.byteLength === 0 || bytes.byteLength > MAX_PACKET_BYTES) fail("packet exceeds the wire-size limit", "LIMIT_EXCEEDED");
  let packet;
  try {
    packet = JSON.parse(typeof input === "string" ? input : decoder.decode(input));
  } catch {
    fail("packet is not valid UTF-8 JSON");
  }
  return validatePacket(packet);
}
