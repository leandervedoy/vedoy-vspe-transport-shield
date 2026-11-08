import assert from "node:assert/strict";
import test from "node:test";
import { decodePacket, encodePacket, PROTOCOL_VERSION, VspeTransportError } from "../index.js";

function packet() {
  return {
    chat_id: "chat-a",
    envelope: {
      version: PROTOCOL_VERSION,
      sequence: 0,
      message_id: Array(16).fill(7),
      public_seed: Array(32).fill(8),
      nonce: Array(12).fill(9),
      pq_ratchet_chunk: [],
      ciphertext: [1, 2, 3]
    }
  };
}

test("encodes and decodes a valid public packet", () => {
  const original = packet();
  assert.deepEqual(decodePacket(encodePacket(original)), original);
});

test("rejects wrong versions and unknown wire fields", () => {
  const wrongVersion = packet();
  wrongVersion.envelope.version = 2;
  assert.throws(() => encodePacket(wrongVersion), VspeTransportError);

  const unknownField = packet();
  unknownField.envelope.extra = true;
  assert.throws(() => encodePacket(unknownField), VspeTransportError);
});
