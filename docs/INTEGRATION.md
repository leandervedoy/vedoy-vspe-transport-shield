# Integration plan — Vedoy Shield Core v0.3.0 (2026-11-06)

## Product boundaries

- **Rust library:** hybrid experimental handshake, optional Signal SPQR, envelope, local encrypted snapshots.
- **React Native / Sent:** UI, notifications, React Native native-bridge, lifecycle, user consent. NOT delivered here.
- **Mobile system:** Android Keystore / iOS Keychain (hardware-backed where supported); PIN lockout and biometric gates. NOT connected here.
- **Relay and VPN:** WireGuard/Proton optional; do not treat exit IP hopping as an E2EE guarantee. NOT delivered here.
- **ID verification backend:** Signicat/BankID verified status, no passport images in chat database. NOT connected here.

## Example sequence (only after future security review)

1. Users verify and pin each other's identity key; no blind trust-on-first-use silently.
2. Server delivers signed asynchronous prekeys; sender performs an audited authenticated PQXDH exchange (current `hybrid.rs` is research-only).
3. Both devices create postquantum ratchet state from agreed secret; complete classical DH ratchet in parallel.
4. Devices enter password #2 and PIN to unlock wrapped local state, additionally gated by hardware keystore.
5. `queue_message` prepares next state + encrypted envelope; saves both in one encrypted file **before** a sendable packet is returned.
6. Network transports an authenticated JSON ciphertext packet. Relays do not see plaintext or private keys.
7. Receiver atomically commits the updated ratchet state + received plaintext inside encrypted local inbox before returning it to UI.
8. Sender removes outbox packet only after an authenticated delivery receipt; retries use identical saved packet, not re-encryption with consumed message keys.

## JSON

A `SentPacket` has `chat_id` and an `envelope`. The envelope contains `version: 3`, `sequence`, `message_id`, `public_seed`, `nonce`, `pq_ratchet_chunk`, and `ciphertext`. Byte vectors are encoded as JSON arrays by serde by default, not base64. A future compact binary framing can be introduced under a new wire version.

Private session JSON includes: `version`, `chat_id`, `next_send`, `ratchet_state`, `outbox` and `inbox`. Never expose it through a network API or browser. It must be contained exclusively inside `EncryptedAtomicStore` and a hardware-bound secret is required before production.

## Atomic snapshot read/write

```
new_state + ciphertext -> outbox -> Argon2id(password2 + PIN)
                              -> AES-256-GCM-SIV
                              -> temp file(0600) -> fsync -> atomic rename
                              -> fsync containing directory -> return packet
```

The library uses exclusive OS advisory locks and compare-and-swap revisions to reduce concurrent mutation risks. Filesystem rollback, rogue privileged device processes and distributed multi-device synchronization are not solved.

## Build and CI

Check `Cargo.toml` version = `0.3.0`. From the repository root run `cargo test --all-targets`. The GitHub workflow lives at `.github/workflows/vedoy-shield-core.yml`.

Do not promote to a production CDN, mobile app store, server or website solely because CI is green. An independent security review is a release blocker.
