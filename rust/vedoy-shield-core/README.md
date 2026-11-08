# Vedoy Shield Core v0.3.0 — experimental Rust / JSON

**Status:** research-only, **NOT audited**, **NOT production-ready**. No production integration or VPN is included. A compile/test run was not possible in the source-authoring environment (no Rust toolchain or network). GitHub Actions should build and test after publication; consult CI status before relying on any result.

Vedoy Shield aims to provide reusable cryptographic building blocks to **Sent** and future Vedoy applications. The critical cryptographic code is in **Rust**; JSON is a wire/data format, never an excuse to export private keys. `legacy-python/` contains only the earlier historical v0.1 proof of concept, not used by this crate.

## What v0.3.0 implements

| Area | Source | What is implemented | Key limitation |
|---|---|---|---|
| Hybrid authenticated startup | `src/hybrid.rs` | Recipient-signed public bundle; sender Ed25519 signature on transcript; both identities must be externally pinned; X25519 + ML-KEM-1024 combined via HKDF-SHA512. | **Not PQXDH**: lacks asynchronously rotated signed + one-time prekeys and durable global replay ledger. Ed25519 authentication is not postquantum. Research protocol not independently reviewed. |
| Reviewed upstream PQ ratchet | `src/ratchet.rs` | **Opt-in** bridge to Signal's upstream SPQR v1.6.0, setting minimum V1, no silent fallback. | SPQR is **AGPL-3.0-only** and normally runs alongside a classical DH ratchet; this bridge **does not implement Triple Ratchet**. Conditional integration is untested. |
| WordForge experimental layer | `src/wordforge.rs` | v3 JSON envelope; per-word HKDF + AEAD; authenticated SPQR chunk; padded outer authenticated encryption. | No proof per-word layers improve security; may increase attack surface/size. |
| Crash-atomic encrypted snapshots | `src/storage.rs` | Argon2id from secondary password **and** 6–12 digit PIN; AES-256-GCM-SIV; 0600 files/0700 dir, advisory locking, fsync file + atomic rename + fsync directory on Unix, revision CAS. | PIN lacks hardware attempts/rate limiting. No rollback resistance against privileged attacker or whole-device compromise. Only local single-filesystem Unix-like storage. |
| Persist-before-network | `src/session.rs` | Snapshot updates SPQR state and encrypted local outbox *before* packet is returned to caller; inbound packet and decrypted inbox stored before UI reveal. | No network transport/ack verification. Replay ledger only for retained inbox; no complete multi-device and prekey replay protection. |
| Identity proofing | `src/identity.rs` | Provider-neutral interface, explicit fail-closed behavior; no passport data in core. | No live provider credentials or verification API integration. |
| JSON | `src/json.rs` | Versioned capabilities and bounded serde JSON encode/decode. | Private session snapshots must remain encrypted and local. |

## Components

```text
React Native / Next.js interface (external)
              |
           Rust FFI  (NOT implemented)
              |
  +-----------v--------------------------+
  | Vedoy Shield Core v0.3.0 (Rust)       |
  | hybrid authenticated startup         |
  | SPQR adapter (optional / AGPL)       |
  | WordForge authenticated envelope     |
  | encrypted local outbox + inbox       |
  | Argon2id password2+PIN atomic vault  |
  +-----------+--------------------------+
              |
    Relay/VPN/Proton/ID provider (external)
```

**Proposed production path:** use a fully reviewed, maintained **PQXDH + Double/Triple Ratchet** implementation (e.g. libsignal) with secure platform key storage, instead of treating this research handshake or SPQR-only bridge as a substitute. The Signal libsignal project itself warns external Rust API consumers are unsupported and it is AGPLv3. Explicit legal/technical review is required before integrating it into commercial Vedoy applications.

## JSON schema examples

Public capabilities:

```json
{
  "core_version": "0.3.0",
  "wire_version": 3,
  "authenticated_hybrid_kem": "experimental-ed25519-x25519-mlkem1024",
  "post_quantum_ratchet_available": false,
  "storage": "unix-atomic-aes256gcmsiv-argon2id-password2-and-pin",
  "production_ready": false
}
```

`post_quantum_ratchet_available` becomes `true` when compiling with the explicitly opted-in `signal-spqr` feature. This reports an enabled adapter, NOT a safety certification.

A sender's public `HybridInvite` JSON includes `version`, `chat_id`, `recipient_bundle_sha256`, `ephemeral_x25519_public`, `mlkem1024_ciphertext`, `invite_id`, `sender_identity_public`, `sender_signature`. No private identities or passwords are part of the wire protocol.

## Local build

Requires Rust >= 1.88, Unix-like environment, access to crates.io and (for SPQR) GitHub. CI runs on Ubuntu. Do not use production secrets in tests.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
# Only after accepting AGPL obligations:
cargo test --all-targets --features signal-spqr
```

The upstream SPQR code is pinned to tag `v1.6.0`. A reproducible release should also commit Cargo.lock and source commit hashes, run `cargo audit`, supply-chain review, differential interoperability tests, and fuzzing. No lockfile was generated here because this environment has no Cargo.

## PIN and password #2

- Account login password is external to this crate.
- Password #2 is a dedicated *local vault* secret, minimum 12 UTF-8 bytes.
- PIN is a separate 6–12 digit secret. Both are required to decrypt a local snapshot.
- Never store password or PIN in JSON, remote databases, crash logs, or analytics.
- **Crucial:** a short PIN offers limited protection against offline theft; production must gate key unwrapping through hardware-backed Android Keystore / iOS Keychain and enforce OS-level retry throttling. The `SecureKeyVault` in `vault.rs` still fails closed until a platform adapter is provided.
- Forgetting both secrets can make local data permanently unrecoverable. Plan explicit, user-consented recovery policies.

## Crash resilience model

1. Prepare the next SPQR state and encrypted packet in memory.
2. Add packet to the local encrypted outbox alongside updated ratchet state.
3. Lock state file, verify revision, encrypt, create new private temporary file.
4. Sync temporary file, rename over prior snapshot atomically, sync containing directory.
5. **Only after** successful disk commit return the packet to network layer.
6. After receiving, persist new ratchet state **and** encrypted inbox before displaying plaintext.

An interrupted commit can leave a stray `.tmp` but the previous committed snapshot should remain readable. Atomic rename + fsync applies to a suitable local Unix filesystem, not arbitrary cloud sync, network FS, damaged storage or adversarial rollback. Concurrent multi-device mutation requires a server protocol and key transparency.

## Security and commercial warnings

This design has **not** undergone formal verification or independent code audit. It is **not** endorsed by Signal, it is not Signal or PQXDH, and is not more secure than Signal based on available evidence. Word-per-cipher research is opt-in and may be removed if it does not demonstrate an advantage.

Signal SPQR v1.6.0 and libsignal use the **AGPL-3.0-only** license. Do not enable this feature in a proprietary commercial app without consulting counsel and complying with the license. The absence of `signal-spqr` means sending sessions fail closed; there is **no** insecure fallback in `src/session.rs`.

See [SECURITY.md](docs/SECURITY.md), [ID-VERIFY.md](docs/ID-VERIFY.md), [INTEGRATION.md](docs/INTEGRATION.md) and [CHANGELOG.md](CHANGELOG.md).

## Upstream specifications

- [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/)
- [Signal Double/Triple Ratchet specification](https://signal.org/docs/specifications/doubleratchet/)
- [Signal SPQR implementation](https://github.com/signalapp/SparsePostQuantumRatchet)
- [NIST FIPS 203 / ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [Signicat NFC/ReadID](https://developer.signicat.com/docs/readid/)