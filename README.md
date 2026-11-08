# Vedoy VSPE Transport Shield

An experimental Rust transport-security core for Vedoy Studio applications.

## Current scope

The library provides a test-covered research implementation of:

- authenticated hybrid startup using X25519 and ML-KEM-1024;
- explicit peer-identity pinning and transcript signatures;
- encrypted, crash-atomic local state and outbox persistence;
- a fail-closed optional bridge to Signal's SPQR ratchet; and
- versioned JSON transport envelopes with bounded parsing.

`transport::encode_packet` and `transport::decode_packet` define the public
wire boundary. They reject malformed or oversized packets, but do not establish
network trust; applications must use authenticated transport and pass decoded
packets through the durable session API before exposing plaintext.

The crate source lives in `rust/vedoy-shield-core/`; the repository-root
`Cargo.toml` is the canonical build entrypoint.

## Security status

**This is not production-ready cryptography.** It has not had an independent
security audit, it is not PQXDH or a complete Double/Triple Ratchet, and it
does not include a relay, VPN, mobile FFI, hardware key-store adapter, account
system, or deployment configuration. No application may describe itself as
post-quantum secure merely by depending on this crate.

In particular, the default build fails closed when the optional SPQR feature is
not enabled. Enabling `signal-spqr` introduces AGPL-3.0-only obligations and
requires legal and security review before any commercial use.

## Build and test

Rust 1.88 or newer and a Unix-like build environment are required.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets

# Only after accepting the Signal SPQR licensing obligations:
cargo test --all-targets --features signal-spqr
```

Do not use production credentials, keys, messages, or identity documents in
tests. See [the core documentation](rust/vedoy-shield-core/README.md), the
[security policy](docs/SECURITY.md), and the
[integration plan](docs/INTEGRATION.md) before integration.

## Node.js package

The repository also contains an ESM Node.js package that validates and encodes
the public encrypted packet format. It intentionally does **not** implement
cryptography, sessions or key management.

```bash
npm install @vedoy/vspe-transport-shield
```

Until the npm package is published under the `@vedoy` scope, install this
repository directly:

```bash
npm install github:leandervedoy/vedoy-vspe-transport-shield
```

Run `npm test` for the Node transport tests and `npm run pack:check` to inspect
the npm tarball before publishing.
