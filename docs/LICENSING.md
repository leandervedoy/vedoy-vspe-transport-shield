# Licensing and redistribution review — 2026-11-06

## Vedoy Shield Core v0.3.0

This repository branch publishes experimental source for technical review. It is **not** a declaration that the code is approved for commercial distribution, safe for production messaging, or open-sourced under any particular license. Do not add a license statement on Vedoy's behalf without an explicit decision by the owner.

### Important upstream dependency

The optional `signal-spqr` Cargo feature depends on `signalapp/SparsePostQuantumRatchet` v1.6.0, which identifies its license as **AGPL-3.0-only**. The project has its own copyright and license; it is not Vedoy-owned. Distributing a combined app can impose source-code disclosure and other AGPL obligations. Consult qualified licensing counsel about the precise architecture and distribution model before enabling it in proprietary Vedoy applications.

The core builds without the optional SPQR feature, but the session functions fail closed rather than silently falling back to a weaker ratchet. Do not remove this safeguard as a licensing workaround.

### Release checklist

1. Decide whether Vedoy Shield will be open-source, dual-licensed, separately licensed, or internal research.
2. Get written legal review for the AGPL dependency and related transitive licenses.
3. Include a complete third-party dependency and copyright notice after locking versions.
4. Publish `LICENSE` / SPDX identifiers only after an explicit business licensing decision.
5. Keep the experimental security disclaimer and independent-review requirements regardless of license selection.
