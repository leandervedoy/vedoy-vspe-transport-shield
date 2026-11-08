# Identity proofing for Sent / Vedoy Shield — 2026-11-06

## Decision

Use an **optional** verified-person badge. Verification must never be required for ordinary private messages, nor become a condition for cryptographic identity key verification. A passport match alone cannot prove that a given Signal-like device key belongs to that account; the proof must be bound explicitly to a pseudonymous account/device key by a trusted backend with valid nonce, issuer, audience and freshness.

## Revolut versus providers

Revolut asks its OWN customers to photograph a passport or national ID and possibly complete selfie/liveness verification. As of this review, we did not identify a documented general-purpose Revolut identity-proofing API for another chat app to use. **Do not infer that Revolut verified identity can be reused by Vedoy.**

**Suggested provider:** Signicat ReadID/Assure API supports NFC e-passport and national ID scanning, document verification, selfie/liveness and hosted flows. Norwegian BankID through Signicat is an option for consent-based electronic identification without directly handling document images. Check supported countries, pricing, contractual/data-processing terms and specific Norwegian regulations before purchasing.

## User flow

1. User chooses **Verify identity (optional)**.
2. Backend creates short-lived nonce linked to pseudonymous Vedoy account; redirects to ID provider's hosted workflow.
3. User scans valid passport or national ID card in vendor's app/SDK, with explicit provider disclosures/consent.
4. Provider completes cryptographic NFC chip check/document authenticity, selfie/liveness where required, and sends a server-authenticated completion callback.
5. Vedoy backend validates issuer, signature, audience, nonce, session state, freshness, anti-replay and account binding against provider docs.
6. Save only minimum necessary verification status, provider transaction reference, assurance level and expiry. Do not save passport number, document image, address, selfie or national identity number in the E2EE message database.
7. Show **verified badge** only for completed proof. Allow user to revoke visibility and delete where legally permissible.

## Data protection

Complete a DPIA/privacy assessment where appropriate, agree on a data processing agreement with the vendor, publish retention periods, define lawful bases, apply data minimization and access controls. Biometric matching raises additional privacy obligations. Never let a client send `verified: true` in JSON and obtain a badge without backend signature validation.

`src/identity.rs` deliberately exposes only a provider-agnostic trait and a fail-closed default. It does **not** claim to read ID documents, verify NFC certificates or contact Signicat. Connecting a live vendor requires an approved business account and secure backend credentials.

## Primary documentation

- Signicat: https://developer.signicat.com/docs/id-document-and-biometric-verification/
- ReadID: https://developer.signicat.com/docs/readid/
- Revolut: https://help.revolut.com/nb-NO/help/sign-up/how-do-i-upload-a-document/