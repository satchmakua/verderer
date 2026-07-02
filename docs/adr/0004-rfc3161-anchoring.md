# 4. RFC 3161 first for anchoring; pinned-root offline verification; self-hosted dev TSA

- **Status:** Accepted (M2b-2 landed 2026-07-01: independent DigiCert + FreeTSA TSAs, roots pinned in the verifier)
- **Date:** 2026-07-01

## Context

M2b anchors each signed checkpoint to a *time* so a bundle can claim "checkpoint root R
existed no later than T" (DESIGN §4.2/§6.3). The verifier (`druid-verify`) must validate
the anchor **offline**. Two candidate mechanisms: RFC 3161 timestamp tokens and
OpenTimestamps (OTS). A research workflow (fan-out + adversarial verification against
crates.io/docs.rs/RFCs) informed these calls.

## Decision

1. **RFC 3161 before OpenTimestamps.** An RFC 3161 token is self-contained and verifies a
   time bound offline the moment it's received (one signature against a pinned TSA cert
   chain). An OTS proof does **not** yield a time offline until it's Bitcoin-confirmed and
   the verifier is handed the relevant block header — so OTS is a strong *independent*
   anchor but a poor fit for "verify offline at bundling time". OTS is M2b-3, carrying the
   block header in-bundle.

2. **Build the verifier on the der-0.7 RustCrypto generation** — `cms` 0.2.3,
   `x509-cert` 0.2.5, `x509-tsp` 0.1 (for `TstInfo`), `rsa` 0.9.10, `ecdsa` 0.16.9,
   `p256`/`p384` 0.13. The der-0.8 generation is not yet matched by a stable `cms` 0.3 /
   `x509-cert` 0.3 (both RC as of 2026-07). No maintained crate verifies an RFC 3161 token
   end-to-end, so ~230 lines are assembled on these audited primitives — not bespoke
   crypto. A `TODO(der-0.8)` marks the migration.

3. **Pinned-root verification, not full RFC 5280 path validation.** The verifier checks:
   messageImprint binding, the signed-attribute cross-checks, the TSA signature over the
   DER `SET OF` signed attributes, the `id-kp-timeStamping` EKU, a verified signature chain
   to an explicitly **pinned** root, and genTime within the signer's validity window. It
   does **not** do revocation, name constraints, or policy processing. For a small set of
   explicitly pinned TSAs this is appropriate; the limit is stated in code and here.

4. **Ship a self-hosted dev TSA now; independent TSAs in M2b-2.** `OpensslTsaAnchorer`
   generates a TSA in the gitignored data dir and mints tokens via `openssl ts`, so
   anchoring works offline end to end today. It is explicitly **not independent** (Druid
   holds the key) and provides no defence against Adversary B — the CLI, docs, and this
   ADR say so. Real third-party TSAs (DigiCert/FreeTSA, ≥2 independent) land in M2b-2 and
   are what make the time bound trustworthy.

## Consequences

- **Easy:** a correct, audited-primitive offline verifier, proven against real
  openssl-minted tokens (valid + four rejection paths); anchoring is demonstrable offline
  with zero network and zero committed secrets.
- **Hard / accepted:** the current time bound is only self-hosted (not yet trustworthy) —
  M2b-2 is required before any "existed no later than T" claim is real. Verification trusts
  pinned roots without revocation/full-path checks. The der-0.7 pin carries a migration
  debt when cms 0.3 / x509-cert 0.3 stabilise.
- **Risk to watch:** don't let the working self-hosted anchor tempt an "anchored, trust
  us" claim. Independence (M2b-2) is the point; until then the anchor proves *mechanism*,
  not *time*.
