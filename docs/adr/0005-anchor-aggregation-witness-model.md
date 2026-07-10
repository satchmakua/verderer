# 5. Anchor aggregation follows the C2SP witness model: unpinned anchors are reported, not fatal

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

M2b-2 embedded the DigiCert/FreeTSA roots in the verifier, which made `verify_bundle`'s
"anchors present but UNCHECKED (empty root set)" branch unreachable: the pinned set is
never empty now, so *every* anchor was routed through full token verification and **any**
failure — including "signer chains to no pinned root" — rejected the whole bundle. A
bundle carrying a self-hosted dev anchor (or, later, any anchor from a TSA a given
verifier build doesn't pin) became INVALID for third parties, even though its inclusion
proof and its DigiCert/FreeTSA anchors were perfectly verifiable. That conflates two
different claims — "this record is in the attested log" (inclusion) and "it existed no
later than T" (per-anchor) — and makes honest bundles fragile against verifier root-set
skew. It also contradicted M2b-1's documented intent ("anchors with no pinned root are
reported UNCHECKED; the inclusion proof stands alone").

## Decision

Aggregate anchors the way C2SP checkpoint verifiers treat witness cosignatures: **verify
what you can, report what you can't, and never let unverifiable provenance poison the
verifiable core.**

- The token-level verifier is unchanged and strict: `verify_rfc3161_token` rejects an
  unpinned signer (`ERR_UNTRUSTED_ROOT`), a mismatched imprint, a bad digest/signature,
  a missing EKU, and an out-of-window genTime.
- `verify_bundle` distinguishes the *one* failure that is not evidence of tampering.
  `ERR_UNTRUSTED_ROOT` means the token is internally consistent but its TSA isn't pinned:
  the anchor is counted and reported as "present but not verified (no pinned root for
  that TSA)", contributes **no** time bound, and the bundle's verdict rests on the
  inclusion proof and the remaining anchors. Unsupported anchor *types* (e.g. a future
  OTS anchor read by an old verifier) are reported the same way instead of being silently
  skipped.
- Every other token failure is corruption or misdirection (the token doesn't commit to
  this bundle's checkpoint, or its crypto doesn't check out) and remains **fatal**:
  tampering anywhere in a bundle rejects the bundle.

## Consequences

- **Easy:** bundles are robust to verifier root-set skew — adding a new TSA (or carrying
  a dev anchor) no longer breaks verification for verifiers that don't know it; the
  reported time bound only ever comes from anchors that actually verified; M8's witness
  cosignatures get the same aggregation semantics for free.
- **Accepted:** "pin the wrong root" now yields `VALID` with `0 verified / N not
  verified` and **no time bound**, rather than `INVALID` (ROADMAP M2b-1's original
  wording updated). A consumer must read the verdict line, not the bundle JSON, for time
  claims — which was already the rule (don't overclaim).
- **Watch:** never count an unverified anchor toward any claim, and never drop one
  silently — both directions of that mistake would quietly overclaim.
