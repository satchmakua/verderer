# 2. M0 ships a signed hash-chain ledger, not the real Merkle log

- **Status:** Accepted
- **Date:** 2026-06-30

## Context

Druid's value depends entirely on a tamper-evident ledger that resists even Druid's own
operators (DESIGN §4). The real implementation is a tile-based Merkle transparency log
(C2SP tlog-tiles + signed checkpoints) with an independent offline verifier, slated for
**M1** and built in Rust on the `tlog_tiles` crate. But M0's job is the *walking
skeleton*: prove the end-to-end shape (observe → store → diff → log → verify) runs, with
one passing test, as fast as possible. Standing up tiles + a Rust kernel + FFI in M0
would blow the "thinnest slice" budget.

## Decision

For M0, the ledger is a **signed append-only hash chain** (`src/druid/ledger/log.py`):
each entry hash-links to the previous (`leaf_hash = H(domain ‖ prev ‖ canonical(record))`),
and the head `(size, head_hash)` is Ed25519-signed. `verify()` recomputes the chain and
checks the head signature. It is deliberately Python-only and labelled, in code and
docs, as a placeholder. **M1 replaces it wholesale** — this module is expected to be
deleted, not extended.

We keep the boundaries that M1 needs already in place: records are canonical-JSON
hashed, leaves carry `index`/`prev`/`leaf_hash`, and the signed-head shape mirrors a
checkpoint (origin / size / root). So the M1 swap is a re-implementation behind the same
"append a leaf, prove the head" seam, not a redesign.

## Consequences

- **Easy:** M0 ships now, fully tested (including a tamper test), with honest
  tamper-evidence and no Rust toolchain required to run it.
- **Hard / accepted trade-off:** the M0 log has **no Merkle inclusion/consistency
  proofs, no external anchoring, and a single signing key** — so it does not yet deliver
  the offline, transferable, anchored guarantees DESIGN promises. That is M1/M2 work and
  must not be claimed before then.
- **Risk to watch:** the temptation to "just extend" the hash chain instead of doing the
  real tile log. Resist it — the chain is a stand-in, and the project's whole credibility
  rests on M1 being the genuine article. Superseded by the M1 ADR when that lands.
