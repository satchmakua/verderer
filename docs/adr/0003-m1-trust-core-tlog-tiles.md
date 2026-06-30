# 3. M1 trust core: a tlog Merkle log in Rust, backed by a stored-hash file

- **Status:** Accepted
- **Date:** 2026-06-30
- **Supersedes:** [ADR-0002](0002-m0-signed-hash-chain-ledger.md)

## Context

M1 replaces the M0 hash-chain stand-in with the real trust core (engineering pillar #1).
The design (DESIGN §4) targets the C2SP **tlog-tiles** standard with signed checkpoints
and an independent offline verifier. Two questions had to be settled while building it:
what to build the Merkle crypto on, and how far to take the tile serialization in this
slice.

## Decision

- **Build on the `tlog_tiles` crate** (Cloudflare Research v0.2, the C2SP tlog
  algorithms ported from Go's `sumdb/tlog`) rather than hand-rolling Merkle crypto — no
  bespoke cryptography. The crate gives `record_hash`, `tree_hash`,
  `prove_record`/`check_record`, `prove_tree`/`check_tree`, and the `Checkpoint` body
  format. We add the **C2SP signed-note** layer (Ed25519) ourselves from the spec, since
  the crate formats the checkpoint body but does not sign it.
- **Back the log with the canonical flat stored-hash file** (the storage model the crate
  is designed around) plus a base64 entries file for the leaf data. A small Rust
  `ledger-core` crate exposes `Ledger` + two binaries (`druid-ledger`, `druid-verify`);
  Python shells out over stdio (no FFI).
- **Defer the HTTP tile-file serialization to M2.** Writing C2SP tile files (and a
  `TileReader`/`TileHashReader` read path) is a *serving/serialization* concern that pays
  off when the verifier fetches tiles from R2/CDN — which is exactly M2's proof-bundle +
  anchoring work. M1 delivers the trust *properties* (tamper-evidence, inclusion +
  consistency proofs, offline verification) without it.

## Consequences

- **Easy:** a correct, audited-dependency Merkle log with a tiny standalone verifier,
  proven by `cargo test` (append/verify, offline inclusion, consistency, tamper) and the
  Python end-to-end + tamper tests. `offline_verify` already gives the transferable,
  no-live-service check the proof bundle will package.
- **Hard / accepted:** the log isn't yet served as static tiles, so a third party can't
  *fetch tiles from the blob store and recompute proofs themselves* yet — they verify the
  explicit proof + signed checkpoint we hand them. External anchoring and multi-mirror
  publication are also still M2/M8. Until M2, "offline-verifiable, anchored" is not fully
  true and must not be claimed.
- **Operational:** the trust kernel must be built (`cargo build --release`) before the
  pipeline runs; `Cargo.lock` is committed for reproducible binaries; `rust/target/` is
  ignored. Decode the binaries' UTF-8 output explicitly (the checkpoint carries a U+2014
  em dash) — `text=True` corrupts it under the Windows cp1252 locale.
