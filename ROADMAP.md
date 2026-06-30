# ROADMAP — Druid

The milestone checklist.

**Rules of the road:**
- Each milestone is an **independently runnable** slice, testable end-to-end.
- Every milestone ends with explicit **Test** steps — the acceptance criteria.
- Build **top-down**: M0–M2 build and harden the trust spine; M3–M4 deepen
  detection; **M5 is the public ship**; M6–M8 are force multipliers.
- Check a box **only after its Test passes**.

See [DESIGN.md §8](DESIGN.md) for the full rationale behind this arc.

---

## Phase 0 — Walking skeleton

- [x] **M0 — Skeleton & it runs.** Python pipeline end-to-end on one target: static
  collector → content-addressed store → a signed hash-chain ledger (the honest M0
  stand-in for M1's Merkle log) → L0 normalisation + L1 term-watch → a CLI
  (`observe` / `log` / `verify` / `targets`). One passing test, lint + typecheck wired.
  **Test:** `pip install -e ".[dev]"`; `python -m druid observe epa-ghgrp` prints a
  `[200]` observation with a content hash; `python -m druid verify` prints `VALID`;
  `pytest` → green. _(Verified at scaffold: 7/7 tests, live observe + verify OK.)_

## Phase 1 — The trust spine

- [x] **M1 — Real trust core (Rust `ledger-core` + offline verifier).** Replaced
  `SignedLog` with a Merkle log on the `tlog_tiles` crate (C2SP tlog algorithms): a
  Rust kernel does append-leaf, signed checkpoint (C2SP signed note, Ed25519),
  inclusion proof, and consistency proof, backed by the canonical stored-hash file; a
  standalone `druid-verify` validates a leaf against a signed checkpoint **offline**.
  Python shells out over stdio (no FFI). _(Confirmed; committed 9570122. HTTP
  tile-file serialization moved to M2c.)_

- **M2 — The citable proof (split into runnable slices).**
  - [ ] **M2a — Self-verifying proof bundle.** _Built; awaiting confirmation._
    `druid bundle <target> [-o file]` exports a single self-contained
    `druid.proofbundle/v1` (observation + raw artifact bytes + Merkle inclusion proof
    + signed checkpoint + pinned key); `druid-verify bundle <file>` validates it fully
    **offline** — artifact bytes hash to the observation, the leaf is included under
    the signed root — trusting neither the source nor Druid. Built on M1's
    `offline_verify`.
    **Test:** `druid observe epa-ghgrp`; `druid bundle epa-ghgrp -o proof.json`;
    `druid verify-bundle proof.json` → `VALID`; edit any byte of `proof.json` →
    `INVALID`. `pytest` + `cargo test` green.
  - [ ] **M2b — External anchoring.** Anchor each checkpoint via OpenTimestamps +
    RFC 3161 + ≥2 mirrors; add the `anchors` array to the bundle and verify the
    "existed no later than T_anchor" proofs offline.
    **Test:** a bundle's anchors validate offline; a forged anchor is rejected.
  - [ ] **M2c — Tile serving.** Emit the C2SP tile files to the blob store
    (R2 / CDN-served) so a verifier can fetch tiles directly and recompute proofs.
    **Test:** the verifier reconstructs an inclusion proof from fetched tiles alone.

## Phase 2 — Detection depth

- [ ] **M3 — Numeric extraction + full taxonomy + render collector.** L2
  numeric/threshold extraction (`pint` + NER); the complete typed taxonomy with
  severities; a Playwright render collector capturing DOM + the page's API calls.
  **Test:** point it at a fixture where a limit changes `10 ppb → 15 ppb` → a
  `NumericThresholdChange [High]` is emitted; a JS-rendered page is observed with its
  data calls captured.

- [ ] **M4 — Dataset collector + dataset diffing.** Dataset collector (CSV/JSON, then
  NetCDF via `xarray`); L4 schema + distributional diff.
  **Test:** feed two versions of a dataset with a dropped column and a re-baselined
  series → `SchemaChange` and `DistributionalShift` are emitted.

## Phase 3 — The public product

- [ ] **M5 — Public record (Astro) + alerts. ★ public ship.** FastAPI + SQLite/
  Litestream index; an Astro site with per-target timelines, diff detail pages,
  permanent content-hash URLs, "download proof bundle" with the in-browser WASM
  verifier; alerts via RSS/Atom + webhook + email by target and diff-type/severity.
  **Test:** open the site, browse a target's timeline, download a bundle and watch the
  in-browser verifier show a green check; subscribe to an RSS feed and see a new diff
  appear.

## Phase 4 — Force multipliers

- [ ] **M6 — Embedding triage + LLM summaries (reviewer aid).** L3 embeddings rank
  reworded passages; L5 Claude summaries for reviewers only.
  **Test:** a reworded-but-not-term-flagged edit is surfaced for review with a
  plain-language summary; the trust core is untouched.

- [ ] **M7 — Federated overlay index + verification badging.** Harvest Wayback CDX /
  OSF / Dataverse / Perma.cc / PEDP metadata into unified search; badge
  Druid-attested (with proof bundle) vs unverified.
  **Test:** search a resource that exists in both Wayback and Druid → it shows the
  attested badge with a downloadable bundle; an unverified-only resource shows no badge.

- [ ] **M8 — Multi-party witnesses.** C2SP `tlog-cosignature`: independent witnesses
  co-sign checkpoints; bundles carry cosignatures; the verifier requires a quorum.
  **Test:** with a 2-of-3 witness set, a bundle missing a quorum of cosignatures is
  rejected; a complete one validates.

---

**North star:** A skeptical third party can verify, offline and trusting neither the
government nor Druid, exactly what a source said and when — and Druid flags the
specific meaningful change, classified and alertable.
