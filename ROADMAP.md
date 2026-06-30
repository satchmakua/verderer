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

- [ ] **M1 — Real trust core (Rust `ledger-core` + tile log + offline verifier).**
  Replace `SignedLog` with a C2SP tlog-tiles Merkle log written as tiles; a Rust
  kernel (on the `tlog_tiles` crate) does append-leaf, signed checkpoint, inclusion
  proof, consistency proof; a standalone `druid-verify` validates a leaf against a
  checkpoint offline. Python shells out over stdio.
  **Test:** observe a target; run `druid-verify` on the resulting leaf → it confirms
  inclusion under the signed checkpoint. Flip one byte of a stored tile/leaf → verify
  **fails**. `pytest` green.

- [ ] **M2 — Anchoring + self-verifying proof bundle.** Each checkpoint anchored via
  OpenTimestamps + RFC 3161 + ≥2 mirrors; `druid bundle <observation>` exports a
  `druid.proofbundle/v1`; `druid-verify bundle.zip` validates fully offline including
  anchor proofs.
  **Test:** export a bundle, copy it to a clean machine with only the verifier, run
  `druid-verify bundle.zip` → it validates without contacting Druid. Tamper any field
  → it rejects.

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
