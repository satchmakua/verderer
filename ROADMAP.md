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
  - **M2b — External anchoring (split; RFC 3161 offline verification is the spine).**
    - [ ] **M2b-1 — RFC 3161 anchor + offline verifier.** _Built; awaiting confirmation._
      A Rust `rfc3161` verifier (on cms/x509-cert/x509-tsp/rsa/ecdsa) validates a
      timestamp token offline: it binds the token's messageImprint to the checkpoint,
      verifies the TSA signature over the signed attributes, checks the timestamping EKU,
      and chains the signer to a **pinned** root. `druid anchor` timestamps the current
      checkpoint (a **self-hosted dev TSA** for now — proves the mechanism, not
      independence); `bundle` embeds the token in `anchors`; `druid verify-bundle
      --root <pem>` reports "anchored no later than T" offline.
      **Test:** `observe` → `anchor` → `bundle` → `verify-bundle --root` → `VALID …
      anchored no later than <T>`; tamper the token or pin the wrong root → `INVALID`.
      `cargo test` (incl. openssl-minted token fixtures) + `pytest` green.
    - [ ] **M2b-2 — Independent third-party TSAs.** _Built; awaiting confirmation._
      `druid anchor --tsa digicert,freetsa` submits over HTTP to real, independent TSAs;
      the verifier **ships their roots pinned**, so those anchors verify with no `--root`.
      The verifier now handles real production tokens (DigiCert RSA-4096; FreeTSA ECDSA
      **P-384 + SHA-512** — curve taken from the key, not the digest). This is the step
      that gives a *real* time bound (self-hosted does not).
      **Test:** `druid anchor --tsa digicert,freetsa` → `bundle` → `verify-bundle` (no
      `--root`) → `VALID … N anchor(s) verified - existed no later than <T>`; `cargo test`
      verifies committed real DigiCert + FreeTSA tokens and rejects each under the other's
      root. (Live submission is network-gated + skips offline.)
    - [ ] **M2b-3 — OpenTimestamps.** Add an OTS proof + the Bitcoin block header needed
      to bound time offline (a distinct `anchors` entry type). **Test:** an OTS anchor
      validates offline against the carried header; a forged one is rejected.
  - [ ] **M2c — Tile serving.** Emit the C2SP tile files to the blob store
    (R2 / CDN-served) so a verifier can fetch tiles directly and recompute proofs.
    **Test:** the verifier reconstructs an inclusion proof from fetched tiles alone.

## Phase 2 — Detection depth

- **M3 — Numeric extraction + render collector (split).**
  - [ ] **M3a — L2 numeric / threshold extraction.** _Built; awaiting confirmation._
    Extract numbers-with-units in a regulatory context (a limit, standard, threshold,
    reporting cutoff) and flag when the value tied to the same context changes →
    `NumericThresholdChange [High]`. High-precision: a number counts only next to a
    regulatory keyword with a plausible unit, so prose numbers (years, counts) are
    ignored. Wired into the differ after L1. _(Cross-unit normalisation via `pint` —
    10 ppb == 0.010 ppm — is the L2 refinement.)_
    **Test:** a page whose "reporting threshold is 10 ppb" becomes "15 ppb" →
    `NumericThresholdChange [High] {from: 10 ppb, to: 15 ppb}`; a page changing years/
    counts emits nothing. `pytest` green.
  - [ ] **M3b — Render collector.** A Playwright headless collector capturing the
    rendered DOM + the page's underlying API/data calls (for JS tools).
    **Test:** a JS-rendered fixture is observed with its data calls captured.

- **M4 — Dataset diffing (split).**
  - [ ] **M4a — Tabular (CSV/JSON) schema + distributional diff.** _Built; awaiting
    confirmation._ A `dataset`-kind target routes to the L4 differ (`differ/dataset.py`,
    pandas): column add/remove/retype → `SchemaChange`; a numeric column re-baselined/
    scaled or the series truncated → `DistributionalShift`. High-precision (distributional
    checks only numeric columns).
    **Test:** two dataset versions — a dropped column → `SchemaChange [High]`; a
    re-baselined series → `DistributionalShift [High]`; truncation → a `row_count`
    `DistributionalShift`. `pytest` green.
  - [ ] **M4b — Scientific/geospatial datasets.** NetCDF/HDF via `xarray` (metadata +
    variable-presence + summary-stat diff); `.zip`/`.xlsx` unpacking.
    **Test:** a NetCDF with a dropped variable / changed summary stat is flagged.

## Phase 3 — The public product

- **M5 — Public record + alerts (split). ★ public ship.**
  - [ ] **M5a — Public record (Astro) + RSS feeds.** _Built; awaiting confirmation._
    `druid export` builds `record.json` + a global and per-target RSS feed from the
    ledger. An Astro static site (`web/`) renders a home page (recent classified changes
    + targets), per-target timelines (attested observations interleaved with diffs), and
    per-event permalinks — each with the integrity/interpretation boundary stated in copy.
    **Test:** `druid export` writes valid `record.json` + `feed.xml`; `cd web && npm run
    build` renders the pages; the home + target pages show the classified changes (incl.
    10→15 ppb). `pytest` green.
  - [ ] **M5b — In-browser WASM verifier.** _Built; awaiting confirmation._ `ledger-core`
    compiles to WASM (`rust/ledger-wasm`, wasm-bindgen), shipping the pinned DigiCert/FreeTSA
    roots; the `/verify` page verifies a downloaded `druid.proofbundle/v1` **entirely in the
    browser** — a green check / red cross, nothing uploaded, trusting neither the source nor
    Druid. _(Client-side search is a small remaining add.)_
    **Test:** in the browser, a real anchored bundle → `VALID … anchored no later than <T>`;
    a tampered artifact → `INVALID`; matches the native `druid-verify`. `cargo build
    --target wasm32` + native `cargo test` green.
  - [ ] **M5c — Push alerts.** Webhook + email delivery by target and diff-type/severity
    (RSS already ships in M5a); a FastAPI read API + SQLite/Litestream index if a live
    query surface is needed.
    **Test:** a new High-severity diff fires a configured webhook.

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
