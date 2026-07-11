# ROADMAP — Druid

The milestone checklist.

**Rules of the road:**
- Each milestone is an **independently runnable** slice — something actually
  testable end-to-end, not an internal-only refactor.
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
  - [x] **M2a — Self-verifying proof bundle.** _Confirmed 2026-07-10._
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
    - [x] **M2b-1 — RFC 3161 anchor + offline verifier.** _Confirmed 2026-07-10._
      A Rust `rfc3161` verifier (on cms/x509-cert/x509-tsp/rsa/ecdsa) validates a
      timestamp token offline: it binds the token's messageImprint to the checkpoint,
      verifies the TSA signature over the signed attributes, checks the timestamping EKU,
      and chains the signer to a **pinned** root. `druid anchor` timestamps the current
      checkpoint (a **self-hosted dev TSA** for now — proves the mechanism, not
      independence); `bundle` embeds the token in `anchors`; `druid verify-bundle
      --root <pem>` reports "anchored no later than T" offline.
      **Test:** `observe` → `anchor` → `bundle` → `verify-bundle --root` → `VALID …
      anchored no later than <T>`; tamper the token → `INVALID`; an anchor whose TSA
      root isn't pinned is reported `not verified` and claims no time bound — the bundle
      stands on its inclusion proof (the C2SP witness model, ADR-0005).
      `cargo test` (incl. openssl-minted token fixtures) + `pytest` green.
    - [x] **M2b-2 — Independent third-party TSAs.** _Confirmed 2026-07-10._
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
  - [x] **M2c — Tile serving.** _Confirmed 2026-07-10._ Every append publishes the C2SP
    tile files (`tile/<h>/<l>/<n>[.p/<w>]`, height 8) beside the ledger; `druid tiles`
    regenerates them for pre-tile ledgers; `druid export` ships `checkpoint` + `tile/`
    so the static site doubles as a tile server. `druid-verify tiles` reconstructs an
    inclusion proof from the tile files alone, authenticating every tile against the
    signed root. _(Hash tiles only — entry bundles wait for a consumer; the record
    bytes travel in the proof bundle.)_
    **Test:** the verifier reconstructs an inclusion proof from fetched tiles alone.
    _(Passes: a dir holding only `tile/` → `VALID … via tiles alone`; a flipped tile
    byte → `INVALID downloaded inconsistent tile`; hash-file deletion doesn't matter.)_

## Phase 2 — Detection depth

- **M3 — Numeric extraction + render collector (split).**
  - [x] **M3a — L2 numeric / threshold extraction.** _Confirmed 2026-07-10._
    Extract numbers-with-units in a regulatory context (a limit, standard, threshold,
    reporting cutoff) and flag when the value tied to the same context changes →
    `NumericThresholdChange [High]`. High-precision: a number counts only next to a
    regulatory keyword with a plausible unit, so prose numbers (years, counts) are
    ignored. Wired into the differ after L1. _(Cross-unit normalisation via `pint` —
    10 ppb == 0.010 ppm — is the L2 refinement.)_
    **Test:** a page whose "reporting threshold is 10 ppb" becomes "15 ppb" →
    `NumericThresholdChange [High] {from: 10 ppb, to: 15 ppb}`; a page changing years/
    counts emits nothing. `pytest` green.
  - [x] **M3b — Render collector.** _Confirmed 2026-07-10._ A Playwright headless
    collector (`collectors/render.py`, behind an injectable `RenderEngine` port so tests
    need no browser) captures the post-JS **rendered DOM** as the attested artifact and
    the page's own **API/data calls** (XHR/fetch) as content-addressed side artifacts
    referenced by a canonical request manifest (`captured_requests_hash`). The pipeline
    dispatches on `target.collector`; detection runs on the rendered content. Playwright
    is an optional `render` extra.
    **Test:** a JS-rendered fixture is observed with its data calls captured. _(Passes:
    a fake engine offline + a live localhost JS page rendered by real headless Chromium →
    the fetched `/api/scores.json` body is captured and retrievable by hash, the mutated
    DOM is attested and tile-verifiable.)_

- **M4 — Dataset diffing (split).**
  - [x] **M4a — Tabular (CSV/JSON) schema + distributional diff.** _Confirmed
    2026-07-10._ A `dataset`-kind target routes to the L4 differ (`differ/dataset.py`,
    pandas): column add/remove/retype → `SchemaChange`; a numeric column re-baselined/
    scaled or the series truncated → `DistributionalShift`. High-precision (distributional
    checks only numeric columns).
    **Test:** two dataset versions — a dropped column → `SchemaChange [High]`; a
    re-baselined series → `DistributionalShift [High]`; truncation → a `row_count`
    `DistributionalShift`. `pytest` green.
  - [x] **M4b — Scientific/geospatial datasets.** _Confirmed 2026-07-10._ `dataset_diff`
    became a magic-byte format router (`detect_format` + `_route`): NetCDF/HDF via
    `xarray` (`differ/netcdf.py` — variable presence, dimension sizes, global/per-variable
    attributes, per-variable summary stats), `.xlsx` per-sheet tabular diff, and `.zip`
    per-member diff recursing into each changed member. The scientific backends
    (xarray/scipy/h5netcdf/openpyxl) are an optional `science` extra; the tabular + zip
    paths need none.
    **Test:** a NetCDF with a dropped variable / changed summary stat is flagged.
    _(Passes offline + live: NetCDF3 and NetCDF4/HDF5 with a dropped `ch4` →
    `SchemaChange [High]`, a re-baselined `co2` → `DistributionalShift [High]`, a changed
    `units` attr → `MetadataChange`; zip member-removal + recursion; xlsx column drop.)_

## Phase 3 — The public product

- **M5 — Public record + alerts (split). ★ public ship.**
  - [x] **M5a — Public record (Astro) + RSS feeds.** _Confirmed 2026-07-10._
    `druid export` builds `record.json` + a global and per-target RSS feed from the
    ledger. An Astro static site (`web/`) renders a home page (recent classified changes
    + targets), per-target timelines (attested observations interleaved with diffs), and
    per-event permalinks — each with the integrity/interpretation boundary stated in copy.
    **Test:** `druid export` writes valid `record.json` + `feed.xml`; `cd web && npm run
    build` renders the pages; the home + target pages show the classified changes (incl.
    10→15 ppb). `pytest` green.
  - [x] **M5b — In-browser WASM verifier.** _Confirmed 2026-07-10._ `ledger-core`
    compiles to WASM (`rust/ledger-wasm`, wasm-bindgen), shipping the pinned DigiCert/FreeTSA
    roots; the `/verify` page verifies a downloaded `druid.proofbundle/v1` **entirely in the
    browser** — a green check / red cross, nothing uploaded, trusting neither the source nor
    Druid. _(Client-side search is a small remaining add.)_
    **Test:** in the browser, a real anchored bundle → `VALID … anchored no later than <T>`;
    a tampered artifact → `INVALID`; matches the native `druid-verify`. `cargo build
    --target wasm32` + native `cargo test` green.
  - [x] **M5c — Push alerts + search.** _Confirmed 2026-07-10._ `druid notify`
    delivers each new diff event to matching subscriptions (`data/subscriptions.toml`) over
    **webhook** (POST `druid.alert/v1`) and **email** (SMTP), filtered by target, diff-type,
    and minimum severity; delivery is idempotent (a per-(sub, event) key persisted in
    `notify-state.json`, so re-runs never re-send and failures retry). Senders are
    injectable → fully offline-testable. The record site gains **client-side search** over
    the changes. _(A FastAPI/SQLite live-query surface is deferred — the static export +
    search covers the read need.)_
    **Test:** `notify --dry-run` lists pending deliveries; dispatch sends matching events
    once (idempotent, failures retry); the site's search filters the change list. `pytest`
    green.

## Phase 4 — Force multipliers

- [x] **M6 — Embedding triage + LLM summaries (reviewer aid).** _Confirmed 2026-07-10._
  **L3** (`differ/embedding.py`, injectable `Embedder`) segments a text change L1/L2
  couldn't explain, embeds each changed passage, and ranks it against its closest prior
  passage: a semantically distant rewrite → `ContentEdit` for review, a near-duplicate
  stays quiet. **L5** (`triage.py`, injectable `Summarizer`, `druid triage`) drafts a
  plain-language Claude summary of a reworded passage into a **review sidecar**
  (`druid-data/review/`), clearly labelled best-effort and **never** in a ledger leaf.
  Both are an optional `triage` extra (sentence-transformers / anthropic).
  **Test:** a reworded-but-not-term-flagged edit is surfaced for review with a
  plain-language summary; the trust core is untouched. _(Passes: L3 flags the reworded
  passage as `ContentEdit [L3-embedding]`; the summary lands in the sidecar with the
  ledger entry count unchanged and `verify` still VALID.)_

- [x] **M7 — Federated overlay index + verification badging.** _Confirmed 2026-07-10._
  `overlay.py` harvests third-party archive metadata behind an injectable `ArchiveSource`
  port (default `WaybackSource` — Internet Archive CDX, polite/read-only; OSF/Dataverse/
  Perma.cc/PEDP are the same port) and `build_overlay` cross-references it with Druid's
  attested observations into a `druid.overlay/v1` index: a resource in both is badged
  **druid-attested** with a downloadable proof bundle, a third-party-only copy shows no
  badge. `druid overlay` writes `overlay.json` + `bundles/`; a `/overlay` Astro page
  renders the badged, searchable list.
  **Test:** search a resource that exists in both Wayback and Druid → it shows the
  attested badge with a downloadable bundle; an unverified-only resource shows no badge.
  _(Passes offline + live: a real Wayback CDX harvest on the ledger badged
  `www.epa.gov/ghgreporting` attested with 7 real captures + a bundle, while
  `ejscreen.epa.gov/mapper` (Wayback-only) got no badge; the `/overlay` page renders both
  with the bundle link resolving to a valid `druid.proofbundle/v1`.)_

- [ ] **M8 — Multi-party witnesses.** C2SP `tlog-cosignature`: independent witnesses
  co-sign checkpoints; bundles carry cosignatures; the verifier requires a quorum.
  **Test:** with a 2-of-3 witness set, a bundle missing a quorum of cosignatures is
  rejected; a complete one validates.

---

**North star:** A skeptical third party can verify, offline and trusting neither the
government nor Druid, exactly what a source said and when — and Druid flags the
specific meaningful change, classified and alertable.
