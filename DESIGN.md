# Druid — Design

> An immutable, provable record of what the government's environmental data said — and how it is being changed.

**Status:** Design draft · **Languages:** Python (pipeline) + Rust (trust kernel) · **Stack target:** Linux service + static web record · **License:** Apache-2.0 (the verifier *must* be open and auditable — see §2)

> **Provenance.** This refines the original `druid-design-doc.md` (now superseded by this file) with current research (verified 2026-06-29): it retargets the trust core from the now-maintenance-mode Trillian model to the **C2SP tlog-tiles** standard, makes the Rust ledger an owned decision (a real crate now exists), adds concrete data models, and reshapes the roadmap into independently-runnable, top-down milestones.

---

## 1. Concept

Federal environmental information is structurally fragile, and that fragility is currently being exploited. Since January 2025 the documented pattern includes removal of thousands of government web pages and datasets; the National Climate Assessments taken offline and the U.S. Global Change Research Program site shut down (NCAs removed 2025-06-30); the climate.gov editorial team terminated; EJScreen/CEJST pulled and unofficially re-hosted by volunteers. As important as deletion is **alteration**: definitions swapped, scope statements softened, terminology substituted ("climate change" → "resilience"), thresholds quietly edited. EDGI documented ~70% more environmental-website changes in the administration's first 100 days than in 2017 (verified 2026-06-29).

A volunteer rescue ecosystem already does real work — **EDGI**, **PEDP** (Public Environmental Data Partners), the **End-of-Term Web Archive**, the **Data Rescue Project**, Harvard's Library Innovation Lab (Perma.cc, Dataverse), the Internet Archive's Wayback Machine. Druid is **complementary, not a competitor.** Two structural gaps define its niche:

1. **The ecosystem is volunteer-bottlenecked.** Coverage is hand-driven and thin relative to the surface area.
2. **Crawlers preserve availability, not integrity.** A snapshot proves a copy *exists*; it does not let a skeptical third party *prove* "the EPA's page asserted exactly X on date Y, and this record has not been altered since — including by the archivist." Nobody treats **provable observation integrity** and **manipulation detection** as first-class features.

**Druid is** an observation pipeline + a verifiable append-only ledger + a semantic differ + a public record with self-verifying evidence bundles, over a curated, high-value target set — with a federated rescue-archive index layered on top later.

**The experience.** A journalist subscribes to "any threshold change in EPA water standards." Months later, a limit silently moves from 10 ppb to 15 ppb. Druid emits a `NumericThresholdChange / High` alert. The journalist clicks through to a permanent, content-hash URL, downloads a single proof bundle, and an open-source verifier — running offline, trusting *neither the government nor Druid* — confirms: *Druid observed exactly this content at this URL, no later than this timestamp, and the record has not been altered.* That bundle is what gets attached to a court filing or linked in a story.

### Engineering pillars (the 1–3 things that make or break this)

1. **A trust kernel that resists Druid's own operators.** The ledger must be tamper-evident even against a malicious insider or future maintainer (Adversary B, §4.1). This is a tile-based Merkle transparency log with signed checkpoints, externally anchored, with an independent offline verifier. **Correctness here is non-negotiable** — a bug voids the entire value proposition. This is the portfolio centerpiece.
2. **Semantic diffing that finds *meaningful* change, not byte noise.** Every page changes constantly (timestamps, tokens, banners). The product value is a layered differ that surfaces the specific, classified, alertable change — and keeps its heuristic interpretation rigorously *outside* the verifiable core.
3. **Heterogeneous, polite, faithful collection.** HTML, JS-rendered tools, tabular datasets, NetCDF, APIs — each captured faithfully (WARC, content-addressed) without becoming a load problem for the source.

---

## 2. Goals / Non-goals

**Goals (v1).**
- For any observation, produce a **downloadable proof bundle** that an independent, open-source verifier validates **offline**, establishing: content `h` was observed at URL `u`, faithfully preserved, included in the log, and the log root existed no later than an external anchor time `T_anchor`.
- Detect and **classify** meaningful change into a typed, severity-scored taxonomy (deletion, term substitution, numeric/threshold change, schema change, distributional shift, …) across HTML and tabular datasets.
- Maintain an **append-only, tamper-evident ledger** over ~12 curated high-value targets, with inclusion + consistency proofs checkable offline.
- Publish a **browsable public record** (per-target timeline; permanent content-hash URLs) and **subscribable alerts** (RSS/Atom, webhook, email) by target and diff-type/severity.
- Keep the **interpretation layer strictly separate** from the trust core: severity labels are heuristic and human-reviewable; the attested observations never change.

**Non-goals (v1).** *(The highest-leverage section for keeping the build on track.)*
- **No claims beyond observation integrity.** Druid never claims to prove the source's *original* contents, or that other clients saw the same bytes (single vantage can't exclude cloaking). See §4.2 non-properties.
- **No data generation.** Druid watches; it does not sense. Independent sensor networks are a different, harder project.
- **No truth adjudication.** The differ flags and classifies; humans interpret. Labels are never authoritative.
- **No general-purpose web archiving.** Not competing with Wayback — interoperable (WARC), differentiated (verifiability). Curated depth, not breadth.
- **No boil-the-ocean coverage.** ~12 curated targets to start, expanded deliberately. The page-count arms race is someone else's failure mode.
- **No live, general dead-tool resurrection.** At most one or two *static* flagship rebuilds (later); full resurrection is a separate project.
- **No administration-specific coupling.** Druid models environmental-data fragility as a *structural, durable* phenomenon. Nothing is keyed to a named administration.
- **No bespoke cryptography.** The trust core builds on the published **C2SP tlog-tiles / checkpoint** specs and an audited crate — not a hand-rolled Merkle scheme.

**Why open-source is load-bearing, not incidental.** You cannot ask anyone to *trust* a closed-source integrity tool. The verifier especially must be open and independently auditable for the proof bundles to mean anything. OSS isn't a nice-to-have — the security model *requires* it. **Apache-2.0** (explicit patent grant; matches the Sigstore/transparency-log ecosystem) for the whole project.

---

## 3. Tech stack

Pinned and verified 2026-06-29. Choices lean on the builder's existing kit (R2, Litestream, Astro) and on the fact that the modern transparency-log ecosystem is largely **Cloudflare-adjacent** — a happy alignment with the R2 + Astro stack.

| Layer | Choice | Why |
|---|---|---|
| **Trust kernel (ledger + verifier)** | **Rust**, on the `tlog_tiles` crate v0.2 (`cloudflare/azul`) + `ed25519-dalek` | Correctness is non-negotiable; `tlog_tiles` is a maintained, audited impl of the exact C2SP tlog-tiles + checkpoint specs, ported from Google's `tlog`. Compiles to a small native CLI *and* WASM for in-browser verification. The portfolio centerpiece. |
| **Pipeline (collectors, differ, API, orchestration)** | **Python 3.12+** | Unbeatable ecosystem for this work; fast iteration where correctness is human-reviewable, not cryptographic. |
| **Static/HTTP collection** | `httpx` + `warcio` | WARC is the Wayback / End-of-Term standard → interop, not reinvention. |
| **Render collection** | **Playwright** (Python) | Headless Chromium for JS tools; captures rendered DOM *and* the page's underlying API/data calls. Actively maintained (release May 2026). |
| **Dataset handling** | `polars`/`pandas`, `xarray` (NetCDF/HDF), `rasterio`/GDAL (GeoTIFF) | Covers tabular + scientific/geospatial formats the targets actually use. |
| **Units & numerics** | `pint` + lightweight NER (`spaCy` or regex rules) | Numbers-with-units in regulatory context are the high-value, tractable signal. |
| **Embeddings (triage only)** | `sentence-transformers` v5.x | Ranks reworded passages for human review. Explicitly *not* a verified property. |
| **API** | **FastAPI** + `uvicorn` | Typed, fast, idiomatic read-mostly API over the record. |
| **Metadata DB** | **SQLite + Litestream v0.5.x** | Read-heavy index workload; LTX format gives point-in-time recovery, replicating to R2. The metadata index is *derived/rebuildable* — the ledger and blobs are the source of truth. |
| **Blob + tile store** | **Cloudflare R2** (S3-compatible) | Snapshots, datasets, and **log tiles** live here. Tiles are immutable, cacheable static files served by Cloudflare CDN → the verifier fetches them directly, no live Druid service in the trust path. |
| **External anchoring** | `opentimestamps-client` 0.7.2 (OTS→Bitcoin) + **RFC 3161** TSAs (FreeTSA / DigiCert / `timestamp.sigstore.dev`) + multi-mirror checkpoint publication | Several simultaneous anchors so no single one is a trust or availability chokepoint (§6.3). |
| **Public UI** | **Astro 6** (MIT; Cloudflare-owned since Jan 2026) on Cloudflare Pages | The public record is overwhelmingly read-heavy/static — Astro's island model is the sweet spot; the WASM verifier runs as one island. |
| **Reviewer LLM aid (later)** | Anthropic API — `claude-opus-4-8` (quality summaries), `claude-haiku-4-5` (cheap bulk triage) | Change-summary drafting for *human reviewers only*; never an authority. |

> **License check before depending:** confirm `tlog_tiles` ships a permissive license (Cloudflare OSS crates are typically Apache-2.0/MIT/BSD-3) compatible with redistribution of the WASM verifier. Tracked in §9.

---

## 4. The verifiability core — get this exactly right

This is the heart of the system; everything else is plumbing around it. The clean line held everywhere downstream: **the snapshots and the ledger are *provable*; the differ's interpretation is *best-effort*. The trust core is never contaminated by heuristics.**

### 4.1 Threat model

Druid does not trust the publisher, and — critically — does not fully trust *itself*.

- **Adversary A — the publisher (agency).** May delete, alter, re-define, or back-date content, then assert "we never published that." → Defended by an independent, externally-timestamped, tamper-evident record. *Publisher untrusted.*
- **Adversary B — the Druid operator / insider / future maintainer.** Could retroactively fabricate a snapshot to manufacture a fake "the government said X," or quietly suppress an inconvenient observation. **The subtle, most important adversary**: the record must resist tampering *by the people who run Druid*. → Hash-linked tile log + signed checkpoints + external anchoring, and (later) multi-party cosigned witnesses.
- **Adversary C — network / MITM / cloaking.** Could feed one crawler false content, or the publisher could serve different content to a known crawler IP. → Mitigated by distributed collectors, recording the served TLS cert chain, and cross-checking against independent archives. *Mitigated, not eliminated.*

### 4.2 Security properties (stated precisely — overclaiming is the failure mode)

**Completeness — what Druid asserts.** For each observation `O`, only: *a collector operating as configured received response `R` (content hash `h`) from URL `u` at wall-clock time `t` (upper-bounded by an external anchor), and `R` is faithfully preserved.* Nothing about ground truth at the source beyond what was observed.

**Soundness — what tampering is detectable.**
- Any post-hoc alteration of a stored snapshot → detectable (content-addressing; hash mismatch).
- Any post-hoc insertion, deletion, or reordering in the ledger → detectable (Merkle inclusion + consistency proofs between two signed checkpoints).
- Any back-dating of the ledger beyond the granularity of the external anchor → detectable (anchored roots fix "this state existed no later than `T_anchor`").
- With multi-party witnesses (M8), forging an observation requires colluding with a quorum of independent cosigners.

**Non-properties — explicitly NOT guaranteed (this section is a feature).**
- Druid does **not** prove the source served the *same* content to other clients at the same time (single vantage can't exclude cloaking).
- Druid does **not** prove the source *originally* published content Druid never observed (coverage gaps are real; the curated list is a human judgment call).
- Druid proves *"observed at `t`"* and *"existed no later than `T_anchor`"* — it does **not** establish a lower time bound earlier than first observation.
- The *interpretation* of a diff — meaningful, deceptive, or benign — is **heuristic and human-reviewable, not a verified property.**

### 4.3 Mechanism — the tile-based transparency log

The trust core is a **tile-based append-only Merkle log** implementing the **C2SP `tlog-tiles`** and **C2SP `checkpoint`** specifications (the modern successor to RFC 6962 / Trillian, which are now in maintenance / being EOL'd; this is the same design Sigstore Rekor v2 and the Static-CT ecosystem moved to). Concretely:

- **Content-addressed storage.** Every artifact (snapshot bytes, rendered DOM, dataset blob) is keyed by a cryptographic digest (SHA-256, stored as **multihash** for agility). Identity = content; tampering = a different key.
- **Leaves.** Each ledger leaf is the RFC 6962 leaf hash (`0x00` domain-separation prefix) of the canonical serialization of an **Observation** or **DiffRecord** (§6). Leaves carry metadata + artifact hashes + collector provenance — never the bytes themselves (those live content-addressed in R2).
- **Tiles.** The Merkle tree is exposed as immutable, cacheable **tiles** (concatenated subtree hashes at a fixed height) written as static files to R2 and served via CDN. A client fetches the tiles it needs in parallel and computes any inclusion/consistency proof itself — **no live Druid service is in the trust path.**
- **Checkpoints.** The signed tree head is a C2SP **checkpoint**: a signed note `origin / tree_size / base64(root_hash)` with an Ed25519 signature over the note body. Checkpoints are the unit that gets published and anchored.
- **External anchoring** (§6.3) commits each checkpoint somewhere Druid cannot silently rewrite.
- **Multi-party witnesses (M8)** co-sign checkpoints per C2SP **`tlog-cosignature`** — the strongest answer to Adversary B.

Two proofs any third party checks offline: an **inclusion proof** (this leaf is in the log at this index, under this signed root) and a **consistency proof** (this newer signed checkpoint is a strict append-only extension of that older one — nothing was rewritten between them).

---

## 5. Architecture

**Pattern: ports-and-adapters (hexagonal) around a hard trust core.** Collectors and anchors are *adapters* behind narrow ports; the differ and indexer are *application services*; the **ledger/verifier is a separate, dependency-light Rust kernel** with its own boundary, invoked by the Python pipeline over a thin CLI/stdio protocol (no FFI). This keeps the part that must be provably correct small, auditable, and independently testable — and lets the verifier ship as a standalone binary and WASM module with *zero* Druid dependencies.

```
                 ┌─────────────────────────── Python pipeline ───────────────────────────┐
  curated        │                                                                        │
  targets ──▶ Collectors ──▶ Observation ──▶ Content-addressed   ──▶  Differ ──▶ DiffRecord │
  (§7)        (static/render/  records       blob store (R2)         (layered,    (typed,   │
              dataset/api)        │              ▲                    §6.2)       severity) │
                                  │              │                       │                  │
                                  ▼              │                       ▼                  │
                          leaf = H(record) ──────┘                  Alerts (RSS/webhook/    │
                                  │                                       email)            │
                                  ▼                                                         │
                 ╔═══════════════════════════════════╗   (CLI/stdio, no FFI)               │
                 ║  Rust ledger-core  (TRUST KERNEL)  ║◀──────────────┐                     │
                 ║  tlog-tiles log + Ed25519 checkpts ║               │                     │
                 ╚═══════════════════════════════════╝               │                     │
                       │ tiles            │ checkpoints               │                     │
                       ▼                  ▼                           │  Metadata index     │
                 R2 (immutable tiles) │ External anchors          SQLite+Litestream ◀───────┤
                  served via CDN      │ (OTS / RFC3161 / mirrors)     │   (derived/rebuildable)
                       │              ▼                               ▼                     │
                       │        Proof-bundle export ─────────▶  FastAPI read API ───────────┘
                       │                                              │
                       ▼                                              ▼
            druid-verify (native CLI + WASM)  ◀───────────  Astro 6 public record + search
            verifies a bundle OFFLINE,                      (timeline, diff pages, in-browser
            trusting neither gov nor Druid                   WASM verify "green check")
```

**Source of truth vs. derived.** The **blobs + the tile log + anchored checkpoints** are the source of truth. The SQLite metadata index is *derived and fully rebuildable* from them — so a corrupted index is an operational annoyance, never a trust problem.

---

## 6. Core systems

### 6.1 Observation & ledger records (the data model)

```python
# druid.observation/v1 — the faithful record of one fetch. Hashes reference R2 blobs; bytes never inline.
@dataclass(frozen=True)
class Observation:
    schema: str = "druid.observation/v1"
    target_id: str                      # stable id of the curated target (§7)
    url: str
    collector_type: Literal["static", "render", "dataset", "api"]
    collector_version: str
    collector_run_id: str               # provenance: which scheduled run produced this
    fetched_at: str                     # RFC3339 UTC, collector wall clock
    http_status: int
    response_headers_hash: str          # multihash of canonically-serialized headers
    raw_bytes_hash: str                 # multihash (sha2-256) of body / WARC payload
    rendered_dom_hash: str | None       # render collector
    captured_requests_hash: str | None  # render: the page's own API/data calls
    tls_cert_chain_hash: str | None     # anti-cloaking evidence (Adversary C)
    warc_record_hash: str | None        # interop with Wayback/End-of-Term

# A leaf is H_leaf(canonical_cbor(record)) with the RFC6962 0x00 prefix.
# Both Observation and DiffRecord are logged as leaves -> interpretation is itself timestamped & tamper-evident,
# but explicitly labeled best-effort. Re-classification APPENDS a new DiffRecord; nothing is ever mutated.
```

```python
# druid.diff/v1 — the differ's best-effort interpretation. Stored ALONGSIDE, never inside, the attested observation.
class DiffType(StrEnum):
    Deletion = "Deletion"                       # default severity High
    TermSubstitution = "TermSubstitution"       # High
    NumericThresholdChange = "NumericThresholdChange"  # High
    SchemaChange = "SchemaChange"               # Medium-High
    DistributionalShift = "DistributionalShift" # High
    MetadataChange = "MetadataChange"           # Medium
    ContentEdit = "ContentEdit"                 # Medium
    Reappearance = "Reappearance"               # Medium
    CosmeticOnly = "CosmeticOnly"               # Info (suppressed)

@dataclass(frozen=True)
class DiffRecord:
    schema: str = "druid.diff/v1"
    target_id: str
    from_observation_hash: str
    to_observation_hash: str
    detected_at: str
    diff_type: DiffType
    severity: Literal["Info", "Low", "Medium", "High"]
    layer: str                          # which differ layer produced it (0..5)
    evidence: dict                      # type-specific, e.g. {"term": "climate change", "from": 12, "to": 0}
    review_state: Literal["auto", "confirmed", "downgraded", "reclassified"] = "auto"
    reviewer: str | None = None
```

### 6.2 Semantic diff engine (the differentiator)

Layered; each layer feeds the typed taxonomy above, which is the alertable unit. **Byte-diffing is worthless** (timestamps, tokens, banners) — Layer 0 makes diffing meaningful, Layers 1–2 are high-precision and cheap, Layers 3–5 are triage-only.

- **L0 — Structural normalization.** Strip nav/footer/scripts/analytics; readability-style main-content extraction; whitespace normalization. *Now* a byte-diff catches real text change.
- **L1 — Term watch** (cheap, high-precision). Curated dictionary of sensitive terms/phrases whose appearance/disappearance/substitution is flagged → `TermSubstitution`. Catches the exact documented manipulations with near-zero false positives.
- **L2 — Numeric / threshold extraction.** NER + `pint` units parsing to extract numbers-with-units in regulatory context → `NumericThresholdChange`. High value, fully tractable, easy to slip past readers.
- **L3 — Embedding similarity** (triage, not truth). Sentence embeddings score reworded passages; low-similarity edits rank up for human review → `ContentEdit`. A *signal*, not a verified property.
- **L4 — Dataset diffing** (largely novel — almost nobody does this). Tabular: schema diff (`SchemaChange`), row-level diff, **distributional diff** (`DistributionalShift` — values silently re-baselined / a series truncated). NetCDF/geospatial: metadata diff, variable-presence diff, summary-statistic diff (`MetadataChange`).
- **L5 — LLM-assisted summarization** (reviewers only). "Summarize what changed and whether it plausibly alters meaning." Drafting aid, never an authority.

### 6.3 External anchoring

The ledger head is committed where Druid's operators cannot silently rewrite it, so even Adversary B's tampering is detectable. **Decision: run three simultaneously from the anchoring milestone** so no single anchor is a trust/availability chokepoint:

1. **OpenTimestamps** (→ Bitcoin) — maximally adversary-resistant "existed no later than" proof; `pending` immediately, upgraded to `bitcoin-confirmed` later. Free.
2. **RFC 3161 TSA** — instant signed timestamp token (FreeTSA / DigiCert / `timestamp.sigstore.dev`). Cheap, well-supported.
3. **Multi-mirror checkpoint publication** — each signed checkpoint pushed to ≥2 independent mirrors *and* submitted to the Wayback Machine, so the signed head is itself archived by a third party.

### 6.4 Proof bundle & offline verifier (the standout feature)

For any observation or diff, a user downloads a single self-verifying bundle. The open-source `druid-verify` (Rust native CLI + WASM) validates it **offline, trusting neither the government nor Druid.**

```jsonc
// druid.proofbundle/v1  (zip: this manifest + the referenced artifact blobs)
{
  "schema": "druid.proofbundle/v1",
  "observation": { /* full Observation record (§6.1) */ },
  "artifacts": [ { "hash": "<multihash>", "media_type": "...", "file": "blobs/<hash>" } ],
  "leaf_index": 12345,
  "leaf_hash": "<multihash>",
  "inclusion_proof": { "tree_size": 20000, "audit_path": ["<h>", "..."] },
  "checkpoint": {                                  // C2SP checkpoint (signed note)
    "body": "druid.example/log\n20000\n<base64 root>\n",
    "signature": "<base64 Ed25519>",
    "cosignatures": []                             // populated from M8 (C2SP tlog-cosignature)
  },
  "consistency_proof": { "from_size": 19000, "to_size": 20000, "path": ["<h>", "..."] },
  "anchors": [
    { "type": "opentimestamps", "ots": "<base64>", "status": "bitcoin-confirmed" },
    { "type": "rfc3161", "tsa": "freetsa.org", "token": "<base64>" }
  ]
}
```

**Verifier checks (all offline):** (1) each artifact's bytes hash to the observation's hashes; (2) `leaf_hash == H_leaf(observation)`; (3) the inclusion proof binds `leaf_index/leaf_hash` to the checkpoint root; (4) the checkpoint signature is valid under Druid's published log key (pinned in the verifier); (5) each anchor proves the checkpoint root existed no later than `T_anchor`; (6) optionally, the consistency proof binds an older trusted checkpoint to this one. **Trust is transferable and never routes through Druid's live service.**

### 6.5 Public record, API & alerts

- **Public record:** browsable append-only timeline; per-target history; every observation and classified diff at a permanent content-hash URL. FastAPI read API over the SQLite index; Astro 6 front end; the in-browser WASM verifier turns "download bundle" into a live green check.
- **Alerts:** subscribable by target and by diff-type/severity via **RSS/Atom, webhook, and email** ("anything touching the NCAs"; "any `NumericThresholdChange` in EPA water standards").

---

## 7. Curated target set & collection

**Depth over breadth.** v1 ships against ~12 hand-picked, high-value targets, expanded deliberately — never by mirroring all of .gov. Initial set:

- EPA climate-change pages and Climate Risk / Adaptation resources
- The National Climate Assessments (all editions) and the USGCRP record
- **EJScreen / CEJST** and related environmental-justice screening resources
- EPA **Greenhouse Gas Reporting Program** datasets (congressionally mandated → high-signal if altered)
- NOAA climate datasets and successors to climate.gov content
- USDA climate-risk / crop-resilience tools (the farmer-facing resources stripped)
- Selected pesticide/herbicide regulatory pages and label/threshold data

**Curation criteria are published** (mandate status, litigation relevance, prior alteration history, public traffic), mirroring how the rescue efforts publish their selection rationale. Lists become community-curatable later.

**Collection is polite by construction:** robots-aware, rate-limited, exponential backoff, identifiable user-agent, no auth-walled or CAPTCHA-bypassing access. U.S. federal works are generally public domain, so the archive is clean from a rights standpoint; the real constraint is courtesy and server load. Collectors are pluggable per type (static / render / dataset / api), each emitting a normalized `Observation`.

---

## 8. Milestones

Independently-runnable slices, built top-down. **M0 is the walking skeleton.** M0–M2 build and harden the trust spine; M3–M4 deepen detection; **M5 is the public ship**; M6–M8 are force multipliers. Counts are budgets — split any milestone that grows too big.

- **M0 — Skeleton & it runs (Python only).** One target (e.g. EPA GHG Reporting Program). Static collector → content-addressed blob store (local FS, SHA-256 multihash) → a *trivial* append-only JSONL log with an Ed25519-signed head → L0 normalization + L1 term-watch → CLI `druid observe <target>` and `druid log` that print the timeline and any flagged diffs. No tiles, no anchoring, no UI. **Proves the end-to-end pipeline shape.** Runs: `python -m druid observe epa-ghgrp && python -m druid log`.
- **M1 — Real trust core (Rust `ledger-core` + tile log + offline verifier).** Replace the toy log with a C2SP tlog-tiles Merkle log written as tiles to the blob store; the Rust kernel (on `tlog_tiles`) does append-leaf, signed checkpoint, inclusion proof, consistency proof; a standalone `druid-verify` validates a leaf against a checkpoint offline. Python shells out over stdio. **Proves tamper-evidence:** flip a stored leaf, watch verify fail.
- **M2 — Anchoring + self-verifying proof bundle.** Each checkpoint anchored via OpenTimestamps + RFC 3161 + ≥2 mirrors; `druid bundle <observation>` exports a `druid.proofbundle/v1`; `druid-verify bundle.zip` validates fully offline incl. anchor proofs. **The "citable" milestone** — trust becomes transferable.
- **M3 — Numeric extraction + full taxonomy + render collector.** L2 numeric/threshold extraction (`pint` + NER); the complete typed taxonomy with severities; Playwright render collector capturing DOM + the page's API calls. **Proves** Druid catches a threshold edit and a JS-page change on real targets.
- **M4 — Dataset collector + dataset diffing.** Dataset collector (CSV/JSON, then NetCDF via `xarray`); L4 schema + distributional diff. **Proves** detection of a silent re-baselining / column drop in a real dataset.
- **M5 — Public record (Astro) + alerts. ★ public ship.** FastAPI + SQLite/Litestream index; Astro 6 site: per-target timeline, diff detail pages, permanent content-hash URLs, "download proof bundle" with the in-browser WASM verifier showing a green check; alerts via RSS/Atom + webhook + email by target and diff-type/severity. **Proves** the public, browsable, subscribable, self-verifying record. *Ships and is immediately useful.*
- **M6 — Embedding triage + LLM summaries (reviewer aid).** L3 embeddings rank reworded passages; L5 Claude summaries for reviewers only. **Proves** better triage without touching the trust core.
- **M7 — Federated overlay index + verification badging.** Harvest Wayback CDX / OSF / Dataverse / Perma.cc / PEDP metadata into unified search; badge **Druid-attested (with proof bundle)** vs unverified third-party copy; optionally one *static* flagship dead-tool rebuild. **Proves** the rescued corpus becomes queryable with verifiability as the differentiator.
- **M8 — Multi-party witnesses.** C2SP `tlog-cosignature`: independent witnesses co-sign checkpoints; bundles carry cosignatures; the verifier requires a quorum. **Proves** forging the record requires colluding with a quorum — the strongest answer to Adversary B.

---

## 9. Risks / open questions

- **Bespoke-crypto risk in the trust kernel** (the whole value prop). → Build on the published **C2SP tlog-tiles/checkpoint** specs and the audited `tlog_tiles` crate; keep the kernel tiny and dependency-light; ship an independent verifier with a property-test + tamper-test suite from M1.
- **`tlog_tiles` license & maturity.** It is v0.2 (Cloudflare Research, `cloudflare/azul`). → Before depending: confirm the license is permissive (Apache/MIT/BSD) and vendor/pin the version; the specs are stable even if the crate churns, so a from-spec reimplementation is a fallback.
- **Decided fork — Rust kernel vs all-Python.** *Decision: Rust `ledger-core` from M1* (a real tile-log crate now exists, and the auditable trust kernel is the portfolio centerpiece). M0 stays Python-only so the walking skeleton ships fast. The live alternative — Python ledger now, rewrite later — trades portfolio value and a WASM verifier for marginally faster early velocity; rejected, but revisit if M1 integration stalls.
- **Cloaking against a known crawler.** A publisher can serve clean content to Druid's IP. → Distributed collectors + recorded TLS cert chain + cross-check vs independent archives; *mitigated, not eliminated*; Druid honestly attests *what it was served*.
- **Coverage gaps.** If Druid never observed a resource before it changed, it cannot attest the prior state. → The curated list is a published judgment call; the overlay (M7) cross-references third-party archives to narrow gaps.
- **Semantic-diff error** (false +/−). → L1/L2 are high-precision; embeddings are triage-only; human review on High-severity classes. The verifiable core is unaffected by differ errors.
- **Anchor availability/deprecation** (TSA/OTS down or sunset). → Three simultaneous anchors; the design is anchor-pluggable.
- **Operational sustainability** (continuous crawl, storage growth — datasets dominate cost; R2 egress economics matter). → Out of design scope but a real gating concern; tile/CDN serving keeps read costs low and cacheable.

---

## 10. References

*Verified 2026-06-29.*

- **C2SP specs** — `tlog-tiles`, `checkpoint`, `tlog-cosignature` (github.com/C2SP/C2SP). The standard the trust core targets.
- **`tlog_tiles`** Rust crate v0.2 — Cloudflare Research, `github.com/cloudflare/azul`; docs.rs/tlog_tiles. Ported from Google's `tlog`.
- **Trillian → Tessera** — Google Trillian now in maintenance mode; `transparency-dev/trillian-tessera` is the recommended tile-based successor (production-ready since 2025). Confirms the move off classic CT.
- **Sigstore Rekor v2 (GA)** — tile-backed, on Tessera; validates the tiles+checkpoint architecture at scale.
- **RFC 6962 EOL** — Let's Encrypt sunsetting classic CT logs (Aug 2025) in favor of Static-CT / tile-based. Don't build on RFC 6962.
- **OpenTimestamps** — `opentimestamps-client` 0.7.2 (PyPI); calendar/server active (server updated Nov 2025).
- **RFC 3161 TSAs** — FreeTSA (`freetsa.org`), DigiCert (`timestamp.digicert.com`), `timestamp.sigstore.dev`, `timestamp.githubapp.com`.
- **Litestream** v0.5.x (Oct 2025) — LTX format, point-in-time recovery; SQLite→R2 replication.
- **Astro** 6 (March 2026, MIT; Cloudflare-owned since Jan 2026) — islands/server-islands; deploys to Cloudflare Pages.
- **Libraries** — Playwright (Python, May 2026), `sentence-transformers` v5.x (2026), `warcio`, `xarray`, `pint`, `polars` — all current/maintained.
- **Ecosystem** — EDGI (`envirodatagov.org`), PEDP, End-of-Term Web Archive, Data Rescue Project, Harvard LIL (Perma.cc, Dataverse), Internet Archive Wayback (CDX API). Druid is complementary; WARC is the interop format. NCAs removed 2025-06-30; ~70% more environmental-site changes in the 2025 first-100-days vs 2017 (EDGI).
- **Reuse with builder's other projects** — R2 blob store, Litestream, and Astro are already in the builder's kit; the trust-log work (tiles, WASM verifier, Ed25519 checkpoints) is a reusable, auditable kernel beyond Druid.

---

*End of design document.*
