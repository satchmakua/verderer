# Druid

> An immutable, provable record of what the government's environmental data said — and how it is being changed.

Druid continuously observes a curated set of high-value U.S. government environmental
pages and datasets, cryptographically attests every observation in a tamper-evident
ledger, detects *meaningful* change (definition swaps, threshold edits, silent dataset
shifts — not byte noise), and emits a public, citable, self-verifying record. Its
differentiator: a **downloadable proof bundle** anyone can verify **offline**, trusting
neither the government nor Druid's operators. Complementary to the volunteer rescue
ecosystem (EDGI, PEDP, End-of-Term, Data Rescue Project) — adding the two things none of
them treat as primary: **provable observation integrity** and **classified manipulation
detection**.

**Status:** **the core roadmap M0–M8 is complete and confirmed**, and the Phase 5–6 "real
tool" arc is underway — **M9–M12 are built and confirmed** (polite collection, the scheduler,
faithful WARC capture, and detection-precision refinements). A provable trust spine: a Rust
Merkle log, C2SP signed checkpoints published as
tile files (M2c) so verifiers recompute proofs with no live service, RFC 3161 anchors from
independent TSAs (M2b), and multi-party **witness cosignatures** with quorum verification
(M8). Change detection spans five layers over static pages, JS-rendered tools (M3b render
collector), and scientific/tabular datasets — CSV/JSON, NetCDF/HDF, zip/xlsx (M4a/M4b) — plus
reviewer-aid triage that ranks reworded passages and drafts plain-language summaries (M6). A
federated overlay (M7) cross-references third-party archives (Wayback CDX) with Druid's
attested record, badging what carries a proof. The public product: a browsable Astro record
with RSS, webhook/email alerts, search, and in-browser (WASM) offline proof verification.
Collection is **polite by construction** (M9): robots.txt (Disallow + Crawl-delay), per-host
rate-limiting with backoff, and conditional GET (a `304` logs nothing). And it now **runs
itself** (M10): `druid run` re-observes the curated set on each target's cadence, appends
diffs, and fires alerts on its own — restart-safe, with `--once` for cron/systemd (see
[docs/deployment.md](docs/deployment.md)). Every observation is archived as a standards
**WARC** (M11) — attested by `warc_record_hash`, recoverable by any archive tool, shipped by
`druid export` — so Druid interoperates with the rescue ecosystem (Wayback / End-of-Term /
EDGI) instead of being self-referential. Detection got sharper (M12): pint cross-unit
numerics (`10 ppb` == `0.010 ppm`), structure/table-aware localized diffs, rendered-DOM noise
suppression, and an index-column truncation fix. Next: M13 (consistency-proof gossip +
OpenTimestamps). Only OpenTimestamps (M2b-3) is deliberately deferred. See
[ROADMAP.md](ROADMAP.md).

---

## Run it

**Prerequisites:** Python ≥ 3.11 and a Rust toolchain (the trust core is in Rust) —
check `python --version` and `cargo --version`.

```bash
# 1) Build the trust kernel (the Merkle log + offline verifier)
cargo build --release --manifest-path rust/Cargo.toml

# 2) The Python pipeline
python -m venv .venv
source .venv/Scripts/activate        # Windows Git Bash; PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"              # once

python -m druid targets              # list the curated targets
python -m druid observe epa-ghgrp    # fetch + content-address + diff + append a signed leaf
python -m druid log                  # print the observation / diff timeline
python -m druid verify               # recompute the Merkle tree + check the signed checkpoint
python -m druid anchor --tsa digicert,freetsa     # timestamp via independent TSAs (over HTTP)
python -m druid bundle epa-ghgrp -o proof.json    # export a self-verifying proof bundle
python -m druid verify-bundle proof.json          # verify it offline — anchors included
python -m druid tiles                             # (re)publish the C2SP tile files for the ledger
python -m druid export --out web/public           # build the public record: record.json + RSS + checkpoint + tiles
python -m druid notify --dry-run                   # push alerts to webhook/email subscriptions (data/subscriptions.toml)
python -m druid run --once                          # observe every due target once + fire alerts (cron/systemd)
python -m druid run                                 # long-lived watchdog loop (see docs/deployment.md)
```

### The public record (Astro site)

```bash
python -m druid export --out web/public           # generate record.json + feed.xml from the ledger
cp web/public/record.json web/src/data/           # (the `npm --prefix web run export` script does both)
cd web && npm install
npm run build:wasm                                # compile the verifier to WASM (needs Rust + wasm-bindgen-cli)
npm run dev                                        # browse the record at http://localhost:4321
```

A browsable, static-leaning record: recent classified changes, per-target timelines
(attested observations + diffs with evidence), per-event permalinks, a subscribable **RSS
feed** (`/feed.xml`, plus per-target feeds), and a **`/verify` page that checks a downloaded
proof bundle entirely in your browser** (WebAssembly — nothing uploaded, trusting neither
the source nor Druid). The home page has client-side search over the classified changes,
and `druid notify` pushes new events to webhook/email subscriptions. The site also serves
the log itself — `/checkpoint` plus the C2SP `/tile/…` files — so an independent verifier
can fetch tiles and recompute inclusion proofs with no live service (M2c).

The anchor gives a **time bound** ("existed no later than T"): `druid anchor` submits the
checkpoint to independent third-party TSAs (**DigiCert**, **FreeTSA**), whose roots ship
pinned in the verifier — so `verify-bundle` checks those anchors offline with no extra
flags. An offline, self-hosted dev TSA is available via `--tsa dev` (proves the mechanism,
not independence; verify it with `--root druid-data/ledger/dev-tsa-root.pem`).

`observe` a target twice with content that changed in between and Druid flags the
specific change (e.g. a watched term disappearing). `verify` proves the ledger hasn't
been altered — corrupt any stored leaf and it reports `INVALID`. The trust core
(`rust/ledger-core`) also produces inclusion/consistency proofs and an **offline**
verifier (`druid-verify`) that confirms a record against a signed checkpoint trusting
neither the source nor Druid. Runtime state lives in `./druid-data/` (gitignored).

### Commands

| Command | What it does |
|---|---|
| `python -m druid observe <id>` | Observe one target now |
| `pytest` | Run the tests |
| `ruff check . && mypy src` | Lint + typecheck |

---

## Project docs

| Doc | What's in it |
|---|---|
| [DESIGN.md](DESIGN.md) | The full design and rationale — the single source of truth. |
| [ROADMAP.md](ROADMAP.md) | The milestone checklist (M0–M9 done; M10–M14 in Phase 5–6). |
| [`docs/`](docs/) | Architecture decision records (ADRs). |

## Tech stack

Python 3.11+ pipeline — `httpx`, `BeautifulSoup`, `cryptography`, `pandas`, and (optional)
`playwright` for the render collector — with a content-addressed store and an append-only
signed ledger. The M1 trust kernel adds a **Rust** tile-based Merkle log (C2SP tlog-tiles)
+ a WASM offline verifier; later milestones add an `xarray` collector, FastAPI +
SQLite/Litestream, and an Astro public record on Cloudflare R2/Pages. See
[DESIGN.md §3](DESIGN.md).

## License

Apache-2.0 — see [LICENSE](LICENSE). The verifier must be open and independently
auditable for the proof bundles to mean anything; the security model *requires* OSS.
