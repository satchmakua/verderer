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

**Status:** _early scaffold_ — **M0 (walking skeleton) shipped.** See
[ROADMAP.md](ROADMAP.md) for the plan.

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
python -m druid bundle epa-ghgrp -o proof.json   # export a self-verifying proof bundle
python -m druid verify-bundle proof.json         # verify it offline (trusts neither gov nor Druid)
```

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
| [ROADMAP.md](ROADMAP.md) | The milestone checklist (M0–M8). |
| [`docs/`](docs/) | Architecture decision records (ADRs). |

## Tech stack

Python 3.11+ pipeline — `httpx`, `BeautifulSoup`, `cryptography` — with a
content-addressed store and an append-only signed ledger. The M1 trust kernel adds a
**Rust** tile-based Merkle log (C2SP tlog-tiles) + a WASM offline verifier; later
milestones add Playwright/`xarray` collectors, FastAPI + SQLite/Litestream, and an Astro
public record on Cloudflare R2/Pages. See [DESIGN.md §3](DESIGN.md).

## License

Apache-2.0 — see [LICENSE](LICENSE). The verifier must be open and independently
auditable for the proof bundles to mean anything; the security model *requires* OSS.
