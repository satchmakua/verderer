# OpenTimestamps fixture (M13b / M2b-3)

A **real** OpenTimestamps anchor over a real Verderer checkpoint — used to prove the offline
OTS verifier against genuine bytes, never a synthetic one (this arc forbids mocks on the
trust path).

- `checkpoint-15` — the exact bytes of the live log's signed checkpoint at tree size 15
  (origin `verderer.watchdog/m1-log`, root `gE5vkgCHaIs76iPCy90FrxPLJ3hZX3IAvoTynqFeJb8=`),
  fetched from `https://verderer.satchelhamilton.com/checkpoint` on 2026-07-21.
  SHA-256 `3b78ae63b11db42c348cc4c91c048f5e4912bef1f1f898ecddf4ae9b42b6043c`.
- `checkpoint-15.ots` — the OpenTimestamps proof for that file's SHA-256.

## Status: PENDING Bitcoin confirmation

Stamped 2026-07-21 against four independent public calendars (alice/bob OpenTimestamps,
Eternitywall finney, Catallaxy). It currently carries only *pending* calendar attestations —
**no Bitcoin block-header attestation yet**. It becomes a usable offline anchor after the
calendars' aggregation transaction confirms (hours) and the proof is upgraded:

```bash
# phase 2 (next session): fill in the Bitcoin attestation, then it self-verifies offline
python -m otsclient.ots upgrade tests/fixtures/ots/checkpoint-15.ots   # or the pure-lib upgrade
python -m otsclient.ots verify   tests/fixtures/ots/checkpoint-15.ots
```

Only once this proof carries a confirmed `BitcoinBlockHeaderAttestation` (a block height +
the merkle path to a header) does M13b's verifier work land: an `ots` entry type in the
proof bundle's `anchors`, offline verification of the merkle path against the carried block
header in the Rust core, and a test that a forged proof is rejected. Until then M13b stays
open — honestly deferred, exactly as ROADMAP.md records.
