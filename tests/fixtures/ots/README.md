# OpenTimestamps fixture (M13b / M2b-3)

A **real, Bitcoin-confirmed** OpenTimestamps anchor over a real Verderer checkpoint — the
offline OTS verifier is tested against genuine bytes, never a synthetic one (this arc forbids
mocks on the trust path).

## Files

- `checkpoint-15` — the exact bytes of the live log's signed checkpoint at tree size 15
  (origin `verderer.watchdog/m1-log`, root `gE5vkgCHaIs76iPCy90FrxPLJ3hZX3IAvoTynqFeJb8=`),
  fetched from `https://verderer.satchelhamilton.com/checkpoint` on 2026-07-21.
  SHA-256 `3b78ae63b11db42c348cc4c91c048f5e4912bef1f1f898ecddf4ae9b42b6043c`.
- `checkpoint-15.ots` — the OpenTimestamps proof for that file's SHA-256, **upgraded** after
  the calendars' aggregation transaction confirmed on Bitcoin.
- `bitcoin-headers.json` — the two attested blocks' raw 80-byte headers (height → hex), so
  verification is fully offline (the verifier never contacts a Bitcoin node).
- `bundle-ots-15.json` — a `verderer.proofbundle/v1` for the `epa-ghgrp` observation whose
  `anchors` carries the OTS anchor; it verifies offline via `verderer-verify bundle`.

## Status: CONFIRMED

Stamped 2026-07-21 against four independent public calendars (alice/bob OpenTimestamps,
Eternitywall finney, Catallaxy); two (alice, bob) confirmed on Bitcoin:

| Block height | Block hash | nTime (UTC) |
|---|---|---|
| **959058** (earliest → the bound) | `00000000000000000000e54f9fb3a4221154f8571dfc31cf5c3a98cf262db90e` | 2026-07-21T21:09:36Z |
| 959061 | `000000000000000000022645eee1e171b271a92e6527728e85441efc88fa04a5` | 2026-07-21T21:34:21Z |

The proof commits `checkpoint-15`'s SHA-256, via {append, prepend, sha256} ops, into each
block's merkle root. `verderer-verify` proves this offline: the ops land in the carried
header's merkle-root field and the header carries valid proof-of-work; the single residual
assumption (that the header is a main-chain block) is checkable in seconds against the block
hash above, from any independent source (DESIGN §4.2 — no overclaim).

## Regenerating / re-verifying

```bash
# verify the anchor directly:
verderer-verify ots   < (checkpoint-15 + checkpoint-15.ots + bitcoin-headers.json as JSON)
# verify the whole bundle offline (no --root needed for OTS):
verderer-verify bundle tests/fixtures/ots/bundle-ots-15.json   # -> VALID ... existed no later than 2026-07-21T21:09:36Z
```

The stamp/upgrade tooling (pure-`opentimestamps`, no bitcoinlib/libssl so it runs on Windows)
lives outside the repo; a fresh stamp of a new checkpoint follows the same two-phase
flow (stamp → wait for Bitcoin → upgrade).
