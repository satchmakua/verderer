# 6. Witness cosignatures ride the bundle as a separate field, not appended to the checkpoint note

- **Status:** Accepted
- **Date:** 2026-07-10

## Context

M8 adds C2SP tlog-cosignatures: independent witnesses co-sign a checkpoint so a verifier
can require a *quorum* and stop trusting the log operator alone (a defence against a
split-view / equivocating log, DESIGN §4). The C2SP model is that a cosigned checkpoint is
a single signed note carrying multiple signature lines — the log's line plus one witness
line per cosignature.

Druid's proof bundle already carries the checkpoint as a signed note, and M2b anchors bind
`sha256(checkpoint_bytes)` to a time via RFC 3161 tokens. If cosignature lines were
appended to the checkpoint note (the literal C2SP layout), the checkpoint bytes — and thus
the anchored hash — would change every time a witness cosigned, invalidating anchors
already collected over that checkpoint.

## Decision

Carry cosignatures in the bundle as a **separate `cosignatures` array** (a list of the
C2SP `— name base64(...)` lines), verified against the checkpoint's *note body*, rather
than appending them to the checkpoint note.

- The **cryptographic content is unchanged and fully C2SP-conformant**: each cosignature
  is an Ed25519 signature over the exact `cosignature/v1\ntime <T>\n<note body>` message,
  with the 76-byte `keyID(4) || timestamp(8) || signature(64)` payload and the 0x04
  algorithm key ID. Only the *packaging* differs — the bundle is Druid's own
  `druid.proofbundle/v1` envelope, so where the lines sit is a Druid choice.
- The checkpoint bytes stay stable, so anchors collected over a checkpoint remain valid
  regardless of how many witnesses later cosign it. Anchoring (time) and cosigning
  (multi-party attestation) compose without interfering.
- `verify_bundle(json, roots, witnesses, quorum)`: with `quorum > 0`, count *distinct*
  pinned witnesses that validly cosigned this checkpoint; reject if fewer than `quorum`.
  A cosignature from an unpinned witness, or a duplicate, does not raise the count. With
  `quorum == 0` (the default, and the in-browser WASM verifier) cosignatures are neither
  required nor trusted — quorum enforcement is a native/service policy.
- Cosigning itself runs through the Rust trust core (`druid-ledger cosign`) so the exact
  C2SP format lives in one audited place — **no bespoke crypto**. Witnesses
  hold their own Ed25519 keys (`witness.py`); the verifier pins the public keys it trusts.

## Consequences

- **Easy:** anchoring and cosigning are orthogonal and both offline-verifiable; the quorum
  check reduces to the checkpoint signature + pinned witness keys, trusting no live
  service; the in-browser verifier is unaffected (quorum 0).
- **Accepted:** a consumer that expects the strict C2SP single-note layout must read
  Druid's `cosignatures` field instead of extra signature lines on the checkpoint. The
  mapping is mechanical (each array entry *is* a valid C2SP signature line over the same
  note body), and documented here + in `cosignature.rs`.
- **Watch:** the quorum counts distinct *pinned* witnesses, so growing or rotating the
  witness set is a verifier-policy change (which keys to pin, what quorum), never a
  re-signing of the log — exactly the independence the feature exists to provide.
