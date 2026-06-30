"""The ledger — Druid's trust core.

The cryptographic core lives in `rust/ledger-core`: a C2SP tlog-tiles Merkle log with
signed checkpoints (Ed25519 signed notes) and an independent offline verifier. This
package's `core.Ledger` is a thin Python front end that owns canonicalisation and
shells out to the `druid-ledger` / `druid-verify` binaries over stdio (no FFI). See
DESIGN §4 and ADR-0003. Build the kernel with:

    cargo build --release --manifest-path rust/Cargo.toml
"""
