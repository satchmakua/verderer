"""The ledger — Druid's trust core.

M0 ships a deliberately simple, signed hash-chain stand-in (``SignedLog``). It is
tamper-evident but it is **not** the real thing: M1 replaces it wholesale with the
Rust ``ledger-core`` (a C2SP tlog-tiles Merkle log + signed checkpoints + an
independent offline verifier). See DESIGN §4.3 and ROADMAP M1.
"""
