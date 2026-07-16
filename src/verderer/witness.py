"""M8 — multi-party witnesses (C2SP tlog-cosignature).

A witness is an *independent* party that observes the log's checkpoint and co-signs it,
so a verifier can require a **quorum** of cosignatures and stop trusting the log operator
alone (a defence against a split-view / equivocating log — DESIGN §4). Each witness holds
its own Ed25519 key; the verifier pins the witness public keys it trusts.

Cosigning itself goes through the Rust trust core (`verderer-ledger cosign`), which
implements the exact C2SP cosignature/v1 format — no bespoke crypto here. This module only
generates/loads witness keys and stores the resulting cosignature lines alongside the
checkpoint they cover, so a proof bundle can carry them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass(frozen=True, slots=True)
class Witness:
    name: str
    seed_hex: str  # 32-byte Ed25519 seed (secret)
    public_hex: str  # 32-byte Ed25519 public key (what a verifier pins)

    def pin(self) -> str:
        """The `name:pubkeyhex` string a verifier passes to `--witness`."""
        return f"{self.name}:{self.public_hex}"


def generate_witness(name: str) -> Witness:
    key = Ed25519PrivateKey.generate()
    seed = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return Witness(name=name, seed_hex=seed.hex(), public_hex=public.hex())


def load_or_create_witness(path: Path, name: str) -> Witness:
    """Load a witness key from `path` (JSON), or generate + persist a new one."""
    path = Path(path)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        return Witness(name=data["name"], seed_hex=data["seed_hex"], public_hex=data["public_hex"])
    witness = generate_witness(name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"name": witness.name, "seed_hex": witness.seed_hex, "public_hex": witness.public_hex}),
        encoding="utf-8",
    )
    return witness
