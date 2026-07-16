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
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .ledger.core import checkpoint_size, cosign_checkpoint_offline, verify_consistency_offline


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


# --- M14c: the independently-run witness service --------------------------------------


@dataclass(frozen=True, slots=True)
class WitnessObservation:
    """What the witness did with a checkpoint it was shown."""

    status: str  # "cosigned" | "refused"
    reason: str = ""
    cosignature: str | None = None  # the C2SP line, set iff status == "cosigned"
    size: int | None = None
    # The exact checkpoint the cosignature covers. A cosignature is only meaningful *about a
    # specific checkpoint*, so the caller must file it against this one — not whatever the log
    # happens to have moved on to (see Verderer.ingest_cosignature).
    checkpoint: str | None = None


class WitnessService:
    """An **independently-run** witness (M14c) — the piece that turns M8 from an in-process
    demo into real multi-party gossip.

    It holds *its own* key and *its own* memory of the log (the last checkpoint it accepted),
    and needs no operator ledger: it is handed a checkpoint it fetched, and decides for itself
    whether to vouch for it. The decision is the point:

    * the checkpoint must be validly signed by the **pinned** log key (a key the witness was
      configured with out-of-band — never one the operator supplies with the checkpoint), and
    * it must **extend** the last checkpoint this witness accepted (M13a's consistency proof).

    If either fails — a fork, a shrink, an equivocation, a bad signature — the witness
    **refuses to cosign** and says why. That refusal is what a quorum is worth: to forge the
    record an operator must now also make an independent party vouch for a history that
    doesn't check out.
    """

    def __init__(self, witness: Witness, log_pubkey_hex: str, state_path: Path) -> None:
        self.witness = witness
        self.log_pubkey_hex = log_pubkey_hex
        self.state_path = Path(state_path)

    def last_accepted(self) -> str | None:
        """The last checkpoint this witness vouched for — its independent memory of the log.

        ``None`` means *genuinely no memory yet* (a first sighting). Any other read failure
        **propagates**: an unreadable memory must never be mistaken for an absent one. That
        distinction is load-bearing — see :meth:`observe`. (Deliberately no ``exists()``
        pre-check: it also reports False when ``stat`` fails, which would smuggle an
        unreadable memory back in as "no memory".)
        """
        try:
            return self.state_path.read_text(encoding="utf-8") or None
        except FileNotFoundError:
            return None

    def _remember(self, checkpoint: str) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(checkpoint, encoding="utf-8")
        os.replace(tmp, self.state_path)  # atomic: never a half-written memory

    def observe(self, checkpoint: str, proof: list[str] | None = None) -> WitnessObservation:
        """Decide whether to vouch for `checkpoint`, and cosign it if so.

        `proof` is the consistency proof from the last checkpoint this witness accepted to
        this one (the operator supplies it; the witness checks it). On the first sighting
        there is no history to extend, so the witness only verifies the signature — but it
        still refuses anything not signed by the pinned log key.
        """
        try:
            previous = self.last_accepted()
        except OSError as error:
            # Fail CLOSED. If the memory exists but can't be read, treating it as "no memory"
            # would drop to the bootstrap path — a signature check only — and cosign a fork
            # this witness had already refused, then *remember* it. One transient I/O fault
            # would silently defeat the only property a witness has. Refuse instead.
            return WitnessObservation(
                status="refused",
                reason=f"cannot read my own memory of the log ({error}); refusing rather than "
                f"re-bootstrapping onto a history I have not verified",
            )
        if previous is None:
            # Bootstrap: nothing to extend yet. A self-consistency check verifies the note's
            # signature under the pinned key (and nothing else) — so an unsigned/forged
            # checkpoint is still refused at first sight.
            ok, message = verify_consistency_offline(checkpoint, checkpoint, [], self.log_pubkey_hex)
        else:
            ok, message = verify_consistency_offline(previous, checkpoint, proof or [], self.log_pubkey_hex)
        if not ok:
            # The whole reason a witness exists: never vouch for a history that doesn't check out.
            return WitnessObservation(status="refused", reason=message)
        line = cosign_checkpoint_offline(checkpoint, self.witness.name, self.witness.seed_hex)
        self._remember(checkpoint)
        return WitnessObservation(
            status="cosigned",
            reason=message,
            cosignature=line,
            size=checkpoint_size(checkpoint),
            checkpoint=checkpoint,
        )
