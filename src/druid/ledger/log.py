"""M0 ledger: an append-only, signed hash-chain log.

This is the honest M0 stand-in for the M1 tile-based Merkle log. It is tamper-evident:

* every entry hash-links to the previous one, so altering, inserting, deleting, or
  reordering any line breaks the chain (detected by :meth:`SignedLog.verify`);
* the head (``size``, ``head_hash``) is signed with an Ed25519 key, so a third party
  holding the public key can pin the log's state.

What it is **not** (yet): a Merkle tree with compact inclusion/consistency proofs, and
it is single-key with no external anchoring. M1 supplies those via the Rust
``ledger-core`` (C2SP tlog-tiles + checkpoints). Keep this module heuristic-free.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_LEAF_DOMAIN = b"druid-m0-leaf:"  # domain separation, in the spirit of RFC 6962 leaf hashing
_HEAD_ORIGIN = "druid-m0"


def _canon(obj: Any) -> bytes:
    """Deterministic JSON serialisation used for hashing and on-disk lines."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _leaf_hash(prev: str, record: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(_LEAF_DOMAIN)
    digest.update(prev.encode())
    digest.update(_canon(record))
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class LeafEntry:
    index: int
    leaf_hash: str
    prev: str
    record: dict[str, Any]


class SignedLog:
    GENESIS = "0" * 64

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / "log.jsonl"
        self.head_path = self.dir / "head.json"
        self.key_path = self.dir / "log_key.json"
        self._key = self._load_or_create_key()

    # --- key management (M0: local key; M1+ this becomes the published log key) ---

    def _load_or_create_key(self) -> Ed25519PrivateKey:
        if self.key_path.exists():
            raw = bytes.fromhex(json.loads(self.key_path.read_text())["private_hex"])
            return Ed25519PrivateKey.from_private_bytes(raw)
        key = Ed25519PrivateKey.generate()
        self.key_path.write_text(
            json.dumps(
                {
                    "private_hex": key.private_bytes_raw().hex(),
                    "public_hex": key.public_key().public_bytes_raw().hex(),
                },
                indent=2,
            )
        )
        return key

    @property
    def public_key_hex(self) -> str:
        return self._key.public_key().public_bytes_raw().hex()

    # --- append-only log ---

    def entries(self) -> list[LeafEntry]:
        if not self.log_path.exists():
            return []
        out: list[LeafEntry] = []
        for line in self.log_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            data = json.loads(line)
            out.append(
                LeafEntry(index=data["index"], leaf_hash=data["leaf_hash"], prev=data["prev"], record=data["record"])
            )
        return out

    def append(self, record: dict[str, Any]) -> LeafEntry:
        entries = self.entries()
        prev = entries[-1].leaf_hash if entries else self.GENESIS
        index = len(entries)
        leaf_hash = _leaf_hash(prev, record)
        line = _canon({"index": index, "leaf_hash": leaf_hash, "prev": prev, "record": record})
        with self.log_path.open("a", encoding="utf-8") as handle:
            handle.write(line.decode() + "\n")
        self._write_head(index + 1, leaf_hash)
        return LeafEntry(index=index, leaf_hash=leaf_hash, prev=prev, record=record)

    def _head_body(self, size: int, head_hash: str) -> bytes:
        return f"{_HEAD_ORIGIN}\n{size}\n{head_hash}".encode()

    def _write_head(self, size: int, head_hash: str) -> None:
        signature = self._key.sign(self._head_body(size, head_hash)).hex()
        self.head_path.write_text(
            json.dumps(
                {"size": size, "head_hash": head_hash, "signature": signature, "public_hex": self.public_key_hex},
                indent=2,
            )
        )

    # --- verification: recompute the chain, then check the signed head ---

    def verify(self) -> tuple[bool, str]:
        entries = self.entries()
        prev = self.GENESIS
        for position, entry in enumerate(entries):
            if entry.index != position:
                return False, f"index mismatch at position {position}: stored {entry.index}"
            if entry.prev != prev:
                return False, f"broken chain at index {position}: prev does not match the previous leaf"
            if _leaf_hash(entry.prev, entry.record) != entry.leaf_hash:
                return False, f"leaf hash mismatch at index {position} (record altered?)"
            prev = entry.leaf_hash

        if not self.head_path.exists():
            return (len(entries) == 0), ("empty log, ok" if not entries else "missing signed head")

        head = json.loads(self.head_path.read_text())
        if head["size"] != len(entries):
            return False, f"head size {head['size']} != {len(entries)} entries"
        expected_head = entries[-1].leaf_hash if entries else self.GENESIS
        if head["head_hash"] != expected_head:
            return False, "head hash does not match the last leaf"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(head["public_hex"])).verify(
                bytes.fromhex(head["signature"]), self._head_body(head["size"], head["head_hash"])
            )
        except InvalidSignature:
            return False, "head signature is invalid"
        return True, f"ok: {len(entries)} entries, head {expected_head[:12]}…"
