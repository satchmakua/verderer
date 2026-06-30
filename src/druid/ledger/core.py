"""Python front end to the Rust trust core (`druid-ledger` / `druid-verify`).

The cryptographic work lives in `rust/ledger-core` (a C2SP tlog-tiles Merkle log with
signed checkpoints and an offline verifier). Python owns canonicalisation and shells
out to the Rust binaries over stdio — no FFI. The binaries must be built:

    cargo build --release --manifest-path rust/Cargo.toml

This replaces the M0 `SignedLog` wholesale (see ADR-0002/0003). Same interface the
pipeline depends on: ``append`` / ``entries`` / ``verify`` / ``public_key_hex``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class LedgerBinaryNotFound(RuntimeError):
    """Raised when the Rust trust-core binaries have not been built."""


def _repo_root() -> Path:
    # src/druid/ledger/core.py -> repo root
    return Path(__file__).resolve().parents[3]


def find_binary(name: str) -> Path:
    """Locate a built Rust binary: `$DRUID_RUST_BIN_DIR`, then rust/target/{release,debug}."""
    exe = name + (".exe" if os.name == "nt" else "")
    candidates: list[Path] = []
    env = os.environ.get("DRUID_RUST_BIN_DIR")
    if env:
        candidates.append(Path(env) / exe)
    root = _repo_root()
    candidates.append(root / "rust" / "target" / "release" / exe)
    candidates.append(root / "rust" / "target" / "debug" / exe)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise LedgerBinaryNotFound(
        f"{name} not found — build the trust kernel: "
        "cargo build --release --manifest-path rust/Cargo.toml"
    )


def _leaf_hash(data: bytes) -> str:
    # RFC 6962 leaf hash, matching the Rust core's record_hash.
    return hashlib.sha256(b"\x00" + data).hexdigest()


def canonical(record: dict[str, Any]) -> bytes:
    """The exact leaf bytes for a record — Python owns canonicalisation."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


@dataclass(frozen=True, slots=True)
class LeafEntry:
    index: int
    leaf_hash: str
    record: dict[str, Any]


class Ledger:
    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)

    # --- writes (via druid-ledger) ---

    def append(self, record: dict[str, Any]) -> LeafEntry:
        data = canonical(record)
        result = subprocess.run(
            [str(find_binary("druid-ledger")), "append", "--dir", str(self.dir)],
            input=data,
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"druid-ledger append failed: {result.stderr.decode(errors='replace').strip()}")
        out = json.loads(result.stdout.decode())
        return LeafEntry(index=out["index"], leaf_hash=out["leaf_hash"], record=record)

    def inclusion(self, index: int) -> dict[str, Any]:
        """An inclusion proof bundle for a record (index, leaf_hash, tree_size, proof, checkpoint)."""
        # Decode as UTF-8 explicitly: the Rust binary emits UTF-8 (the checkpoint's
        # signature line contains a U+2014 em dash); `text=True` would use the platform
        # locale (cp1252 on Windows) and corrupt it.
        result = subprocess.run(
            [str(find_binary("druid-ledger")), "inclusion", "--dir", str(self.dir), "--index", str(index)],
            capture_output=True,
            encoding="utf-8",
        )
        if result.returncode != 0:
            raise RuntimeError(f"druid-ledger inclusion failed: {result.stderr.strip()}")
        return json.loads(result.stdout)

    def offline_verify(self, index: int) -> tuple[bool, str]:
        """Build an inclusion bundle for a record and verify it offline via `druid-verify`.

        This is the transferable, no-live-service check (DESIGN §6.4) and the seed of
        the M2 proof bundle. The bundle is passed to the verifier as UTF-8 bytes.
        """
        incl = self.inclusion(index)
        line = (self.dir / "entries.b64").read_text(encoding="utf-8").splitlines()[index]
        bundle = {
            "record_b64": line,  # the exact stored leaf bytes, already base64
            "index": index,
            "proof": incl["proof"],
            "checkpoint": incl["checkpoint"],
            "pubkey_hex": self.public_key_hex,
        }
        result = subprocess.run(
            [str(find_binary("druid-verify")), "inclusion"],
            input=json.dumps(bundle).encode("utf-8"),
            capture_output=True,
        )
        return result.returncode == 0, result.stdout.decode(errors="replace").strip()

    # --- reads (the entries file is the published leaf data) ---

    def entry_b64(self, index: int) -> str:
        """The exact stored leaf bytes (base64) for a ledger index — what was hashed."""
        return (self.dir / "entries.b64").read_text(encoding="utf-8").splitlines()[index]

    def entries(self) -> list[LeafEntry]:
        path = self.dir / "entries.b64"
        if not path.exists():
            return []
        out: list[LeafEntry] = []
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            raw = base64.b64decode(line)
            out.append(LeafEntry(index=index, leaf_hash=_leaf_hash(raw), record=json.loads(raw)))
        return out

    # --- verification (via druid-verify, the independent verifier) ---

    def verify(self) -> tuple[bool, str]:
        try:
            verifier = find_binary("druid-verify")
        except LedgerBinaryNotFound as error:
            return False, str(error)
        result = subprocess.run([str(verifier), "log", "--dir", str(self.dir)], capture_output=True, encoding="utf-8")
        return result.returncode == 0, (result.stdout or result.stderr).strip()

    @property
    def public_key_hex(self) -> str:
        path = self.dir / "key.json"
        if path.exists():
            return str(json.loads(path.read_text(encoding="utf-8"))["public_hex"])
        return ""
