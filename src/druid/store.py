"""Content-addressed blob store (DESIGN §4.3): snapshot bytes keyed by multihash.

M0 backs it with the local filesystem; the production store is Cloudflare R2. The
interface is deliberately tiny so the backend can be swapped behind it (the store is
a *port* in the hexagonal layout).
"""

from __future__ import annotations

from pathlib import Path

from .hashing import multihash_sha256


class ContentAddressedStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, mh: str) -> Path:
        digest = mh[4:]  # drop the 4-char multihash prefix
        return self.root / digest[:2] / digest  # shard to keep directories small

    def put(self, data: bytes) -> str:
        mh = multihash_sha256(data)
        path = self._path(mh)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return mh

    def get(self, mh: str) -> bytes:
        return self._path(mh).read_bytes()

    def has(self, mh: str) -> bool:
        return self._path(mh).exists()
