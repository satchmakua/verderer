"""Content-addressed blob store (DESIGN §4.3): snapshot bytes keyed by multihash.

The interface is deliberately tiny so the backend can be swapped behind it (the store is a
*port* in the hexagonal layout): dev = the local filesystem, prod = any S3-compatible object
store (Cloudflare R2 / Backblaze B2 / AWS S3 / MinIO) via `store_s3.S3Store` (M14a).

The port's contract is what makes the swap safe, and it is *content-addressed*, so it is
unusually strong: `put` returns the multihash of exactly the bytes stored, `get(put(b)) == b`,
`has` is true iff a `get` would succeed, and `put` is idempotent (the same bytes are the same
key). `tests/test_store.py` runs that contract against *every* backend, so an adapter can't
quietly differ from the filesystem one the whole pipeline was built on.
"""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .hashing import multihash_sha256


class BlobStore(Protocol):
    """The port the pipeline depends on. Any backend satisfying this contract can back it."""

    def put(self, data: bytes) -> str:
        """Store `data`; return its multihash (the content address)."""
        ...

    def get(self, mh: str) -> bytes:
        """The exact bytes stored under `mh`."""
        ...

    def has(self, mh: str) -> bool:
        """Whether `mh` is present (i.e. a `get` would succeed)."""
        ...


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
