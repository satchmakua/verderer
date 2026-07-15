"""Content addressing. Identity = content; tampering = a different key.

Digests are stored as a **multihash** (DESIGN §4.3) for algorithm agility: a short
type/length prefix in front of the raw digest. M0 uses sha2-256 only.
"""

from __future__ import annotations

import hashlib

# Multihash prefix for sha2-256: function code 0x12, digest length 0x20 (32 bytes).
_SHA2_256_PREFIX = "1220"


def multihash_sha256(data: bytes) -> str:
    """Return the sha2-256 multihash of ``data`` as a lowercase hex string."""
    return _SHA2_256_PREFIX + hashlib.sha256(data).hexdigest()


def verify_multihash(data: bytes, mh: str) -> bool:
    """True iff ``data`` hashes to the given multihash."""
    return multihash_sha256(data) == mh
