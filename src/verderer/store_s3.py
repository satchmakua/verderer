"""S3-compatible content-addressed store (DESIGN §4.3, M14a) — the production backend.

The same tiny `BlobStore` port the filesystem store implements, backed by any S3-compatible
object store: **Cloudflare R2**, **Backblaze B2**, **AWS S3**, or a self-hosted **MinIO**. The
adapter speaks plain S3 (via the audited `boto3`), so the vendor is a config line, not a code
change — Druid never gets welded to one provider's console.

Why this is safe to swap under a running watchdog: the port is *content-addressed*, so its
contract is nearly a mathematical identity (`get(put(b)) == b`; the key is a hash of the bytes)
rather than a behavioural agreement an adapter could drift from. `tests/test_store.py` runs one
contract suite against every backend — and it is proven live against a real S3 server, not a
mock, because a mock would only re-assert the adapter's own assumptions.

**The store is not the trust core.** A blob is only ever *referenced by hash* from an attested
leaf, so a store that lies — serves wrong bytes, loses an object, is seized — cannot forge
history: the hash simply won't match and the proof bundle fails closed. That is exactly why a
remote, third-party-operated store is an acceptable production dependency here when it would
not be for the ledger.

Config (env, so no credential ever lands in a file or a commit):
    VERDERER_STORE=s3
    VERDERER_S3_BUCKET=verderer
    VERDERER_S3_ENDPOINT=https://<account>.r2.cloudflarestorage.com   # omit for AWS S3
    VERDERER_S3_ACCESS_KEY=...  /  VERDERER_S3_SECRET_KEY=...          # or the usual AWS_* vars
    VERDERER_S3_REGION=auto                                            # R2 wants "auto"
    VERDERER_S3_PREFIX=blobs/
"""

from __future__ import annotations

import os
from typing import Any

from .hashing import multihash_sha256
from .store import BlobStore, ContentAddressedStore

DEFAULT_PREFIX = "blobs/"


class S3Store:
    """A `BlobStore` over an S3-compatible bucket. Keys mirror the filesystem store's sharded
    layout (`<prefix><aa>/<digest>`) so a bucket and a data dir are inspectably the same shape
    — and either can be rsynced/mirrored into the other."""

    def __init__(
        self,
        bucket: str,
        *,
        endpoint_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        region: str = "auto",
        prefix: str = DEFAULT_PREFIX,
        client: Any = None,
    ) -> None:
        self.bucket = bucket
        self.prefix = prefix
        if client is not None:
            self._client = client  # an already-built boto3 client (tests, custom sessions)
            return
        import boto3  # lazy: the `s3` extra, only needed when actually using S3

        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

    def _key(self, mh: str) -> str:
        digest = mh[4:]  # drop the 4-char multihash prefix, as the filesystem store does
        return f"{self.prefix}{digest[:2]}/{digest}"

    def put(self, data: bytes) -> str:
        mh = multihash_sha256(data)
        # Content-addressed: identical bytes are the same key, so a re-put is a no-op. Skipping
        # it saves a needless upload on every unchanged re-observation (the common case for a
        # watchdog), and makes put idempotent under the scheduler's retries.
        if not self.has(mh):
            self._client.put_object(Bucket=self.bucket, Key=self._key(mh), Body=data)
        return mh

    def get(self, mh: str) -> bytes:
        response = self._client.get_object(Bucket=self.bucket, Key=self._key(mh))
        body = response["Body"].read()
        return bytes(body)

    def has(self, mh: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self.bucket, Key=self._key(mh))
        except ClientError as error:
            # A missing object is a *legitimate* answer (404/NoSuchKey); anything else — auth,
            # network, a bucket that vanished — is an infrastructure fault the caller must see,
            # never a quiet "no". Swallowing it would turn an outage into silent data loss: the
            # pipeline would re-upload blindly, or `get` would fail on an object we said existed.
            if error.response.get("Error", {}).get("Code") in ("404", "NoSuchKey", "NotFound"):
                return False
            raise
        return True


def store_from_env(data_dir: Any) -> BlobStore:
    """The configured store: S3 when `VERDERER_STORE=s3`, else the filesystem one under
    `data_dir/blobs`. Credentials come from the environment only — never a config file, so
    they can't be committed by accident."""
    if os.environ.get("VERDERER_STORE", "").lower() != "s3":
        return ContentAddressedStore(data_dir / "blobs")
    bucket = os.environ.get("VERDERER_S3_BUCKET")
    if not bucket:
        raise ValueError("VERDERER_STORE=s3 requires VERDERER_S3_BUCKET")
    return S3Store(
        bucket,
        endpoint_url=os.environ.get("VERDERER_S3_ENDPOINT") or None,
        access_key=os.environ.get("VERDERER_S3_ACCESS_KEY") or None,
        secret_key=os.environ.get("VERDERER_S3_SECRET_KEY") or None,
        region=os.environ.get("VERDERER_S3_REGION", "auto"),
        prefix=os.environ.get("VERDERER_S3_PREFIX", DEFAULT_PREFIX),
    )
