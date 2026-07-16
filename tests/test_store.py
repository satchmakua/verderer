"""The blob-store port contract (DESIGN §4.3) — run against **every** backend.

The store is a port: dev = filesystem, prod = any S3-compatible bucket (M14a). An adapter that
quietly differs from the filesystem store the whole pipeline was built on would be a silent
data bug, so the contract below is parameterized over backends rather than written twice.

The S3 backend is exercised against a **real S3 server** (a local MinIO, or any bucket the
`VERDERER_S3_*` env points at) — never a mock, which would only re-assert the adapter's own
assumptions about S3 instead of testing S3. It skips when no server is configured.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from verderer.hashing import multihash_sha256
from verderer.store import ContentAddressedStore
from verderer.store_s3 import S3Store, store_from_env

# --- backends under test ---------------------------------------------------------------


@pytest.fixture
def filesystem_store(tmp_path: Path) -> ContentAddressedStore:
    return ContentAddressedStore(tmp_path / "blobs")


@pytest.fixture
def s3_store() -> Iterator[S3Store]:
    """A live S3-compatible bucket. Points at `VERDERER_S3_*` when set; otherwise a local MinIO
    on :9000 if one is running (how this is proven in development).

    Skips only when no server is available *and* `VERDERER_REQUIRE_S3` is unset — a laptop with
    no MinIO shouldn't fail the suite. CI sets `VERDERER_REQUIRE_S3=1` against a real MinIO
    service, so there a missing server is a **failure**: a silent skip in CI is
    indistinguishable from a pass, and would let an S3 adapter regression merge green while the
    docs still claimed every backend was covered.
    """
    required = os.environ.get("VERDERER_REQUIRE_S3") == "1"
    if required:
        import boto3  # noqa: F401  — must be installed where S3 coverage is mandatory
    else:
        pytest.importorskip("boto3")
    endpoint = os.environ.get("VERDERER_S3_ENDPOINT", "http://127.0.0.1:9000")
    bucket = os.environ.get("VERDERER_S3_BUCKET", "verderer-test")
    access = os.environ.get("VERDERER_S3_ACCESS_KEY", "verdereradmin")
    secret = os.environ.get("VERDERER_S3_SECRET_KEY", "verdererpassword")
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError

    client = boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        region_name=os.environ.get("VERDERER_S3_REGION", "auto"),
    )
    try:  # a real round-trip, so a dead endpoint skips rather than fails the suite
        client.list_buckets()
        try:
            client.create_bucket(Bucket=bucket)
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
                raise
    except (BotoCoreError, ClientError) as error:  # pragma: no cover - environment dependent
        if required:
            pytest.fail(f"VERDERER_REQUIRE_S3=1 but no S3-compatible server at {endpoint}: {error}")
        pytest.skip(f"no S3-compatible server at {endpoint}: {error}")
    # A per-test prefix keeps runs isolated (and leaves the bucket reusable).
    yield S3Store(bucket, client=client, prefix=f"t-{uuid.uuid4().hex[:8]}/")


def _backends(request: pytest.FixtureRequest) -> object:
    return request.getfixturevalue(request.param)


@pytest.fixture(params=["filesystem_store", "s3_store"])
def store(request: pytest.FixtureRequest) -> object:
    """Every backend, one contract."""
    return request.getfixturevalue(request.param)


# --- the contract ----------------------------------------------------------------------


def test_put_is_content_addressed_and_dedups(store) -> None:  # type: ignore[no-untyped-def]
    first = store.put(b"hello")
    again = store.put(b"hello")
    assert first == again  # identity = content
    assert store.has(first)
    assert store.get(first) == b"hello"
    assert store.put(b"world") != first


def test_put_returns_the_multihash_of_exactly_those_bytes(store) -> None:  # type: ignore[no-untyped-def]
    # The key *is* the hash of the stored bytes — the property the whole attestation chain
    # leans on (a leaf references a blob by hash; a bundle re-hashes it).
    data = b"<html>reporting threshold is 10 ppb</html>"
    assert store.put(data) == multihash_sha256(data)


def test_get_round_trips_binary_and_empty(store) -> None:  # type: ignore[no-untyped-def]
    for payload in (b"", b"\x00\x01\x02\xff\xfe", bytes(range(256)) * 40):
        assert store.get(store.put(payload)) == payload


def test_has_is_false_for_absent_and_true_after_put(store) -> None:  # type: ignore[no-untyped-def]
    absent = multihash_sha256(b"never stored")
    assert store.has(absent) is False
    assert store.has(store.put(b"now stored")) is True


# --- S3-specific behaviour --------------------------------------------------------------


def test_s3_keys_mirror_the_filesystem_sharding(s3_store: S3Store) -> None:
    mh = s3_store.put(b"shard me")
    digest = mh[4:]
    assert s3_store._key(mh) == f"{s3_store.prefix}{digest[:2]}/{digest}"


def test_s3_has_surfaces_infrastructure_faults_instead_of_saying_no(s3_store: S3Store) -> None:
    # A missing object is a legitimate "no"; an auth/network fault must NOT be swallowed as
    # one, or an outage would look like an empty store and the pipeline would silently
    # re-upload (or `get` would fail on something `has` claimed was there).
    from botocore.exceptions import ClientError

    broken = S3Store(
        "verderer-test",
        endpoint_url="http://127.0.0.1:9000",
        access_key="wrong",
        secret_key="wrongwrongwrong",
        prefix=s3_store.prefix,
    )
    with pytest.raises((ClientError, Exception)):
        broken.has(multihash_sha256(b"anything"))


def test_store_from_env_defaults_to_filesystem(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VERDERER_STORE", raising=False)
    assert isinstance(store_from_env(tmp_path), ContentAddressedStore)


def test_store_from_env_selects_s3(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERDERER_STORE", "s3")
    monkeypatch.setenv("VERDERER_S3_BUCKET", "verderer-test")
    monkeypatch.setenv("VERDERER_S3_ENDPOINT", "http://127.0.0.1:9000")
    monkeypatch.setenv("VERDERER_S3_ACCESS_KEY", "verdereradmin")
    monkeypatch.setenv("VERDERER_S3_SECRET_KEY", "verdererpassword")
    pytest.importorskip("boto3")
    assert isinstance(store_from_env(tmp_path), S3Store)


def test_store_from_env_requires_a_bucket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERDERER_STORE", "s3")
    monkeypatch.delenv("VERDERER_S3_BUCKET", raising=False)
    with pytest.raises(ValueError, match="VERDERER_S3_BUCKET"):
        store_from_env(tmp_path)
