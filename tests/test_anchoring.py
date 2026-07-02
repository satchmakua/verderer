"""End-to-end M2b-1 anchoring, fully offline via the self-hosted openssl dev TSA:
observe -> anchor -> bundle (embeds the RFC 3161 token) -> verify-bundle with the pinned
root -> VALID with a time bound; tampering the anchor token -> INVALID. Skipped if the
Rust kernel isn't built or openssl isn't on PATH.
"""

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from druid.anchors import OpensslTsaAnchorer
from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.ledger.core import find_binary
from druid.pipeline import Druid

PAGE = b"<html><body><p>EPA reporting threshold is 10 ppb.</p></body></html>"


@pytest.fixture
def openssl_available() -> None:
    if not shutil.which("openssl"):
        pytest.skip("openssl not on PATH")


def _make_druid(tmp_path: Path) -> Druid:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=PAGE)

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["threshold"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def _verify_bundle(bundle: dict, tmp_path: Path, root: Path, name: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return subprocess.run(
        [str(find_binary("druid-verify")), "bundle", str(path), "--root", str(root)],
        capture_output=True,
        encoding="utf-8",
    )


def test_anchor_bundle_and_verify_offline(tmp_path: Path, ledger_built: None, openssl_available: None) -> None:
    druid = _make_druid(tmp_path)
    druid.observe("t")

    anchorer = OpensslTsaAnchorer(tmp_path / "data" / "anchors" / "dev-tsa")
    info = druid.anchor(anchorer)
    assert info["tsa"] == "dev-tsa"

    bundle = druid.bundle("t")
    assert len(bundle["anchors"]) == 1
    assert bundle["anchors"][0]["type"] == "rfc3161"

    root = tmp_path / "data" / "ledger" / "dev-tsa-root.pem"
    ok = _verify_bundle(bundle, tmp_path, root, "proof")
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "no later than" in ok.stdout

    # Tamper the anchor token -> the bundle must be rejected.
    bundle["anchors"][0]["token"] = base64.b64encode(b"not a real token").decode()
    bad = _verify_bundle(bundle, tmp_path, root, "tampered")
    assert bad.returncode != 0
    assert "INVALID" in bad.stdout


def test_anchor_rejected_under_wrong_root(tmp_path: Path, ledger_built: None, openssl_available: None) -> None:
    # A bundle anchored by one dev TSA must not verify against a different TSA's root.
    druid = _make_druid(tmp_path)
    druid.observe("t")
    druid.anchor(OpensslTsaAnchorer(tmp_path / "data" / "anchors" / "dev-tsa"))
    bundle = druid.bundle("t")

    other_root = tmp_path / "other-root.pem"
    OpensslTsaAnchorer(tmp_path / "other-tsa")  # generates an independent root
    other_root.write_text((tmp_path / "other-tsa" / "root.pem").read_text(encoding="utf-8"), encoding="utf-8")

    result = _verify_bundle(bundle, tmp_path, other_root, "wrongroot")
    assert result.returncode != 0  # does not chain to the pinned (wrong) root


def test_live_digicert_anchor_verifies_with_embedded_root(
    tmp_path: Path, ledger_built: None, openssl_available: None
) -> None:
    """The real M2b-2 path: submit to DigiCert over HTTP, then verify the bundle with NO
    --root (the verifier ships DigiCert's root pinned). Skips if the TSA is unreachable."""
    import httpx

    from druid.anchors import HttpTsaAnchorer

    druid = _make_druid(tmp_path)
    druid.observe("t")
    try:
        druid.anchor(HttpTsaAnchorer("digicert"))
    except (httpx.HTTPError, OSError) as error:
        pytest.skip(f"DigiCert TSA unreachable: {error}")

    bundle = druid.bundle("t")
    assert any(a["tsa_name"] == "digicert" for a in bundle["anchors"])
    path = tmp_path / "live.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    # No --root: the verifier trusts DigiCert's root by default.
    result = subprocess.run(
        [str(find_binary("druid-verify")), "bundle", str(path)], capture_output=True, encoding="utf-8"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "no later than" in result.stdout
