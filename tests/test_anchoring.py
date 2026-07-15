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

from annals.anchors import OpensslTsaAnchorer
from annals.collectors.base import FetchResult
from annals.collectors.static import StaticCollector
from annals.config import Target
from annals.ledger.core import find_binary
from annals.pipeline import Annals

PAGE = b"<html><body><p>EPA reporting threshold is 10 ppb.</p></body></html>"


@pytest.fixture
def openssl_available() -> None:
    if not shutil.which("openssl"):
        pytest.skip("openssl not on PATH")


def _make_annals(tmp_path: Path) -> Annals:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=PAGE)

    return Annals(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["threshold"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def _verify_bundle(bundle: dict, tmp_path: Path, root: Path, name: str) -> subprocess.CompletedProcess[str]:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return subprocess.run(
        [str(find_binary("annals-verify")), "bundle", str(path), "--root", str(root)],
        capture_output=True,
        encoding="utf-8",
    )


def test_anchor_bundle_and_verify_offline(tmp_path: Path, ledger_built: None, openssl_available: None) -> None:
    annals = _make_annals(tmp_path)
    annals.observe("t")

    anchorer = OpensslTsaAnchorer(tmp_path / "data" / "anchors" / "dev-tsa")
    info = annals.anchor(anchorer)
    assert info["tsa"] == "dev-tsa"

    bundle = annals.bundle("t")
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


def test_unpinned_anchor_is_reported_not_fatal(tmp_path: Path, ledger_built: None, openssl_available: None) -> None:
    # An anchor from a TSA whose root isn't pinned is like an unknown C2SP witness
    # cosignature: it proves nothing and spoils nothing. The bundle stays VALID on the
    # inclusion proof, the anchor is reported unverified, and no time bound is claimed.
    annals = _make_annals(tmp_path)
    annals.observe("t")
    annals.anchor(OpensslTsaAnchorer(tmp_path / "data" / "anchors" / "dev-tsa"))
    bundle = annals.bundle("t")

    other_root = tmp_path / "other-root.pem"
    OpensslTsaAnchorer(tmp_path / "other-tsa")  # generates an independent root
    other_root.write_text((tmp_path / "other-tsa" / "root.pem").read_text(encoding="utf-8"), encoding="utf-8")

    result = _verify_bundle(bundle, tmp_path, other_root, "wrongroot")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "not verified" in result.stdout  # the anchor is surfaced, not silently dropped
    assert "no later than" not in result.stdout  # and no time bound is claimed from it

    # A *corrupt* token is a different matter entirely: tampering is fatal no matter
    # which roots are pinned.
    token = bytearray(base64.b64decode(bundle["anchors"][0]["token"]))
    token[5] ^= 0xFF  # an early header byte: fails CMS parsing, which is always fatal
    bundle["anchors"][0]["token"] = base64.b64encode(bytes(token)).decode()
    bad = _verify_bundle(bundle, tmp_path, other_root, "corrupt-token")
    assert bad.returncode != 0
    assert "INVALID" in bad.stdout


def test_live_digicert_anchor_verifies_with_embedded_root(
    tmp_path: Path, ledger_built: None, openssl_available: None
) -> None:
    """The real M2b-2 path: submit to DigiCert over HTTP, then verify the bundle with NO
    --root (the verifier ships DigiCert's root pinned). Skips if the TSA is unreachable."""
    import httpx

    from annals.anchors import HttpTsaAnchorer

    annals = _make_annals(tmp_path)
    annals.observe("t")
    try:
        annals.anchor(HttpTsaAnchorer("digicert"))
    except (httpx.HTTPError, OSError) as error:
        pytest.skip(f"DigiCert TSA unreachable: {error}")

    bundle = annals.bundle("t")
    assert any(a["tsa_name"] == "digicert" for a in bundle["anchors"])
    path = tmp_path / "live.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    # No --root: the verifier trusts DigiCert's root by default.
    result = subprocess.run(
        [str(find_binary("annals-verify")), "bundle", str(path)], capture_output=True, encoding="utf-8"
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "no later than" in result.stdout
