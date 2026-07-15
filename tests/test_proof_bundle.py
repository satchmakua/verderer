"""The self-verifying proof bundle (M2 slice 1): build a bundle for an observation and
confirm `annals-verify bundle` validates it offline, then that tampering is rejected.
Skipped if the Rust binaries aren't built.
"""

import json
import subprocess
from pathlib import Path

from annals.collectors.base import FetchResult
from annals.collectors.static import StaticCollector
from annals.config import Target
from annals.ledger.core import find_binary
from annals.pipeline import Annals

PAGE = b"<html><body><p>EPA reporting threshold is 10 ppb.</p></body></html>"


def _make_annals(tmp_path: Path) -> Annals:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=PAGE)

    return Annals(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["threshold"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def _verify_bundle(path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        [str(find_binary("annals-verify")), "bundle", str(path)], capture_output=True, encoding="utf-8"
    )
    return result.returncode == 0, (result.stdout or result.stderr).strip()


def test_bundle_verifies_offline(tmp_path: Path, ledger_built: None) -> None:
    annals = _make_annals(tmp_path)
    annals.observe("t")
    bundle = annals.bundle("t")
    assert bundle["schema"] == "annals.proofbundle/v1"

    path = tmp_path / "proof.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    ok, message = _verify_bundle(path)
    assert ok, message
    assert "included offline" in message


def test_tampered_bundle_is_rejected(tmp_path: Path, ledger_built: None) -> None:
    annals = _make_annals(tmp_path)
    annals.observe("t")
    bundle = annals.bundle("t")

    # Corrupt the artifact bytes — they no longer hash to the observation's content.
    import base64

    bundle["artifacts"][0]["bytes_b64"] = base64.b64encode(b"<html>EDITED</html>").decode()
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    ok, message = _verify_bundle(path)
    assert not ok
    assert "INVALID" in message
