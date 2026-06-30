"""The self-verifying proof bundle (M2 slice 1): build a bundle for an observation and
confirm `druid-verify bundle` validates it offline, then that tampering is rejected.
Skipped if the Rust binaries aren't built.
"""

import json
import subprocess
from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.ledger.core import find_binary
from druid.pipeline import Druid

PAGE = b"<html><body><p>EPA reporting threshold is 10 ppb.</p></body></html>"


def _make_druid(tmp_path: Path) -> Druid:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=PAGE)

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["threshold"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def _verify_bundle(path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        [str(find_binary("druid-verify")), "bundle", str(path)], capture_output=True, encoding="utf-8"
    )
    return result.returncode == 0, (result.stdout or result.stderr).strip()


def test_bundle_verifies_offline(tmp_path: Path, ledger_built: None) -> None:
    druid = _make_druid(tmp_path)
    druid.observe("t")
    bundle = druid.bundle("t")
    assert bundle["schema"] == "druid.proofbundle/v1"

    path = tmp_path / "proof.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    ok, message = _verify_bundle(path)
    assert ok, message
    assert "included offline" in message


def test_tampered_bundle_is_rejected(tmp_path: Path, ledger_built: None) -> None:
    druid = _make_druid(tmp_path)
    druid.observe("t")
    bundle = druid.bundle("t")

    # Corrupt the artifact bytes — they no longer hash to the observation's content.
    import base64

    bundle["artifacts"][0]["bytes_b64"] = base64.b64encode(b"<html>EDITED</html>").decode()
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    ok, message = _verify_bundle(path)
    assert not ok
    assert "INVALID" in message
