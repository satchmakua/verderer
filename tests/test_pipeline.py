"""End-to-end M1 slice with a fake collector (no network): observe twice, detect a
term substitution, verify the ledger via the Rust trust core, then prove tampering is
caught. Skipped if the Rust binaries aren't built (see conftest `ledger_built`).
"""

import base64
from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.models import DiffType
from druid.pipeline import Druid

PAGE_BEFORE = b"<html><body><p>EPA works on climate change adaptation.</p></body></html>"
PAGE_AFTER = b"<html><body><p>EPA works on resilience adaptation.</p></body></html>"


def _make_druid(tmp_path: Path, pages: list[bytes], cursor: dict[str, int]) -> Druid:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        body = pages[min(cursor["i"], len(pages) - 1)]
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=body)

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["climate change", "resilience"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def test_observe_diff_and_verify(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    druid = _make_druid(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)

    first = druid.observe("t")
    assert first.is_first
    assert first.diffs == []

    cursor["i"] = 1
    second = druid.observe("t")
    assert DiffType.TermSubstitution in {d.diff_type for d in second.diffs}

    ok, message = druid.log.verify()
    assert ok, message
    assert len(druid.log.public_key_hex) == 64  # an Ed25519 public key, hex-encoded


def test_inclusion_proof_round_trips(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    druid = _make_druid(tmp_path, [PAGE_BEFORE], cursor)
    druid.observe("t")
    incl = druid.log.inclusion(0)
    assert incl["tree_size"] >= 1
    assert incl["checkpoint"].startswith("druid.watchdog/m1-log")
    assert isinstance(incl["proof"], list)


def test_offline_inclusion_verifies(tmp_path: Path, ledger_built: None) -> None:
    # Append a few leaves, then confirm leaf 0 verifies offline against the signed
    # checkpoint — the transferable proof the verifier checks without the live service.
    cursor = {"i": 0}
    druid = _make_druid(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)
    druid.observe("t")
    cursor["i"] = 1
    druid.observe("t")

    ok, message = druid.log.offline_verify(0)
    assert ok, message
    assert "included in tree size" in message


def test_tampering_breaks_verification(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    druid = _make_druid(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)
    druid.observe("t")
    cursor["i"] = 1
    druid.observe("t")
    assert druid.log.verify()[0]

    # Corrupt a stored leaf (re-encode a different record into line 0); the recomputed
    # root no longer matches the signed checkpoint.
    entries = tmp_path / "data" / "ledger" / "entries.b64"
    lines = entries.read_text(encoding="utf-8").splitlines()
    lines[0] = base64.b64encode(b'{"schema":"druid.observation/v1","tampered":true}').decode()
    entries.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, _ = druid.log.verify()
    assert not ok  # tampering with a stored leaf is detected
