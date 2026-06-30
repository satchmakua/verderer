"""End-to-end M0 slice with a fake collector (no network): observe twice, detect a
term substitution, verify the ledger, then prove tampering is caught.
"""

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


def test_observe_diff_and_verify(tmp_path: Path) -> None:
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


def test_tampering_breaks_verification(tmp_path: Path) -> None:
    cursor = {"i": 0}
    druid = _make_druid(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)
    druid.observe("t")
    cursor["i"] = 1
    druid.observe("t")
    assert druid.log.verify()[0]

    log_file = tmp_path / "data" / "ledger" / "log.jsonl"
    tampered = log_file.read_text(encoding="utf-8").replace("resilience", "RESILIENCE", 1)
    log_file.write_text(tampered, encoding="utf-8")

    ok, _ = druid.log.verify()
    assert not ok  # altering a stored leaf breaks the hash chain
