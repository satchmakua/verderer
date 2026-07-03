"""M5a — the public-record export + RSS feeds, offline via a fake collector + real ledger."""

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.pipeline import Druid
from druid.web.export import export_site
from druid.web.feed import render_rss
from druid.web.record import build_record

BEFORE = b"<html><body><p>EPA works on climate change; threshold is 10 ppb.</p></body></html>"
AFTER = b"<html><body><p>EPA works on resilience; threshold is 15 ppb.</p></body></html>"


def _druid_with_changes(tmp_path: Path) -> Druid:
    cursor = {"i": 0}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=[BEFORE, AFTER][min(cursor["i"], 1)])

    druid = Druid(
        tmp_path / "data",
        targets={"epa": Target(id="epa", title="EPA GHGRP", url="https://epa.gov/x")},
        terms=["climate change", "resilience"],
        collector=StaticCollector(fetcher=fake),
    )
    druid.observe("epa")
    cursor["i"] = 1
    druid.observe("epa")
    return druid


def test_build_record_has_targets_observations_and_events(tmp_path: Path, ledger_built: None) -> None:
    record = build_record(_druid_with_changes(tmp_path))
    assert record["schema"] == "druid.record/v1"
    assert len(record["public_key"]) == 64
    epa = next(t for t in record["targets"] if t["id"] == "epa")
    assert len(epa["observations"]) == 2
    # A term substitution and a numeric threshold change should be recorded as events.
    kinds = {e["diff_type"] for e in record["events"]}
    assert "TermSubstitution" in kinds
    assert "NumericThresholdChange" in kinds
    # Events carry permanent leaf-hash ids and are newest-first.
    assert all(len(e["id"]) == 64 for e in record["events"])


def test_rss_is_wellformed_with_one_item_per_event(tmp_path: Path, ledger_built: None) -> None:
    record = build_record(_druid_with_changes(tmp_path))
    xml = render_rss(record["events"], title="T", link="https://x", description="d")
    root = ET.fromstring(xml)  # parses => well-formed
    items = root.findall("./channel/item")
    assert len(items) == len(record["events"]) >= 1
    assert items[0].find("pubDate") is not None
    assert items[0].find("guid").text is not None


def test_export_writes_record_and_feeds(tmp_path: Path, ledger_built: None) -> None:
    druid = _druid_with_changes(tmp_path)
    out = tmp_path / "site-data"
    info = export_site(druid, out)
    assert (out / "record.json").exists()
    assert (out / "feed.xml").exists()
    assert (out / "feeds" / "epa.xml").exists()
    loaded = json.loads((out / "record.json").read_text(encoding="utf-8"))
    assert loaded["size"] >= 3
    assert info["events"] >= 1
    ET.fromstring((out / "feed.xml").read_text(encoding="utf-8"))  # valid XML
