"""M5a — the public-record export + RSS feeds, offline via a fake collector + real ledger."""

import json
from pathlib import Path
from xml.etree import ElementTree as ET

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.pipeline import Verderer
from verderer.web.export import export_site
from verderer.web.feed import render_rss
from verderer.web.record import build_record

BEFORE = b"<html><body><p>EPA works on climate change; threshold is 10 ppb.</p></body></html>"
AFTER = b"<html><body><p>EPA works on resilience; threshold is 15 ppb.</p></body></html>"


def _verderer_with_changes(tmp_path: Path) -> Verderer:
    cursor = {"i": 0}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=[BEFORE, AFTER][min(cursor["i"], 1)])

    verderer = Verderer(
        tmp_path / "data",
        targets={"epa": Target(id="epa", title="EPA GHGRP", url="https://epa.gov/x")},
        terms=["climate change", "resilience"],
        collector=StaticCollector(fetcher=fake),
    )
    verderer.observe("epa")
    cursor["i"] = 1
    verderer.observe("epa")
    return verderer


def test_build_record_has_targets_observations_and_events(tmp_path: Path, ledger_built: None) -> None:
    record = build_record(_verderer_with_changes(tmp_path))
    assert record["schema"] == "verderer.record/v1"
    assert len(record["public_key"]) == 64
    epa = next(t for t in record["targets"] if t["id"] == "epa")
    assert len(epa["observations"]) == 2
    # A term substitution and a numeric threshold change should be recorded as events.
    kinds = {e["diff_type"] for e in record["events"]}
    assert "TermSubstitution" in kinds
    assert "NumericThresholdChange" in kinds
    # Events carry permanent leaf-hash ids and are newest-first.
    assert all(len(e["id"]) == 64 for e in record["events"])


def test_rss_is_wellformed_with_one_item_per_change(tmp_path: Path, ledger_built: None) -> None:
    record = build_record(_verderer_with_changes(tmp_path))
    xml = render_rss(record["changes"], title="T", link="https://x", description="d")
    root = ET.fromstring(xml)  # parses => well-formed
    items = root.findall("./channel/item")
    assert len(items) == len(record["changes"]) >= 1
    assert items[0].find("pubDate") is not None
    assert items[0].find("guid").text is not None


def test_export_writes_record_and_feeds(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer_with_changes(tmp_path)
    out = tmp_path / "site-data"
    info = export_site(verderer, out)
    assert (out / "record.json").exists()
    assert (out / "feed.xml").exists()
    assert (out / "feeds" / "epa.xml").exists()
    loaded = json.loads((out / "record.json").read_text(encoding="utf-8"))
    assert loaded["size"] >= 3
    assert info["events"] >= 1
    ET.fromstring((out / "feed.xml").read_text(encoding="utf-8"))  # valid XML


# --- the reader-facing views: interpretation and operator-reported health, kept apart from the attested leaves ---


def test_record_explains_findings_and_groups_them_into_a_change(tmp_path: Path, ledger_built: None) -> None:
    record = build_record(_verderer_with_changes(tmp_path), generated_at="2026-01-01T00:00:00Z")
    assert record["generated_at"] == "2026-01-01T00:00:00Z"
    assert set(record["legend"]) == {"attested", "interpretation", "operator_reported"}
    assert record["checkpoint"]["size"] == record["size"] and record["checkpoint"]["origin"]

    # Every finding reads as a sentence and belongs to a change.
    assert all(e["explain"]["title"] and e["explain"]["summary"] and e["change_id"] for e in record["events"])
    (change,) = record["changes"]
    assert sorted(change["event_ids"]) == sorted(e["id"] for e in record["events"])
    assert change["category"] == "notable" and change["severity"] == "High"
    assert change["headline"].startswith("Regulatory number changed: 10 ppb")
    assert change["from"]["observed_at"] <= change["to"]["observed_at"]

    summary = record["summary"]
    assert (summary["targets"], summary["observations"], summary["changes"], summary["notable_changes"]) == (1, 2, 1, 1)
    assert summary["findings"] == len(record["events"]) and summary["error_page_churn"] == 0
    assert summary["states"] == {"live": 1}

    epa = record["targets"][0]
    assert epa["state"]["code"] == "live" and epa["change_count"] == 1
    assert epa["last_change_at"] == change["detected_at"]
    # The per-target event list carries the same explanations as the global one.
    assert all("explain" in e for e in epa["events"])


def test_record_reports_scheduler_health_as_the_operators_account(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer_with_changes(tmp_path)
    assert build_record(verderer)["targets"][0]["monitor"] is None  # never scheduled: nothing to report

    state = {"entries": [{"target_id": "epa", "next_due": 1_800_000_000.0, "last_run": 1_799_990_000.0,
                          "last_status": "unchanged", "consecutive_failures": 0, "last_ok": 1_799_990_000.0, "last_error": ""}]}
    (verderer.data_dir / "schedule-state.json").write_text(json.dumps(state), encoding="utf-8")
    record = build_record(verderer)
    monitor = record["targets"][0]["monitor"]
    assert monitor["last_status"] == "unchanged" and monitor["last_checked"] == "2027-01-15T05:13:20Z"
    assert monitor["last_answered"] == monitor["last_checked"] and monitor["next_due"] == "2027-01-15T08:00:00Z"
    assert record["summary"]["last_checked_at"] == monitor["last_checked"]


def test_a_source_that_never_answered_is_in_the_record_as_unreachable(tmp_path: Path, ledger_built: None) -> None:
    verderer = Verderer(
        tmp_path / "data",
        targets={
            "dead": Target(
                id="dead", title="Dead", url="https://dead.gov/", criteria="[mandate][removed] Flagship deletion watch."
            ),
        },
        terms=[],
        collectors={},
    )
    entry = {"target_id": "dead", "next_due": 2.0, "last_run": 1.0, "last_status": "error", "consecutive_failures": 409}
    state = {"entries": [entry]}
    (verderer.data_dir / "schedule-state.json").write_text(json.dumps(state), encoding="utf-8")
    record = build_record(verderer)
    (dead,) = record["targets"]
    assert dead["state"]["code"] == "unreachable" and "409 consecutive checks failed" in dead["state"]["detail"]
    assert dead["tags"] == ["mandate", "removed"] and dead["criteria_text"] == "Flagship deletion watch."
    assert record["summary"]["states"] == {"unreachable": 1}
    assert record["criteria_tags"]["removed"].startswith("Already gone")


def test_a_feed_item_is_one_change_read_as_sentences(tmp_path: Path, ledger_built: None) -> None:
    record = build_record(_verderer_with_changes(tmp_path))
    xml = render_rss(
        record["changes"], title="T", link="https://x/target/epa", description="d",
        site_url="https://x", titles={"epa": "EPA GHGRP"},
    )
    (item,) = ET.fromstring(xml).findall("./channel/item")
    (change,) = record["changes"]
    assert (item.findtext("title") or "").startswith("[High] EPA GHGRP: Regulatory number changed: 10 ppb \u2192 15 ppb")
    description = item.findtext("description") or ""
    assert "\u201cclimate change\u201d appeared 1 time in the previous version and is now gone." in description
    assert "best-effort" in description and "{" not in description  # sentences, not raw evidence dicts
    assert item.findtext("link") == f"https://x/change/{change['id']}"  # the permanent page, not an anchor
    # The guid is a ledger leaf hash (the change's first finding): permanent, never re-notifies.
    assert item.findtext("guid") == change["id"] == change["event_ids"][0]
    assert {c.text for c in item.findall("category")} == {"NumericThresholdChange", "TermSubstitution"}


def test_feed_skips_error_page_churn_and_notes_a_reversal() -> None:
    def change(change_id: str, category: str, headline: str, at: str, **extra: object) -> dict:
        return {"id": change_id, "target_id": "t", "severity": "Medium", "category": category, "headline": headline,
                "points": [headline + "."], "event_ids": [change_id], "detected_at": at, "diff_types": ["ContentEdit"],
                "reverted_by": None, "reverts": None, **extra}

    changes = [
        change("c" * 64, "routine", "Terms restored", "2026-01-04T00:00:00Z", reverts="b" * 64),
        change("b" * 64, "notable", "Terms removed", "2026-01-03T00:00:00Z", reverted_by="c" * 64),
        change("a" * 64, "churn", "Error page changed", "2026-01-02T00:00:00Z"),
    ]
    items = ET.fromstring(render_rss(changes, title="T", link="https://x", description="d")).findall("./channel/item")
    assert [item.findtext("guid") for item in items] == ["c" * 64, "b" * 64]  # the churn is not news
    assert "reverses the previous change" in (items[0].findtext("description") or "")
    assert "was reversed on 2026-01-04" in (items[1].findtext("description") or "")


def test_export_uses_the_public_base_url_and_leads_each_target_feed_with_the_newest(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer_with_changes(tmp_path)
    out = tmp_path / "site-data"
    export_site(verderer, out, base_url="https://record.example.org")
    for name in ("feed.xml", "feeds/epa.xml"):
        feed = ET.fromstring((out / name).read_text(encoding="utf-8"))
        links = [item.findtext("link") or "" for item in feed.findall("./channel/item")]
        assert links and all(link.startswith("https://record.example.org/change/") for link in links)
    record = json.loads((out / "record.json").read_text(encoding="utf-8"))
    assert record["changes"] and record["summary"]["changes"] == 1
