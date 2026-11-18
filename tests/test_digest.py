"""The weekly digest: changes grouped by ISO week (Monday-Sunday, UTC), quiet weeks included."""

import datetime as dt
from xml.etree import ElementTree as ET

from verderer.web.digest import build_weeks, span_text, summarise, week_id, week_start
from verderer.web.feed import render_digest_rss


def _change(cid: str, when: str, *, severity: str = "Medium", category: str = "routine", target: str = "a") -> dict:
    return {
        "id": cid,
        "target_id": target,
        "detected_at": when,
        "severity": severity,
        "category": category,
        "headline": f"headline {cid}",
        "points": [],
        "diff_types": ["ContentEdit"],
        "event_ids": [cid],
    }


TARGETS = [
    {
        "id": "a",
        "title": "Source A",
        "observations": [{"fetched_at": "2026-11-02T10:00:00Z"}, {"fetched_at": "2026-11-10T10:00:00Z"}],
    },
    {"id": "b", "title": "Source B", "observations": [{"fetched_at": "2026-11-11T08:00:00Z"}]},
]
CHANGES = [
    _change("m1", "2026-11-10T10:00:00Z"),
    _change("h1", "2026-11-11T08:00:00Z", severity="High", category="notable", target="b"),
    _change("m2", "2026-11-13T09:00:00Z"),
    _change("c1", "2026-11-12T09:00:00Z", category="churn"),
    _change("m3", "2026-11-17T01:00:00Z"),
]


def test_weeks_run_monday_to_sunday_and_include_quiet_ones() -> None:
    assert week_start(dt.date(2026, 11, 15)) == dt.date(2026, 11, 9)  # a Sunday belongs to its Monday
    assert week_id(dt.date(2026, 11, 9)) == "2026-W46"
    weeks = build_weeks(CHANGES, TARGETS, generated_at="2026-11-18T03:00:00Z")
    assert [w["id"] for w in weeks] == ["2026-W47", "2026-W46", "2026-W45"]  # newest first, no gap

    current, busy, quiet = weeks
    assert current["complete"] is False and current["changes"] == 1  # the week still in progress
    assert busy["complete"] is True and busy["start"] == "2026-11-09" and busy["end"] == "2026-11-15"
    # Severity first, then newest; error-page churn is counted apart, never listed.
    assert busy["change_ids"] == ["h1", "m2", "m1"]
    assert (busy["changes"], busy["notable"], busy["churn"], busy["observations"]) == (3, 1, 1, 2)
    assert busy["sources"] == ["a", "b"] and busy["summary"] == "3 changes across 2 sources, 1 high severity"
    assert quiet["changes"] == 0 and quiet["summary"] == "No changes" and quiet["observations"] == 1


def test_no_recorded_response_means_no_weeks() -> None:
    assert build_weeks(CHANGES, [{"id": "a", "observations": []}], generated_at="2026-11-18T03:00:00Z") == []
    assert build_weeks([], TARGETS, generated_at="not a time") == []


def test_wording() -> None:
    assert summarise(1, 0, 1) == "1 change across 1 source"
    assert span_text({"start": "2026-11-09", "end": "2026-11-15"}) == "Nov 9 - 15, 2026"
    assert span_text({"start": "2026-11-30", "end": "2026-12-06"}) == "Nov 30 - Dec 6, 2026"
    assert span_text({"start": "2026-12-28", "end": "2027-01-03"}) == "Dec 28, 2026 - Jan 3, 2027"


def test_digest_feed_has_one_item_per_completed_week() -> None:
    weeks = build_weeks(CHANGES, TARGETS, generated_at="2026-11-18T03:00:00Z")
    xml = render_digest_rss(
        weeks, CHANGES, link="https://verderer.example", titles={"a": "Source A", "b": "Source B"}
    )
    items = ET.fromstring(xml).findall("./channel/item")
    assert len(items) == 2  # the week in progress is not published until it ends
    busy, quiet = items
    assert busy.findtext("title") == "Week of Nov 9 - 15, 2026: 3 changes across 2 sources, 1 high severity"
    assert busy.findtext("link") == "https://verderer.example/digest/2026-W46"
    assert busy.findtext("guid") == "verderer-digest-2026-W46"
    assert busy.findtext("pubDate") == "Mon, 16 Nov 2026 00:00:00 +0000"  # the moment the week closed
    description = busy.findtext("description") or ""
    assert description.startswith("[High] Source B: headline h1.") and "1 error-page change set aside." in description
    assert "c1" not in description
    assert "No changes were detected" in (quiet.findtext("description") or "")
