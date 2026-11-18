"""RSS 2.0 alert feeds over the record's changes (DESIGN §7). Built with stdlib ElementTree so
the XML is well-formed and escaped, with no extra dependency. A journalist subscribes to
the global feed or a per-target feed.

An item is one *change* — everything the differ found in one observed transition — because
that is the unit a reader acts on: a list that shifted is one item saying what was removed, not
nineteen saying each position moved. Items read as sentences (`explain.py`), link to the
change's permanent page, and skip error-page churn: a block page rewording itself is recorded,
but it is not news. An item's ``guid`` is the ledger leaf hash of the change's first finding, so
it is permanent and a reader is never shown an old item twice.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from email.utils import format_datetime
from typing import Any
from xml.etree import ElementTree as ET

SITE_TITLE = "Verderer - verifiable environmental-data watchdog"
_DISCLAIMER = (
    "This classification is a best-effort, human-reviewable interpretation. The observations "
    "behind it are cryptographically attested and can be verified offline."
)
_MAX_ITEMS = 200


def _rfc822(iso: str | None) -> str:
    """RSS pubDate is RFC 822. Convert our RFC3339 UTC timestamps."""
    if not iso:
        return format_datetime(dt.datetime.now(dt.UTC))
    try:
        when = dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return iso
    return format_datetime(when)


def _describe(change: Mapping[str, Any], by_id: Mapping[Any, Mapping[str, Any]]) -> str:
    parts = [" ".join(str(point) for point in change.get("points") or [])]
    undone = by_id.get(change.get("reverted_by"))
    if undone is not None:
        parts.append(f"This change was reversed on {str(undone.get('detected_at'))[:10]}.")
    if change.get("reverts") is not None:
        parts.append("This reverses the previous change to this source.")
    findings = len(change.get("event_ids") or [])
    parts.append(
        f"[severity {change.get('severity')}, {findings} finding{'' if findings == 1 else 's'}, "
        f"detected {change.get('detected_at')}]"
    )
    parts.append(_DISCLAIMER)
    return " ".join(part for part in parts if part)


def render_rss(
    changes: Sequence[Mapping[str, Any]],
    *,
    title: str,
    link: str,
    description: str,
    site_url: str | None = None,
    titles: Mapping[str, str] | None = None,
) -> str:
    """Render ``changes`` (the record's change views, newest first) as an RSS channel.
    ``site_url`` is the site root the permalinks hang off (defaults to the channel ``link``);
    ``titles`` maps a target id to its human title."""
    root = (site_url or link).rstrip("/")
    names = titles or {}
    by_id = {change.get("id"): change for change in changes}
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = title
    ET.SubElement(channel, "link").text = link
    ET.SubElement(channel, "description").text = description
    ET.SubElement(channel, "generator").text = "verderer"
    news = [change for change in changes if change.get("category") != "churn"]
    for change in news[:_MAX_ITEMS]:
        item = ET.SubElement(channel, "item")
        target_id = str(change.get("target_id"))
        ET.SubElement(item, "title").text = (
            f"[{change.get('severity')}] {names.get(target_id, target_id)}: {change.get('headline')}"
        )
        ET.SubElement(item, "description").text = _describe(change, by_id)
        for diff_type in change.get("diff_types") or []:
            ET.SubElement(item, "category").text = str(diff_type)
        guid = ET.SubElement(item, "guid", {"isPermaLink": "false"})
        guid.text = str(change.get("id") or "")
        ET.SubElement(item, "pubDate").text = _rfc822(change.get("detected_at"))
        ET.SubElement(item, "link").text = f"{root}/change/{change.get('id') or ''}"
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(rss, encoding="unicode")


_MAX_WEEKS = 52


def render_digest_rss(
    weeks: Sequence[Mapping[str, Any]],
    changes: Sequence[Mapping[str, Any]],
    *,
    link: str,
    site_url: str | None = None,
    titles: Mapping[str, str] | None = None,
) -> str:
    """The weekly digest as an RSS channel: one item per **completed** week (so an item, once
    published, does not change under a reader), quiet weeks included - a week in which nothing
    changed is still an answer, and it shows the watchdog was running."""
    from .digest import span_text

    root = (site_url or link).rstrip("/")
    names = titles or {}
    by_id = {change.get("id"): change for change in changes}
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = f"{SITE_TITLE} - weekly digest"
    ET.SubElement(channel, "link").text = f"{root}/digest"
    ET.SubElement(channel, "description").text = (
        "One item a week: what changed in the government environmental pages and datasets Verderer watches."
    )
    ET.SubElement(channel, "generator").text = "verderer"
    done = [week for week in weeks if week.get("complete")]
    for week in done[:_MAX_WEEKS]:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = f"Week of {span_text(week)}: {str(week.get('summary')).lower()}"
        lines: list[str] = []
        for change_id in week.get("change_ids") or []:
            change = by_id.get(change_id)
            if change is None:
                continue
            target_id = str(change.get("target_id"))
            lines.append(f"[{change.get('severity')}] {names.get(target_id, target_id)}: {change.get('headline')}.")
        if not lines:
            lines.append("No changes were detected in the sources that answered.")
        observed = int(week.get("observations") or 0)
        lines.append(f"{observed} new response{'' if observed == 1 else 's'} recorded.")
        churn = int(week.get("churn") or 0)
        if churn:
            lines.append(f"{churn} error-page change{'' if churn == 1 else 's'} set aside.")
        lines.append(_DISCLAIMER)
        ET.SubElement(item, "description").text = " ".join(lines)
        guid = ET.SubElement(item, "guid", {"isPermaLink": "false"})
        guid.text = f"verderer-digest-{week.get('id')}"
        # Published the moment the week ends: 00:00 UTC on the following Monday.
        closes = dt.date.fromisoformat(str(week.get("end"))) + dt.timedelta(days=1)
        ET.SubElement(item, "pubDate").text = format_datetime(
            dt.datetime(closes.year, closes.month, closes.day, tzinfo=dt.UTC)
        )
        ET.SubElement(item, "link").text = f"{root}/digest/{week.get('id')}"
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(rss, encoding="unicode")
