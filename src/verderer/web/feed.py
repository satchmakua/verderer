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
