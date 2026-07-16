"""RSS 2.0 alert feeds over diff events (DESIGN §7). Built with stdlib ElementTree so
the XML is well-formed and escaped, with no extra dependency. A journalist subscribes to
the global feed or a per-target feed; each item is a classified change.
"""

from __future__ import annotations

import datetime as dt
from email.utils import format_datetime
from typing import Any
from xml.etree import ElementTree as ET

SITE_TITLE = "Verderer - verifiable environmental-data watchdog"


def _rfc822(iso: str | None) -> str:
    """RSS pubDate is RFC 822. Convert our RFC3339 UTC timestamps."""
    if not iso:
        return format_datetime(dt.datetime.now(dt.UTC))
    try:
        when = dt.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return iso
    return format_datetime(when)


def _describe(event: dict[str, Any]) -> str:
    return (
        f"{event.get('diff_type')} [{event.get('severity')}] in {event.get('target_id')}: "
        f"{event.get('evidence', {})}"
    )


def render_rss(events: list[dict[str, Any]], *, title: str, link: str, description: str) -> str:
    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = title
    ET.SubElement(channel, "link").text = link
    ET.SubElement(channel, "description").text = description
    ET.SubElement(channel, "generator").text = "verderer"
    for event in events[:200]:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = (
            f"{event.get('diff_type')} [{event.get('severity')}] - {event.get('target_id')}"
        )
        ET.SubElement(item, "description").text = _describe(event)
        guid = ET.SubElement(item, "guid", {"isPermaLink": "false"})
        guid.text = str(event.get("id", ""))
        ET.SubElement(item, "pubDate").text = _rfc822(event.get("detected_at"))
        ET.SubElement(item, "link").text = f"{link}#event-{str(event.get('id') or '')[:16]}"
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(rss, encoding="unicode")
