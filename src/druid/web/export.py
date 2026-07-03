"""Export the public record to a directory the Astro site (and feed readers) consume:
`record.json`, a global `feed.xml`, and per-target `feeds/<id>.xml`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..pipeline import Druid
from .feed import SITE_TITLE, render_rss
from .record import build_record


def export_site(druid: Druid, out_dir: Path, *, base_url: str = "https://druid.example") -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    record = build_record(druid)

    (out / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    (out / "feed.xml").write_text(
        render_rss(
            record["events"],
            title=SITE_TITLE,
            link=base_url,
            description="All classified changes across curated targets.",
        ),
        encoding="utf-8",
    )

    feeds = out / "feeds"
    feeds.mkdir(exist_ok=True)
    for target in record["targets"]:
        (feeds / f"{target['id']}.xml").write_text(
            render_rss(
                target["events"],
                title=f"{SITE_TITLE}: {target['title']}",
                link=f"{base_url}/target/{target['id']}",
                description=f"Classified changes for {target['title']}.",
            ),
            encoding="utf-8",
        )

    return {
        "out": str(out),
        "targets": len(record["targets"]),
        "events": len(record["events"]),
    }
