"""Export the public record to a directory the Astro site (and feed readers) consume:
`record.json`, a global `feed.xml`, per-target `feeds/<id>.xml`, and — since M2c — the
signed `checkpoint` plus the C2SP `tile/` files, so the published site doubles as a
static tile server a verifier can fetch from and recompute inclusion proofs against.
"""

from __future__ import annotations

import json
import shutil
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

    # M2c: publish the log itself — the signed checkpoint + the C2SP tile files. Static
    # files only (CDN-friendly); a verifier fetches them and recomputes proofs, trusting
    # nothing but the checkpoint signature.
    tiles = 0
    ledger_dir = druid.data_dir / "ledger"
    if (ledger_dir / "checkpoint").exists():
        shutil.copyfile(ledger_dir / "checkpoint", out / "checkpoint")
    tile_dir = ledger_dir / "tile"
    if tile_dir.exists():
        # Mirror, don't merge: partials the ledger has pruned must not linger here.
        shutil.rmtree(out / "tile", ignore_errors=True)
        shutil.copytree(tile_dir, out / "tile")
        tiles = sum(1 for p in (out / "tile").rglob("*") if p.is_file())

    return {
        "out": str(out),
        "targets": len(record["targets"]),
        "events": len(record["events"]),
        "tiles": tiles,
    }
