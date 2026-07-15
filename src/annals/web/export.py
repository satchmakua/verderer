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

from ..pipeline import Annals, _checkpoint_size
from .feed import SITE_TITLE, render_rss
from .record import build_record


def export_site(annals: Annals, out_dir: Path, *, base_url: str = "https://annals.example") -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    record = build_record(annals)

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

    # M11: ship the WARCs. Each observation's archived capture is written to warc/<hash>.warc
    # (content-addressed name), so the published record is a standards web archive a third
    # party can ingest/replay, and the record.json's `warc` links resolve.
    warcs = 0
    warc_out = out / "warc"
    warc_out.mkdir(exist_ok=True)
    seen: set[str] = set()
    for target in record["targets"]:
        for obs in target["observations"]:
            warc_hash = obs.get("warc_record_hash")
            if not warc_hash or warc_hash in seen:
                continue
            seen.add(warc_hash)
            if annals.store.has(warc_hash):
                (warc_out / f"{warc_hash[4:]}.warc").write_bytes(annals.store.get(warc_hash))
                warcs += 1

    # M2c: publish the log itself — the signed checkpoint + the C2SP tile files. Static
    # files only (CDN-friendly); a verifier fetches them and recomputes proofs, trusting
    # nothing but the checkpoint signature.
    tiles = 0
    ledger_dir = annals.data_dir / "ledger"
    consistency = 0
    if (ledger_dir / "checkpoint").exists():
        shutil.copyfile(ledger_dir / "checkpoint", out / "checkpoint")
        # M13 gossip: publish a consistency proof linking this checkpoint to the previously-
        # published one, so a client following the site can verify — offline — that the log
        # never forked, shrank, or rewrote history between exports. The chain of published
        # checkpoints is the gossip carrier a static site needs (DESIGN §6.3). Its own marker,
        # distinct from `annals consistency`'s, so the two tools don't consume each other's chain.
        current_cp = (ledger_dir / "checkpoint").read_text(encoding="utf-8")
        published = ledger_dir / "export-published-checkpoint"
        previous_cp = published.read_text(encoding="utf-8") if published.exists() else None
        try:
            grew = previous_cp is not None and _checkpoint_size(previous_cp) < _checkpoint_size(current_cp)
        except (ValueError, IndexError):
            grew = False  # a corrupt marker -> skip the link this pass, re-baseline below
        if grew:
            assert previous_cp is not None
            bundle = annals.gossip_bundle(previous_cp)
            # Never publish a bundle that doesn't verify: a self-consistency failure means the
            # operator's own log forked/corrupted — surface it (don't advance the chain) rather
            # than shipping a broken proof.
            ok, _ = annals.log.verify_consistency(bundle["old_checkpoint"], bundle["new_checkpoint"], bundle["proof"])
            if ok:
                (out / "consistency.json").write_text(json.dumps(bundle, indent=2), encoding="utf-8")
                consistency = 1
                published.write_text(current_cp, encoding="utf-8")  # advance only a proven chain
        else:
            published.write_text(current_cp, encoding="utf-8")  # first export / re-baseline
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
        "warcs": warcs,
        "consistency": consistency,
    }
