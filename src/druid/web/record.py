"""Build the public record from the ledger: per-target timelines of attested
observations and classified diff events, each keyed by a permanent leaf hash.
"""

from __future__ import annotations

from typing import Any

from ..pipeline import Druid

RECORD_SCHEMA = "druid.record/v1"


def _observation_view(leaf_hash: str, record: dict[str, Any], *, warc_available: bool) -> dict[str, Any]:
    warc_hash = record.get("warc_record_hash")
    return {
        "id": leaf_hash,  # permanent: the ledger leaf hash
        "content_hash": record.get("raw_bytes_hash"),
        "fetched_at": record.get("fetched_at"),
        "http_status": record.get("http_status"),
        "url": record.get("url"),
        # M11: the standards WARC archiving this fetch. `warc_record_hash` is the attested
        # fact (always shown); the `warc` download link is advertised only when the blob is
        # actually available to ship — never advertise a hash a download can't back.
        "warc_record_hash": warc_hash,
        "warc": f"warc/{warc_hash[4:]}.warc" if warc_hash and warc_available else None,
    }


def _event_view(leaf_hash: str, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": leaf_hash,
        "target_id": record.get("target_id"),
        "diff_type": record.get("diff_type"),
        "severity": record.get("severity"),
        "layer": record.get("layer"),
        "detected_at": record.get("detected_at"),
        "evidence": record.get("evidence", {}),
        "from_hash": record.get("from_observation_hash"),
        "to_hash": record.get("to_observation_hash"),
    }


def build_record(druid: Druid) -> dict[str, Any]:
    """A JSON-serialisable snapshot of the public record for the UI + feeds."""
    targets: dict[str, dict[str, Any]] = {}
    for target in druid.targets.values():
        targets[target.id] = {
            "id": target.id,
            "title": target.title,
            "url": target.url,
            "kind": target.kind,
            "criteria": target.criteria,
            "observations": [],
            "events": [],
        }

    def _bucket(target_id: str | None) -> dict[str, Any]:
        tid = target_id or "(unknown)"
        if tid not in targets:
            targets[tid] = {
                "id": tid,
                "title": tid,
                "url": "",
                "kind": "page",
                "criteria": "(no longer in the curated set)",
                "observations": [],
                "events": [],
            }
        return targets[tid]

    all_events: list[dict[str, Any]] = []
    for entry in druid.log.entries():
        record = entry.record
        schema = record.get("schema")
        if schema == "druid.observation/v1":
            warc_hash = record.get("warc_record_hash")
            warc_available = isinstance(warc_hash, str) and druid.store.has(warc_hash)
            _bucket(record.get("target_id"))["observations"].append(
                _observation_view(entry.leaf_hash, record, warc_available=warc_available)
            )
        elif schema == "druid.diff/v1":
            event = _event_view(entry.leaf_hash, record)
            _bucket(record.get("target_id"))["events"].append(event)
            all_events.append(event)

    all_events.sort(key=lambda e: e.get("detected_at") or "", reverse=True)
    ordered = sorted(targets.values(), key=lambda t: t["id"])
    return {
        "schema": RECORD_SCHEMA,
        "public_key": druid.log.public_key_hex,
        "size": len(druid.log.entries()),
        "targets": ordered,
        "events": all_events,
    }
