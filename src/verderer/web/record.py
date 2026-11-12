"""Build the public record from the ledger: per-target timelines of attested observations and
classified diff events, each keyed by a permanent leaf hash — plus the reader-facing views
derived from them (DESIGN §6.5).

Three kinds of information live in the record, and the boundary between them is kept explicit
(the ``legend`` entry states it in the file itself):

* **attested** — observations and diff events. Each is a ledger leaf, provable offline.
* **interpretation** — ``explain``, ``state``, ``changes``, ``summary``: plain-language readings
  derived from the leaves by `explain.py`. Best-effort, never attested.
* **operator-reported** — ``monitor``: the scheduler's own account of when each source was last
  checked. "We looked and nothing changed" leaves no leaf, so this is the only place it can be
  said — and it is the operator's word, not a proof.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from ..pipeline import Verderer
from ..scheduler import ScheduleEntry, load_schedule_state
from .explain import CRITERIA_TAGS, build_changes, parse_criteria, target_state

RECORD_SCHEMA = "verderer.record/v1"

LEGEND = {
    "attested": (
        "targets[].observations[] and events[] (fields id, content_hash, fetched_at, http_status, url, "
        "warc_record_hash, diff_type, severity, layer, detected_at, evidence, from_hash, to_hash) are "
        "ledger leaves: provable offline against the signed checkpoint."
    ),
    "interpretation": (
        "explain, state, changes, summary, tags and criteria_text are best-effort plain-language "
        "readings derived from those leaves. They are not attested and can be re-derived."
    ),
    "operator_reported": (
        "monitor is the scheduler's own account of its checks (a check that finds nothing new "
        "appends no leaf). It is the operator's word, not a proof."
    ),
}


def _iso(epoch: float | None) -> str | None:
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


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


def _monitor_view(entry: ScheduleEntry | None) -> dict[str, Any] | None:
    if entry is None:
        return None
    return {
        "last_checked": _iso(entry.last_run),
        "last_status": entry.last_status,
        "last_answered": _iso(entry.last_ok),
        "consecutive_failures": entry.consecutive_failures,
        "last_error": entry.last_error,
        "next_due": _iso(entry.next_due),
    }


def _checkpoint_view(verderer: Verderer) -> dict[str, Any] | None:
    """The signed checkpoint's body, parsed for display (origin / tree size / root). Parsed,
    not trusted: the signature is what a verifier checks, against the published file."""
    path = verderer.data_dir / "ledger" / "checkpoint"
    try:
        origin, size, root = path.read_text(encoding="utf-8").splitlines()[:3]
        return {"origin": origin, "size": int(size), "root": root}
    except (OSError, ValueError):
        return None


def build_record(verderer: Verderer, *, generated_at: str | None = None) -> dict[str, Any]:
    """A JSON-serialisable snapshot of the public record for the UI + feeds."""
    schedule = load_schedule_state(verderer.data_dir / "schedule-state.json")
    targets: dict[str, dict[str, Any]] = {}
    for target in verderer.targets.values():
        tags, criteria_text = parse_criteria(target.criteria)
        targets[target.id] = {
            "id": target.id,
            "title": target.title,
            "url": target.url,
            "kind": target.kind,
            "criteria": target.criteria,
            "tags": tags,
            "criteria_text": criteria_text,
            "interval_seconds": target.interval_seconds,
            "curated": True,
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
                "tags": [],
                "criteria_text": "No longer in the curated set; its attested history remains.",
                "interval_seconds": None,
                "curated": False,
                "observations": [],
                "events": [],
            }
        return targets[tid]

    ledger_events: list[dict[str, Any]] = []  # ledger order: oldest first
    entries = verderer.log.entries()
    for entry in entries:
        record = entry.record
        schema = record.get("schema")
        if schema == "verderer.observation/v1":
            warc_hash = record.get("warc_record_hash")
            warc_available = isinstance(warc_hash, str) and verderer.store.has(warc_hash)
            _bucket(record.get("target_id"))["observations"].append(
                _observation_view(entry.leaf_hash, record, warc_available=warc_available)
            )
        elif schema == "verderer.diff/v1":
            event = _event_view(entry.leaf_hash, record)
            _bucket(record.get("target_id"))["events"].append(event)
            ledger_events.append(event)

    # Interpretation: explain every finding and group findings into changes (this annotates
    # the event views in place, so the per-target lists carry the same explanations).
    changes = build_changes(ledger_events, {tid: t["observations"] for tid, t in targets.items()})
    changes.reverse()  # newest first, like the events
    meaningful = [c for c in changes if c["category"] != "churn"]

    for tid, view in targets.items():
        monitor = _monitor_view(schedule.get(tid)) if view["curated"] else None
        view["monitor"] = monitor
        view["state"] = target_state(view["url"], view["observations"], monitor)
        own = [c for c in meaningful if c["target_id"] == tid]
        view["change_count"] = len(own)
        view["last_change_at"] = own[0]["detected_at"] if own else None

    all_events = sorted(ledger_events, key=lambda e: e.get("detected_at") or "", reverse=True)
    ordered = sorted(targets.values(), key=lambda t: t["id"])
    observation_times = [o["fetched_at"] for t in ordered for o in t["observations"] if o.get("fetched_at")]
    checks = [t["monitor"]["last_checked"] for t in ordered if t["monitor"] and t["monitor"]["last_checked"]]
    return {
        "schema": RECORD_SCHEMA,
        "generated_at": generated_at or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "public_key": verderer.log.public_key_hex,
        "size": len(entries),
        "checkpoint": _checkpoint_view(verderer),
        "legend": LEGEND,
        "criteria_tags": CRITERIA_TAGS,
        "watched_terms": list(verderer.terms),  # the published L1 dictionary the term watch uses
        "summary": {
            "targets": len(ordered),
            "states": dict(Counter(t["state"]["code"] for t in ordered)),
            "observations": len(observation_times),
            "findings": len(all_events),
            "changes": len(meaningful),
            "notable_changes": sum(1 for c in meaningful if c["category"] == "notable"),
            "error_page_churn": len(changes) - len(meaningful),
            "first_observed_at": min(observation_times, default=None),
            "last_observed_at": max(observation_times, default=None),
            "last_checked_at": max(checks, default=None),
        },
        "targets": ordered,
        "events": all_events,
        "changes": changes,
    }
