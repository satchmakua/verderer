"""M7 — federated overlay index + verification badging (DESIGN §8, §10 risk-coverage).

Druid observes a *curated* set; the volunteer rescue ecosystem (Wayback, OSF, Dataverse,
Perma.cc, PEDP) has already archived far more. This overlay cross-references those
third-party archives against Druid's own attested record and produces one queryable index
where each resource is badged by its strongest guarantee:

  * **druid-attested** — Druid observed this URL, so there is a self-verifying proof
    bundle: exactly-these-bytes, faithfully preserved, offline-verifiable, trusting no one.
  * **unverified** — a third-party copy exists (a real, valuable archive) but Druid never
    observed it, so there is nothing to *prove* about its bytes. No badge.

That badge distinction is the whole point (DESIGN §1): verifiability is Druid's
differentiator over an ordinary archive index. Each `ArchiveSource` is injected behind a
narrow port so the harvest is testable offline; the default `WaybackSource` queries the
Internet Archive CDX API politely (identifiable UA, bounded timeout, read-only). OSF /
Dataverse / Perma.cc / PEDP adapters are the same port over their metadata APIs.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import urlsplit

from .pipeline import Druid

OVERLAY_SCHEMA = "druid.overlay/v1"
USER_AGENT = "DruidWatchdog/0.0 (+https://github.com/satchmakua/Druid) polite-overlay-harvester"


@dataclass(frozen=True, slots=True)
class OverlayCapture:
    """One third-party archive capture of a resource (normalised across sources)."""

    source: str  # "wayback", "osf", ...
    url: str  # the archived resource's URL
    timestamp: str  # the capture time (source-native string)
    archive_url: str  # a link to the archived copy
    mime: str | None = None
    status: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {"timestamp": self.timestamp, "archive_url": self.archive_url, "mime": self.mime, "status": self.status}


class ArchiveSource(Protocol):
    name: str

    def captures(self, url: str) -> list[OverlayCapture]:
        """Return third-party captures of `url` (exact, or matching resources)."""
        ...


# --- Wayback (Internet Archive CDX) ---

CdxFetcher = Callable[[str, bool, int], list[list[str]]]


def wayback_cdx_fetch(url: str, match_prefix: bool = False, limit: int = 20) -> list[list[str]]:
    """Query the Wayback CDX API. Returns the raw CDX rows (row 0 is the field header).

    Read-only, polite: one GET with an identifiable UA and a bounded timeout.
    """
    import httpx  # imported lazily so offline tests never need the dependency

    params = {"url": url, "output": "json", "limit": str(limit), "collapse": "digest"}
    if match_prefix:
        params["matchType"] = "prefix"
    with httpx.Client(timeout=30.0, headers={"User-Agent": USER_AGENT}, follow_redirects=True) as client:
        response = client.get("http://web.archive.org/cdx/search/cdx", params=params)
        response.raise_for_status()
        data = response.json()
    return data if isinstance(data, list) else []


class WaybackSource:
    name = "wayback"

    def __init__(self, fetcher: CdxFetcher = wayback_cdx_fetch, *, match_prefix: bool = False, limit: int = 20) -> None:
        self._fetch = fetcher
        self._match_prefix = match_prefix
        self._limit = limit

    def captures(self, url: str) -> list[OverlayCapture]:
        rows = self._fetch(url, self._match_prefix, self._limit)
        if not rows or len(rows) < 2:
            return []
        header = rows[0]
        idx = {name: i for i, name in enumerate(header)}
        needed = max((idx[k] for k in ("timestamp", "original", "mimetype", "statuscode") if k in idx), default=-1)
        out: list[OverlayCapture] = []
        for row in rows[1:]:
            if len(row) <= needed:
                continue  # a ragged/truncated CDX row — skip it, never abort the harvest
            ts = row[idx["timestamp"]] if "timestamp" in idx else ""
            original = row[idx["original"]] if "original" in idx else url
            out.append(
                OverlayCapture(
                    source=self.name,
                    url=original,
                    timestamp=ts,
                    archive_url=f"http://web.archive.org/web/{ts}/{original}",
                    mime=row[idx["mimetype"]] if "mimetype" in idx else None,
                    status=row[idx["statuscode"]] if "statuscode" in idx else None,
                )
            )
        return out


# --- overlay construction + badging ---


def _norm(url: str) -> str:
    """A lenient identity key so `https://www.epa.gov/x/` and `http://epa.gov/x` match."""
    parts = urlsplit(url if "://" in url else "http://" + url)
    host = parts.netloc.lower()
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/") or "/"
    key = host + path
    if parts.query:
        key += "?" + parts.query
    return key


def _attested_resources(druid: Druid) -> dict[str, dict[str, Any]]:
    """Per normalised-URL resource, the *latest* attested observation leaf. Identity,
    ledger index, and content hash all move together to the newest leaf for that URL, so
    the advertised hash and the leaf a bundle will prove are the same observation — the
    overlay must never advertise a hash its downloadable bundle doesn't attest."""
    attested: dict[str, dict[str, Any]] = {}
    for entry in druid.log.entries():  # ledger order is append/chronological
        record = entry.record
        if record.get("schema") != "druid.observation/v1":
            continue
        url = record.get("url", "")
        info = attested.setdefault(_norm(url), {"observations": 0})
        info["observations"] += 1
        info["url"] = url  # last-seen (latest) wins for every identity field, in lockstep
        info["target_id"] = record.get("target_id")
        info["index"] = entry.index
        info["content_hash"] = record.get("raw_bytes_hash")
        info["fetched_at"] = record.get("fetched_at")
    return attested


def build_overlay(
    druid: Druid, sources: list[ArchiveSource], *, query_urls: list[str] | None = None
) -> dict[str, Any]:
    """Cross-reference third-party archive captures with Druid's attested observations into
    a single `druid.overlay/v1` index. Each resource is badged druid-attested (with a proof
    bundle reference) or left unverified.

    `query_urls` defaults to the curated target URLs; a source may return captures for
    sibling resources (e.g. Wayback prefix matching), which appear as unverified rows.
    """
    attested = _attested_resources(druid)
    if query_urls is None:
        query_urls = [t.url for t in druid.targets.values()]

    resources: dict[str, dict[str, Any]] = {}
    for query in query_urls:
        for source in sources:
            for capture in source.captures(query):
                key = _norm(capture.url)
                res = resources.setdefault(key, {"url": capture.url, "external": {}})
                res["external"].setdefault(capture.source, []).append(capture)
    # Include attested resources even if no third-party archive surfaced them.
    for key, info in attested.items():
        resources.setdefault(key, {"url": info["url"], "external": {}})

    records: list[dict[str, Any]] = []
    for key, res in resources.items():
        matched = attested.get(key)
        record: dict[str, Any] = {
            # For an attested resource, show the URL Druid actually observed (what the
            # bundle proves), not a third party's equivalent-but-different capture URL.
            "url": matched["url"] if matched is not None else res["url"],
            "attested": matched is not None,
            "badge": "druid-attested" if matched is not None else None,
            "druid": None,
            "external": [
                {"source": name, "captures": [c.to_json() for c in caps]}
                for name, caps in sorted(res["external"].items())
            ],
        }
        if matched is not None:
            # The bundle is keyed on the *specific* attested leaf (its ledger index), so it
            # proves exactly the observation whose hash this row advertises.
            record["druid"] = {
                "target_id": matched["target_id"],
                "index": matched["index"],
                "observations": matched["observations"],
                "content_hash": matched["content_hash"],
                "fetched_at": matched["fetched_at"],
                "bundle": f"bundles/{matched['index']}.json",
            }
        records.append(record)

    records.sort(key=lambda r: (not r["attested"], r["url"]))
    return {
        "schema": OVERLAY_SCHEMA,
        "sources": [s.name for s in sources],
        "attested_count": sum(1 for r in records if r["attested"]),
        "resource_count": len(records),
        "resources": records,
    }


def write_overlay(
    druid: Druid, out_dir: Any, sources: list[ArchiveSource], *, query_urls: list[str] | None = None
) -> dict[str, Any]:
    """Build the overlay and write `overlay.json` plus a downloadable proof bundle
    (`bundles/<target>.json`) for every attested resource. Returns a summary."""
    from pathlib import Path

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    overlay = build_overlay(druid, sources, query_urls=query_urls)
    (out / "overlay.json").write_text(json.dumps(overlay, indent=2), encoding="utf-8")

    bundles = out / "bundles"
    written = 0
    seen: set[int] = set()
    for resource in overlay["resources"]:
        druid_info = resource.get("druid")
        if not druid_info or druid_info.get("index") is None:
            continue
        index = druid_info["index"]
        if index in seen:
            continue
        seen.add(index)
        try:
            # Prove the *specific* leaf this resource advertises, not the target's latest.
            bundle = druid.bundle(druid_info["target_id"], index)
        except Exception:  # a leaf that can't be bundled — skip, don't emit a broken link
            continue
        bundles.mkdir(parents=True, exist_ok=True)
        (bundles / f"{index}.json").write_text(json.dumps(bundle), encoding="utf-8")
        written += 1

    return {
        "out": str(out),
        "sources": overlay["sources"],
        "resources": overlay["resource_count"],
        "attested": overlay["attested_count"],
        "bundles": written,
    }
