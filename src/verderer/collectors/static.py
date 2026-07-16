"""Static collector: a polite plain-HTTP fetch of HTML/text/PDF (DESIGN §7).

Crawling is courteous by construction: an identifiable user agent, redirects followed,
a bounded timeout. (Rate-limiting/backoff across a run arrives with the scheduler in a
later milestone.)
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime

from ..config import Target
from ..hashing import multihash_sha256
from ..models import Observation
from .base import Capture, Collected, Fetcher, FetchResult

USER_AGENT = "VerdererWatchdog/0.0 (+https://github.com/satchmakua/verderer) polite-archival-collector"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def httpx_fetcher(url: str, *, timeout: float = 30.0, headers: Mapping[str, str] | None = None) -> FetchResult:
    """Plain-HTTP GET with our identifiable UA. ``headers`` carries optional conditional-GET
    validators (``If-None-Match`` / ``If-Modified-Since``) supplied by the politeness layer;
    a ``304`` response is returned faithfully (an empty body) for that layer to interpret."""
    import httpx  # imported lazily so offline tests never need the dependency

    request_headers = {"User-Agent": USER_AGENT, **(dict(headers) if headers else {})}
    with httpx.Client(follow_redirects=True, timeout=timeout, headers=request_headers) as client:
        response = client.get(url)
        return FetchResult(
            url=str(response.url),
            status=response.status_code,
            headers=dict(response.headers),
            body=response.content,
        )


class StaticCollector:
    type = "static"
    version = "0.1.0"

    def __init__(self, fetcher: Fetcher = httpx_fetcher) -> None:
        self._fetch = fetcher

    def collect(self, target: Target) -> Collected:
        result = self._fetch(target.url)
        headers_canon = json.dumps(dict(sorted(result.headers.items())), separators=(",", ":")).encode()
        fetched_at = _utc_now()
        observation = Observation(
            target_id=target.id,
            url=result.url,
            collector_type=self.type,
            collector_version=self.version,
            fetched_at=fetched_at,
            http_status=result.status,
            raw_bytes_hash=multihash_sha256(result.body),
            response_headers_hash=multihash_sha256(headers_canon),
        )
        capture = Capture(
            target_uri=result.url,
            fetched_at=fetched_at,
            record_type="response",  # a real HTTP fetch -> request + response WARC records
            status=result.status,
            response_headers=result.headers,
            content_type=result.headers.get("content-type", "application/octet-stream"),
        )
        return Collected(observation=observation, body=result.body, capture=capture)
