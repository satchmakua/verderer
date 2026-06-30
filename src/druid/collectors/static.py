"""Static collector: a polite plain-HTTP fetch of HTML/text/PDF (DESIGN §7).

Crawling is courteous by construction: an identifiable user agent, redirects followed,
a bounded timeout. (Rate-limiting/backoff across a run arrives with the scheduler in a
later milestone.)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..config import Target
from ..hashing import multihash_sha256
from ..models import Observation
from .base import Fetcher, FetchResult

USER_AGENT = "DruidWatchdog/0.0 (+https://github.com/satchmakua/Druid) polite-archival-collector"


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def httpx_fetcher(url: str, *, timeout: float = 30.0) -> FetchResult:
    import httpx  # imported lazily so offline tests never need the dependency

    with httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
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

    def collect(self, target: Target) -> tuple[Observation, bytes]:
        result = self._fetch(target.url)
        headers_canon = json.dumps(dict(sorted(result.headers.items())), separators=(",", ":")).encode()
        observation = Observation(
            target_id=target.id,
            url=result.url,
            collector_type=self.type,
            collector_version=self.version,
            fetched_at=_utc_now(),
            http_status=result.status,
            raw_bytes_hash=multihash_sha256(result.body),
            response_headers_hash=multihash_sha256(headers_canon),
        )
        return observation, result.body
