"""Collector ports: the narrow seams the pipeline depends on (hexagonal boundary).

``Fetcher`` (static) and ``RenderEngine`` (render) are injectable so collection is
testable offline — tests pass a fake in place of the network / a real browser.

A collector returns a :class:`Collected`: the primary artifact (the bytes the pipeline
content-addresses, diffs, and bundles) plus any ``side_artifacts`` — additional
content-addressed blobs the observation references by hash (a rendered DOM's captured
API/data calls, a dataset's unpacked members, …). DESIGN §3/§4.3.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from ..config import Target
from ..models import Observation


@dataclass(frozen=True, slots=True)
class FetchResult:
    url: str  # final URL after redirects
    status: int
    headers: Mapping[str, str]
    body: bytes


class Fetcher(Protocol):
    def __call__(self, url: str, *, timeout: float = ...) -> FetchResult: ...


@dataclass(frozen=True, slots=True)
class Capture:
    """What a collector saw on the wire, enough for the pipeline to archive the observation
    as a standards WARC (M11). ``record_type="response"`` is a real HTTP fetch (a request +
    response record pair, payload = the response body); ``"resource"`` is a derived artifact
    like a rendered DOM (a single resource record). The payload is the collector's ``body``,
    so it isn't duplicated here. DESIGN §2/§7."""

    target_uri: str  # final URL after redirects (WARC-Target-URI)
    fetched_at: str  # RFC3339 UTC, = Observation.fetched_at (WARC-Date)
    record_type: str = "response"  # "response" | "resource"
    status: int = 200
    response_headers: Mapping[str, str] = field(default_factory=dict)
    content_type: str = "application/octet-stream"


@dataclass(frozen=True, slots=True)
class Collected:
    """A collector's output: the attested observation, its primary artifact bytes, any
    additional content-addressed blobs (already referenced by hash in the record), and —
    when the collector fetched something archivable — a :class:`Capture` the pipeline turns
    into a WARC referenced by ``Observation.warc_record_hash``."""

    observation: Observation
    body: bytes  # the primary artifact -> Observation.raw_bytes_hash (diffed + bundled)
    side_artifacts: tuple[bytes, ...] = ()  # extra blobs to store (e.g. captured requests)
    capture: Capture | None = None  # WARC source (M11); None = no archival capture


class Collector(Protocol):
    type: str
    version: str

    def collect(self, target: Target) -> Collected:
        """Fetch ``target`` and return its :class:`Collected`."""
        ...


# --- render collector port (M3b) ---


@dataclass(frozen=True, slots=True)
class RenderedCall:
    """One data call the rendered page issued on its own (an XHR/fetch), with its raw
    response bytes. The collector owns hashing: it stores ``body`` content-addressed and
    records the hash in the observation's request manifest — so the engine stays a thin,
    fakeable seam and the multihash is computed in exactly one place."""

    url: str
    method: str
    status: int
    resource_type: str  # "xhr" | "fetch" | "document" | ...
    body: bytes


@dataclass(frozen=True, slots=True)
class RenderResult:
    final_url: str
    status: int  # the main document's HTTP status
    headers: Mapping[str, str]
    rendered_dom: bytes  # page content after the network went idle (the post-JS DOM)
    calls: tuple[RenderedCall, ...] = field(default_factory=tuple)  # the page's own data calls


class RenderEngine(Protocol):
    def __call__(self, url: str, *, timeout: float = ...) -> RenderResult: ...
