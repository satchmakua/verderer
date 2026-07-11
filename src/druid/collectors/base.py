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
class Collected:
    """A collector's output: the attested observation, its primary artifact bytes, and
    any additional content-addressed blobs (already referenced by hash in the record)."""

    observation: Observation
    body: bytes  # the primary artifact -> Observation.raw_bytes_hash (diffed + bundled)
    side_artifacts: tuple[bytes, ...] = ()  # extra blobs to store (e.g. captured requests)


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
