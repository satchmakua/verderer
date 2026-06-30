"""Collector ports: the narrow seams the pipeline depends on (hexagonal boundary).

``Fetcher`` is injectable so collection is testable offline — tests pass a fake fetch
function instead of touching the network.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
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


class Collector(Protocol):
    type: str
    version: str

    def collect(self, target: Target) -> tuple[Observation, bytes]:
        """Fetch ``target`` and return its Observation plus the raw body bytes."""
        ...
