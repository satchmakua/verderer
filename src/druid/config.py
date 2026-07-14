"""Curated targets and the L1 sensitive-term dictionary, loaded from ``data/`` TOML.

Depth over breadth (DESIGN §7): a small, hand-picked, published target set — never a
crawl of all of .gov.
"""

from __future__ import annotations

import math
import tomllib
from dataclasses import dataclass
from pathlib import Path

DEFAULT_INTERVAL = "1d"
_UNIT_SECONDS = {"s": 1.0, "m": 60.0, "h": 3600.0, "d": 86400.0}


def parse_duration(value: str | int | float) -> float:
    """Parse a human cadence into seconds: ``"6h"``, ``"30m"``, ``"1d"``, ``"90s"``, or a
    bare number (seconds). Used for a target's re-observation interval (M10 scheduler).

    Rejects non-positive / non-finite durations: a ``0`` or negative interval would make the
    scheduler treat a target as perpetually due and hot-spin the loop, so a config typo must
    fail fast at load rather than silently wedge the watchdog."""
    if isinstance(value, int | float):
        seconds = float(value)
    else:
        text = str(value).strip().lower()
        if not text:
            raise ValueError("empty duration")
        unit = text[-1]
        seconds = float(text[:-1]) * _UNIT_SECONDS[unit] if unit in _UNIT_SECONDS else float(text)
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"interval must be a positive, finite duration; got {value!r}")
    return seconds


@dataclass(frozen=True, slots=True)
class Target:
    id: str
    title: str
    url: str
    collector: str = "static"
    kind: str = "page"  # "page" (HTML/text) | "dataset" (CSV/TSV/JSON) — selects the differ
    criteria: str = ""
    interval_seconds: float = 86400.0  # re-observation cadence (M10 scheduler); 1 day default


def load_targets(path: Path) -> dict[str, Target]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    targets: dict[str, Target] = {}
    for item in data.get("target", []):
        target = Target(
            id=item["id"],
            title=item["title"],
            url=item["url"],
            collector=item.get("collector", "static"),
            kind=item.get("kind", "page"),
            criteria=item.get("criteria", ""),
            interval_seconds=parse_duration(item.get("interval", DEFAULT_INTERVAL)),
        )
        targets[target.id] = target
    return targets


def load_terms(path: Path) -> list[str]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return [str(term).lower() for term in data.get("terms", [])]
