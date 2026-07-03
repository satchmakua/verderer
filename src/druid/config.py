"""Curated targets and the L1 sensitive-term dictionary, loaded from ``data/`` TOML.

Depth over breadth (DESIGN §7): a small, hand-picked, published target set — never a
crawl of all of .gov.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Target:
    id: str
    title: str
    url: str
    collector: str = "static"
    kind: str = "page"  # "page" (HTML/text) | "dataset" (CSV/TSV/JSON) — selects the differ
    criteria: str = ""


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
        )
        targets[target.id] = target
    return targets


def load_terms(path: Path) -> list[str]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    return [str(term).lower() for term in data.get("terms", [])]
