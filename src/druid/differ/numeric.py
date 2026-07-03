"""L2 — numeric / threshold extraction (DESIGN §6.2).

Extract numbers-with-units that sit in a *regulatory context* (a limit, standard,
threshold, reporting cutoff) and flag when the value tied to the same context changes —
a limit moving 10 -> 15 ppb, a cutoff shifting. High value and easy to slip past a
reader. High-precision by construction: a number counts only when a regulatory keyword
sits just before it AND the unit is a plausible measurement unit, so prose numbers
(years, page counts, list indices) are ignored.

Scope (M3a): same-unit value changes, keyed on the keyword phrase + unit. Cross-unit
normalisation (e.g. recognising 10 ppb == 0.010 ppm via `pint`) is the planned L2
refinement — until then differing units simply don't match, which avoids false positives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import DiffRecord, DiffType

# Keywords that make a nearby number a regulatory quantity rather than prose.
CONTEXT_KEYWORDS: tuple[str, ...] = (
    "threshold", "limit", "maximum", "minimum", "standard", "level", "concentration",
    "cutoff", "cut-off", "reporting", "allowable", "permissible", "criterion", "criteria",
    "exceed", "no more than", "up to", "baseline", "deadline", "cap", "mcl",
)

# Plausible measurement units (env/regulatory). A unit also counts if it carries a
# special character (%, /, micro, degree) — e.g. "mg/L", "µg/m3", "°C".
KNOWN_UNITS: frozenset[str] = frozenset(
    {
        "ppb", "ppm", "ppt", "ppbv", "ppmv", "pptv", "mg", "µg", "ug", "ng", "pg", "g",
        "kg", "mol", "mmol", "l", "ml", "µl", "ul", "cfu", "ntu", "psu", "ph", "mcl",
        "mgd", "mw", "gw", "kw", "tpy", "tons", "ton", "mt", "kt", "celsius",
        "fahrenheit", "kelvin", "degrees", "percent", "pct",
    }
)
_SPECIAL = set("%/µ°·")

_NUMBER = r"[-+]?\d{1,3}(?:,\d{3})+(?:\.\d+)?|[-+]?\d+(?:\.\d+)?"
_UNIT = r"[A-Za-zµ°%][A-Za-z0-9µ°%]*(?:/[A-Za-zµ°0-9]+)?"
_QTY = re.compile(rf"(?P<value>{_NUMBER})\s?(?P<unit>{_UNIT})")
_WS = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class Quantity:
    context: str  # the keyword phrase leading up to the number
    value: float
    unit: str
    raw: str  # "10 ppb" as written


def _plausible_unit(unit: str) -> bool:
    return unit.lower() in KNOWN_UNITS or any(c in _SPECIAL for c in unit)


def _context_before(text: str, number_start: int) -> str | None:
    prefix = text[max(0, number_start - 70) : number_start]
    lowered = prefix.lower()
    best = -1
    for keyword in CONTEXT_KEYWORDS:
        best = max(best, lowered.rfind(keyword))
    if best == -1:
        return None
    return _WS.sub(" ", prefix[best:]).strip()


def extract(text: str) -> dict[str, Quantity]:
    """Map a context key -> the regulatory Quantity found there (last occurrence wins)."""
    found: dict[str, Quantity] = {}
    for match in _QTY.finditer(text):
        unit = match.group("unit")
        if not _plausible_unit(unit):
            continue
        context = _context_before(text, match.start())
        if context is None:
            continue
        try:
            value = float(match.group("value").replace(",", ""))
        except ValueError:
            continue
        key = f"{context.lower()} <n> {unit.lower()}"
        found[key] = Quantity(context=context, value=value, unit=unit, raw=f"{match.group('value')} {unit}")
    return found


def numeric_watch(
    prev_text: str,
    curr_text: str,
    *,
    target_id: str,
    detected_at: str,
    from_hash: str | None,
    to_hash: str,
) -> list[DiffRecord]:
    before = extract(prev_text)
    after = extract(curr_text)
    diffs: list[DiffRecord] = []
    for key, current in after.items():
        previous = before.get(key)
        if previous is None or previous.value == current.value:
            continue
        diffs.append(
            DiffRecord(
                target_id=target_id,
                from_observation_hash=from_hash,
                to_observation_hash=to_hash,
                detected_at=detected_at,
                diff_type=DiffType.NumericThresholdChange,
                severity="High",
                layer="L2-numeric",
                evidence={"context": current.context, "unit": current.unit, "from": previous.raw, "to": current.raw},
            )
        )
    return diffs
