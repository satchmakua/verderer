"""L2 — numeric / threshold extraction (DESIGN §6.2).

Extract numbers-with-units that sit in a *regulatory context* (a limit, standard,
threshold, reporting cutoff) and flag when the value tied to the same context changes —
a limit moving 10 -> 15 ppb, a cutoff shifting. High value and easy to slip past a
reader. High-precision by construction: a number counts only when a regulatory keyword
sits just before it AND the unit is a plausible measurement unit, so prose numbers
(years, page counts, list indices) are ignored.

M12 refinement: cross-unit normalisation via `pint`. A quantity is keyed on its regulatory
*context* alone (not context + unit), and two quantities under the same context are compared
by their magnitude in base units — so `10 ppb` and `0.010 ppm` are recognised as the *same*
value (no false `NumericThresholdChange`), while a real move across units (`10 ppb -> 0.020
ppm`) is caught. `pint` doesn't ship the parts-per units, so ppb/ppm/ppt are defined as the
dimensionless ratios they are. Anything `pint` can't parse falls back to a strict same-unit
comparison (never a cross-unit false positive).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

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


_UREG: Any = None


def _registry() -> Any:
    """A lazily-built pint registry with the parts-per units pint doesn't ship (they are
    dimensionless ratios). Built once; pint is a core dep but imported lazily so the module
    loads (and the same-unit fallback works) even if it is somehow absent."""
    global _UREG
    if _UREG is None:
        import pint

        ureg: Any = pint.UnitRegistry()
        ureg.define("ppm = 1e-6 = parts_per_million")
        ureg.define("ppb = 1e-9 = parts_per_billion")
        ureg.define("ppt = 1e-12 = parts_per_trillion")
        ureg.define("ppmv = 1e-6")
        ureg.define("ppbv = 1e-9")
        ureg.define("pptv = 1e-12")
        _UREG = ureg
    return _UREG


def _base(value: float, unit: str) -> tuple[float, Any] | None:
    """``(magnitude in base units, dimensionality)`` for ``value unit``, or ``None`` if pint
    can't parse the unit — in which case the caller falls back to a same-unit comparison."""
    try:
        quantity = _registry().Quantity(value, unit).to_base_units()
        return float(quantity.magnitude), quantity.dimensionality
    except Exception:
        return None


def _dim_key(value: float, unit: str) -> str:
    """The keying token for a quantity's *dimension*: pint's dimensionality when parseable,
    else the raw unit. Keying a context's quantity on (context, dimension) means two quantities
    are only ever compared *within one physical dimension* — so 10 ppb vs 0.010 ppm (both
    dimensionless) compare and cross-unit-normalise, while 10 ppb vs 5 mg/L (a different
    dimension under the same lead-in phrase) stay distinct and are both tracked, and a unit
    pint *misparses* to a surprise dimension (e.g. `pct` -> [mass]) can never cross-fire against
    its correct-dimension sibling (`percent` -> dimensionless)."""
    base = _base(value, unit)
    return str(base[1]) if base is not None else unit.lower()


def _values_differ(previous: Quantity, current: Quantity) -> bool:
    """Whether two same-(context, dimension) quantities represent a *real* change. By keying,
    they share a dimensionality, so cross-unit-equal (10 ppb == 0.010 ppm) is not a change and a
    cross-unit move is; when pint can't parse the unit they also share the raw unit, so a strict
    value comparison is correct."""
    prev_base = _base(previous.value, previous.unit)
    curr_base = _base(current.value, current.unit)
    if prev_base is not None and curr_base is not None:
        return not math.isclose(prev_base[0], curr_base[0], rel_tol=1e-9, abs_tol=0.0)
    return not math.isclose(previous.value, current.value, rel_tol=1e-9, abs_tol=0.0)


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
        # Key on the regulatory context AND the quantity's physical dimension — so the same
        # threshold is compared across units within a dimension (10 ppb vs 0.010 ppm), while
        # two different-dimension thresholds sharing a lead-in phrase don't collide (and last-
        # win drop one), and a pint unit-misparse can't cross-fire against its correct sibling.
        key = f"{context.lower().strip()} | {_dim_key(value, unit)}"
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
        if previous is None or not _values_differ(previous, current):
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
