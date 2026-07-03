"""L4 — dataset diffing (DESIGN §6.2): the largely-novel capability.

For tabular data (CSV/TSV/JSON), detect the silent manipulations that are easy to slip
past a reader:

  * `SchemaChange`        — a column added / removed / retyped
  * `DistributionalShift` — a column's values re-baselined/scaled, or the series truncated

M4a covers tabular CSV/JSON. NetCDF/HDF via `xarray` (metadata + variable-presence diff)
is M4b. Only numeric columns get a distributional check, which keeps it high-precision.
"""

from __future__ import annotations

import io
import math
from typing import Any

import pandas as pd

from ..models import DiffRecord, DiffType, Severity


def parse_table(body: bytes) -> pd.DataFrame:
    text = body.decode("utf-8", errors="replace").lstrip()
    if not text:
        return pd.DataFrame()
    if text[:1] in ("{", "["):
        return pd.read_json(io.StringIO(text))
    sep = "\t" if "\t" in text.splitlines()[0] else ","
    return pd.read_csv(io.StringIO(text), sep=sep)


def _numeric_stats(series: pd.Series) -> dict[str, float]:
    numeric = pd.to_numeric(series, errors="coerce").dropna()
    if numeric.empty:
        return {}
    return {
        "count": float(numeric.count()),
        "mean": float(numeric.mean()),
        "min": float(numeric.min()),
        "max": float(numeric.max()),
    }


def _distribution_changed(before: dict[str, float], after: dict[str, float]) -> bool:
    # A re-baselining/scaling moves mean/min/max; truncation is caught separately by row count.
    return any(
        not math.isclose(before[k], after[k], rel_tol=1e-9, abs_tol=1e-12) for k in ("mean", "min", "max")
    )


def dataset_diff(
    prev_body: bytes,
    curr_body: bytes,
    *,
    target_id: str,
    detected_at: str,
    from_hash: str | None,
    to_hash: str,
) -> list[DiffRecord]:
    def record(diff_type: DiffType, severity: Severity, evidence: dict[str, Any]) -> DiffRecord:
        return DiffRecord(
            target_id=target_id,
            from_observation_hash=from_hash,
            to_observation_hash=to_hash,
            detected_at=detected_at,
            diff_type=diff_type,
            severity=severity,
            layer="L4-dataset",
            evidence=evidence,
        )

    try:
        prev = parse_table(prev_body)
        curr = parse_table(curr_body)
    except Exception as error:  # malformed/unsupported payload — surface, don't crash
        return [record(DiffType.MetadataChange, "Medium", {"note": f"could not parse dataset: {error}"})]

    prev_cols = [str(c) for c in prev.columns]
    curr_cols = [str(c) for c in curr.columns]
    prev_set, curr_set = set(prev_cols), set(curr_cols)
    diffs: list[DiffRecord] = []

    for col in prev_cols:
        if col not in curr_set:
            diffs.append(record(DiffType.SchemaChange, "High", {"change": "column_removed", "column": col}))
    for col in curr_cols:
        if col not in prev_set:
            diffs.append(record(DiffType.SchemaChange, "Medium", {"change": "column_added", "column": col}))

    for col in prev_cols:
        if col not in curr_set:
            continue
        prev_dtype, curr_dtype = str(prev[col].dtype), str(curr[col].dtype)
        if prev_dtype != curr_dtype:
            diffs.append(
                record(
                    DiffType.SchemaChange,
                    "Medium",
                    {"change": "column_retyped", "column": col, "from": prev_dtype, "to": curr_dtype},
                )
            )
        before, after = _numeric_stats(prev[col]), _numeric_stats(curr[col])
        if before and after and _distribution_changed(before, after):
            diffs.append(record(DiffType.DistributionalShift, "High", {"column": col, "from": before, "to": after}))

    if len(prev) != len(curr):
        diffs.append(
            record(DiffType.DistributionalShift, "High", {"change": "row_count", "from": len(prev), "to": len(curr)})
        )

    return diffs
