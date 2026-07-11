"""L4 — dataset diffing (DESIGN §6.2): the largely-novel capability.

Detect the silent manipulations that are easy to slip past a reader — a dropped column,
a re-baselined series, a truncated record set — across the dataset formats agencies
actually publish. A `dataset`-kind target's bytes are sniffed by magic number and routed:

  * CSV / TSV / JSON      -> tabular diff (`SchemaChange` / `DistributionalShift`)
  * `.xlsx`               -> per-sheet tabular diff (M4b)
  * `.zip`                -> per-member diff, recursing into each changed member (M4b)
  * NetCDF / HDF5         -> `netcdf.netcdf_diff` via xarray (M4b)

Only numeric fields get a distributional check, which keeps it high-precision. The
scientific formats (NetCDF/HDF via xarray, xlsx via openpyxl) are an optional `science`
extra, imported lazily; if absent, parsing fails soft to a `MetadataChange`.
"""

from __future__ import annotations

import io
import math
import zipfile
from collections.abc import Callable
from typing import Any

import pandas as pd

from ..models import DiffRecord, DiffType, Severity

RecordFn = Callable[[DiffType, Severity, dict[str, Any]], DiffRecord]


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


def distribution_changed(before: dict[str, float], after: dict[str, float]) -> bool:
    # A re-baselining/scaling moves mean/min/max; truncation is caught separately by count.
    return any(
        not math.isclose(before[k], after[k], rel_tol=1e-9, abs_tol=1e-12) for k in ("mean", "min", "max")
    )


# --- format detection ---


def _is_xlsx(body: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            names = archive.namelist()
    except zipfile.BadZipFile:
        return False
    return "[Content_Types].xml" in names and any(n.startswith("xl/") for n in names)


def detect_format(body: bytes) -> str:
    # Match on the *full* magic signature, not a 2-3 byte prefix: a CSV whose first column
    # is literally named "PK…" or "CDF…" (common in DB exports / scientific tables) must
    # not be mistaken for a zip/NetCDF and then fail to parse.
    head = body[:8]
    if head[:3] == b"CDF" and head[3:4] in (b"\x01", b"\x02", b"\x05"):  # NetCDF classic
        return "netcdf"
    if head == b"\x89HDF\r\n\x1a\n":  # HDF5 signature (NetCDF-4 is HDF5-backed)
        return "hdf5"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):  # ZIP local/central/spanned
        return "xlsx" if _is_xlsx(body) else "zip"
    text = body.decode("utf-8", errors="replace").lstrip()
    if text[:1] in ("{", "["):
        return "json"
    return "csv"


# A dataset's serialization can change between publications (a JSON export becomes CSV);
# route by *handler family* so json<->csv still diffs as tabular, and only a genuinely
# incompatible switch (e.g. csv -> netcdf) reports a bare format change.
_HANDLER = {"netcdf": "xarray", "hdf5": "xarray", "xlsx": "xlsx", "zip": "zip", "json": "tabular", "csv": "tabular"}


# --- per-format diffs ---


def _tabular_diff(prev: pd.DataFrame, curr: pd.DataFrame, record: RecordFn, *, scope: str | None = None) -> list[DiffRecord]:
    def rec(diff_type: DiffType, severity: Severity, evidence: dict[str, Any]) -> DiffRecord:
        return record(diff_type, severity, {"scope": scope, **evidence} if scope else evidence)

    prev_cols = [str(c) for c in prev.columns]
    curr_cols = [str(c) for c in curr.columns]
    prev_set, curr_set = set(prev_cols), set(curr_cols)
    diffs: list[DiffRecord] = []

    for col in prev_cols:
        if col not in curr_set:
            diffs.append(rec(DiffType.SchemaChange, "High", {"change": "column_removed", "column": col}))
    for col in curr_cols:
        if col not in prev_set:
            diffs.append(rec(DiffType.SchemaChange, "Medium", {"change": "column_added", "column": col}))

    for col in prev_cols:
        if col not in curr_set:
            continue
        prev_dtype, curr_dtype = str(prev[col].dtype), str(curr[col].dtype)
        if prev_dtype != curr_dtype:
            diffs.append(
                rec(
                    DiffType.SchemaChange,
                    "Medium",
                    {"change": "column_retyped", "column": col, "from": prev_dtype, "to": curr_dtype},
                )
            )
        before, after = _numeric_stats(prev[col]), _numeric_stats(curr[col])
        if before and after and distribution_changed(before, after):
            diffs.append(rec(DiffType.DistributionalShift, "High", {"column": col, "from": before, "to": after}))

    if len(prev) != len(curr):
        diffs.append(rec(DiffType.DistributionalShift, "High", {"change": "row_count", "from": len(prev), "to": len(curr)}))

    return diffs


def _xlsx_diff(prev_body: bytes, curr_body: bytes, record: RecordFn) -> list[DiffRecord]:
    prev = pd.read_excel(io.BytesIO(prev_body), sheet_name=None)  # dict[sheet_name, DataFrame]
    curr = pd.read_excel(io.BytesIO(curr_body), sheet_name=None)
    diffs: list[DiffRecord] = []
    for sheet in sorted(set(prev) - set(curr)):
        diffs.append(record(DiffType.SchemaChange, "High", {"change": "sheet_removed", "sheet": sheet}))
    for sheet in sorted(set(curr) - set(prev)):
        diffs.append(record(DiffType.SchemaChange, "Medium", {"change": "sheet_added", "sheet": sheet}))
    for sheet in sorted(set(prev) & set(curr)):
        diffs += _tabular_diff(prev[sheet], curr[sheet], record, scope=f"sheet:{sheet}")
    return diffs


def _zip_members(body: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        return {name: archive.read(name) for name in archive.namelist() if not name.endswith("/")}


def _scoped(record: RecordFn, member: str) -> RecordFn:
    def scoped(diff_type: DiffType, severity: Severity, evidence: dict[str, Any]) -> DiffRecord:
        # Accumulate nested container paths (a.zip -> data.csv) instead of the inner
        # member silently overwriting the outer one via the ** merge.
        inner = evidence.get("member")
        path = f"{member}/{inner}" if inner else member
        return record(diff_type, severity, {**evidence, "member": path})

    return scoped


def _zip_diff(prev_body: bytes, curr_body: bytes, record: RecordFn) -> list[DiffRecord]:
    prev = _zip_members(prev_body)
    curr = _zip_members(curr_body)
    diffs: list[DiffRecord] = []
    for name in sorted(set(prev) - set(curr)):
        diffs.append(record(DiffType.SchemaChange, "High", {"change": "member_removed", "member": name}))
    for name in sorted(set(curr) - set(prev)):
        diffs.append(record(DiffType.SchemaChange, "Medium", {"change": "member_added", "member": name}))
    for name in sorted(set(prev) & set(curr)):
        if prev[name] != curr[name]:  # only diff changed members — no noise
            diffs += _route(prev[name], curr[name], _scoped(record, name))
    return diffs


def _route(prev_body: bytes, curr_body: bytes, record: RecordFn) -> list[DiffRecord]:
    prev_fmt, curr_fmt = detect_format(prev_body), detect_format(curr_body)
    handler = _HANDLER[prev_fmt]
    if handler != _HANDLER[curr_fmt]:
        return [record(DiffType.MetadataChange, "Medium", {"note": f"format changed: {prev_fmt} -> {curr_fmt}"})]
    try:
        if handler == "xarray":
            from .netcdf import netcdf_diff

            return netcdf_diff(prev_body, curr_body, record=record)
        if handler == "xlsx":
            return _xlsx_diff(prev_body, curr_body, record)
        if handler == "zip":
            return _zip_diff(prev_body, curr_body, record)
        return _tabular_diff(parse_table(prev_body), parse_table(curr_body), record)
    except Exception as error:  # malformed/unsupported payload — surface, don't crash
        return [record(DiffType.MetadataChange, "Medium", {"note": f"could not parse dataset: {error}"})]


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

    return _route(prev_body, curr_body, record)
