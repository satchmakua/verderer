"""L4 (scientific) — NetCDF/HDF dataset diffing via xarray (DESIGN §6.2, M4b).

Scientific/geospatial datasets (NOAA/EPA NetCDF, HDF5) hide the same silent
manipulations as tabular data, one layer down: a dropped variable, a re-baselined field,
a quietly edited unit or fill value. This differ opens both versions with xarray and
flags:

  * `SchemaChange`        — a variable added / removed
  * `DistributionalShift` — a variable's summary stats (mean/min/max) moved, or a
                            dimension resized (re-baselining / scaling / truncation)
  * `MetadataChange`      — global or per-variable attributes added/removed/changed
                            (units, fill values, provenance)

`xarray` (+ a NetCDF backend) is an optional `science` extra, imported lazily; a
`dataset`-kind target whose bytes are NetCDF/HDF route here from `dataset._route`.
"""

from __future__ import annotations

import contextlib
import io
import math
from collections.abc import Callable, Mapping
from typing import Any

from ..models import DiffRecord, DiffType, Severity
from .dataset import distribution_changed

RecordFn = Callable[[DiffType, Severity, dict[str, Any]], DiffRecord]


def _scalar(value: object) -> Any:
    """Coerce an attribute value to something JSON-serialisable and stable to compare.

    Everything eventually lands in a ledger leaf via canonical JSON, so the result must be
    a plain str/int/float/bool/None — and never a non-finite float, whose `NaN`/`Infinity`
    JSON tokens are non-standard (and would make identical NaN attrs compare unequal)."""
    item = getattr(value, "item", None)
    if callable(item):
        try:
            value = item()  # numpy scalar -> Python scalar (do NOT return yet: keep it JSON-safe)
        except (ValueError, TypeError):
            pass
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else str(value)  # "nan"/"inf"/"-inf": JSON-safe + self-equal
    if isinstance(value, int):
        return value
    return str(value)  # complex / datetime64 / timedelta64 / arrays -> a stable string form


def _var_stats(data_array: object) -> dict[str, float] | None:
    """Summary stats for a numeric variable. `None` = not a numeric variable (skip); an
    empty dict = numeric but no finite data (all NaN/fill — a silent wipe to flag)."""
    import numpy as np

    dtype = getattr(data_array, "dtype", None)
    if dtype is None or not np.issubdtype(dtype, np.number):
        return None
    values = np.asarray(data_array.values)  # type: ignore[attr-defined]
    finite = values[np.isfinite(values)]
    if finite.size == 0:
        return {}
    return {
        "count": float(finite.size),
        "mean": float(finite.mean()),
        "min": float(finite.min()),
        "max": float(finite.max()),
    }


def _attr_changes(prev_attrs: Mapping[str, object], curr_attrs: Mapping[str, object]) -> dict[str, Any]:
    prev_a = {str(k): _scalar(v) for k, v in prev_attrs.items()}
    curr_a = {str(k): _scalar(v) for k, v in curr_attrs.items()}
    removed = sorted(set(prev_a) - set(curr_a))
    added = sorted(set(curr_a) - set(prev_a))
    changed = {
        k: {"from": prev_a[k], "to": curr_a[k]} for k in sorted(set(prev_a) & set(curr_a)) if prev_a[k] != curr_a[k]
    }
    out: dict[str, Any] = {}
    if removed:
        out["removed"] = removed
    if added:
        out["added"] = added
    if changed:
        out["changed"] = changed
    return out


def netcdf_diff(prev_body: bytes, curr_body: bytes, *, record: RecordFn) -> list[DiffRecord]:
    import xarray as xr  # lazy: optional `science` extra

    # ExitStack closes prev even if opening curr raises (no leaked backend file handle).
    with contextlib.ExitStack() as stack:
        prev = stack.enter_context(xr.open_dataset(io.BytesIO(prev_body)))
        curr = stack.enter_context(xr.open_dataset(io.BytesIO(curr_body)))
        diffs: list[DiffRecord] = []

        prev_vars = {str(v) for v in prev.variables}
        curr_vars = {str(v) for v in curr.variables}
        for name in sorted(prev_vars - curr_vars):
            diffs.append(record(DiffType.SchemaChange, "High", {"change": "variable_removed", "variable": name}))
        for name in sorted(curr_vars - prev_vars):
            diffs.append(record(DiffType.SchemaChange, "Medium", {"change": "variable_added", "variable": name}))

        prev_dims = {str(k): int(v) for k, v in prev.sizes.items()}
        curr_dims = {str(k): int(v) for k, v in curr.sizes.items()}
        for dim in sorted(set(prev_dims) & set(curr_dims)):
            if prev_dims[dim] != curr_dims[dim]:
                diffs.append(
                    record(
                        DiffType.DistributionalShift,
                        "High",
                        {"change": "dimension_size", "dimension": dim, "from": prev_dims[dim], "to": curr_dims[dim]},
                    )
                )

        global_attrs = _attr_changes(prev.attrs, curr.attrs)
        if global_attrs:
            diffs.append(record(DiffType.MetadataChange, "Medium", {"scope": "global_attrs", **global_attrs}))

        for name in sorted(prev_vars & curr_vars):
            before, after = _var_stats(prev[name]), _var_stats(curr[name])
            if before is not None and after is not None:  # both numeric variables
                if before and after:
                    if distribution_changed(before, after):
                        diffs.append(
                            record(DiffType.DistributionalShift, "High", {"variable": name, "from": before, "to": after})
                        )
                elif before != after:  # one side has finite data, the other is all-NaN/fill: a silent wipe
                    diffs.append(
                        record(
                            DiffType.DistributionalShift,
                            "High",
                            {"variable": name, "change": "finite_data_presence", "from": before or None, "to": after or None},
                        )
                    )
            var_attrs = _attr_changes(prev[name].attrs, curr[name].attrs)
            if var_attrs:
                diffs.append(record(DiffType.MetadataChange, "Medium", {"scope": f"var:{name}", **var_attrs}))

        return diffs
