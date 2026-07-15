"""M4b — scientific/geospatial + packed dataset diffing.

Zip unpacking uses only stdlib and always runs; NetCDF/HDF (xarray) and xlsx (openpyxl)
are gated on the optional `science` extra. Format detection routes a `dataset`-kind
target's bytes by magic number.
"""

import io
import zipfile

import pytest

from annals.differ.dataset import dataset_diff, detect_format
from annals.models import DiffType


def _diff(a: bytes, b: bytes) -> list:
    return dataset_diff(a, b, target_id="t", detected_at="2026-01-01T00:00:00Z", from_hash="a", to_hash="b")


# --- format detection ---


def test_detect_format_by_magic() -> None:
    assert detect_format(b"CDF\x02\x00\x00") == "netcdf"
    assert detect_format(b"\x89HDF\r\n\x1a\n....") == "hdf5"
    assert detect_format(b"year,co2\n2020,412\n") == "csv"
    assert detect_format(b'[{"a":1}]') == "json"


def test_magic_prefix_does_not_collide_with_text_columns() -> None:
    # A CSV whose first column is named "PK…" or "CDF…" must not be mistaken for zip/NetCDF
    # (the magic check requires the full signature, not a 2-3 byte prefix).
    assert detect_format(b"PK_id,co2_ppm\n1,412.5\n") == "csv"
    assert detect_format(b"CDF,value\n1,2\n") == "csv"
    # ...and the real distributional shift still surfaces, not a "could not parse" note.
    diffs = _diff(b"PK_id,co2_ppm\n1,412.5\n2,414.0\n", b"PK_id,co2_ppm\n1,312.5\n2,314.0\n")
    assert any(d.diff_type is DiffType.DistributionalShift and d.evidence.get("column") == "co2_ppm" for d in diffs)


def test_serialization_switch_still_diffs_as_tabular() -> None:
    # JSON -> CSV is a serialization change, not an incompatible format: a dropped column
    # must still be flagged (both handled by the tabular differ), not masked as a note.
    prev = b'[{"year":2020,"co2":412.5},{"year":2021,"co2":414.2}]'
    curr = b"year\n2020\n2021\n"  # co2 column dropped
    diffs = _diff(prev, curr)
    removed = [d for d in diffs if d.evidence.get("change") == "column_removed"]
    assert removed and removed[0].evidence["column"] == "co2" and removed[0].severity == "High"


# --- zip (stdlib, always runs) ---


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, body in members.items():
            archive.writestr(name, body)
    return buf.getvalue()


CSV = b"year,co2_ppm\n2020,412.5\n2021,414.2\n2022,416.0\n"
CSV_REBASED = b"year,co2_ppm\n2020,312.5\n2021,314.2\n2022,316.0\n"


def test_zip_member_removed_is_schema_change() -> None:
    before = _zip({"a.csv": CSV, "b.csv": CSV})
    after = _zip({"a.csv": CSV})
    diffs = _diff(before, after)
    removed = [d for d in diffs if d.evidence.get("change") == "member_removed"]
    assert removed and removed[0].diff_type is DiffType.SchemaChange and removed[0].severity == "High"
    assert removed[0].evidence["member"] == "b.csv"


def test_zip_recurses_into_changed_member() -> None:
    before = _zip({"data.csv": CSV})
    after = _zip({"data.csv": CSV_REBASED})
    diffs = _diff(before, after)
    shifts = [d for d in diffs if d.diff_type is DiffType.DistributionalShift and d.evidence.get("column") == "co2_ppm"]
    assert shifts and shifts[0].evidence["member"] == "data.csv"  # member scope is tagged


def test_zip_unchanged_member_is_quiet() -> None:
    assert _diff(_zip({"a.csv": CSV}), _zip({"a.csv": CSV})) == []


def test_nested_zip_member_path_is_preserved() -> None:
    # A zip of zips: the outer container name must not be lost when the inner member
    # tags its own evidence (the scope accumulates as a path).
    before = _zip({"a.zip": _zip({"data.csv": CSV})})
    after = _zip({"a.zip": _zip({"data.csv": CSV_REBASED})})
    diffs = _diff(before, after)
    shifts = [d for d in diffs if d.diff_type is DiffType.DistributionalShift and "member" in d.evidence]
    assert shifts and shifts[0].evidence["member"] == "a.zip/data.csv"


def test_format_change_is_flagged() -> None:
    diffs = _diff(CSV, _zip({"a.csv": CSV}))
    assert any(d.diff_type is DiffType.MetadataChange and "format changed" in d.evidence.get("note", "") for d in diffs)


# --- NetCDF / HDF (gated on xarray) ---


@pytest.fixture
def xarray_available():
    return pytest.importorskip("xarray")


def _netcdf(data_vars: dict, attrs: dict | None = None, engine: str = "scipy") -> bytes:
    import numpy as np
    import xarray as xr

    ds = xr.Dataset(
        {k: ("time", np.array(v, dtype=float)) for k, v in data_vars.items()},
        coords={"time": [2020, 2021, 2022]},
        attrs=attrs or {},
    )
    if engine == "scipy":
        return bytes(ds.to_netcdf(engine="scipy"))
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".nc", delete=False) as handle:
        path = handle.name
    ds.to_netcdf(path, engine=engine)
    with open(path, "rb") as fh:
        body = fh.read()
    import os

    os.unlink(path)
    return body


def test_netcdf_dropped_variable_is_schema_change(xarray_available) -> None:
    before = _netcdf({"co2": [412.5, 414.2, 416.0], "ch4": [1.90, 1.91, 1.92]})
    after = _netcdf({"co2": [412.5, 414.2, 416.0]})  # ch4 dropped
    diffs = _diff(before, after)
    removed = [d for d in diffs if d.evidence.get("change") == "variable_removed"]
    assert removed and removed[0].diff_type is DiffType.SchemaChange and removed[0].severity == "High"
    assert removed[0].evidence["variable"] == "ch4"


def test_netcdf_summary_stat_shift_is_distributional(xarray_available) -> None:
    before = _netcdf({"co2": [412.5, 414.2, 416.0]})
    after = _netcdf({"co2": [312.5, 314.2, 316.0]})  # re-baselined -100
    diffs = _diff(before, after)
    shifts = [d for d in diffs if d.diff_type is DiffType.DistributionalShift and d.evidence.get("variable") == "co2"]
    assert shifts and shifts[0].severity == "High"
    assert shifts[0].evidence["from"]["mean"] != shifts[0].evidence["to"]["mean"]


def test_netcdf_attribute_change_is_metadata(xarray_available) -> None:
    before = _netcdf({"co2": [412.5, 414.2, 416.0]}, attrs={"title": "CO2 record", "units": "ppm"})
    after = _netcdf({"co2": [412.5, 414.2, 416.0]}, attrs={"title": "CO2 record", "units": "ppb"})
    diffs = _diff(before, after)
    meta = [d for d in diffs if d.diff_type is DiffType.MetadataChange and d.evidence.get("scope") == "global_attrs"]
    assert meta and "units" in meta[0].evidence["changed"]


def test_netcdf_identical_is_quiet(xarray_available) -> None:
    body = _netcdf({"co2": [412.5, 414.2, 416.0]})
    assert _diff(body, body) == []


def test_netcdf_all_nan_wipe_is_flagged(xarray_available) -> None:
    # A variable whose real data is silently replaced with all-NaN (same shape, still
    # present) is exactly the manipulation this differ must catch.
    import numpy as np

    before = _netcdf({"co2": [412.5, 414.2, 416.0]})
    after = _netcdf({"co2": [np.nan, np.nan, np.nan]})
    diffs = _diff(before, after)
    wipe = [d for d in diffs if d.evidence.get("change") == "finite_data_presence"]
    assert wipe and wipe[0].diff_type is DiffType.DistributionalShift and wipe[0].severity == "High"
    assert wipe[0].evidence["variable"] == "co2"


def test_netcdf_nan_attribute_is_not_spuriously_changed(xarray_available) -> None:
    # An identical NaN-valued attribute must not read as changed (nan != nan), and must
    # not put a bare NaN token in the leaf. The differ + canonical() both guard this.
    import numpy as np

    body_a = _netcdf({"co2": [412.5, 414.2, 416.0]}, attrs={"valid_min": float(np.nan)})
    body_b = _netcdf({"co2": [412.5, 414.2, 416.0]}, attrs={"valid_min": float(np.nan)})
    meta = [d for d in _diff(body_a, body_b) if d.diff_type is DiffType.MetadataChange]
    assert meta == []


def test_netcdf_corrupt_curr_fails_soft(xarray_available) -> None:
    # A valid prev + a corrupt (but CDF-magic) curr must not crash — it fails soft to a
    # MetadataChange, and the prev handle is released (ExitStack) even though curr raised.
    valid = _netcdf({"co2": [412.5, 414.2, 416.0]})
    corrupt = b"CDF\x02" + b"\x00garbage-not-a-real-netcdf"
    diffs = _diff(valid, corrupt)
    assert diffs and diffs[0].diff_type is DiffType.MetadataChange
    assert "could not parse" in diffs[0].evidence.get("note", "")


def test_canonical_rejects_non_finite() -> None:
    import pytest as _pytest

    from annals.ledger.core import canonical

    with _pytest.raises(ValueError):
        canonical({"x": float("nan")})


def test_scalar_coerces_to_json_safe_types() -> None:
    # Attribute values must land in a leaf as plain JSON types — never a complex, a
    # datetime, or a non-finite float (which would crash or corrupt canonical()).
    import datetime
    import json

    from annals.differ.netcdf import _scalar

    assert _scalar("ppm") == "ppm"
    assert _scalar(42) == 42
    assert _scalar(3.5) == 3.5
    assert _scalar(float("inf")) == "inf"
    assert _scalar(complex(1, 2)) == "(1+2j)"
    assert _scalar(datetime.date(2026, 1, 1)) == "2026-01-01"
    # every result round-trips through strict JSON (allow_nan=False)
    for value in (float("nan"), complex(1, 2), datetime.date(2026, 1, 1), 42, "x"):
        json.dumps(_scalar(value), allow_nan=False)


def test_netcdf4_hdf5_backend(xarray_available) -> None:
    pytest.importorskip("h5netcdf")
    pytest.importorskip("h5py")
    before = _netcdf({"co2": [412.5, 414.2, 416.0], "ch4": [1.9, 1.91, 1.92]}, engine="h5netcdf")
    after = _netcdf({"co2": [412.5, 414.2, 416.0]}, engine="h5netcdf")
    assert detect_format(before) == "hdf5"
    diffs = _diff(before, after)
    assert any(d.evidence.get("change") == "variable_removed" for d in diffs)


# --- xlsx (gated on openpyxl) ---


def test_xlsx_sheet_and_column_diff() -> None:
    pytest.importorskip("openpyxl")
    import pandas as pd

    def xlsx(sheets: dict) -> bytes:
        buf = io.BytesIO()
        with pd.ExcelWriter(buf) as writer:
            for name, df in sheets.items():
                df.to_excel(writer, sheet_name=name, index=False)
        return buf.getvalue()

    before = xlsx({"emissions": pd.DataFrame({"year": [2020, 2021], "co2": [412.5, 414.2]})})
    after = xlsx({"emissions": pd.DataFrame({"year": [2020, 2021]})})  # co2 column dropped
    assert detect_format(before) == "xlsx"
    diffs = _diff(before, after)
    dropped = [d for d in diffs if d.evidence.get("change") == "column_removed"]
    assert dropped and dropped[0].evidence.get("scope") == "sheet:emissions"
