"""L4 dataset diffing (M4a): schema changes and distributional shifts over tabular data."""

from pathlib import Path

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.differ.dataset import dataset_diff, parse_table
from verderer.models import DiffType
from verderer.pipeline import Verderer

CSV = b"year,co2_ppm,site\n2020,412.5,A\n2021,414.2,B\n2022,416.0,C\n"
CSV_DROP_COL = b"year,site\n2020,A\n2021,B\n2022,C\n"  # co2_ppm removed
CSV_REBASED = b"year,co2_ppm,site\n2020,312.5,A\n2021,314.2,B\n2022,316.0,C\n"  # values -100
CSV_TRUNCATED = b"year,co2_ppm,site\n2020,412.5,A\n"  # rows dropped


def _diff(a: bytes, b: bytes) -> list:
    return dataset_diff(a, b, target_id="t", detected_at="2026-01-01T00:00:00Z", from_hash="a", to_hash="b")


def test_column_removed_is_schema_change_high() -> None:
    diffs = _diff(CSV, CSV_DROP_COL)
    removed = [d for d in diffs if d.evidence.get("change") == "column_removed"]
    assert removed and removed[0].diff_type is DiffType.SchemaChange
    assert removed[0].severity == "High"
    assert removed[0].evidence["column"] == "co2_ppm"


def test_rebaselined_series_is_distributional_shift() -> None:
    diffs = _diff(CSV, CSV_REBASED)
    shifts = [d for d in diffs if d.diff_type is DiffType.DistributionalShift and d.evidence.get("column") == "co2_ppm"]
    assert shifts and shifts[0].severity == "High"
    assert shifts[0].evidence["from"]["mean"] != shifts[0].evidence["to"]["mean"]


def test_truncation_flagged_by_row_count() -> None:
    diffs = _diff(CSV, CSV_TRUNCATED)
    assert any(d.diff_type is DiffType.DistributionalShift and d.evidence.get("change") == "row_count" for d in diffs)


def test_identical_dataset_yields_no_diffs() -> None:
    assert _diff(CSV, CSV) == []


def test_json_records_parse() -> None:
    df = parse_table(b'[{"a":1,"b":"x"},{"a":2,"b":"y"}]')
    assert list(df.columns) == ["a", "b"]
    assert len(df) == 2


def test_pipeline_routes_dataset_targets_to_l4(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    pages = [CSV, CSV_DROP_COL]

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={"content-type": "text/csv"}, body=pages[min(cursor["i"], 1)])

    verderer = Verderer(
        tmp_path / "data",
        targets={"ds": Target(id="ds", title="DS", url="https://example.gov/d.csv", kind="dataset")},
        terms=[],
        collector=StaticCollector(fetcher=fake),
    )
    verderer.observe("ds")
    cursor["i"] = 1
    result = verderer.observe("ds")
    assert any(d.diff_type is DiffType.SchemaChange for d in result.diffs)
