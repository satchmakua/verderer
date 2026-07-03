from druid.differ.numeric import extract, numeric_watch
from druid.models import DiffType


def test_extracts_regulatory_quantity_only_near_a_keyword() -> None:
    q = extract("The reporting threshold is 10 ppb this year.")
    assert any(v.raw == "10 ppb" and v.value == 10.0 for v in q.values())
    # A bare number with no regulatory keyword nearby is ignored (no false positive).
    assert extract("The report has 10 pages and 3 tables.") == {}


def test_flags_threshold_change_high() -> None:
    diffs = numeric_watch(
        "The reporting threshold is 10 ppb.",
        "The reporting threshold is 15 ppb.",
        target_id="t",
        detected_at="2026-01-01T00:00:00Z",
        from_hash="a",
        to_hash="b",
    )
    assert len(diffs) == 1
    d = diffs[0]
    assert d.diff_type is DiffType.NumericThresholdChange
    assert d.severity == "High"
    assert d.evidence["from"] == "10 ppb"
    assert d.evidence["to"] == "15 ppb"


def test_no_flag_when_value_unchanged() -> None:
    diffs = numeric_watch(
        "The limit is 5 mg/L.",
        "The limit is 5 mg/L (unchanged).",
        target_id="t",
        detected_at="2026-01-01T00:00:00Z",
        from_hash="a",
        to_hash="b",
    )
    assert diffs == []


def test_ignores_prose_numbers() -> None:
    # Years, counts, and list indices must not be read as regulatory thresholds.
    diffs = numeric_watch(
        "Established in 1990, it lists 12 items across 3 sections.",
        "Established in 2025, it lists 14 items across 4 sections.",
        target_id="t",
        detected_at="2026-01-01T00:00:00Z",
        from_hash="a",
        to_hash="b",
    )
    assert diffs == []
