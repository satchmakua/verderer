"""L2 for tables: a limit in a table cell is named by its row and column header, not by a
keyword beside the number, so the flat-text numeric watch cannot see it as regulatory."""

from hypothesis import given, settings
from hypothesis import strategies as st

from verderer.differ.numeric import quantities_in
from verderer.differ.structure import table_numeric_watch
from verderer.models import DiffType


def _page(rows: list[tuple[str, str, str]]) -> bytes:
    body = "".join(f"<tr><td>{a}</td><td>{b}</td><td>{c}</td></tr>" for a, b, c in rows)
    head = "<tr><th>Compound</th><th>Final MCLG</th><th>Final MCL (enforceable levels)</th></tr>"
    return f"<html><body><main><table>{head}{body}</table></main></body></html>".encode()


BEFORE = [
    ("PFOA", "Zero", "4.0 parts per trillion (ppt)"),
    ("PFHxS", "10 ppt", "10 ppt"),
    ("PFNA", "10 ppt", "10 ppt"),
]


def _watch(before: bytes, after: bytes, **kwargs: object) -> list:
    return table_numeric_watch(before, after, target_id="t", detected_at="now", from_hash="a", to_hash="b", **kwargs)  # type: ignore[arg-type]


def test_a_limit_moved_in_a_table_cell_is_a_threshold_change() -> None:
    after = [BEFORE[0], ("PFHxS", "10 ppt", "20 ppt"), BEFORE[2]]
    (diff,) = _watch(_page(BEFORE), _page(after))
    assert diff.diff_type == DiffType.NumericThresholdChange and diff.severity == "High" and diff.layer == "L2-table"
    assert diff.evidence == {
        "context": "PFHxS - Final MCL (enforceable levels)",
        "unit": "ppt",
        "from": "10 ppt",
        "to": "20 ppt",
        "block": "table[0].row[2].col[2]",
    }


def test_spelled_out_units_and_cross_unit_equality() -> None:
    assert [q.raw for q in quantities_in("4.0 parts per trillion (ppt) (also expressed as ng/L)")] == ["4.0 ppt"]
    # The same limit restated in another unit is not a change; a real cross-unit move is.
    same = [("PFOA", "Zero", "0.004 ppb"), *BEFORE[1:]]
    assert _watch(_page(BEFORE), _page(same)) == []
    moved = [("PFOA", "Zero", "0.010 ppb"), *BEFORE[1:]]
    (diff,) = _watch(_page(BEFORE), _page(moved))
    assert diff.evidence["from"] == "4.0 ppt" and diff.evidence["to"] == "0.010 ppb"


def test_a_shifted_or_relabelled_row_is_not_compared() -> None:
    # A row inserted above shifts every later row: positions no longer name the same limit.
    inserted = [("PFOS", "Zero", "4.0 ppt"), *BEFORE]
    assert _watch(_page(BEFORE), _page(inserted)) == []
    # Same shape, but the row now names a different compound: not the same limit either.
    relabelled = [BEFORE[0], ("GenX", "10 ppt", "20 ppt"), BEFORE[2]]
    assert _watch(_page(BEFORE), _page(relabelled)) == []


def test_text_edits_and_already_reported_moves_are_left_alone() -> None:
    reworded = [("PFOA", "None", "4.0 parts per trillion (ppt)"), *BEFORE[1:]]
    assert _watch(_page(BEFORE), _page(reworded)) == []  # no quantity moved: the structure diff's job
    after = [BEFORE[0], ("PFHxS", "10 ppt", "20 ppt"), BEFORE[2]]
    assert _watch(_page(BEFORE), _page(after), already=frozenset({("10 ppt", "20 ppt")})) == []


@settings(max_examples=60, deadline=None)
@given(st.binary(max_size=400), st.binary(max_size=400))
def test_total_on_arbitrary_bytes(before: bytes, after: bytes) -> None:
    for diff in _watch(b"<table>" + before, b"<table>" + after):
        assert diff.diff_type == DiffType.NumericThresholdChange


def test_a_table_without_a_header_row_is_compared_from_its_first_row() -> None:
    def bare(first: str) -> bytes:
        return f"<table><tr><td>Benzene</td><td>{first}</td></tr><tr><td>Lead</td><td>15 ppb</td></tr></table>".encode()

    (diff,) = _watch(bare("10 ppb"), bare("5 ppb"))
    assert diff.evidence["context"] == "Benzene" and diff.evidence["block"] == "table[0].row[0].col[1]"
