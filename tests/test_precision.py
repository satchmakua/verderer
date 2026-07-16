"""M12 — detection precision. Four refinements that cut misses + false positives:
(a) L2 pint cross-unit normalization, (b) structure-aware table diffing, (c) rendered-DOM
noise suppression, (d) the L4 index-column false positive on truncation. Ledger-backed cases
skip if the Rust kernel isn't built.
"""

from __future__ import annotations

from pathlib import Path

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.differ.dataset import _is_index_like, dataset_diff
from verderer.differ.normalize import normalize_for_diff, suppress_noise
from verderer.differ.numeric import numeric_watch
from verderer.differ.structure import structure_watch
from verderer.models import DiffType
from verderer.pipeline import Verderer

_KW = {"target_id": "t", "detected_at": "2026-01-01T00:00:00Z", "from_hash": "a", "to_hash": "b"}


# --- (a) L2 cross-unit normalization ---------------------------------------------------


def _num(prev: str, curr: str) -> list:
    return numeric_watch(prev, curr, **_KW)


def test_cross_unit_equal_is_not_a_change() -> None:
    # 10 ppb == 0.010 ppm — a re-expression, not a threshold move.
    assert _num("The reporting threshold is 10 ppb.", "The reporting threshold is 0.010 ppm.") == []


def test_cross_unit_move_is_flagged() -> None:
    # 10 ppb -> 0.020 ppm (= 20 ppb) is a real doubling across units.
    diffs = _num("The reporting threshold is 10 ppb.", "The reporting threshold is 0.020 ppm.")
    assert len(diffs) == 1 and diffs[0].diff_type is DiffType.NumericThresholdChange
    assert diffs[0].evidence["from"] == "10 ppb" and diffs[0].evidence["to"] == "0.020 ppm"


def test_same_unit_change_still_flagged() -> None:
    assert len(_num("the limit is 10 ppb.", "the limit is 15 ppb.")) == 1


def test_non_pint_unit_falls_back_to_same_unit() -> None:
    # A unit pint can't parse (cfu) still catches a same-unit change...
    assert len(_num("the limit is 100 cfu.", "the limit is 200 cfu.")) == 1
    # ...but two different unparseable units are not cross-compared (no false positive).
    assert _num("the limit is 100 cfu.", "the limit is 100 ntu.") == []


def test_percent_abbreviation_reformat_is_not_a_change() -> None:
    # Review regression: pint misparses "pct" to a [mass] dimensionality, so a benign
    # percent-abbreviation reformat (same value) must not fire a High false alarm — keying
    # on (context, dimension) keeps the misparse from cross-firing against "percent".
    assert _num("the allowable level is 50 percent.", "the allowable level is 50 pct.") == []
    assert len(_num("the allowable level is 50 percent.", "the allowable level is 60 percent.")) == 1


def test_shared_context_different_dimensions_do_not_collide() -> None:
    # Review regression: two different-dimension thresholds under one lead-in phrase must both
    # be tracked (not last-win dropped) — a move in one is still caught.
    diffs = _num("the limit is 10 ppb and the limit is 5 mg/L.", "the limit is 15 ppb and the limit is 5 mg/L.")
    assert len(diffs) == 1 and diffs[0].evidence["from"] == "10 ppb" and diffs[0].evidence["to"] == "15 ppb"


# --- (b) structure-aware diffing -------------------------------------------------------

_TABLE = "<html><body><table><tr><td>Benzene</td><td>10 ppb</td></tr><tr><td>Lead</td><td>{lead}</td></tr></table></body></html>"
TABLE_V1 = _TABLE.format(lead="15 ppb").encode()
TABLE_V2 = _TABLE.format(lead="99 ppb").encode()


def test_structure_localizes_a_single_table_cell() -> None:
    diffs = structure_watch(TABLE_V1, TABLE_V2, **_KW)
    assert len(diffs) == 1
    d = diffs[0]
    assert d.layer == "L0-structure"
    assert d.evidence["block"] == "table[0].row[1].col[1]"  # names the exact cell
    assert d.evidence["from"] == "15 ppb" and d.evidence["to"] == "99 ppb"


def test_structure_ignores_page_chrome() -> None:
    # Review regression: a rotating nav/footer block must not be localized as a ContentEdit —
    # structure_watch strips the same chrome L0 does. Only the real <table> cell edit remains.
    prev = b"<html><body><nav><ul><li>Home v1</li></ul></nav><table><tr><td>x</td><td>1</td></tr></table></body></html>"
    curr = b"<html><body><nav><ul><li>Home v2</li></ul></nav><table><tr><td>x</td><td>9</td></tr></table></body></html>"
    diffs = structure_watch(prev, curr, **_KW)
    blocks = {d.evidence["block"] for d in diffs}
    assert blocks == {"table[0].row[0].col[1]"}  # the nav <li> change is not reported


def test_structure_declines_a_broad_change() -> None:
    # A wholesale rewrite (every list item changes) re-indexes everything — not a localised
    # edit, so structure_watch declines and lets the coarse floor summarise.
    prev = b"<html><body><ul>" + b"".join(f"<li>item {i}</li>".encode() for i in range(25)) + b"</ul></body></html>"
    curr = b"<html><body><ul>" + b"".join(f"<li>changed {i}</li>".encode() for i in range(25)) + b"</ul></body></html>"
    assert structure_watch(prev, curr, **_KW) == []


def test_pipeline_table_cell_change_is_localized(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}

    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=[TABLE_V1, TABLE_V2][cursor["i"]])

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=[],  # no watched term; the cell value isn't a term
        collector=StaticCollector(fetcher=fetch),
    )
    verderer.observe("t")
    cursor["i"] = 1
    diffs = verderer.observe("t").diffs
    localized = [d for d in diffs if d.layer == "L0-structure"]
    assert localized and localized[0].evidence["block"] == "table[0].row[1].col[1]"


# --- (c) rendered-DOM noise suppression ------------------------------------------------


def test_noise_suppression_redacts_tokens_and_timestamps() -> None:
    assert suppress_noise("trace a1b2c3d4e5f6a7b8c9d0e1f2a3b4 end") == "trace <token> end"
    assert suppress_noise("updated 2026-07-12T14:31:40Z ok") == "updated <ts> ok"
    # A real long word (no digit) is left alone — only random-looking tokens are redacted.
    assert "supercalifragilisticexpialidocious" in suppress_noise("supercalifragilisticexpialidocious")


def test_rotating_nonce_normalizes_to_identical() -> None:
    dom1 = b"<html><body><p>Air quality</p><span>nonce a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6</span></body></html>"
    dom2 = b"<html><body><p>Air quality</p><span>nonce ff11ee22dd33cc44bb55aa66990088aa</span></body></html>"
    assert normalize_for_diff(dom1) == normalize_for_diff(dom2)


def test_pipeline_rotating_nonce_yields_no_diff(tmp_path: Path, ledger_built: None) -> None:
    # The DOM differs only by a rotating nonce -> the bytes (and raw_bytes_hash) differ, so a
    # faithful observation is still logged, but NO diff is classified.
    cursor = {"i": 0}
    doms = [
        b"<html><body><h1>EJScreen</h1><span>session-id 1111aaaa2222bbbb3333cccc4444dddd</span></body></html>",
        b"<html><body><h1>EJScreen</h1><span>session-id 9999zzzz8888yyyy7777xxxx6666wwww</span></body></html>",
    ]

    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=doms[cursor["i"]])

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["ejscreen"],
        collector=StaticCollector(fetcher=fetch),
    )
    verderer.observe("t")
    cursor["i"] = 1
    result = verderer.observe("t")
    assert result.status == "observed"  # bytes changed -> a faithful leaf is logged
    assert result.diffs == []  # ...but the nonce-only change fires no diff


# --- (d) L4 index-column false positive on truncation ----------------------------------


def test_truncation_flags_row_count_not_index_column(tmp_path: Path, ledger_built: None) -> None:
    # A dataset with a positional index column (idx) and a constant data column (val),
    # truncated. Only the row-count change should fire — never a spurious index-column shift.
    prev = b"idx,val\n0,5\n1,5\n2,5\n3,5\n4,5\n"
    curr = b"idx,val\n0,5\n1,5\n"
    diffs = dataset_diff(prev, curr, **_KW)
    shifts = [d for d in diffs if d.diff_type is DiffType.DistributionalShift]
    assert any(d.evidence.get("change") == "row_count" for d in shifts)  # truncation is caught
    assert not any(d.evidence.get("column") == "idx" for d in shifts)  # index column is NOT
    assert not any(d.evidence.get("column") == "val" for d in shifts)  # constant column is NOT


def test_is_index_like_detection() -> None:
    import pandas as pd

    assert _is_index_like(pd.Series([0, 1, 2, 3]), "anything")  # 0-based contiguous run
    assert _is_index_like(pd.Series([1, 2, 3, 4]), "rownum")  # 1-based contiguous run
    assert _is_index_like(pd.Series([42, 43, 44]), "Unnamed: 0")  # index-y name
    assert not _is_index_like(pd.Series([10, 11, 12]), "temperature")  # data run, not 0/1-based
    assert not _is_index_like(pd.Series([0, 2, 4, 6]), "evens")  # not contiguous
    # Review regression: ambiguous names ("no", "#") no longer auto-classify a data column.
    assert not _is_index_like(pd.Series([12, 47, 3]), "no")


def test_rebaselined_column_indexlike_only_before_is_still_flagged() -> None:
    # Review regression: the guard requires BOTH versions to look like an index. A real column
    # that was a 0-based run before but is re-baselined after must still be flagged (the `and`,
    # not `or`, means curr not-index-like -> checked).
    prev = b"reading\n0\n1\n2\n3\n"
    curr = b"reading\n100\n205\n311\n404\n"  # re-baselined; no longer a 0/1-based run
    diffs = dataset_diff(prev, curr, **_KW)
    assert any(d.diff_type is DiffType.DistributionalShift and d.evidence.get("column") == "reading" for d in diffs)
