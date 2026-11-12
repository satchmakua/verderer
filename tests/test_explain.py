"""The plain-language reading of the record (DESIGN §6.5): every finding type gets a sentence,
findings group into one change per observed transition, a position-by-position cascade nets to
what was actually added or removed, an exact reversal is linked, and each source's state is
derived honestly from its attested observations plus the scheduler's own account."""

from __future__ import annotations

from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from verderer.web.explain import (
    build_changes,
    describe_block,
    explain_event,
    parse_criteria,
    status_phrase,
    target_state,
    to_ascii,
    word_diff,
)

# --- one finding -----------------------------------------------------------------------


def _event(diff_type: str, evidence: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"diff_type": diff_type, "severity": "Medium", "evidence": evidence, **extra}


def test_a_term_that_vanishes_reads_as_removed() -> None:
    out = explain_event(_event("TermSubstitution", {"term": "climate change", "from": 2, "to": 0}))
    assert out["kind"] == "term_removed"
    assert out["title"] == "Watched term removed: “climate change”"
    assert "appeared 2 times" in out["summary"] and "now gone" in out["summary"]


def test_term_counts_read_in_the_direction_they_moved() -> None:
    kinds = {
        (0, 3): "term_added",
        (6, 4): "term_reduced",
        (1, 5): "term_increased",
        (1, 0): "term_removed",
    }
    for (before, after), kind in kinds.items():
        assert explain_event(_event("TermSubstitution", {"term": "methane", "from": before, "to": after}))["kind"] == kind
    singular = explain_event(_event("TermSubstitution", {"term": "methane", "from": 1, "to": 0}))["summary"]
    assert "appeared 1 time in" in singular  # not "1 times"


def test_a_numeric_change_states_both_values_and_the_size_of_the_move() -> None:
    out = explain_event(
        _event(
            "NumericThresholdChange",
            {"context": "level is 1.3 mg/L , and for lead is", "unit": "mg/L", "from": "0.010 mg/L", "to": "0.015 mg/L"},
        )
    )
    assert out["kind"] == "number_changed"
    assert out["title"] == "Regulatory number changed: 0.010 mg/L → 0.015 mg/L"
    assert "(+50%)" in out["summary"] and "for lead is" in out["summary"]


def test_a_cross_unit_change_is_sized_in_base_units_and_an_incomparable_one_is_not_sized() -> None:
    cross = explain_event(_event("NumericThresholdChange", {"context": "limit", "from": "10 ppb", "to": "0.020 ppm"}))
    assert "(+100%)" in cross["summary"]
    apples = explain_event(_event("NumericThresholdChange", {"context": "limit", "from": "10 ppb", "to": "5 mg/L"}))
    assert "%" not in apples["summary"]


def test_an_edited_passage_carries_a_word_level_diff() -> None:
    before = "vital for the monarch butterfly; EPA is committed to protecting pollinators"
    after = "vital for the monarch butterfly. EPA is committed to protecting pollinators"
    out = explain_event(_event("ContentEdit", {"block": "li[32]", "from": before, "to": after}))
    assert out["kind"] == "text_edited" and out["title"] == "Text edited (list item 33)"
    assert out["diff"]["removed"] == "butterfly;" and out["diff"]["added"] == "butterfly."
    assert out["diff"]["before"].endswith("the monarch") and out["diff"]["after"].startswith("EPA is")


def test_added_removed_and_unlocalised_text() -> None:
    added = explain_event(_event("ContentEdit", {"block": "h2[0]", "change": "added", "to": "New section"}))
    assert (added["kind"], added["title"]) == ("text_added", "Text added (heading 1 (h2))")
    removed = explain_event(_event("ContentEdit", {"block": "table[0].row[2].col[1]", "change": "removed", "from": "5 ppb"}))
    assert (removed["kind"], removed["title"]) == ("text_removed", "Text removed (table 1, row 3, column 2)")
    floor = explain_event(_event("ContentEdit", {"note": "normalised content changed; no watched term moved"}))
    assert floor["kind"] == "page_edited" and "too broad to pin" in floor["summary"]


def test_an_edit_to_an_error_page_is_churn_not_a_content_change() -> None:
    event = _event("ContentEdit", {"note": "normalised content changed; no watched term moved"})
    assert explain_event(event, to_status=200)["kind"] == "page_edited"
    churn = explain_event(event, to_status=403)
    assert churn["kind"] == "error_page_churn" and "was not served" in churn["summary"]
    # Only content edits are reinterpreted: a real finding on the same transition is not.
    assert explain_event(_event("TermSubstitution", {"term": "x", "from": 1, "to": 0}), to_status=403)["kind"] == "term_removed"


def test_availability_findings() -> None:
    gone = explain_event(_event("Deletion", {"from_status": 200, "to_status": 404}))
    assert gone["kind"] == "removed" and gone["title"] == "No longer served: HTTP 200 → 404"
    assert "HTTP 404 Not Found" in gone["summary"]

    back = explain_event(_event("Reappearance", {"from_status": 404, "to_status": 200, "versus_last_served": "changed"}))
    assert back["kind"] == "reappeared" and "differs from the last version" in back["summary"]
    same = explain_event(_event("Reappearance", {"from_status": 404, "to_status": 200, "versus_last_served": "identical"}))
    assert "byte-identical" in same["summary"]

    still = explain_event(_event("MetadataChange", {"scope": "http_status", "from_status": 403, "to_status": 404}))
    assert still["kind"] == "status_changed" and "HTTP 403 Forbidden" in still["summary"]
    moved = explain_event(
        _event("MetadataChange", {"scope": "final_url", "from_url": "https://a.gov/x", "to_url": "https://b.gov/y"})
    )
    assert moved["kind"] == "redirect_changed" and "https://b.gov/y" in moved["summary"]


def test_dataset_findings() -> None:
    dropped = explain_event(_event("SchemaChange", {"change": "column_removed", "column": "ch4"}))
    assert dropped["kind"] == "column_removed" and dropped["title"] == "Column removed: “ch4”"
    in_sheet = explain_event(
        _event("SchemaChange", {"change": "column_added", "column": "n2o", "scope": "Sheet1", "member": "a.xlsx"})
    )
    assert "(in a.xlsx, Sheet1)" in in_sheet["summary"]
    retyped = explain_event(
        _event("SchemaChange", {"change": "column_retyped", "column": "co2", "from": "float64", "to": "object"})
    )
    assert "from float64 to object" in retyped["summary"]
    member = explain_event(_event("SchemaChange", {"change": "member_removed", "member": "2023.csv"}))
    assert member["title"] == "File in the archive removed: “2023.csv”"

    rows = explain_event(_event("DistributionalShift", {"change": "row_count", "from": 1000, "to": 600}))
    assert rows["kind"] == "rows_changed" and "(-40%)" in rows["summary"]
    shifted = explain_event(
        _event(
            "DistributionalShift", {"column": "co2", "from": {"mean": 410.0, "max": 420.0}, "to": {"mean": 310.0, "max": 420.0}}
        )
    )
    assert shifted["kind"] == "distribution_shifted" and "mean 410 → 310" in shifted["summary"]
    assert "max" not in shifted["summary"]  # only what moved

    attrs = explain_event(_event("MetadataChange", {"scope": "var:co2", "changed": {"units": ["ppm", "ppb"]}}))
    assert attrs["title"] == "Metadata changed (co2)" and "changed: units" in attrs["summary"]


def test_unknown_types_and_malformed_evidence_still_get_an_honest_reading() -> None:
    odd = explain_event({"diff_type": "SomethingNew", "evidence": {"a": 1}})
    assert odd == {"kind": "other", "title": "SomethingNew", "summary": "a: 1"}
    assert explain_event({})["title"] == "Change detected"
    assert explain_event({"diff_type": "TermSubstitution", "evidence": "not a mapping"})["kind"] == "other"
    assert explain_event(_event("TermSubstitution", {"term": "x", "from": "many", "to": None}))["kind"] == "other"
    assert explain_event(_event("SchemaChange", {"change": "exploded"}))["kind"] == "other"


_SCALAR = st.one_of(st.none(), st.booleans(), st.integers(), st.floats(), st.text(max_size=40))
_EVIDENCE = st.one_of(
    _SCALAR,
    st.lists(_SCALAR, max_size=4),
    st.dictionaries(
        st.sampled_from(
            [
                "term",
                "from",
                "to",
                "block",
                "change",
                "note",
                "context",
                "scope",
                "column",
                "member",
                "from_status",
                "to_status",
                "changed",
                "removed",
                "passage",
            ]
        ),
        st.one_of(_SCALAR, st.lists(_SCALAR, max_size=3), st.dictionaries(st.text(max_size=5), _SCALAR, max_size=3)),
        max_size=6,
    ),
)
_DIFF_TYPES = st.sampled_from(
    [
        "Deletion",
        "TermSubstitution",
        "NumericThresholdChange",
        "SchemaChange",
        "DistributionalShift",
        "MetadataChange",
        "ContentEdit",
        "Reappearance",
        "CosmeticOnly",
        "Unknown",
        "",
    ]
)


@given(_DIFF_TYPES, _EVIDENCE, st.one_of(st.none(), st.integers(min_value=0, max_value=999)))
def test_explain_event_is_total(diff_type: str, evidence: object, to_status: int | None) -> None:
    out = explain_event({"diff_type": diff_type, "evidence": evidence}, to_status=to_status)
    assert set(out) >= {"kind", "title", "summary"}
    assert all(isinstance(out[key], str) and out[key] for key in ("kind", "title", "summary"))


# --- helpers ---------------------------------------------------------------------------


def test_block_paths_criteria_and_status_phrases_read_naturally() -> None:
    assert describe_block("li[0]") == "list item 1"
    assert describe_block("something/else") == "something/else"
    assert parse_criteria("[mandate][traffic] Congressionally mandated program.") == (
        ["mandate", "traffic"],
        "Congressionally mandated program.",
    )
    assert parse_criteria("No tags here.") == ([], "No tags here.")
    assert parse_criteria("") == ([], "")
    assert status_phrase(451) == "HTTP 451 Unavailable For Legal Reasons"
    assert status_phrase(799) == "HTTP 799" and status_phrase(None) == "an unknown status"


def test_word_diff_isolates_the_change_and_ascii_output_is_safe_for_a_terminal() -> None:
    diff = word_diff("the limit is 10 ppb for lead", "the limit is 15 ppb for lead")
    assert diff == {"before": "the limit is", "removed": "10", "added": "15", "after": "ppb for lead"}
    assert word_diff("same text", "same text") == {"before": "same text", "removed": "", "added": "", "after": ""}
    assert word_diff("", "all new")["added"] == "all new"
    sentence = explain_event(_event("NumericThresholdChange", {"context": "limit", "from": "10 ppb", "to": "15 ppb"}))["summary"]
    ascii_only = to_ascii(sentence)
    assert ascii_only.isascii() and "10 ppb to 15 ppb" in ascii_only and '"...limit"' in ascii_only


# --- findings grouped into changes -----------------------------------------------------


def _obs(target: str, content_hash: str, at: str, status: int = 200) -> dict[str, Any]:
    return {
        "id": f"leaf-{content_hash}-{at}",
        "content_hash": content_hash,
        "fetched_at": at,
        "http_status": status,
        "url": f"https://x.gov/{target}",
        "warc": None,
    }


def _finding(
    n: int,
    target: str,
    diff_type: str,
    evidence: dict[str, Any],
    *,
    frm: str,
    to: str,
    at: str,
    severity: str = "Medium",
    layer: str = "L1-termwatch",
) -> dict[str, Any]:
    return {
        "id": f"e{n:02d}",
        "target_id": target,
        "diff_type": diff_type,
        "severity": severity,
        "layer": layer,
        "detected_at": at,
        "evidence": evidence,
        "from_hash": frm,
        "to_hash": to,
    }


def test_findings_from_one_transition_become_one_change_led_by_what_matters_most() -> None:
    observations = {"t": [_obs("t", "h1", "2026-09-21T00:00:00Z"), _obs("t", "h2", "2026-09-22T04:57:00Z")]}
    events = [
        _finding(
            1,
            "t",
            "TermSubstitution",
            {"term": "greenhouse gas", "from": 6, "to": 4},
            frm="h1",
            to="h2",
            at="2026-09-22T04:57:11Z",
        ),
        _finding(
            2,
            "t",
            "TermSubstitution",
            {"term": "climate change", "from": 2, "to": 0},
            frm="h1",
            to="h2",
            at="2026-09-22T04:57:11Z",
            severity="High",
        ),
        _finding(
            3,
            "t",
            "TermSubstitution",
            {"term": "methane", "from": 1, "to": 0},
            frm="h1",
            to="h2",
            at="2026-09-22T04:57:11Z",
            severity="High",
        ),
    ]
    (change,) = build_changes(events, observations)
    assert change["id"] == "e01" and change["event_ids"] == ["e01", "e02", "e03"]
    assert change["severity"] == "High" and change["category"] == "notable"
    assert change["headline"] == "2 watched terms removed: “climate change”, “methane” (+1 more)"
    assert change["points"][0].startswith("“climate change” appeared 2 times")  # removals lead
    assert change["from"]["observed_at"] == "2026-09-21T00:00:00Z" and change["to"]["http_status"] == 200
    assert all(e["change_id"] == "e01" and e["explain"]["kind"].startswith("term_") for e in events)


def test_a_shifted_list_nets_to_the_one_item_that_was_removed() -> None:
    items = ["Alpha notice", "Bravo notice", "Charlie notice", "Delta notice"]
    # Removing "Alpha" re-indexes the rest: the structure diff sees three edits and a removal.
    events = [
        _finding(
            1,
            "t",
            "ContentEdit",
            {"block": "li[0]", "from": items[0], "to": items[1]},
            frm="a",
            to="b",
            at="2026-11-04T06:22:55Z",
            layer="L0-structure",
        ),
        _finding(
            2,
            "t",
            "ContentEdit",
            {"block": "li[1]", "from": items[1], "to": items[2]},
            frm="a",
            to="b",
            at="2026-11-04T06:22:55Z",
            layer="L0-structure",
        ),
        _finding(
            3,
            "t",
            "ContentEdit",
            {"block": "li[2]", "from": items[2], "to": items[3]},
            frm="a",
            to="b",
            at="2026-11-04T06:22:55Z",
            layer="L0-structure",
        ),
        _finding(
            4,
            "t",
            "ContentEdit",
            {"block": "li[3]", "change": "removed", "from": items[3]},
            frm="a",
            to="b",
            at="2026-11-04T06:22:55Z",
            layer="L0-structure",
        ),
    ]
    (change,) = build_changes(events, {"t": [_obs("t", "a", "2026-11-03T00:00:00Z"), _obs("t", "b", "2026-11-04T06:22:50Z")]})
    assert change["netted"] is True and change["category"] == "routine"
    assert change["headline"] == "Text removed: “Alpha notice”"
    assert change["points"][0] == "Removed: “Alpha notice”"
    assert "4 position-by-position edits" in change["points"][-1]


def test_independent_edits_are_not_netted() -> None:
    events = [
        _finding(
            n,
            "t",
            "ContentEdit",
            {"block": f"li[{n}]", "from": f"old {n}", "to": f"new {n}"},
            frm="a",
            to="b",
            at="2026-01-02T00:00:00Z",
            layer="L0-structure",
        )
        for n in range(3)
    ]
    (change,) = build_changes(events, {"t": [_obs("t", "a", "2026-01-01T00:00:00Z"), _obs("t", "b", "2026-01-02T00:00:00Z")]})
    assert change["netted"] is False and change["headline"] == "Text edited in 3 places"
    assert len(change["points"]) == 3


def test_error_page_churn_is_set_apart_from_real_changes() -> None:
    observations = {"t": [_obs("t", "a", "2026-01-01T00:00:00Z", 403), _obs("t", "b", "2026-01-02T00:00:00Z", 403)]}
    events = [
        _finding(
            1,
            "t",
            "ContentEdit",
            {"note": "normalised content changed; no watched term moved"},
            frm="a",
            to="b",
            at="2026-01-02T00:00:05Z",
            layer="L0-normalize",
        )
    ]
    (change,) = build_changes(events, observations)
    assert change["category"] == "churn" and change["headline"] == "Error page changed"
    assert change["to"]["http_status"] == 403


def test_an_exact_reversal_is_linked_both_ways_but_a_partial_one_is_not() -> None:
    observations = {
        "t": [
            _obs("t", "h1", "2026-09-21T00:00:00Z"),
            _obs("t", "h2", "2026-09-22T04:57:00Z"),
            _obs("t", "h3", "2026-09-22T21:20:00Z"),
            _obs("t", "h4", "2026-09-23T00:00:00Z"),
        ]
    }
    events = [
        _finding(
            1,
            "t",
            "TermSubstitution",
            {"term": "climate change", "from": 2, "to": 0},
            frm="h1",
            to="h2",
            at="2026-09-22T04:57:11Z",
            severity="High",
        ),
        _finding(
            2,
            "t",
            "TermSubstitution",
            {"term": "methane", "from": 1, "to": 0},
            frm="h1",
            to="h2",
            at="2026-09-22T04:57:11Z",
            severity="High",
        ),
        _finding(
            3,
            "t",
            "TermSubstitution",
            {"term": "climate change", "from": 0, "to": 2},
            frm="h2",
            to="h3",
            at="2026-09-22T21:20:01Z",
        ),
        _finding(
            4, "t", "TermSubstitution", {"term": "methane", "from": 0, "to": 1}, frm="h2", to="h3", at="2026-09-22T21:20:01Z"
        ),
        # A later change that only half-undoes the previous one must not be called a reversal.
        _finding(
            5,
            "t",
            "TermSubstitution",
            {"term": "climate change", "from": 2, "to": 0},
            frm="h3",
            to="h4",
            at="2026-09-23T00:00:05Z",
            severity="High",
        ),
    ]
    removed, restored, partial = build_changes(events, observations)
    assert removed["reverted_by"] == restored["id"] and restored["reverts"] == removed["id"]
    assert restored["reverted_by"] is None and partial["reverts"] is None
    assert restored["headline"] == "2 watched terms appeared: “climate change”, “methane”"


def test_a_change_with_no_well_defined_opposite_is_never_linked() -> None:
    observations = {"t": [_obs("t", h, f"2026-01-0{i + 1}T00:00:00Z") for i, h in enumerate(["a", "b", "c"])]}
    note = {"note": "normalised content changed; no watched term moved"}
    events = [
        _finding(1, "t", "ContentEdit", note, frm="a", to="b", at="2026-01-02T00:00:01Z", layer="L0-normalize"),
        _finding(2, "t", "ContentEdit", note, frm="b", to="a", at="2026-01-03T00:00:01Z", layer="L0-normalize"),
    ]
    first, second = build_changes(events, observations)
    assert first["reverted_by"] is None and second["reverts"] is None


def test_a_reappearance_change_points_at_the_error_it_followed() -> None:
    observations = {
        "t": [
            _obs("t", "live", "2026-01-01T00:00:00Z"),
            _obs("t", "err", "2026-01-02T00:00:00Z", 404),
            _obs("t", "live2", "2026-01-03T00:00:00Z"),
        ]
    }
    events = [
        _finding(
            1,
            "t",
            "Reappearance",
            {"from_status": 404, "to_status": 200, "versus_last_served": "changed"},
            frm="err",
            to="live2",
            at="2026-01-03T00:00:02Z",
            layer="L0-status",
        ),
        # ...and its content is compared with the last *served* version, further back.
        _finding(
            2,
            "t",
            "TermSubstitution",
            {"term": "climate change", "from": 1, "to": 0},
            frm="live",
            to="live2",
            at="2026-01-03T00:00:02Z",
            severity="High",
        ),
    ]
    (change,) = build_changes(events, observations)
    assert change["from"]["http_status"] == 404 and change["to"]["http_status"] == 200
    assert change["headline"].startswith("Watched term removed") and change["category"] == "notable"


# --- a source's state ------------------------------------------------------------------


def _monitor(status: str = "unchanged", failures: int = 0, error: str = "") -> dict[str, Any]:
    return {"last_status": status, "consecutive_failures": failures, "last_error": error}


def test_states_follow_the_latest_attested_response() -> None:
    url = "https://www.epa.gov/page"
    live = target_state(url, [_obs("t", "a", "2026-01-01T00:00:00Z") | {"url": url}], _monitor())
    assert (live["code"], live["label"], live["final_url"]) == ("live", "Live", None)

    gone = target_state(url, [_obs("t", "a", "2026-01-01T00:00:00Z", 404) | {"url": url}], _monitor())
    assert gone["code"] == "gone" and "absence is attested" in gone["detail"]

    blocked = target_state(
        "https://hazards.fema.gov/nri/",
        [
            _obs("t", "a", "2026-01-01T00:00:00Z", 403) | {"url": "https://www.fema.gov/other-tool"},
            _obs("t", "b", "2026-01-02T00:00:00Z", 403) | {"url": "https://www.fema.gov/other-tool"},
        ],
        _monitor("observed"),
    )
    assert blocked["code"] == "blocked" and blocked["final_url"] == "https://www.fema.gov/other-tool"
    assert "after redirecting to https://www.fema.gov/other-tool" in blocked["detail"]
    assert "other visitors may be served something different" in blocked["detail"]  # no overclaim
    assert blocked["since"] == "2026-01-01T00:00:00Z"  # in this state since the first refusal

    odd = target_state(url, [_obs("t", "a", "2026-01-01T00:00:00Z", 500) | {"url": url}], _monitor())
    assert odd["code"] == "error"


def test_a_trailing_slash_or_www_is_not_a_redirect() -> None:
    state = target_state(
        "https://www.climatehubs.usda.gov/",
        [_obs("t", "a", "2026-01-01T00:00:00Z") | {"url": "https://climatehubs.usda.gov"}],
        None,
    )
    assert state["code"] == "live" and state["final_url"] is None


def test_a_source_that_never_answered_is_unreachable_with_the_reason_when_known() -> None:
    never = target_state("https://gone.gov/", [], _monitor("error", 409))
    assert never["code"] == "unreachable" and "409 consecutive checks failed" in never["detail"]
    dns = target_state("https://gone.gov/", [], _monitor("error", 3, "ConnectError: [Errno -2] Name or service not known"))
    assert "domain name no longer resolves" in dns["detail"]
    # A collector fault is said to be one — it is not evidence about the source.
    broken = target_state("https://x.gov/", [], _monitor("error", 3, "RuntimeError: playwright is not installed"))
    assert "collector fault, not evidence about the source" in broken["detail"]
    assert target_state("https://x.gov/", [], _monitor("skipped"))["code"] == "excluded"
    assert target_state("https://x.gov/", [], None)["code"] == "pending"


def test_a_source_that_stops_answering_is_called_out_but_one_blip_is_not() -> None:
    url = "https://x.gov/page"
    history = [_obs("t", "a", "2026-03-01T00:00:00Z") | {"url": url}]
    blip = target_state(url, history, _monitor("error", 1, "ReadTimeout: timed out"))
    assert blip["code"] == "live"
    down = target_state(url, history, _monitor("error", 5, "ReadTimeout: timed out"))
    assert down["code"] == "failing" and down["label"] == "Not responding"
    assert "last answered on 2026-03-01" in down["detail"] and "connection times out" in down["detail"]
