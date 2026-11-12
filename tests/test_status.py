"""The status watch (DESIGN §6.1 — `Deletion`, `Reappearance`): availability is classified from
the attested HTTP status and final URL alone, before any content layer runs."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from verderer.differ.status import (
    DIFFERS_FROM_LAST_SERVED,
    LAYER,
    is_served,
    status_watch,
)
from verderer.models import DiffType, Observation


def _obs(status: int, *, url: str = "https://example.gov/t", body_hash: str = "1220aa") -> Observation:
    return Observation(
        target_id="t",
        url=url,
        collector_type="static",
        collector_version="0",
        fetched_at="2026-01-01T00:00:00Z",
        http_status=status,
        raw_bytes_hash=body_hash,
        response_headers_hash="1220bb",
    )


def _watch(prev: Observation, curr: Observation, **kwargs: str | None) -> list:
    return status_watch(prev, curr, detected_at="2026-01-02T00:00:00Z", **kwargs)


def test_only_2xx_counts_as_served() -> None:
    assert is_served(200) and is_served(204)
    assert not any(is_served(s) for s in (0, 199, 301, 304, 403, 404, 410, 451, 500, 503))


def test_served_to_error_is_a_high_deletion() -> None:
    (diff,) = _watch(_obs(200), _obs(404, body_hash="1220cc"))
    assert diff.diff_type is DiffType.Deletion and diff.severity == "High"
    assert diff.layer == LAYER
    assert diff.evidence == {"from_status": 200, "to_status": 404}
    assert (diff.from_observation_hash, diff.to_observation_hash) == ("1220aa", "1220cc")


def test_error_to_served_is_a_medium_reappearance_carrying_the_comparison() -> None:
    (diff,) = _watch(_obs(404), _obs(200), versus_last_served=DIFFERS_FROM_LAST_SERVED)
    assert diff.diff_type is DiffType.Reappearance and diff.severity == "Medium"
    assert diff.evidence == {"from_status": 404, "to_status": 200, "versus_last_served": "changed"}


def test_a_different_error_is_a_metadata_change_but_the_same_error_is_silent() -> None:
    (diff,) = _watch(_obs(403), _obs(404))
    assert diff.diff_type is DiffType.MetadataChange
    assert diff.evidence == {"scope": "http_status", "from_status": 403, "to_status": 404}
    # The same refusal with a different body is the error page changing, not the resource.
    assert _watch(_obs(403, body_hash="1220aa"), _obs(403, body_hash="1220dd")) == []


def test_two_served_responses_leave_content_to_the_content_layers() -> None:
    assert _watch(_obs(200, body_hash="1220aa"), _obs(200, body_hash="1220dd")) == []


def test_a_changed_final_url_is_flagged_whatever_the_status() -> None:
    moved = _obs(200, url="https://example.gov/elsewhere")
    (diff,) = _watch(_obs(200), moved)
    assert diff.diff_type is DiffType.MetadataChange
    assert diff.evidence == {
        "scope": "final_url",
        "from_url": "https://example.gov/t",
        "to_url": "https://example.gov/elsewhere",
    }
    # ...and it rides alongside a deletion rather than replacing it.
    both = _watch(_obs(200), _obs(404, url="https://example.gov/elsewhere"))
    assert [d.diff_type for d in both] == [DiffType.Deletion, DiffType.MetadataChange]


@given(st.integers(min_value=0, max_value=999), st.integers(min_value=0, max_value=999))
def test_status_watch_is_total_and_never_double_reports(prev_status: int, curr_status: int) -> None:
    diffs = _watch(_obs(prev_status), _obs(curr_status))
    assert len(diffs) <= 1  # same URL: at most one availability finding
    if is_served(prev_status) and is_served(curr_status):
        assert diffs == []
    if prev_status == curr_status:
        assert diffs == []
