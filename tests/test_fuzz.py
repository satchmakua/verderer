"""M14 — property-based / fuzz tests. The differ and the WARC reader ingest *untrusted*
bytes (whatever a government site or a third-party archive serves), so they must never crash,
hang, or mis-behave on adversarial or malformed input — only ever return a result or a
controlled, typed error. Hypothesis explores the input space to prove that.

These guard the two properties the whole project rests on: the best-effort layers degrade
gracefully (never take down a run), and the reader/normaliser are total functions on bytes.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from annals.differ.dataset import dataset_diff, detect_format
from annals.differ.normalize import normalize_for_diff, suppress_noise
from annals.differ.numeric import numeric_watch
from annals.differ.structure import structure_watch
from annals.differ.termwatch import term_watch
from annals.models import DiffRecord
from annals.warc import archived_payload, build_warc, iter_records

_KW = {"target_id": "t", "detected_at": "2026-01-01T00:00:00Z", "from_hash": "a", "to_hash": "b"}
_SETTINGS = settings(max_examples=250, deadline=None)


# --- the differ never crashes on untrusted bytes ---------------------------------------


@_SETTINGS
@given(a=st.binary(max_size=4000), b=st.binary(max_size=4000))
def test_dataset_diff_is_total(a: bytes, b: bytes) -> None:
    # A `dataset`-kind target routes arbitrary downloaded bytes here; it must always return a
    # (possibly empty) list of records — a parse failure degrades to a MetadataChange, never a raise.
    out = dataset_diff(a, b, **_KW)
    assert isinstance(out, list) and all(isinstance(d, DiffRecord) for d in out)


@_SETTINGS
@given(body=st.binary(max_size=4000))
def test_detect_format_is_total(body: bytes) -> None:
    assert detect_format(body) in {"netcdf", "hdf5", "xlsx", "zip", "json", "csv"}


@_SETTINGS
@given(a=st.binary(max_size=4000), b=st.binary(max_size=4000))
def test_structure_watch_is_total(a: bytes, b: bytes) -> None:
    out = structure_watch(a, b, **_KW)
    assert isinstance(out, list) and all(isinstance(d, DiffRecord) for d in out)


@_SETTINGS
@given(body=st.binary(max_size=4000))
def test_normalize_for_diff_is_total(body: bytes) -> None:
    assert isinstance(normalize_for_diff(body), str)


@_SETTINGS
@given(a=st.text(max_size=4000), b=st.text(max_size=4000))
def test_term_and_numeric_watch_are_total(a: str, b: str) -> None:
    assert isinstance(term_watch(a, b, ["climate", "threshold"], **_KW), list)
    assert isinstance(numeric_watch(a, b, **_KW), list)


# --- differ invariants -----------------------------------------------------------------


@_SETTINGS
@given(text=st.text(max_size=4000))
def test_suppress_noise_is_idempotent(text: str) -> None:
    once = suppress_noise(text)
    assert suppress_noise(once) == once  # redacting again finds nothing new to redact


@_SETTINGS
@given(body=st.binary(max_size=4000))
def test_comparing_identical_content_yields_no_diff(body: bytes) -> None:
    # A target re-observed with byte-identical content must never produce a spurious diff,
    # whatever the bytes are.
    text = normalize_for_diff(body)
    assert term_watch(text, text, ["climate"], **_KW) == []
    assert numeric_watch(text, text, **_KW) == []
    assert structure_watch(body, body, **_KW) == []


# --- the WARC reader: a total function with a clean error contract ---------------------


@_SETTINGS
@given(data=st.binary(max_size=6000))
def test_warc_reader_only_raises_valueerror(data: bytes) -> None:
    # A verifier replays third-party WARC bytes with this dependency-free reader; malformed
    # input must fail as a controlled ValueError, never a surprise exception or a hang.
    try:
        for _headers, _block in iter_records(data):
            pass
    except ValueError:
        pass


@_SETTINGS
@given(payload=st.binary(max_size=6000))
def test_response_warc_round_trips_any_payload(payload: bytes) -> None:
    # The written WARC replays exactly the payload it archived — the M11 invariant, for any bytes.
    warc = build_warc(
        target_uri="https://x.gov/p", fetched_at="2026-07-12T00:00:00Z",
        payload=payload, record_type="response", status=200, response_headers={"Content-Type": "text/plain"},
    )
    assert archived_payload(warc) == payload


@_SETTINGS
@given(payload=st.binary(max_size=6000))
def test_resource_warc_round_trips_any_payload(payload: bytes) -> None:
    warc = build_warc(
        target_uri="https://x.gov/p", fetched_at="2026-07-12T00:00:00Z",
        payload=payload, record_type="resource", content_type="application/octet-stream",
    )
    assert archived_payload(warc) == payload
