"""M11 — faithful WARC capture + archive interop. An observation is archived as a standards
WARC whose payload hashes to raw_bytes_hash; a warcio-independent reader replays the bytes;
warc_record_hash attests the stored WARC; the export ships the WARCs. Ledger-backed cases
skip if the Rust kernel isn't built.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.hashing import multihash_sha256
from verderer.pipeline import Verderer
from verderer.warc import archived_payload, build_warc, iter_records
from verderer.web.export import export_site

BODY = b"<html><body><p>reporting threshold is 10 ppb. climate change.</p></body></html>"


# --- warc.py unit: build + independent read --------------------------------------------


def test_response_warc_round_trips_via_independent_reader() -> None:
    warc = build_warc(
        target_uri="https://www.epa.gov/ghgreporting",
        fetched_at="2026-07-12T14:31:40Z",
        payload=BODY,
        record_type="response",
        status=200,
        response_headers={"Content-Type": "text/html"},
    )
    types = [h.get("warc-type") for h, _ in iter_records(warc)]
    assert types == ["response", "request"]  # a real HTTP fetch archives both
    assert archived_payload(warc) == BODY  # the response body replays byte-for-byte


def test_resource_warc_round_trips() -> None:
    dom = b"<html>rendered <b>dom</b></html>"
    warc = build_warc(
        target_uri="https://ejscreen.epa.gov/mapper/",
        fetched_at="2026-07-12T14:31:40Z",
        payload=dom,
        record_type="resource",
        content_type="text/html; charset=utf-8",
    )
    types = [h.get("warc-type") for h, _ in iter_records(warc)]
    assert types == ["resource"]  # a derived artifact -> a single resource record
    assert archived_payload(warc) == dom


def test_independent_reader_agrees_with_warcio() -> None:
    # Proves the container is real WARC, not a warcio-only dialect: warcio and our tiny
    # dependency-free reader extract the identical payload.
    from warcio.archiveiterator import ArchiveIterator

    warc = build_warc(
        target_uri="https://www.epa.gov/x", fetched_at="2026-07-12T00:00:00Z", payload=BODY,
        response_headers={"Content-Type": "text/html"},
    )
    via_warcio = None
    for rec in ArchiveIterator(io.BytesIO(warc)):
        if rec.rec_type == "response":
            via_warcio = rec.content_stream().read()
    assert via_warcio == BODY == archived_payload(warc)


def test_decoded_body_drops_wire_encoding_headers() -> None:
    # httpx decompresses transparently, so the stored payload is decoded. The archived HTTP
    # headers must not claim Content-Encoding: gzip over plain bytes (a replayer would choke),
    # and Content-Length must match the decoded payload.
    warc = build_warc(
        target_uri="https://www.epa.gov/x", fetched_at="2026-07-12T00:00:00Z", payload=BODY,
        record_type="response", status=200,
        response_headers={"Content-Type": "text/html", "Content-Encoding": "gzip", "Content-Length": "999"},
    )
    block = next(block for h, block in iter_records(warc) if h.get("warc-type") == "response")
    http_head = block.split(b"\r\n\r\n", 1)[0].lower()
    assert b"content-encoding" not in http_head  # the wire encoding was stripped
    assert b"content-length: %d" % len(BODY) in http_head  # length matches the decoded body
    assert archived_payload(warc) == BODY


def test_payload_with_embedded_crlfcrlf_round_trips() -> None:
    # The HTTP header/body split must be the FIRST CRLFCRLF (separating headers from body);
    # a body that itself contains CRLFCRLF (and lines that look like headers) must survive.
    tricky = b"intro\r\n\r\nHost: not-a-header\r\n\r\ntrailing\r\n\r\n"
    warc = build_warc(
        target_uri="https://x.gov/p", fetched_at="2026-07-12T00:00:00Z", payload=tricky,
        record_type="response", status=200, response_headers={"Content-Type": "text/plain"},
    )
    assert archived_payload(warc) == tricky


def test_empty_payload_round_trips() -> None:
    warc = build_warc(
        target_uri="https://x.gov/e", fetched_at="2026-07-12T00:00:00Z", payload=b"",
        record_type="response", status=204,
    )
    assert archived_payload(warc) == b""


def test_404_status_line_is_faithful() -> None:
    warc = build_warc(
        target_uri="https://www.epa.gov/gone", fetched_at="2026-07-12T00:00:00Z",
        payload=b"not found", record_type="response", status=404,
    )
    block = next(block for h, block in iter_records(warc) if h.get("warc-type") == "response")
    assert block.startswith(b"HTTP/1.1 404 Not Found\r\n")


def test_unknown_status_code_keeps_the_required_space() -> None:
    # A status not in http.HTTPStatus (e.g. a Cloudflare 520) has an empty reason-phrase, but
    # RFC 7230 still requires the SP after the code: "HTTP/1.1 520 ".
    warc = build_warc(
        target_uri="https://x.gov/p", fetched_at="2026-07-12T00:00:00Z", payload=b"x",
        record_type="response", status=520,
    )
    block = next(block for h, block in iter_records(warc) if h.get("warc-type") == "response")
    assert block.startswith(b"HTTP/1.1 520 \r\n")
    assert archived_payload(warc) == b"x"


# --- pipeline: an observation produces + attests a WARC --------------------------------

TARGET = Target(id="t", title="T", url="https://example.gov/t")


def _verderer(tmp_path: Path, fetcher: object) -> Verderer:
    return Verderer(
        tmp_path / "data",
        targets={"t": TARGET},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fetcher),  # type: ignore[arg-type]
    )


def _fetch(body: bytes = BODY, status: int = 200):
    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=status, headers={"Content-Type": "text/html"}, body=body)

    return fetch


def test_observation_is_archived_and_attested(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer(tmp_path, _fetch())
    obs = verderer.observe("t").observation
    assert obs is not None
    # The leaf attests a WARC hash...
    assert obs.warc_record_hash is not None
    # ...which resolves to the stored WARC...
    warc = verderer.store.get(obs.warc_record_hash)
    # ...whose hash matches what the leaf claims (no unprovable advertised hash)...
    assert multihash_sha256(warc) == obs.warc_record_hash
    # ...and whose archived payload hashes to the observation's raw_bytes_hash.
    payload = archived_payload(warc)
    assert multihash_sha256(payload) == obs.raw_bytes_hash
    assert payload == BODY


def test_dedup_does_not_archive_a_second_identical_warc(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer(tmp_path, _fetch())
    first = verderer.observe("t")
    assert first.observation is not None and first.observation.warc_record_hash is not None
    warc_hash = first.observation.warc_record_hash

    second = verderer.observe("t")  # byte-identical -> deduped before a WARC is built
    assert second.status == "unchanged" and second.observation is None
    assert verderer.store.has(warc_hash)  # the one WARC from the baseline is still there


def test_export_ships_the_warcs(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer(tmp_path, _fetch())
    obs = verderer.observe("t").observation
    assert obs is not None

    info = export_site(verderer, tmp_path / "site")
    assert info["warcs"] == 1
    warc_file = tmp_path / "site" / "warc" / f"{obs.warc_record_hash[4:]}.warc"
    assert warc_file.exists()
    assert archived_payload(warc_file.read_bytes()) == BODY  # the shipped WARC replays

    record = json.loads((tmp_path / "site" / "record.json").read_text(encoding="utf-8"))
    view = record["targets"][0]["observations"][0]
    assert view["warc_record_hash"] == obs.warc_record_hash
    assert view["warc"] == f"warc/{obs.warc_record_hash[4:]}.warc"


def test_warc_failure_does_not_drop_the_observation(tmp_path: Path, ledger_built: None) -> None:
    # WARC archival is layered on the trust core, never a prerequisite: if building the WARC
    # fails (here, a URL warcio can't ASCII-encode), the observation is still attested — just
    # without a warc_record_hash — rather than losing the observation (which under the M10
    # scheduler would retry-loop the target forever).
    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url="https://example.gov/café", status=200, headers={}, body=BODY)

    verderer = Verderer(
        tmp_path / "data", targets={"t": Target(id="t", title="T", url="https://example.gov/x")},
        terms=[], collector=StaticCollector(fetcher=fetch),
    )
    result = verderer.observe("t")
    assert result.status == "observed" and result.observation is not None
    assert result.observation.warc_record_hash is None  # WARC skipped, observation kept
    assert result.observation.raw_bytes_hash is not None  # still fully attested


def test_record_omits_warc_link_when_blob_is_missing(tmp_path: Path, ledger_built: None) -> None:
    from verderer.web.record import build_record

    verderer = _verderer(tmp_path, _fetch())
    obs = verderer.observe("t").observation
    assert obs is not None and obs.warc_record_hash is not None
    # Simulate a store that no longer holds the WARC (a pruned/partial blob dir).
    verderer.store._path(obs.warc_record_hash).unlink()

    view = build_record(verderer)["targets"][0]["observations"][0]
    assert view["warc_record_hash"] == obs.warc_record_hash  # the attested fact is still shown
    assert view["warc"] is None  # but no dangling download link is advertised


def test_render_observation_is_archived_as_resource(tmp_path: Path, ledger_built: None) -> None:
    from verderer.collectors.base import RenderResult
    from verderer.collectors.render import RenderCollector

    dom = b"<html><body>rendered climate change dashboard</body></html>"

    def engine(url: str, *, timeout: float = 30.0) -> RenderResult:
        return RenderResult(final_url=url, status=200, headers={"content-type": "text/html"}, rendered_dom=dom)

    verderer = Verderer(
        tmp_path / "data",
        targets={"tool": Target(id="tool", title="Tool", url="https://example.gov/tool", collector="render")},
        terms=[],
        collectors={"render": RenderCollector(engine=engine)},
    )
    obs = verderer.observe("tool").observation
    assert obs is not None and obs.warc_record_hash is not None
    warc = verderer.store.get(obs.warc_record_hash)
    assert [h.get("warc-type") for h, _ in iter_records(warc)] == ["resource"]
    assert archived_payload(warc) == dom  # the attested rendered DOM replays from the WARC
