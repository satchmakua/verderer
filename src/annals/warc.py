"""Faithful WARC capture (DESIGN §2/§7, M11): archive each observation as a standards
**WARC** record so Annals interoperates with the web-archiving ecosystem (Wayback,
End-of-Term, EDGI) instead of being self-referential.

The WARC is the *faithful capture* the design promised: the exact request + response bytes,
in the ISO 28500 container every archive replays. It is stored content-addressed and
referenced by ``Observation.warc_record_hash`` in the attested leaf, so the raw artifact is
recoverable from a standards archive, and a third party can replay precisely what Annals was
served.

Two halves, deliberately split along the trust boundary:

* **Writing** goes through the audited ``warcio`` library, so the output is conformant ISO
  28500 that any archive tool ingests — no hand-rolled container.
* **Reading** is a tiny dependency-free parser (:func:`iter_records` / :func:`archived_payload`)
  so a verifier can pull the archived bytes back out **without trusting warcio or Annals** —
  the same "open, dependency-light verifier" principle as the trust core. It doubles as the
  proof that the container is real WARC, not a warcio-specific dialect.

A ``response`` capture (the ``static`` collector's real HTTP fetch) carries a WARC ``request``
+ ``response`` record pair. A ``resource`` capture (the ``render`` collector's post-JS DOM —
a *derived* artifact, not a byte-for-byte HTTP response) carries a single ``resource`` record,
which is the honest WARC type for rendered/synthesised content.
"""

from __future__ import annotations

import io
from collections.abc import Iterator, Mapping
from http import HTTPStatus
from urllib.parse import urlsplit

DEFAULT_USER_AGENT = "AnnalsWatchdog/0.0 (+https://github.com/satchmakua/annals) polite-archival-collector"

# HTTP headers that describe the *encoding on the wire*, not the decoded payload. The client
# (httpx) transparently decompresses, so the stored artifact is the DECODED body — archiving
# these verbatim would tell a replayer to un-gzip already-plain bytes. Dropped; Content-Length
# is then set to the real decoded length so the response record is internally consistent.
_ENCODING_HEADERS = frozenset({"content-encoding", "transfer-encoding", "content-length"})


def _reason(status: int) -> str:
    try:
        return HTTPStatus(status).phrase
    except ValueError:
        return ""


def build_warc(
    *,
    target_uri: str,
    fetched_at: str,
    payload: bytes,
    record_type: str = "response",
    status: int = 200,
    response_headers: Mapping[str, str] | None = None,
    content_type: str = "application/octet-stream",
    user_agent: str = DEFAULT_USER_AGENT,
) -> bytes:
    """Build a WARC (ISO 28500) archiving one observation, via ``warcio``.

    ``record_type="response"``: a real HTTP fetch → a ``response`` record (HTTP status line +
    headers + ``payload``) and a matching ``request`` record. ``record_type="resource"``: a
    derived artifact (a rendered DOM) → a single ``resource`` record whose block is the
    ``payload`` itself. ``fetched_at`` (RFC3339) becomes the ``WARC-Date`` for fidelity; the
    ``WARC-Record-ID`` is warcio's per-record UUID, so identical fetches yield distinct WARCs
    — harmless, since ``warc_record_hash`` attests the exact stored bytes, and a byte-identical
    re-observation is deduped before a WARC is ever stored.
    """
    from warcio.statusandheaders import StatusAndHeaders  # lazy: only when actually capturing
    from warcio.warcwriter import WARCWriter

    buffer = io.BytesIO()
    writer = WARCWriter(buffer, gzip=False)
    warc_date = {"WARC-Date": fetched_at}

    if record_type == "resource":
        record = writer.create_warc_record(
            target_uri,
            "resource",
            payload=io.BytesIO(payload),
            length=len(payload),
            warc_content_type=content_type,
            warc_headers_dict=warc_date,
        )
        writer.write_record(record)
        return buffer.getvalue()

    if record_type != "response":
        raise ValueError(f"unknown WARC record_type {record_type!r}")

    # Reconcile the archived HTTP headers with the decoded payload (see _ENCODING_HEADERS).
    archived_headers = [(k, v) for k, v in (response_headers or {}).items() if k.lower() not in _ENCODING_HEADERS]
    archived_headers.append(("Content-Length", str(len(payload))))
    # Keep the SP after the status code even when the reason-phrase is empty (a status not in
    # http.HTTPStatus, e.g. a Cloudflare 520) — RFC 7230 requires `code SP reason`.
    http_response = StatusAndHeaders(
        f"{status} {_reason(status)}", archived_headers, protocol="HTTP/1.1"
    )
    response = writer.create_warc_record(
        target_uri,
        "response",
        payload=io.BytesIO(payload),
        length=len(payload),
        http_headers=http_response,
        warc_headers_dict=warc_date,
    )
    writer.write_record(response)

    parts = urlsplit(target_uri)
    request_target = parts.path or "/"
    if parts.query:
        request_target += f"?{parts.query}"
    http_request = StatusAndHeaders(
        f"GET {request_target} HTTP/1.1",
        [("Host", parts.netloc), ("User-Agent", user_agent)],
        is_http_request=True,
    )
    request = writer.create_warc_record(
        target_uri, "request", http_headers=http_request, warc_headers_dict=warc_date
    )
    writer.write_record(request)
    return buffer.getvalue()


# --- dependency-free reader (verifier side; no warcio) ---------------------------------


def iter_records(data: bytes) -> Iterator[tuple[dict[str, str], bytes]]:
    """Parse a WARC into ``(warc_headers, block)`` pairs without warcio. ``block`` is the
    record's raw content (for a ``response``: the HTTP status line + headers + CRLFCRLF +
    payload; for a ``resource``: the payload itself)."""
    index = 0
    length = len(data)
    while index < length:
        while data[index : index + 2] == b"\r\n":  # skip record-separating CRLFs
            index += 2
        if index >= length:
            break
        eol = data.index(b"\r\n", index)
        if not data[index:eol].startswith(b"WARC/"):
            raise ValueError("not a WARC record header")
        index = eol + 2
        headers: dict[str, str] = {}
        while True:
            eol = data.index(b"\r\n", index)
            line = data[index:eol]
            index = eol + 2
            if not line:
                break
            key, _, value = line.partition(b": ")
            headers[key.decode("ascii", "replace").lower()] = value.decode("utf-8", "replace")
        if "content-length" not in headers:
            raise ValueError("WARC record has no Content-Length")
        try:
            block_len = int(headers["content-length"])
        except ValueError:
            raise ValueError("WARC record has a non-integer Content-Length") from None
        if block_len < 0:
            raise ValueError("WARC record has a negative Content-Length")
        block = data[index : index + block_len]
        index += block_len
        yield headers, block


def archived_payload(data: bytes) -> bytes:
    """Extract the archived artifact bytes from a WARC — the HTTP response body of the
    ``response`` record, or the block of the ``resource`` record. This is what must hash to
    the observation's ``raw_bytes_hash``."""
    for headers, block in iter_records(data):
        record_type = headers.get("warc-type")
        if record_type == "response":
            separator = block.find(b"\r\n\r\n")
            if separator == -1:
                raise ValueError("response record has no HTTP header/body separator")
            return block[separator + 4 :]
        if record_type == "resource":
            return block
    raise ValueError("WARC has no response or resource record")
