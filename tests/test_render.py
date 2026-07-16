"""M3b — render collector. Offline via an injected fake render engine (no browser): a
JS page is observed with its post-JS DOM as the attested artifact and its API/data calls
captured as content-addressed side artifacts. A gated live test drives real Playwright
against a localhost JS page. Ledger-backed cases skip if the Rust kernel isn't built.
"""

import json
from pathlib import Path

import pytest

from verderer.collectors.base import Collected, RenderedCall, RenderResult
from verderer.collectors.render import RenderCollector
from verderer.config import Target
from verderer.models import DiffType
from verderer.pipeline import Verderer

RENDER_TARGET = Target(id="tool", title="JS Tool", url="https://example.gov/tool", collector="render")

DOM_V1 = b"<html><body><h1>Climate change dashboard</h1><p>benzene threshold 10 ppb</p></body></html>"
DOM_V2 = b"<html><body><h1>Environmental dashboard</h1><p>benzene threshold 15 ppb</p></body></html>"
DATA_CALL = RenderedCall(
    url="https://example.gov/api/scores.json",
    method="GET",
    status=200,
    resource_type="xhr",
    body=b'{"benzene_ppb": 10}',
)


def _engine(dom: bytes, calls: tuple[RenderedCall, ...] = (DATA_CALL,)):
    def engine(url: str, *, timeout: float = 30.0) -> RenderResult:
        return RenderResult(
            final_url=url,
            status=200,
            headers={"content-type": "text/html"},
            rendered_dom=dom,
            calls=calls,
        )

    return engine


def _verderer(tmp_path: Path, engine) -> Verderer:
    return Verderer(
        tmp_path / "data",
        targets={"tool": RENDER_TARGET},
        terms=["climate change"],
        collectors={"render": RenderCollector(engine=engine)},
    )


def test_collect_captures_dom_and_data_calls() -> None:
    collected = RenderCollector(engine=_engine(DOM_V1)).collect(RENDER_TARGET)
    assert isinstance(collected, Collected)
    obs = collected.observation

    # The post-JS DOM is the primary attested artifact.
    assert collected.body == DOM_V1
    assert obs.collector_type == "render"
    assert obs.rendered_dom_hash == obs.raw_bytes_hash
    assert obs.captured_requests_hash is not None

    # Side artifacts = the request manifest + each captured response body.
    manifest_bytes, *bodies = collected.side_artifacts
    assert DATA_CALL.body in bodies
    manifest = json.loads(manifest_bytes)
    assert manifest["schema"] == "verderer.captured_requests/v1"
    assert len(manifest["calls"]) == 1
    call = manifest["calls"][0]
    assert call["url"] == DATA_CALL.url
    assert call["resource_type"] == "xhr"
    from verderer.hashing import multihash_sha256

    assert call["response_hash"] == multihash_sha256(DATA_CALL.body)


def test_manifest_hash_is_call_order_independent() -> None:
    # Response arrival order is timing noise; an identical set of data calls must hash
    # to the same captured_requests_hash regardless of the order the engine saw them.
    call_a = RenderedCall(url="https://e.gov/a.json", method="GET", status=200, resource_type="fetch", body=b'{"a":1}')
    call_b = RenderedCall(url="https://e.gov/b.json", method="GET", status=200, resource_type="xhr", body=b'{"b":2}')
    forward = RenderCollector(engine=_engine(DOM_V1, calls=(call_a, call_b))).collect(RENDER_TARGET)
    reverse = RenderCollector(engine=_engine(DOM_V1, calls=(call_b, call_a))).collect(RENDER_TARGET)
    assert forward.observation.captured_requests_hash == reverse.observation.captured_requests_hash
    assert set(forward.side_artifacts) == set(reverse.side_artifacts)


def test_pipeline_routes_render_target_and_stores_side_artifacts(tmp_path: Path, ledger_built: None) -> None:
    verderer = _verderer(tmp_path, _engine(DOM_V1))
    result = verderer.observe("tool")
    assert result.is_first
    obs = result.observation
    assert obs.collector_type == "render"

    # The attested DOM and the captured API/data calls are all resolvable from the store.
    assert verderer.store.get(obs.raw_bytes_hash) == DOM_V1
    manifest = json.loads(verderer.store.get(obs.captured_requests_hash))
    response_hash = manifest["calls"][0]["response_hash"]
    assert verderer.store.get(response_hash) == DATA_CALL.body


def test_detection_runs_on_rendered_dom(tmp_path: Path, ledger_built: None) -> None:
    # The whole point of rendering: a change in the *rendered* content (not the static
    # shell) is detected. "climate change" disappears from the post-JS DOM.
    engine = {"dom": DOM_V1}
    verderer = Verderer(
        tmp_path / "data",
        targets={"tool": RENDER_TARGET},
        terms=["climate change"],
        collectors={"render": RenderCollector(engine=lambda u, *, timeout=30.0: RenderResult(
            final_url=u, status=200, headers={}, rendered_dom=engine["dom"], calls=(DATA_CALL,)
        ))},
    )
    assert verderer.observe("tool").is_first
    engine["dom"] = DOM_V2
    diffs = verderer.observe("tool").diffs
    assert DiffType.TermSubstitution in {d.diff_type for d in diffs}


def test_render_observation_is_citable(tmp_path: Path, ledger_built: None) -> None:
    # A render observation flows through the proof bundle like any other: the attested
    # artifact (the rendered DOM) hashes correctly and the leaf verifies offline.
    verderer = _verderer(tmp_path, _engine(DOM_V1))
    verderer.observe("tool")
    ok, message = verderer.log.offline_verify(0)
    assert ok, message


def test_unregistered_collector_is_rejected(tmp_path: Path, ledger_built: None) -> None:
    verderer = Verderer(
        tmp_path / "data",
        targets={"x": Target(id="x", title="X", url="https://e.gov/x", collector="bogus")},
        terms=[],
        collectors={"static": RenderCollector(engine=_engine(DOM_V1))},  # no "bogus"
    )
    with pytest.raises(ValueError, match="bogus"):
        verderer.observe("x")


# --- gated live test: real Playwright against a localhost JS page ---


@pytest.fixture
def chromium_available() -> None:
    pytest.importorskip("playwright")
    from playwright.sync_api import sync_playwright

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
    except Exception as error:  # pragma: no cover - environment dependent
        pytest.skip(f"Chromium not installed (run `playwright install chromium`): {error}")


def test_live_playwright_renders_and_captures(chromium_available: None) -> None:  # pragma: no cover - gated
    import http.server
    import socketserver
    import threading

    from verderer.collectors.render import playwright_engine

    page_html = (
        b"<html><body><div id='out'>loading</div>"
        b"<script>fetch('/api/scores.json').then(r=>r.json())"
        b".then(d=>{document.getElementById('out').textContent='benzene='+d.benzene_ppb;});</script>"
        b"</body></html>"
    )
    data = b'{"benzene_ppb": 12}'

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            body = data if self.path == "/api/scores.json" else page_html
            ctype = "application/json" if self.path == "/api/scores.json" else "text/html"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args: object) -> None:
            pass

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as httpd:
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            result = playwright_engine(f"http://127.0.0.1:{port}/", timeout=15.0)
        finally:
            httpd.shutdown()

    assert b"benzene=12" in result.rendered_dom  # the JS ran and mutated the DOM
    scores = [c for c in result.calls if c.url.endswith("/api/scores.json")]
    assert scores and scores[0].body == data  # the page's own data call was captured
