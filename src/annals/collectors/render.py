"""Render collector: a headless-browser capture of a JS-rendered page (DESIGN §7, M3b).

Static collection sees only the initial HTML — for a JavaScript tool (EJScreen, an
interactive map/dashboard) that shell is nearly empty and the real content arrives via
the page's own API/data calls. This collector drives a headless browser to capture two
things faithfully:

* the **rendered DOM** after the network goes idle (the post-JS content) — the primary
  attested artifact, so detection (term/numeric watch) runs on what a *reader* sees;
* the page's **own API/data calls** (XHR/fetch) — each response body stored
  content-addressed, referenced by hash from a canonical request manifest.

The browser is injected behind the :class:`RenderEngine` port, so tests exercise the
collector with a fake engine and need no browser. The default engine drives Playwright
(an optional dependency, lazily imported); collection stays polite — an identifiable
user agent, a bounded timeout, no auth-walled or CAPTCHA-bypassing access. (Robots-
awareness and cross-run rate-limiting arrive with the scheduler, as for ``static``.)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..config import Target
from ..hashing import multihash_sha256
from ..models import Observation
from .base import Capture, Collected, RenderedCall, RenderEngine, RenderResult

USER_AGENT = "AnnalsWatchdog/0.0 (+https://github.com/satchmakua/annals) polite-archival-collector; headless"

# The resource types we treat as the page's data calls (not decoration).
DATA_RESOURCE_TYPES = frozenset({"xhr", "fetch"})


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def playwright_engine(url: str, *, timeout: float = 30.0, settle: float = 3.0) -> RenderResult:
    """The default :class:`RenderEngine`: headless Chromium via Playwright.

    Lazily imports Playwright so the dependency is needed only when actually rendering
    (``pip install 'annals[render]'`` + ``playwright install chromium``).

    Load strategy: wait for ``domcontentloaded`` (reliable — it always fires), then a
    *bounded* ``networkidle`` settle so client-side JS can issue its data calls, but
    capture whatever rendered if that window elapses. Plain ``networkidle`` is avoided
    deliberately: a live map/dashboard that polls or streams (SSE) never goes idle, so it
    would time out and yield *no* observation — failing hardest on exactly the JS-heavy
    pages this collector exists for.
    """
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError  # lazy: optional dep
    from playwright.sync_api import sync_playwright

    calls: list[RenderedCall] = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context = browser.new_context(user_agent=USER_AGENT)
            page = context.new_page()

            def _on_response(response: object) -> None:
                try:
                    request = response.request  # type: ignore[attr-defined]
                    if request.resource_type not in DATA_RESOURCE_TYPES:
                        return
                    body = response.body()  # type: ignore[attr-defined]
                    calls.append(
                        RenderedCall(
                            url=response.url,  # type: ignore[attr-defined]
                            method=request.method,
                            status=response.status,  # type: ignore[attr-defined]
                            resource_type=request.resource_type,
                            body=body,
                        )
                    )
                except Exception:  # a redirect / bodyless response — skip, never fail the render
                    return

            page.on("response", _on_response)
            response = page.goto(url, wait_until="domcontentloaded", timeout=int(timeout * 1000))
            try:
                page.wait_for_load_state("networkidle", timeout=int(settle * 1000))
            except PlaywrightTimeoutError:
                pass  # a page that polls/streams forever — capture what rendered by now
            rendered_dom = page.content().encode("utf-8")
            final_url = page.url
            status = response.status if response is not None else 0
            headers = dict(response.headers) if response is not None else {}
        finally:
            browser.close()

    return RenderResult(
        final_url=final_url,
        status=status,
        headers=headers,
        rendered_dom=rendered_dom,
        calls=tuple(calls),
    )


class RenderCollector:
    type = "render"
    version = "0.1.0"

    def __init__(self, engine: RenderEngine = playwright_engine) -> None:
        self._render = engine

    def collect(self, target: Target) -> Collected:
        result = self._render(target.url)

        # The page's own data calls: store each response body, reference it by hash in a
        # canonical manifest. The manifest is itself a content-addressed side artifact.
        # Sort by a stable key so an identical set of calls hashes identically — response
        # *arrival* order is timing noise and must not perturb captured_requests_hash.
        manifest_calls = sorted(
            (
                {
                    "url": call.url,
                    "method": call.method,
                    "status": call.status,
                    "resource_type": call.resource_type,
                    "response_hash": multihash_sha256(call.body),
                }
                for call in result.calls
            ),
            key=lambda c: (c["url"], c["method"], c["status"], c["response_hash"]),
        )
        manifest = {
            "schema": "annals.captured_requests/v1",
            "final_url": result.final_url,
            "calls": manifest_calls,
        }
        manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
        side_artifacts = (manifest_bytes, *(call.body for call in result.calls))

        headers_canon = json.dumps(dict(sorted(result.headers.items())), separators=(",", ":")).encode()
        dom_hash = multihash_sha256(result.rendered_dom)
        fetched_at = _utc_now()
        observation = Observation(
            target_id=target.id,
            url=result.final_url,
            collector_type=self.type,
            collector_version=self.version,
            fetched_at=fetched_at,
            http_status=result.status,
            raw_bytes_hash=dom_hash,  # the primary artifact IS the rendered DOM
            response_headers_hash=multihash_sha256(headers_canon),
            rendered_dom_hash=dom_hash,  # explicit: this body is a post-JS DOM
            captured_requests_hash=multihash_sha256(manifest_bytes),
        )
        # The rendered DOM is a *derived* artifact (post-JS), not a byte-for-byte HTTP
        # response, so it is archived as a WARC `resource` record — the honest type.
        capture = Capture(
            target_uri=result.final_url,
            fetched_at=fetched_at,
            record_type="resource",
            status=result.status,
            content_type="text/html; charset=utf-8",
        )
        return Collected(
            observation=observation, body=result.rendered_dom, side_artifacts=side_artifacts, capture=capture
        )
