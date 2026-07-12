"""M9 — polite collection layer. Offline via an injected fake clock + canned robots/
responses (no real sleeping, no network): a Disallow-ed path is never fetched, requests
to one host are spaced by the min interval / Crawl-delay, a 304 conditional GET yields no
new leaf, and a transient 503 is retried with backoff before succeeding. A gated live test
does one real polite fetch of a curated target. Ledger-backed cases skip if the Rust
kernel isn't built.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

from druid.collectors.base import FetchResult, RenderResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.pipeline import Druid
from druid.politeness import (
    CollectionSkipped,
    NotModified,
    PolitenessPolicy,
    RetryConfig,
    TransientFetchError,
)

# --- test doubles ----------------------------------------------------------------------


class FakeClock:
    """A virtual clock: monotonic() advances only when sleep() is called, and every sleep
    is recorded — so rate-limiting/backoff are asserted without wall-clock time passing."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.sleeps.append(seconds)
            self.now += seconds


class CannedFetcher:
    """A conditional Fetcher returning programmed responses and recording the request
    headers it saw (to prove conditional-GET validators were sent)."""

    def __init__(self, responses: list[FetchResult]) -> None:
        self._responses = list(responses)
        self.seen_headers: list[dict[str, str]] = []

    def __call__(self, url: str, *, timeout: float = 30.0, headers: Mapping[str, str] | None = None) -> FetchResult:
        self.seen_headers.append(dict(headers or {}))
        return self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]


def _ok(body: bytes = b"<html>hello</html>", *, etag: str | None = None, status: int = 200) -> FetchResult:
    headers = {"Content-Type": "text/html"}
    if etag is not None:
        headers["ETag"] = etag
    return FetchResult(url="https://example.gov/p", status=status, headers=headers, body=body)


def _policy(clock: FakeClock, robots: str | None, **kw: object) -> PolitenessPolicy:
    # jitter -> full delay (deterministic, non-zero) so backoff sleeps are observable.
    kw.setdefault("min_interval", 0.0)
    kw.setdefault("jitter", lambda d: d)
    return PolitenessPolicy(clock=clock, robots_fetcher=lambda _u: robots, **kw)  # type: ignore[arg-type]


# --- robots.txt: Disallow --------------------------------------------------------------


def test_disallowed_path_is_not_fetched() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok()])
    policy = _policy(clock, "User-agent: *\nDisallow: /secret/\n")
    with pytest.raises(CollectionSkipped):
        policy.fetch("https://example.gov/secret/page", inner)
    assert inner.seen_headers == []  # never called — no network touched


def test_allowed_path_is_fetched() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok()])
    policy = _policy(clock, "User-agent: *\nDisallow: /secret/\n")
    result = policy.fetch("https://example.gov/public", inner)
    assert result.status == 200
    assert len(inner.seen_headers) == 1


def test_missing_robots_allows_everything() -> None:
    # A missing/unreachable robots.txt (fetcher -> None) is fail-open: allow-all.
    clock = FakeClock()
    inner = CannedFetcher([_ok()])
    policy = _policy(clock, None)
    assert policy.fetch("https://example.gov/anything", inner).status == 200


def test_robots_is_fetched_once_and_cached() -> None:
    calls = {"n": 0}

    def robots_fetcher(_url: str) -> str:
        calls["n"] += 1
        return "User-agent: *\nDisallow: /x/\n"

    policy = PolitenessPolicy(clock=FakeClock(), robots_fetcher=robots_fetcher, min_interval=0.0)
    inner = CannedFetcher([_ok()])
    policy.fetch("https://example.gov/a", inner)
    policy.fetch("https://example.gov/b", inner)
    assert calls["n"] == 1  # cached within the TTL, one robots fetch per host


# --- rate limiting + Crawl-delay -------------------------------------------------------


def test_rate_limit_spaces_consecutive_requests() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok()])
    policy = _policy(clock, None, min_interval=5.0)
    policy.fetch("https://host.gov/a", inner)  # first: no prior, no wait
    policy.fetch("https://host.gov/b", inner)  # second: must wait >= min_interval
    assert clock.sleeps == [5.0]


def test_crawl_delay_overrides_min_interval() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok()])
    policy = _policy(clock, "User-agent: *\nCrawl-delay: 7\n", min_interval=1.0)
    policy.fetch("https://host.gov/a", inner)
    policy.fetch("https://host.gov/b", inner)
    assert clock.sleeps == [7.0]  # Crawl-delay (7) wins over the 1s floor


def test_different_hosts_are_not_spaced_against_each_other() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok()])
    policy = _policy(clock, None, min_interval=5.0)
    policy.fetch("https://a.gov/p", inner)
    policy.fetch("https://b.gov/p", inner)  # different host — no wait
    assert clock.sleeps == []


# --- backoff on transient errors -------------------------------------------------------


def test_transient_503_retries_then_succeeds() -> None:
    clock = FakeClock()
    # 503 then 200: one retry, one backoff sleep, then success.
    inner = CannedFetcher([_ok(status=503), _ok(status=200, body=b"ok")])
    policy = _policy(clock, None, retry=RetryConfig(base_delay=1.0))
    result = policy.fetch("https://host.gov/p", inner)
    assert result.status == 200 and result.body == b"ok"
    assert clock.sleeps == [1.0]  # base_delay * 2**0, full jitter
    assert len(inner.seen_headers) == 2  # exactly two attempts


def test_backoff_grows_exponentially() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok(status=503), _ok(status=503), _ok(status=200)])
    policy = _policy(clock, None, retry=RetryConfig(base_delay=1.0, max_retries=4))
    policy.fetch("https://host.gov/p", inner)
    assert clock.sleeps == [1.0, 2.0]  # 1*2^0, 1*2^1


def test_backoff_is_capped() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok(status=503)] * 5 + [_ok(status=200)])
    policy = _policy(clock, None, retry=RetryConfig(base_delay=10.0, max_delay=15.0, max_retries=6))
    policy.fetch("https://host.gov/p", inner)
    assert max(clock.sleeps) <= 15.0  # 10, 15 (capped), 15, ...


def test_transient_error_gives_up_after_max_retries() -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok(status=503)])  # always 503
    policy = _policy(clock, None, retry=RetryConfig(base_delay=1.0, max_retries=3))
    with pytest.raises(TransientFetchError):
        policy.fetch("https://host.gov/p", inner)
    assert len(inner.seen_headers) == 4  # max_retries + 1 attempts


def test_network_exception_is_retried() -> None:
    clock = FakeClock()
    attempts = {"n": 0}

    def flaky(url: str, *, timeout: float = 30.0, headers: Mapping[str, str] | None = None) -> FetchResult:
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ConnectionError("boom")
        return _ok(status=200)

    policy = _policy(clock, None, retry=RetryConfig(base_delay=1.0))
    assert policy.fetch("https://host.gov/p", flaky).status == 200
    assert attempts["n"] == 2 and clock.sleeps == [1.0]


# --- conditional GET -------------------------------------------------------------------


def test_conditional_get_sends_validators_and_304_raises_not_modified() -> None:
    clock = FakeClock()
    # First 200 carries an ETag; the second call should send If-None-Match and get a 304.
    inner = CannedFetcher([_ok(status=200, etag='"v1"'), _ok(status=304, etag='"v1"')])
    policy = _policy(clock, None)
    first = policy.fetch("https://example.gov/p", inner)
    assert first.status == 200
    assert inner.seen_headers[0] == {}  # no validator on the first request
    with pytest.raises(NotModified):
        policy.fetch("https://example.gov/p", inner)
    assert inner.seen_headers[1].get("If-None-Match") == '"v1"'


def test_last_modified_validator_is_sent() -> None:
    clock = FakeClock()
    lm = "Wed, 09 Jul 2026 10:00:00 GMT"
    inner = CannedFetcher(
        [
            FetchResult(url="https://example.gov/p", status=200, headers={"Last-Modified": lm}, body=b"x"),
            FetchResult(url="https://example.gov/p", status=304, headers={}, body=b""),
        ]
    )
    policy = _policy(clock, None)
    policy.fetch("https://example.gov/p", inner)
    with pytest.raises(NotModified):
        policy.fetch("https://example.gov/p", inner)
    assert inner.seen_headers[1].get("If-Modified-Since") == lm


def test_validators_persist_across_policy_instances(tmp_path: Path) -> None:
    state = tmp_path / "politeness-state.json"
    inner = CannedFetcher([_ok(status=200, etag='"vX"')])
    PolitenessPolicy(clock=FakeClock(), robots_fetcher=lambda _u: None, min_interval=0.0, state_path=state).fetch(
        "https://example.gov/p", inner
    )
    assert state.exists()
    # A fresh policy (new process) loads the stored validator and sends it.
    inner2 = CannedFetcher([_ok(status=304, etag='"vX"')])
    reloaded = PolitenessPolicy(clock=FakeClock(), robots_fetcher=lambda _u: None, min_interval=0.0, state_path=state)
    with pytest.raises(NotModified):
        reloaded.fetch("https://example.gov/p", inner2)
    assert inner2.seen_headers[0].get("If-None-Match") == '"vX"'


# --- render path: robots + rate-limit (no conditional GET) -----------------------------


def _render(url: str, *, timeout: float = 30.0) -> RenderResult:
    return RenderResult(final_url=url, status=200, headers={}, rendered_dom=b"<html>dom</html>")


def test_render_respects_robots_disallow() -> None:
    policy = _policy(FakeClock(), "User-agent: *\nDisallow: /app/\n")
    with pytest.raises(CollectionSkipped):
        policy.render("https://example.gov/app/tool", _render)


def test_render_is_rate_limited() -> None:
    clock = FakeClock()
    policy = _policy(clock, None, min_interval=4.0)
    policy.render("https://host.gov/a", _render)
    policy.render("https://host.gov/b", _render)
    assert clock.sleeps == [4.0]


# --- pipeline integration --------------------------------------------------------------

TARGET = Target(id="t", title="T", url="https://example.gov/p", collector="static")


def _druid(tmp_path: Path, inner: CannedFetcher, robots: str | None, clock: FakeClock | None = None) -> Druid:
    policy = PolitenessPolicy(
        clock=clock or FakeClock(),
        robots_fetcher=lambda _u: robots,
        min_interval=0.0,
        jitter=lambda d: d,
        state_path=tmp_path / "pol.json",
    )
    return Druid(
        tmp_path / "data",
        targets={"t": TARGET},
        terms=["climate"],
        collectors={"static": StaticCollector(fetcher=policy.fetcher(inner))},
        politeness=policy,
    )


def _entry_count(druid: Druid) -> int:
    return len(list(druid.log.entries()))


def test_pipeline_304_yields_no_new_leaf(tmp_path: Path, ledger_built: None) -> None:
    inner = CannedFetcher([_ok(status=200, etag='"v1"'), _ok(status=304, etag='"v1"')])
    druid = _druid(tmp_path, inner, robots=None)
    first = druid.observe("t")
    assert first.status == "observed" and first.is_first
    count_after_first = _entry_count(druid)

    second = druid.observe("t")
    assert second.status == "unchanged"
    assert second.observation is None
    assert _entry_count(druid) == count_after_first  # no leaf appended on a 304
    assert druid.log.offline_verify(0)[0]  # the ledger is still valid


def test_pipeline_disallow_is_skipped_with_no_leaf(tmp_path: Path, ledger_built: None) -> None:
    inner = CannedFetcher([_ok(status=200)])
    druid = _druid(tmp_path, inner, robots="User-agent: *\nDisallow: /p\n")
    result = druid.observe("t")
    assert result.status == "skipped"
    assert result.observation is None
    assert "robots" in result.reason
    assert _entry_count(druid) == 0  # nothing fetched or logged
    assert inner.seen_headers == []


def test_pipeline_transient_then_success_logs_one_leaf(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeClock()
    inner = CannedFetcher([_ok(status=503), _ok(status=200, body=b"<html>climate ok</html>")])
    druid = _druid(tmp_path, inner, robots=None, clock=clock)
    result = druid.observe("t")
    assert result.status == "observed"
    assert result.observation is not None and result.observation.http_status == 200
    assert clock.sleeps == [1.0]  # one backoff before the retry succeeded


def test_default_collectors_are_polite(tmp_path: Path) -> None:
    # A Druid built without injected collectors wires a real PolitenessPolicy into both the
    # static and render seams — polite by construction (the M9 hard constraint).
    druid = Druid(tmp_path / "data", targets={}, terms=[])
    assert druid.politeness is not None
    assert set(druid.collectors) == {"static", "render"}


# --- gated live test: one real polite fetch of a curated target ------------------------


@pytest.fixture
def network() -> None:
    httpx = pytest.importorskip("httpx")
    try:
        httpx.get("https://www.epa.gov/robots.txt", timeout=10.0)
    except Exception as error:  # pragma: no cover - environment dependent
        pytest.skip(f"no network: {error}")


def test_live_polite_fetch_of_real_target(network: None) -> None:  # pragma: no cover - gated
    from druid.collectors.static import httpx_fetcher

    policy = PolitenessPolicy(min_interval=1.0)  # real clock, real robots fetcher
    url = "https://www.epa.gov/ghgreporting"
    # robots.txt is really fetched, parsed, and honored; the page is really fetched.
    if not policy.can_fetch(url):
        pytest.skip("target is disallowed by live robots.txt")
    result = policy.fetch(url, httpx_fetcher, timeout=30.0)
    assert result.status in (200, 301, 302, 304)
    assert result.body  # got real bytes
