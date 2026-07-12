"""Polite collection layer (DESIGN §2 hard constraint, §7): make every real fetch
robots-aware, rate-limited, backed-off, and conditional — so Druid never becomes a load
problem for a source, and re-observing an unchanged page costs the server (and the ledger)
nothing.

M0–M8 fetched courteously *by construction* (identifiable UA, bounded timeout, no
auth-walled/CAPTCHA access) but only *half*-met the stated constraint: no robots.txt, no
cross-run rate-limiting, no conditional GET. M9 closes that gap with one injectable
``PolitenessPolicy`` that wraps a collector's network seam:

* **robots.txt** — fetched once per host (cached with a TTL), parsed by the stdlib
  ``urllib.robotparser`` (no bespoke parsing), honoring ``Disallow`` and ``Crawl-delay``
  for our user agent. A disallowed URL is *never* fetched.
* **per-host rate-limiting** — a minimum interval between requests to a host (raised to the
  host's ``Crawl-delay`` when robots declares one), enforced through an injectable clock.
* **exponential backoff with jitter** — a transient error (429/5xx or a network exception)
  is retried with a capped, jittered backoff before giving up.
* **conditional GET** — the stored ``ETag`` / ``Last-Modified`` for a URL is sent as
  ``If-None-Match`` / ``If-Modified-Since``; a ``304 Not Modified`` means *no new
  observation is logged* (the bytes are unchanged, so there is nothing to attest).

The clock, the robots fetcher, and the jitter are all injectable, so the whole layer is
exercised offline with a fake clock and canned robots/responses — while the production
default drives real HTTP. This is a *courtesy* layer, not part of the trust core: it
decides only *whether and when* to fetch, never what is attested.
"""

from __future__ import annotations

import json
import os
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeVar
from urllib.parse import urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser

from .collectors.base import Fetcher, FetchResult, RenderEngine, RenderResult
from .collectors.static import USER_AGENT

# Transient HTTP statuses worth a backed-off retry (a temporary server condition, not a
# definitive answer). A persistent one after retries is surfaced as a failure, not logged.
DEFAULT_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})


class _HasStatus(Protocol):
    # A read-only property (not a bare attribute) so frozen dataclasses — FetchResult,
    # RenderResult — satisfy the bound; a bare `status: int` would demand a settable field.
    @property
    def status(self) -> int: ...


_R = TypeVar("_R", bound=_HasStatus)


# --- collection signals (control flow the pipeline maps to an observe outcome) ---------


class NotModified(Exception):
    """The conditional GET returned ``304`` — the resource is byte-identical to the last
    observation, so nothing new is fetched or logged."""


class CollectionSkipped(Exception):
    """robots.txt disallows this URL for our user agent — no fetch was performed."""


class TransientFetchError(Exception):
    """A transient error (429/5xx or a network exception) persisted after every retry."""


# --- injectable seams ------------------------------------------------------------------


class Clock(Protocol):
    """The scheduler's view of time — injectable so rate-limiting/backoff run on a fake
    clock in tests (no real sleeping) and a real one in production."""

    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    """The production clock: real monotonic time and real sleeping."""

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


class ConditionalFetcher(Protocol):
    """The network seam the polite fetcher wraps: like :class:`~druid.collectors.base.Fetcher`
    but able to carry conditional-GET request headers. ``httpx_fetcher`` satisfies it."""

    def __call__(self, url: str, *, timeout: float = ..., headers: Mapping[str, str] | None = ...) -> FetchResult: ...


class RobotsFetcher(Protocol):
    """Fetches a host's ``robots.txt`` and returns its text, or ``None`` when there is no
    usable policy to honor (missing / unreachable → fail-open; see :func:`httpx_robots_fetcher`)."""

    def __call__(self, robots_url: str) -> str | None: ...


class RenderFetcher(Protocol):
    """A headless-render seam (:class:`~druid.collectors.base.RenderEngine`) the polite
    wrapper guards with robots + rate-limit + backoff (no conditional GET — a render always
    yields the current DOM)."""

    def __call__(self, url: str, *, timeout: float = ...) -> RenderResult: ...


def _full_jitter(delay: float) -> float:
    """AWS "full jitter": a uniform sample in ``[0, delay]``. Injected as a constant in
    tests so backoff is deterministic."""
    return random.uniform(0.0, delay)


def httpx_robots_fetcher(robots_url: str, *, timeout: float = 15.0) -> str | None:
    """Default :class:`RobotsFetcher`: fetch ``robots.txt`` over HTTP with our identifiable
    UA. A ``200`` returns the policy text; anything else (404/410/5xx) or a network error
    returns ``None`` — *fail-open*.

    Fail-open is a deliberate, documented choice for this tool: the curated targets are a
    small, hand-vetted set of public-domain U.S. federal resources, and a flaky robots
    endpoint must not silently halt the watchdog. A *present* robots policy is honored
    strictly; only an absent/unreachable one is treated as "no rule to apply".
    """
    import httpx  # lazy: offline tests inject a fake robots fetcher and never import httpx

    try:
        with httpx.Client(follow_redirects=True, timeout=timeout, headers={"User-Agent": USER_AGENT}) as client:
            response = client.get(robots_url)
    except httpx.HTTPError:
        return None
    return response.text if response.status_code == 200 else None


@dataclass(frozen=True, slots=True)
class RetryConfig:
    max_retries: int = 4
    base_delay: float = 1.0
    max_delay: float = 60.0
    retry_statuses: frozenset[int] = DEFAULT_RETRY_STATUSES


def _host(url: str) -> str:
    return urlsplit(url).netloc.lower()


def _robots_url(url: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, "/robots.txt", "", ""))


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup (HTTP header names are case-insensitive; httpx and
    canned test headers differ in casing)."""
    lname = name.lower()
    for key, value in headers.items():
        if key.lower() == lname:
            return value
    return None


@dataclass
class _RobotsEntry:
    parser: RobotFileParser
    fetched_at: float


class PolitenessPolicy:
    """Courtesy gate around a collector's network seam. One instance is shared by a host's
    collectors so robots, rate-limit state, and conditional-GET validators are coordinated.

    Injectables: ``clock`` (rate-limit/backoff timing), ``robots_fetcher`` (robots.txt
    text), ``jitter`` (backoff randomness). ``state_path`` persists conditional-GET
    validators across observe calls / process restarts so ``304`` works at all.
    """

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        robots_fetcher: RobotsFetcher = httpx_robots_fetcher,
        jitter: Callable[[float], float] = _full_jitter,
        user_agent: str = USER_AGENT,
        min_interval: float = 1.0,
        retry: RetryConfig | None = None,
        robots_ttl: float = 86_400.0,
        respect_robots: bool = True,
        state_path: Path | None = None,
    ) -> None:
        self.clock: Clock = clock or SystemClock()
        self._robots_fetcher = robots_fetcher
        self._jitter = jitter
        self.user_agent = user_agent
        self.min_interval = min_interval
        self.retry = retry or RetryConfig()
        self.robots_ttl = robots_ttl
        self.respect_robots = respect_robots
        self.state_path = Path(state_path) if state_path is not None else None
        self._robots: dict[str, _RobotsEntry] = {}
        self._last_fetch_at: dict[str, float] = {}
        self._validators: dict[str, dict[str, str]] = self._load_validators()

    # -- robots ------------------------------------------------------------------------

    def _robots_for(self, url: str) -> RobotFileParser:
        host = _host(url)
        entry = self._robots.get(host)
        now = self.clock.monotonic()
        if entry is not None and (now - entry.fetched_at) < self.robots_ttl:
            return entry.parser
        parser = RobotFileParser()
        text = self._robots_fetcher(_robots_url(url))
        # An absent/unreachable robots.txt (text is None) parses to an empty ruleset, which
        # RobotFileParser treats as allow-all — exactly the fail-open behavior we want.
        parser.parse((text or "").splitlines())
        # RobotFileParser.can_fetch / crawl_delay return conservative defaults until the
        # file is marked "read" (last_checked set). parse() does this, but assert it
        # explicitly so we never depend on that CPython internal.
        parser.modified()
        self._robots[host] = _RobotsEntry(parser=parser, fetched_at=now)
        return parser

    def can_fetch(self, url: str) -> bool:
        if not self.respect_robots:
            return True
        return self._robots_for(url).can_fetch(self.user_agent, url)

    def crawl_delay(self, url: str) -> float | None:
        if not self.respect_robots:
            return None
        raw = self._robots_for(url).crawl_delay(self.user_agent)
        return float(raw) if raw is not None else None

    # -- rate limiting -----------------------------------------------------------------

    def _space(self, host: str, interval: float) -> None:
        """Wait, if needed, so consecutive requests to ``host`` are ≥ ``interval`` apart,
        then record this request's time. Uses the injected clock (a no-op wait offline)."""
        now = self.clock.monotonic()
        last = self._last_fetch_at.get(host)
        if last is not None:
            due = last + interval
            if now < due:
                self.clock.sleep(due - now)
        self._last_fetch_at[host] = self.clock.monotonic()

    def _backoff(self, attempt: int) -> None:
        capped = min(self.retry.max_delay, self.retry.base_delay * (2**attempt))
        self.clock.sleep(self._jitter(capped))

    # -- conditional GET validators ----------------------------------------------------

    def _load_validators(self) -> dict[str, dict[str, str]]:
        if self.state_path is None or not self.state_path.exists():
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            validators = data["validators"]
            return {str(k): dict(v) for k, v in validators.items()}
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            # A corrupt/partial courtesy cache (e.g. a crash mid-write, a truncated file)
            # must never crash the CLI — least of all the trust-core read paths
            # (`druid verify` / `log`), which do not depend on politeness at all. Discard
            # it; the next successful fetch rebuilds it (worst case: one unconditional GET).
            return {}

    def _save_validators(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        # Write-then-rename so a crash / disk-full / concurrent run can never leave a
        # half-written state file that would fail to parse on the next load. os.replace is
        # atomic within a filesystem on both POSIX and Windows.
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps({"validators": self._validators}, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.state_path)

    def conditional_headers(self, url: str) -> dict[str, str]:
        validators = self._validators.get(url)
        if not validators:
            return {}
        headers: dict[str, str] = {}
        if validators.get("etag"):
            headers["If-None-Match"] = validators["etag"]
        if validators.get("last_modified"):
            headers["If-Modified-Since"] = validators["last_modified"]
        return headers

    def _record_validators(self, url: str, response_headers: Mapping[str, str]) -> None:
        etag = _header(response_headers, "etag")
        last_modified = _header(response_headers, "last-modified")
        fresh = {k: v for k, v in {"etag": etag, "last_modified": last_modified}.items() if v}
        if fresh:
            self._validators[url] = fresh
            self._save_validators()

    def forget(self, url: str) -> None:
        """Drop any stored conditional-GET validator for ``url``, forcing the next fetch to
        be unconditional (a full ``200``). The pipeline calls this before the *first*
        observation of a target so a validator that has desynced from the ledger — a crash
        between saving the validator and appending the leaf, a ledger rebuild that leaves
        this cache behind, or two targets pointed at one URL — can never let a ``304``
        silently suppress a target's *baseline* attestation. A ``304`` may only ever
        suppress a leaf relative to a genuine prior observation of that same target."""
        if self._validators.pop(url, None) is not None:
            self._save_validators()

    # -- public wrappers ---------------------------------------------------------------

    def fetch(self, url: str, inner: ConditionalFetcher, *, timeout: float = 30.0) -> FetchResult:
        """Robots-check, rate-limit, conditional-GET, and backoff-retry a static fetch.

        Returns the ``FetchResult`` on success. Raises :class:`CollectionSkipped` (robots
        disallow), :class:`NotModified` (``304``), or :class:`TransientFetchError`
        (transient error survived every retry).
        """
        if not self.can_fetch(url):
            raise CollectionSkipped(f"robots.txt disallows {url} for {self.user_agent!r}")
        headers = self.conditional_headers(url)
        host = _host(url)
        interval = max(self.min_interval, self.crawl_delay(url) or 0.0)

        result = self._attempt(host, interval, lambda: inner(url, timeout=timeout, headers=headers), url)
        if result.status == 304:
            raise NotModified(url)
        self._record_validators(url, dict(result.headers))
        return result

    def render(self, url: str, inner: RenderFetcher, *, timeout: float = 30.0) -> RenderResult:
        """Robots-check, rate-limit, and backoff-retry a headless render. No conditional
        GET (a render always produces the current DOM). Raises :class:`CollectionSkipped`
        or :class:`TransientFetchError`."""
        if not self.can_fetch(url):
            raise CollectionSkipped(f"robots.txt disallows {url} for {self.user_agent!r}")
        host = _host(url)
        interval = max(self.min_interval, self.crawl_delay(url) or 0.0)
        return self._attempt(host, interval, lambda: inner(url, timeout=timeout), url)

    def _attempt(self, host: str, interval: float, call: Callable[[], _R], url: str) -> _R:
        """Shared retry driver: space each attempt against the host budget, retry a
        transient status or a network exception with jittered backoff, give up after
        ``max_retries``. ``call`` is a zero-arg thunk returning a result with a ``.status``."""
        last_exc: Exception | None = None
        for attempt in range(self.retry.max_retries + 1):
            self._space(host, interval)
            try:
                result = call()
            except Exception as exc:  # a network error — retry with backoff, then give up
                last_exc = exc
                if attempt == self.retry.max_retries:
                    raise TransientFetchError(f"{url}: {exc}") from exc
                self._backoff(attempt)
                continue
            if result.status in self.retry.retry_statuses:
                if attempt == self.retry.max_retries:
                    raise TransientFetchError(f"{url}: HTTP {result.status} after {attempt + 1} attempts")
                self._backoff(attempt)
                continue
            return result
        raise TransientFetchError(f"{url}: {last_exc}")  # pragma: no cover - loop always returns/raises

    # -- collector adapters ------------------------------------------------------------

    def fetcher(self, inner: ConditionalFetcher) -> Fetcher:
        """Adapt this policy into a :class:`~druid.collectors.base.Fetcher` the static
        collector can use unchanged: it calls ``fetch(url)`` and gets a ``FetchResult`` or
        one of the collection signals."""

        def polite(url: str, *, timeout: float = 30.0) -> FetchResult:
            return self.fetch(url, inner, timeout=timeout)

        return polite

    def engine(self, inner: RenderFetcher) -> RenderEngine:
        """Adapt this policy into a :class:`~druid.collectors.base.RenderEngine`."""

        def polite(url: str, *, timeout: float = 30.0) -> RenderResult:
            return self.render(url, inner, timeout=timeout)

        return polite
