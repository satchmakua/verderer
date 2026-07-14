"""M10 — the scheduler. Offline via a fake wall clock + injected collectors (no network,
no real sleeping): a due target is re-observed and a changed page produces a diff AND a
notify delivery; a not-yet-due target is skipped; schedule state survives a restart; --once
processes exactly the due set; a failed target is retried, not lost. Ledger-backed cases
skip if the Rust kernel isn't built.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path

import pytest

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target, parse_duration
from druid.pipeline import Druid
from druid.politeness import PolitenessPolicy
from druid.scheduler import ScheduleEntry, Scheduler

# --- test doubles ----------------------------------------------------------------------


class FakeWallClock:
    """A settable epoch clock: now() returns a virtual time, sleep() records + advances it."""

    def __init__(self, start: float = 1_000_000.0) -> None:
        self.t = start
        self.sleeps: list[float] = []

    def now(self) -> float:
        return self.t

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            self.sleeps.append(seconds)
            self.t += seconds

    def advance(self, seconds: float) -> None:
        self.t += seconds


class MutableFetcher:
    """Returns a programmed body per call (the last repeats), so re-observes can 'change'."""

    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = list(bodies)
        self.calls = 0

    def __call__(self, url: str, *, timeout: float = 30.0, headers: Mapping[str, str] | None = None) -> FetchResult:
        body = self.bodies[min(self.calls, len(self.bodies) - 1)]
        self.calls += 1
        return FetchResult(url=url, status=200, headers={}, body=body)


class FlakyFetcher:
    """Raises for the first ``fail_times`` calls, then returns 200 — models a transient
    outage that outlives M9's in-fetch backoff and reaches the scheduler as an exception."""

    def __init__(self, fail_times: int) -> None:
        self.fail_times = fail_times
        self.calls = 0

    def __call__(self, url: str, *, timeout: float = 30.0, headers: Mapping[str, str] | None = None) -> FetchResult:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise ConnectionError("origin down")
        return FetchResult(url=url, status=200, headers={}, body=b"<html>climate ok</html>")


class RecordingNotify:
    """Stands in for the M5c notify pipeline: delivers each diff event once (idempotent),
    counting deliveries so a test can assert an alert fired for a new change."""

    def __init__(self) -> None:
        self.seen: set[str] = set()
        self.calls = 0

    def __call__(self, druid: Druid) -> list[dict[str, object]]:
        from druid.notify import events

        self.calls += 1
        deliveries: list[dict[str, object]] = []
        for event in events(druid):
            if event["id"] not in self.seen:
                self.seen.add(str(event["id"]))
                deliveries.append({"subscription": "s", "channel": "webhook", "event": event["id"], "dest": "x"})
        return deliveries


NO_JITTER = lambda interval, fraction: 0.0  # noqa: E731 - deterministic scheduling in tests


def _target(tid: str, interval: float = 100.0, collector: str = "static") -> Target:
    return Target(id=tid, title=tid, url=f"https://example.gov/{tid}", collector=collector, interval_seconds=interval)


def _druid(tmp_path: Path, targets: dict[str, Target], fetcher: object, terms: list[str] | None = None) -> Druid:
    return Druid(
        tmp_path / "data",
        targets=targets,
        terms=terms or [],
        collectors={"static": StaticCollector(fetcher=fetcher)},  # type: ignore[arg-type]
    )


def _scheduler(druid: Druid, clock: FakeWallClock, notify: object = None, **kw: object) -> Scheduler:
    kw.setdefault("jitter", NO_JITTER)
    return Scheduler(druid, clock=clock, notify=notify, **kw)  # type: ignore[arg-type]


# --- duration parsing ------------------------------------------------------------------


def test_parse_duration() -> None:
    assert parse_duration("90s") == 90
    assert parse_duration("30m") == 1800
    assert parse_duration("6h") == 21600
    assert parse_duration("1d") == 86400
    assert parse_duration("120") == 120  # bare number = seconds
    assert parse_duration(300) == 300.0


def test_parse_duration_rejects_non_positive() -> None:
    # A 0 / negative interval would make the scheduler treat a target as perpetually due and
    # hot-spin the loop; a config typo must fail fast at load, not silently wedge the watchdog.
    for bad in ("0s", "0", "-5", "-1h"):
        with pytest.raises(ValueError):
            parse_duration(bad)


# --- due / not-due ---------------------------------------------------------------------


def test_due_target_observed_not_yet_due_skipped(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    targets = {"fast": _target("fast", interval=100.0), "slow": _target("slow", interval=10_000.0)}
    druid = _druid(tmp_path, targets, MutableFetcher([b"<html>a</html>"]))
    sched = _scheduler(druid, clock)

    first = sched.run_due()  # both fresh -> both due
    assert set(first.observed) == {"fast", "slow"}

    clock.advance(100.0)  # only 'fast' comes due again (slow next_due is +10000)
    second = sched.run_due()
    # 'fast' was re-observed (identical content -> deduped to "unchanged"); 'slow' untouched.
    assert second.due_count == 1
    assert second.unchanged == ["fast"]
    assert "slow" not in second.unchanged and "slow" not in second.observed


# --- changed page -> diff + notify -----------------------------------------------------


def test_changed_page_produces_diff_and_notify(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    body_v1 = b"<html>climate change is real; reporting threshold 10 ppb</html>"
    body_v2 = b"<html>weather variability is real; reporting threshold 10 ppb</html>"
    druid = _druid(
        tmp_path, {"t": _target("t", interval=100.0)}, MutableFetcher([body_v1, body_v2]), terms=["climate change"]
    )
    notify = RecordingNotify()
    sched = _scheduler(druid, clock, notify=notify)

    first = sched.run_due()  # baseline, no diff
    assert first.observed == ["t"] and first.diffs == 0 and first.deliveries == 0

    clock.advance(100.0)
    second = sched.run_due()  # "climate change" removed -> a diff, and an alert fires
    assert second.diffs >= 1
    assert second.deliveries >= 1
    assert notify.calls == 2  # fired once per tick


# --- persistence across restart --------------------------------------------------------


def test_schedule_state_persists_across_restart(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    targets = {"a": _target("a", interval=1_000.0), "b": _target("b", interval=1_000.0)}
    druid = _druid(tmp_path, targets, MutableFetcher([b"<html>x</html>"]))
    sched = _scheduler(druid, clock)
    sched.run_due()  # both observed, next_due = now + 1000, state saved to disk
    due_a = sched.entries["a"].next_due
    assert (tmp_path / "data" / "schedule-state.json").exists()

    # A fresh scheduler (process restart) at the same time must resume, not re-observe.
    restarted = _scheduler(_druid(tmp_path, targets, MutableFetcher([b"<html>x</html>"])), clock)
    assert restarted.entries["a"].next_due == due_a
    assert restarted.run_due().due_count == 0  # nothing due yet -> no re-hit after restart


# --- --once processes exactly the due set ----------------------------------------------


def test_once_processes_exactly_the_due_set(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    now = clock.now()
    targets = {tid: _target(tid, interval=1_000.0) for tid in ("a", "b", "c")}
    # Pre-seed schedule state: a,b due now; c due in the future.
    state = {
        "entries": [
            {"target_id": "a", "next_due": now - 1, "last_run": None, "last_status": "", "consecutive_failures": 0},
            {"target_id": "b", "next_due": now, "last_run": None, "last_status": "", "consecutive_failures": 0},
            {"target_id": "c", "next_due": now + 5_000, "last_run": None, "last_status": "", "consecutive_failures": 0},
        ]
    }
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "schedule-state.json").write_text(json.dumps(state), encoding="utf-8")

    druid = _druid(tmp_path, targets, MutableFetcher([b"<html>x</html>"]))
    sched = _scheduler(druid, clock)
    result = sched.run_due()
    assert set(result.observed) == {"a", "b"}  # exactly the due set; c untouched
    assert "c" not in result.observed


# --- failure is retried, not lost ------------------------------------------------------


def test_failed_target_is_retried_not_lost(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    # Large cadence so the retry (capped at 300s) is demonstrably SOONER than a full cycle.
    druid = _druid(tmp_path, {"t": _target("t", interval=100_000.0)}, FlakyFetcher(fail_times=1))
    sched = _scheduler(druid, clock)
    now0 = clock.now()

    first = sched.run_due()
    assert first.errored and first.errored[0].startswith("t:")  # recorded, not dropped
    entry = sched.entries["t"]
    assert entry.last_status == "error" and entry.consecutive_failures == 1
    assert entry.next_due == now0 + 300.0  # retry soon (< the 100000s cadence)

    clock.advance(300.0)  # retry window arrives
    second = sched.run_due()
    assert second.observed == ["t"]  # the retry succeeded
    assert sched.entries["t"].consecutive_failures == 0  # failure counter reset


# --- 304 through the scheduler ---------------------------------------------------------


class ConditionalOrigin:
    def __init__(self, etag: str) -> None:
        self.etag = etag

    def __call__(self, url: str, *, timeout: float = 30.0, headers: Mapping[str, str] | None = None) -> FetchResult:
        if dict(headers or {}).get("If-None-Match") == self.etag:
            return FetchResult(url=url, status=304, headers={"ETag": self.etag}, body=b"")
        return FetchResult(url=url, status=200, headers={"ETag": self.etag}, body=b"<html>same</html>")


def test_unchanged_304_is_no_diff_no_alert(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    policy = PolitenessPolicy(robots_fetcher=lambda _u: None, min_interval=0.0, state_path=tmp_path / "pol.json")
    target = _target("t", interval=100.0)
    druid = Druid(
        tmp_path / "data",
        targets={"t": target},
        terms=[],
        collectors={"static": StaticCollector(fetcher=policy.fetcher(ConditionalOrigin(etag='"v1"')))},
        politeness=policy,
    )
    notify = RecordingNotify()
    sched = _scheduler(druid, clock, notify=notify)

    first = sched.run_due()
    assert first.observed == ["t"]

    clock.advance(100.0)
    second = sched.run_due()  # conditional GET -> 304
    assert second.unchanged == ["t"]
    assert second.diffs == 0 and second.deliveries == 0  # nothing changed -> no alert


# --- jitter + loop ---------------------------------------------------------------------


def test_jitter_offsets_next_due(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    druid = _druid(tmp_path, {"t": _target("t", interval=100.0)}, MutableFetcher([b"<html>x</html>"]))
    # jitter returns +half the interval, deterministically.
    sched = _scheduler(druid, clock, jitter=lambda interval, fraction: 0.5 * interval)
    now0 = clock.now()
    sched.run_due()
    assert sched.entries["t"].next_due == now0 + 100.0 + 50.0


def test_run_forever_is_bounded_for_service_loop(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    druid = _druid(tmp_path, {"t": _target("t", interval=100.0)}, MutableFetcher([b"<html>x</html>"]))
    sched = _scheduler(druid, clock)
    sched.run_forever(poll_cap=50.0, max_iterations=3)
    # 3 ticks: tick0 observes (next_due=+100), then each loop sleeps <= poll_cap.
    assert len(clock.sleeps) == 3
    assert all(s <= 50.0 for s in clock.sleeps)


def test_notify_failure_does_not_kill_the_loop(tmp_path: Path, ledger_built: None) -> None:
    # Regression (M10 review): a failing alert pass (e.g. a corrupt notify state) must be
    # recorded, never propagate out of run_due and kill the whole watchdog. Observation of
    # the target must still happen and the target must still be rescheduled.
    clock = FakeWallClock()

    def boom(_druid: Druid) -> list[dict[str, object]]:
        raise RuntimeError("notify blew up")

    druid = _druid(tmp_path, {"t": _target("t", interval=100.0)}, MutableFetcher([b"<html>x</html>"]))
    sched = _scheduler(druid, clock, notify=boom)
    result = sched.run_due()  # must not raise
    assert result.observed == ["t"]  # observation happened despite the notify failure
    assert result.notify_error and "blew up" in result.notify_error
    assert sched.entries["t"].next_due > clock.now()  # rescheduled, not stuck


def test_retry_backoff_never_overflows_on_a_long_dead_target(tmp_path: Path, ledger_built: None) -> None:
    # Regression (M10 review): a permanently-dead target that fails every cycle would grow
    # the backoff exponent until 2**n overflowed float (~1025 failures) and crashed the loop.
    clock = FakeWallClock()
    druid = _druid(tmp_path, {"t": _target("t", interval=100_000.0)}, FlakyFetcher(fail_times=10_000))
    sched = _scheduler(druid, clock)
    sched.entries["t"] = ScheduleEntry(target_id="t", next_due=clock.now(), consecutive_failures=2_000)
    result = sched.run_due()  # would raise OverflowError before the fix
    assert result.errored  # the failure is recorded, not fatal
    entry = sched.entries["t"]
    assert entry.consecutive_failures == 2_001
    assert math.isfinite(entry.next_due)
    assert entry.next_due - clock.now() <= 3_600.0  # capped at RETRY_MAX


def test_corrupt_schedule_state_starts_fresh(tmp_path: Path) -> None:
    (tmp_path / "data").mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "schedule-state.json").write_text("{ broken json", encoding="utf-8")
    druid = _druid(tmp_path, {"t": _target("t")}, MutableFetcher([b"<html>x</html>"]))
    sched = Scheduler(druid, clock=FakeWallClock(), jitter=NO_JITTER)  # must not raise
    assert sched.entries == {}


def test_scheduler_state_save_is_atomic(tmp_path: Path, ledger_built: None) -> None:
    clock = FakeWallClock()
    druid = _druid(tmp_path, {"t": _target("t")}, MutableFetcher([b"<html>x</html>"]))
    sched = _scheduler(druid, clock)
    sched.run_due()
    state = tmp_path / "data" / "schedule-state.json"
    assert state.exists() and not state.with_name(state.name + ".tmp").exists()
    json.loads(state.read_text(encoding="utf-8"))  # valid JSON
