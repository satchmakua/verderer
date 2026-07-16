"""The scheduler (DESIGN §7, M10): the piece that turns a manual demo into a watchdog.

`verderer observe <t>` is a one-shot. To actually *watch* a corpus, Verderer must re-observe the
curated set on its own, on a per-target cadence, forever — politely (through the M9 layer),
appending any diffs, and firing the M5c alert pipeline the moment a meaningful change lands,
without a human in the loop. This module is that loop.

Design:

* **Per-target cadence.** Each target carries an ``interval_seconds`` (``data/targets.toml``,
  ``interval = "6h"``). After an attempt, the next due time is ``now + interval ± jitter``
  (jitter de-synchronises targets so they don't all hit a host in the same second).
* **Persisted schedule state.** ``verderer-data/schedule-state.json`` records each target's last
  run, next-due time, last status, and consecutive-failure count — so a restart resumes
  exactly where it left off (a target already observed 10 minutes ago is not re-hit). The
  stored ``ETag``/``Last-Modified`` that drives conditional GET lives in the M9 politeness
  layer, not here — one owner, no second copy to desync.
* **Only what is due.** A tick observes just the targets whose ``next_due <= now``; the rest
  are skipped untouched.
* **Alerts fire on their own.** After processing the due set, the scheduler runs the notify
  pipeline (idempotent: M5c's per-(sub,event) state means re-runs never double-send and a
  failed delivery is retried next tick).
* **A failure is retried, not lost.** If an observe raises (a transient error that survived
  M9's backoff, a parse failure), the target is rescheduled *soon* (a short, capped
  exponential retry) rather than dropped until its next full cadence.

Time and jitter are injected, so ``--once`` and the long-lived loop are both exercised
offline on a fake clock; production uses the wall clock. Wall-clock (epoch) time is used
deliberately — schedule state must survive a process restart, which a monotonic clock cannot.
"""

from __future__ import annotations

import json
import os
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .pipeline import ObserveResult, Verderer

# A failed target retries after this base delay, doubling per consecutive failure, capped at
# both `RETRY_MAX` and the target's own cadence (never wait longer than a normal cycle).
RETRY_BASE_SECONDS = 300.0
RETRY_MAX_SECONDS = 3600.0

# The notify seam: given the pipeline, deliver any new diff events and return the deliveries.
# Injected so the scheduler is testable without webhooks/SMTP; the CLI wires the real M5c path.
NotifyFn = Callable[[Verderer], list[dict[str, object]]]


class WallClock(Protocol):
    """Epoch-seconds wall clock (must persist across restarts, so not monotonic)."""

    def now(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemWallClock:
    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)


def _default_jitter(interval: float, fraction: float) -> float:
    """A symmetric jitter in ``±fraction`` of the interval (de-synchronises targets)."""
    if fraction <= 0:
        return 0.0
    return random.uniform(-fraction, fraction) * interval


@dataclass
class ScheduleEntry:
    target_id: str
    next_due: float  # epoch seconds; a due target has next_due <= now
    last_run: float | None = None
    last_status: str = ""  # last ObserveResult.status, or "error"
    consecutive_failures: int = 0

    def to_record(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "next_due": self.next_due,
            "last_run": self.last_run,
            "last_status": self.last_status,
            "consecutive_failures": self.consecutive_failures,
        }

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> ScheduleEntry:
        last_run = rec.get("last_run")
        return cls(
            target_id=str(rec["target_id"]),
            next_due=float(rec["next_due"]),
            last_run=None if last_run is None else float(last_run),
            last_status=str(rec.get("last_status", "")),
            consecutive_failures=int(rec.get("consecutive_failures", 0)),
        )


@dataclass
class TickResult:
    """What one `run_due` pass did — for CLI reporting and tests."""

    observed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    errored: list[str] = field(default_factory=list)
    diffs: int = 0
    deliveries: int = 0
    notify_error: str = ""  # set if the alert pass failed (never fatal — the loop continues)

    @property
    def due_count(self) -> int:
        return len(self.observed) + len(self.unchanged) + len(self.skipped) + len(self.errored)


class Scheduler:
    def __init__(
        self,
        verderer: Verderer,
        *,
        clock: WallClock | None = None,
        notify: NotifyFn | None = None,
        jitter_fraction: float = 0.1,
        jitter: Callable[[float, float], float] = _default_jitter,
        state_path: Path | None = None,
    ) -> None:
        self.verderer = verderer
        self.clock: WallClock = clock or SystemWallClock()
        self._notify = notify
        self.jitter_fraction = jitter_fraction
        self._jitter = jitter
        self.state_path = Path(state_path) if state_path is not None else verderer.data_dir / "schedule-state.json"
        self.entries: dict[str, ScheduleEntry] = self._load_state()

    # -- state persistence -------------------------------------------------------------

    def _load_state(self) -> dict[str, ScheduleEntry]:
        if not self.state_path.exists():
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
            return {
                str(rec["target_id"]): ScheduleEntry.from_record(rec) for rec in data.get("entries", [])
            }
        except (OSError, ValueError, TypeError, KeyError):
            # A corrupt schedule file must not brick the watchdog; start fresh (every target
            # simply becomes due now). The ledger and attested record are untouched.
            return {}

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"entries": [e.to_record() for e in self.entries.values()]}
        tmp = self.state_path.with_name(self.state_path.name + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.state_path)  # atomic: a crash never leaves a half-written file

    # -- scheduling ---------------------------------------------------------------------

    def _entry(self, target_id: str, now: float) -> ScheduleEntry:
        entry = self.entries.get(target_id)
        if entry is None:
            # A never-seen target is due immediately.
            entry = ScheduleEntry(target_id=target_id, next_due=now)
            self.entries[target_id] = entry
        return entry

    def due_targets(self, now: float) -> list[str]:
        """Curated targets whose next-due time has arrived, in a stable order."""
        due = []
        for target_id in self.verderer.targets:
            if self._entry(target_id, now).next_due <= now:
                due.append(target_id)
        return due

    def next_wakeup(self, now: float) -> float:
        """The soonest next-due time across all targets (epoch seconds); the loop sleeps to
        it. ``now`` when something is already due."""
        upcoming = [self._entry(tid, now).next_due for tid in self.verderer.targets]
        return min(upcoming) if upcoming else now

    def _reschedule(self, entry: ScheduleEntry, target_interval: float, now: float, *, failed: bool) -> None:
        entry.last_run = now
        if failed:
            entry.consecutive_failures += 1
            # Clamp the exponent before doubling: a permanently-dead target (a takedown — the
            # very case this watchdog exists to catch) would otherwise grow the shift until
            # `2 ** n` overflows float (~1025 failures) and an uncaught OverflowError killed
            # the whole loop. The delay is capped regardless, so a bounded exponent is
            # behaviourally identical — it just never overflows.
            exp = min(entry.consecutive_failures - 1, 30)
            delay = min(
                RETRY_BASE_SECONDS * (2**exp),
                RETRY_MAX_SECONDS,
                target_interval,  # never wait longer than a normal cycle
            )
            entry.next_due = now + delay
        else:
            entry.consecutive_failures = 0
            entry.next_due = now + target_interval + self._jitter(target_interval, self.jitter_fraction)

    # -- execution ----------------------------------------------------------------------

    def run_target(self, target_id: str, result: TickResult) -> None:
        """Observe one target, record its outcome, and reschedule it. Never raises — a
        failure is recorded and retried, so one bad target can't halt the run."""
        now = self.clock.now()
        entry = self._entry(target_id, now)
        interval = self.verderer.targets[target_id].interval_seconds
        try:
            outcome: ObserveResult = self.verderer.observe(target_id)
        except Exception as error:  # transient/parse failure — retry soon, do not lose it
            entry.last_status = "error"
            self._reschedule(entry, interval, now, failed=True)
            result.errored.append(f"{target_id}: {error}")
            self._save_state()
            return
        entry.last_status = outcome.status
        self._reschedule(entry, interval, now, failed=False)
        if outcome.status == "observed":
            result.observed.append(target_id)
            result.diffs += len(outcome.diffs)
        elif outcome.status == "unchanged":
            result.unchanged.append(target_id)
        else:  # skipped (robots disallow)
            result.skipped.append(target_id)
        self._save_state()

    def run_due(self) -> TickResult:
        """One pass: observe every currently-due target, then fire the notify pipeline once
        for any new diffs (idempotent). Returns a summary of the pass."""
        result = TickResult()
        now = self.clock.now()
        for target_id in self.due_targets(now):
            self.run_target(target_id, result)
        # Fire alerts after the batch. Idempotent by construction (M5c per-(sub,event) state),
        # so this also retries any delivery that failed on an earlier tick. Isolated: an
        # alert-pipeline failure (a corrupt notify-state, a config error) is recorded but must
        # never take down the watchdog loop — observation of every target has already happened.
        if self._notify is not None:
            try:
                deliveries = self._notify(self.verderer)
                result.deliveries = len([d for d in deliveries if "error" not in d])
            except Exception as error:
                result.notify_error = str(error)
        return result

    def run_forever(self, *, poll_cap: float = 300.0, max_iterations: int | None = None) -> None:
        """The long-lived service loop: process the due set, sleep until the next due time
        (capped at ``poll_cap`` so config/state changes are picked up), repeat. ``max_iterations``
        bounds the loop for tests; production leaves it ``None`` (runs until killed)."""
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            self.run_due()
            now = self.clock.now()
            wait = min(max(self.next_wakeup(now) - now, 0.0), poll_cap)
            self.clock.sleep(wait)
            iterations += 1
