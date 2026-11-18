"""The weekly digest (DESIGN §6.5, §7): the record's changes grouped by ISO week, so a reader
who does not follow the feed day by day can ask one question — "what changed this week?" —
and get one page, or one feed item, that answers it.

A week is Monday through Sunday, UTC. Weeks run from the first recorded response to the week
the record was generated in, quiet ones included: "nothing changed" is an answer too, and a
gap in the list would read as the watchdog having been off. Like every reader-facing view
this is interpretation derived from the attested leaves — never attested itself.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Mapping, Sequence
from typing import Any

from .explain import SEVERITY_RANK

_DAY = dt.timedelta(days=1)


def _moment(iso: object) -> dt.datetime | None:
    try:
        return dt.datetime.strptime(str(iso), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError:
        return None


def week_id(day: dt.date) -> str:
    year, week, _ = day.isocalendar()
    return f"{year}-W{week:02d}"


def week_start(day: dt.date) -> dt.date:
    """The Monday of ``day``'s ISO week."""
    return day - dt.timedelta(days=day.isoweekday() - 1)


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def summarise(changes: int, notable: int, sources: int) -> str:
    if changes == 0:
        return "No changes"
    text = f"{_plural(changes, 'change')} across {_plural(sources, 'source')}"
    return f"{text}, {notable} high severity" if notable else text


def build_weeks(
    changes: Sequence[Mapping[str, Any]],
    targets: Sequence[Mapping[str, Any]],
    *,
    generated_at: str,
) -> list[dict[str, Any]]:
    """The weekly digest views, newest week first. ``changes`` are the record's change views
    (any order); ``targets`` its target views (for the recorded responses per week)."""
    fetched = [
        moment
        for target in targets
        for observation in target.get("observations", [])
        if (moment := _moment(observation.get("fetched_at"))) is not None
    ]
    now = _moment(generated_at)
    if not fetched or now is None:
        return []

    first, last = week_start(min(fetched).date()), week_start(now.date())
    weeks: dict[str, dict[str, Any]] = {}
    monday = first
    while monday <= last:
        sunday = monday + 6 * _DAY
        weeks[week_id(monday)] = {
            "id": week_id(monday),
            "start": monday.isoformat(),
            "end": sunday.isoformat(),
            # Complete once the record was generated after the week's last day: its page and
            # feed item will not change again (short of a re-classification).
            "complete": now.date() > sunday,
            "observations": 0,
            "changes": 0,
            "notable": 0,
            "churn": 0,
            "sources": [],
            "change_ids": [],
        }
        monday += 7 * _DAY

    for moment in fetched:
        week = weeks.get(week_id(moment.date()))
        if week is not None:
            week["observations"] += 1

    listed: dict[str, list[Mapping[str, Any]]] = {}
    for change in changes:
        moment = _moment(change.get("detected_at"))
        week = weeks.get(week_id(moment.date())) if moment is not None else None
        if week is None:
            continue
        if change.get("category") == "churn":
            week["churn"] += 1
            continue
        listed.setdefault(week["id"], []).append(change)

    for key, found in listed.items():
        week = weeks[key]
        # What matters most first: severity, then newest.
        found.sort(key=lambda c: str(c.get("detected_at")), reverse=True)
        found.sort(key=lambda c: SEVERITY_RANK.get(str(c.get("severity")), 0), reverse=True)
        week["changes"] = len(found)
        week["notable"] = sum(1 for c in found if c.get("category") == "notable")
        week["sources"] = sorted({str(c.get("target_id")) for c in found})
        week["change_ids"] = [c.get("id") for c in found]

    for week in weeks.values():
        week["summary"] = summarise(week["changes"], week["notable"], len(week["sources"]))
    return sorted(weeks.values(), key=lambda w: w["start"], reverse=True)


def span_text(week: Mapping[str, Any]) -> str:
    """``Nov 9 - 15, 2026`` (or across a month / year boundary, both ends in full)."""
    start, end = dt.date.fromisoformat(week["start"]), dt.date.fromisoformat(week["end"])
    if start.year != end.year:
        return f"{start:%b} {start.day}, {start.year} - {end:%b} {end.day}, {end.year}"
    if start.month != end.month:
        return f"{start:%b} {start.day} - {end:%b} {end.day}, {end.year}"
    return f"{start:%b} {start.day} - {end.day}, {end.year}"
