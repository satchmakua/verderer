"""Push alerts (DESIGN §7): deliver classified diff events to subscribers by target,
diff-type, and severity — over webhooks and email. RSS already ships (see `web/feed.py`);
this is the push side.

Delivery is idempotent: a per-(subscription, event) key is recorded in
`annals-data/notify-state.json`, so re-running `annals notify` never re-sends, and adding a
new subscription still receives the historical events it matches. Senders are injectable
(a port) so the whole path is testable offline.
"""

from __future__ import annotations

import json
import os
import smtplib
import tomllib
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from .pipeline import Annals

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}


@dataclass(frozen=True, slots=True)
class Subscription:
    name: str
    channel: str  # "webhook" | "email"
    dest: str  # URL or email address
    min_severity: str = "Info"
    targets: tuple[str, ...] = ()  # empty = all targets
    diff_types: tuple[str, ...] = ()  # empty = all diff types


def load_subscriptions(path: Path) -> list[Subscription]:
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    subs: list[Subscription] = []
    for item in data.get("subscription", []):
        subs.append(
            Subscription(
                name=item["name"],
                channel=item["channel"],
                dest=item["dest"],
                min_severity=item.get("min_severity", "Info"),
                targets=tuple(item.get("targets", [])),
                diff_types=tuple(item.get("diff_types", [])),
            )
        )
    return subs


def events(annals: Annals) -> list[dict[str, Any]]:
    """The classified diff events from the ledger, oldest-first (delivery order)."""
    out: list[dict[str, Any]] = []
    for entry in annals.log.entries():
        record = entry.record
        if record.get("schema") != "annals.diff/v1":
            continue
        out.append(
            {
                "id": entry.leaf_hash,
                "target_id": record.get("target_id"),
                "diff_type": record.get("diff_type"),
                "severity": record.get("severity"),
                "layer": record.get("layer"),
                "detected_at": record.get("detected_at"),
                "evidence": record.get("evidence", {}),
                "from_hash": record.get("from_observation_hash"),
                "to_hash": record.get("to_observation_hash"),
            }
        )
    return out


def matches(sub: Subscription, event: dict[str, Any]) -> bool:
    if SEVERITY_ORDER.get(event.get("severity", ""), 0) < SEVERITY_ORDER.get(sub.min_severity, 0):
        return False
    if sub.targets and event.get("target_id") not in sub.targets:
        return False
    if sub.diff_types and event.get("diff_type") not in sub.diff_types:
        return False
    return True


class Notifier(Protocol):
    channel: str

    def send(self, sub: Subscription, event: dict[str, Any]) -> None: ...


def alert_payload(sub: Subscription, event: dict[str, Any]) -> dict[str, Any]:
    return {"schema": "annals.alert/v1", "subscription": sub.name, **event}


class HttpWebhookNotifier:
    channel = "webhook"

    def __init__(self, poster: Any = None, timeout: float = 10.0) -> None:
        self._poster = poster  # injectable (url, payload) -> None; default uses httpx
        self.timeout = timeout

    def send(self, sub: Subscription, event: dict[str, Any]) -> None:
        payload = alert_payload(sub, event)
        if self._poster is not None:
            self._poster(sub.dest, payload)
            return
        import httpx

        httpx.post(
            sub.dest,
            json=payload,
            timeout=self.timeout,
            headers={"User-Agent": "AnnalsWatchdog/0.0 (+https://github.com/satchmakua/annals)"},
        ).raise_for_status()


def build_email(sub: Subscription, event: dict[str, Any], *, from_addr: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = f"[Annals] {event['diff_type']} [{event['severity']}] - {event['target_id']}"
    msg["From"] = from_addr
    msg["To"] = sub.dest
    body = (
        f"Annals detected a change on {event['target_id']}.\n\n"
        f"  type:     {event['diff_type']} [{event['severity']}]\n"
        f"  detected: {event['detected_at']}\n"
        f"  evidence: {event['evidence']}\n\n"
        f"This classification is Annals' best-effort, human-reviewable interpretation. The underlying\n"
        f"observations are cryptographically attested and offline-verifiable.\n\n"
        f"  event id: {event['id']}\n"
    )
    msg.set_content(body)
    return msg


class SmtpEmailNotifier:
    channel = "email"

    def __init__(
        self,
        host: str = "localhost",
        port: int = 25,
        from_addr: str = "annals@localhost",
        sender: Any = None,
    ) -> None:
        self.host = host
        self.port = port
        self.from_addr = from_addr
        self._sender = sender  # injectable (EmailMessage) -> None; default uses smtplib

    def send(self, sub: Subscription, event: dict[str, Any]) -> None:
        msg = build_email(sub, event, from_addr=self.from_addr)
        if self._sender is not None:
            self._sender(msg)
            return
        with smtplib.SMTP(self.host, self.port) as smtp:
            smtp.send_message(msg)


@dataclass
class DispatchState:
    delivered: set[str] = field(default_factory=set)


def load_state(data_dir: Path) -> DispatchState:
    path = Path(data_dir) / "notify-state.json"
    if not path.exists():
        return DispatchState()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return DispatchState(delivered=set(data["delivered"]))
    except (OSError, ValueError, TypeError, KeyError):
        # A corrupt/partial state file (a crash mid-write) must never crash the caller —
        # least of all the M10 `annals run` loop, which loads this every tick and would
        # otherwise die and re-crash on restart. Start fresh; the worst case is that a few
        # already-sent alerts resend, which is far better than a dead watchdog. The atomic
        # write below makes such corruption unlikely in the first place.
        return DispatchState()


def save_state(data_dir: Path, state: DispatchState) -> None:
    path = Path(data_dir) / "notify-state.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename so an interrupted write can never leave a half-written file that
    # would fail to parse on the next load (os.replace is atomic within a filesystem).
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps({"delivered": sorted(state.delivered)}, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def dispatch(
    event_list: list[dict[str, Any]],
    subscriptions: list[Subscription],
    notifiers: dict[str, Notifier],
    state: DispatchState,
) -> list[dict[str, Any]]:
    """Send each new matching event to its subscription. Only successful sends are marked
    delivered, so a failed webhook/email is retried on the next run."""
    deliveries: list[dict[str, Any]] = []
    for event in event_list:
        for sub in subscriptions:
            key = f"{sub.name}:{event['id']}"
            if key in state.delivered or not matches(sub, event):
                continue
            notifier = notifiers.get(sub.channel)
            if notifier is None:
                continue
            base = {"subscription": sub.name, "channel": sub.channel, "event": event["id"], "dest": sub.dest}
            try:
                notifier.send(sub, event)
            except Exception as error:  # network/SMTP failure — leave undelivered for retry
                deliveries.append({**base, "error": str(error)})
                continue
            state.delivered.add(key)
            deliveries.append(base)
    return deliveries
