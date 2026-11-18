"""Push alerts (DESIGN §7): tell subscribers about changes by target, diff-type, and
severity — over a webhook, email, or an issue on a GitHub repository. RSS already ships (see
`web/feed.py`); this is the push side.

The unit of an alert is a **change** (`alerts`): everything one comparison between two
recorded versions found, read as one headline — the same grouping the site and the feeds
use — so a page that lost a term in nineteen list items sends one message, not nineteen.
Error-page churn is never alerted. The lower-level per-finding path (`events`) remains for
callers that want every classified leaf.

Delivery is idempotent: a per-(subscription, alert) key is recorded in
`verderer-data/notify-state.json`, so re-running `verderer notify` never re-sends. A new
subscription receives the history it matches unless it sets `since`. A destination can be
written `env:NAME` so a secret address stays out of the repository; while that variable is
unset the subscription is simply inactive. Senders are injectable (a port) so the whole path
is testable offline.
"""

from __future__ import annotations

import json
import os
import smtplib
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Any, Protocol

from .pipeline import Verderer
from .web.explain import explain_event

SEVERITY_ORDER = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}


@dataclass(frozen=True, slots=True)
class Subscription:
    name: str
    channel: str  # "webhook" | "email" | "github-issue"
    dest: str  # URL, email address, or "owner/repo"; "" while an `env:` destination is unset
    min_severity: str = "Info"
    targets: tuple[str, ...] = ()  # empty = all targets
    diff_types: tuple[str, ...] = ()  # empty = all diff types
    since: str = ""  # ISO date/time: only alert on changes detected at or after it
    source: str = ""  # how the destination was written, when it came from `env:NAME`

    @property
    def active(self) -> bool:
        return bool(self.dest)

    @property
    def label(self) -> str:
        """The destination as it may be printed: never a secret read from the environment."""
        return self.source or self.dest


def load_subscriptions(path: Path, env: Mapping[str, str] | None = None) -> list[Subscription]:
    """Read the subscriptions. A destination written `env:NAME` is taken from the environment
    (so a webhook URL or an address never has to be committed); if that variable is unset or
    empty the subscription loads inactive and is skipped by `dispatch`."""
    environ = os.environ if env is None else env
    data = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    subs: list[Subscription] = []
    for item in data.get("subscription", []):
        written = str(item["dest"])
        from_env = written.startswith("env:")
        subs.append(
            Subscription(
                name=item["name"],
                channel=item["channel"],
                dest=environ.get(written[4:], "").strip() if from_env else written,
                min_severity=item.get("min_severity", "Info"),
                targets=tuple(item.get("targets", [])),
                diff_types=tuple(item.get("diff_types", [])),
                since=str(item.get("since", "")),
                source=written if from_env else "",
            )
        )
    return subs


def events(verderer: Verderer) -> list[dict[str, Any]]:
    """The classified diff events from the ledger, oldest-first (delivery order)."""
    out: list[dict[str, Any]] = []
    for entry in verderer.log.entries():
        record = entry.record
        if record.get("schema") != "verderer.diff/v1":
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


def alerts(verderer: Verderer, *, site_url: str = "") -> list[dict[str, Any]]:
    """One alert per change, oldest-first (delivery order): the reader-facing grouping of the
    ledger's findings, minus error-page churn. An alert's `id` is its change id (the leaf hash
    of the change's first finding), so it is as permanent as the ledger. Interpretation, like
    the classification it summarises — never attested."""
    from .web.record import build_record  # local: the record view imports the scheduler

    record = build_record(verderer)
    titles = {t["id"]: t["title"] for t in record["targets"]}
    root = site_url.rstrip("/")
    out: list[dict[str, Any]] = []
    for change in reversed(record["changes"]):  # the record lists newest first
        if change["category"] == "churn":
            continue
        diff_types = list(change["diff_types"])
        out.append(
            {
                "id": change["id"],
                "target_id": change["target_id"],
                "title": titles.get(change["target_id"], change["target_id"]),
                "severity": change["severity"],
                "diff_type": diff_types[0] if diff_types else "",
                "diff_types": diff_types,
                "detected_at": change["detected_at"],
                "headline": change["headline"],
                "points": list(change["points"]),
                "findings": len(change["event_ids"]),
                "reverts": change.get("reverts"),
                "url": f"{root}/change/{change['id']}" if root else "",
            }
        )
    return out


def matches(sub: Subscription, event: dict[str, Any]) -> bool:
    if SEVERITY_ORDER.get(event.get("severity", ""), 0) < SEVERITY_ORDER.get(sub.min_severity, 0):
        return False
    if sub.targets and event.get("target_id") not in sub.targets:
        return False
    if sub.diff_types:
        found = event.get("diff_types") or [event.get("diff_type")]
        if not any(diff_type in sub.diff_types for diff_type in found):
            return False
    if sub.since and str(event.get("detected_at") or "") < sub.since:
        return False
    return True


def _is_change(event: Mapping[str, Any]) -> bool:
    return "headline" in event


def alert_line(event: Mapping[str, Any]) -> str:
    """A change alert as one line of plain text (what a chat webhook or a subject shows)."""
    return f"[{event['severity']}] {event.get('title') or event['target_id']}: {event['headline']}"


def alert_text(event: Mapping[str, Any]) -> str:
    """A change alert as a short plain-text message: headline, what moved, where to read it."""
    lines = [alert_line(event), ""]
    lines += [f"- {point}" for point in event.get("points", [])]
    if event.get("reverts"):
        lines.append("- This puts back what an earlier change altered.")
    lines += ["", f"Detected {event['detected_at']} ({event.get('findings', 1)} finding(s))."]
    if event.get("url"):
        lines.append(f"Details and proof: {event['url']}")
    lines += [
        "",
        "The classification is Verderer's best-effort reading. The recorded responses behind it are "
        "signed and can be verified offline.",
    ]
    return "\n".join(lines)


class Notifier(Protocol):
    channel: str

    def send(self, sub: Subscription, event: dict[str, Any]) -> None: ...


def alert_payload(sub: Subscription, event: dict[str, Any]) -> dict[str, Any]:
    """The webhook body: the classified event as logged, plus a plain-language reading
    (``explain`` — interpretation, like the classification itself) so a receiver can show a
    sentence without re-deriving one from the typed evidence."""
    if _is_change(event):
        # A change alert. `text` and `content` carry the same short message, so the payload
        # can be posted as-is to a Slack-, Mattermost- or Discord-style incoming webhook.
        short = alert_line(event) + (f"\n{event['url']}" if event.get("url") else "")
        return {"schema": "verderer.alert/v2", "subscription": sub.name, **event, "text": short, "content": short}
    explain = explain_event(event)
    return {
        "schema": "verderer.alert/v1",
        "subscription": sub.name,
        **event,
        "explain": {"title": explain["title"], "summary": explain["summary"]},
    }


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
            headers={"User-Agent": "VerdererWatchdog/0.0 (+https://github.com/satchmakua/verderer)"},
        ).raise_for_status()


def build_email(sub: Subscription, event: dict[str, Any], *, from_addr: str) -> EmailMessage:
    if _is_change(event):
        message = EmailMessage()
        message["Subject"] = f"[Verderer] {alert_line(event)}"
        message["From"] = from_addr
        message["To"] = sub.dest
        message.set_content(alert_text(event) + f"\n\nchange id: {event['id']}\n")
        return message
    explain = explain_event(event)
    msg = EmailMessage()
    msg["Subject"] = (
        f"[Verderer] {event['diff_type']} [{event['severity']}] - {event['target_id']}: {explain['title']}"
    )
    msg["From"] = from_addr
    msg["To"] = sub.dest
    body = (
        f"Verderer detected a change on {event['target_id']}.\n\n"
        f"  {explain['title']}\n"
        f"  {explain['summary']}\n\n"
        f"  type:     {event['diff_type']} [{event['severity']}]\n"
        f"  detected: {event['detected_at']}\n"
        f"  evidence: {event['evidence']}\n\n"
        f"This classification is Verderer's best-effort, human-reviewable interpretation. The underlying\n"
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
        from_addr: str = "verderer@localhost",
        sender: Any = None,
        *,
        username: str = "",
        password: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.from_addr = from_addr
        self._sender = sender  # injectable (EmailMessage) -> None; default uses smtplib
        self._username = username
        self._password = password

    def send(self, sub: Subscription, event: dict[str, Any]) -> None:
        msg = build_email(sub, event, from_addr=self.from_addr)
        if self._sender is not None:
            self._sender(msg)
            return
        with smtplib.SMTP(self.host, self.port, timeout=30) as smtp:
            if self._username:
                # A hosted relay: credentials only ever travel over TLS.
                smtp.starttls()
                smtp.login(self._username, self._password)
            smtp.send_message(msg)


class GithubIssueNotifier:
    """Open an issue on a GitHub repository (`dest` = ``owner/repo``) for a change. Anyone
    watching that repository is then notified by GitHub itself, so this needs no address list
    and no secret beyond a token that may open issues there."""

    channel = "github-issue"

    def __init__(self, token: str = "", poster: Any = None, timeout: float = 15.0) -> None:
        self._token = token
        self._poster = poster  # injectable (url, payload) -> None; default uses httpx
        self.timeout = timeout

    def send(self, sub: Subscription, event: dict[str, Any]) -> None:
        if not _is_change(event):
            raise ValueError("the github-issue channel delivers change alerts only")
        owner, _, repo = sub.dest.partition("/")
        if not owner or not repo or "/" in repo:
            raise ValueError(f"github-issue destination must be owner/repo, got {sub.dest!r}")
        url = f"https://api.github.com/repos/{owner}/{repo}/issues"
        payload = {"title": alert_line(event)[:240], "body": alert_text(event), "labels": ["change-alert"]}
        if self._poster is not None:
            self._poster(url, payload)
            return
        if not self._token:
            raise RuntimeError("no GitHub token available to open the issue (set GITHUB_TOKEN)")
        import httpx

        httpx.post(
            url,
            json=payload,
            timeout=self.timeout,
            headers={
                "Authorization": f"Bearer {self._token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "VerdererWatchdog/0.0 (+https://github.com/satchmakua/verderer)",
            },
        ).raise_for_status()


def default_notifiers(
    *, smtp_host: str, smtp_port: int, email_from: str, env: Mapping[str, str] | None = None
) -> dict[str, Notifier]:
    """The production senders. SMTP credentials and the GitHub token come from the
    environment (`VERDERER_SMTP_USER` / `VERDERER_SMTP_PASSWORD`, `GITHUB_TOKEN`), never
    from a tracked file."""
    environ = os.environ if env is None else env
    return {
        "webhook": HttpWebhookNotifier(),
        "email": SmtpEmailNotifier(
            environ.get("VERDERER_SMTP_HOST") or smtp_host,
            int(environ.get("VERDERER_SMTP_PORT") or smtp_port),
            environ.get("VERDERER_SMTP_FROM") or email_from,
            username=environ.get("VERDERER_SMTP_USER", ""),
            password=environ.get("VERDERER_SMTP_PASSWORD", ""),
        ),
        "github-issue": GithubIssueNotifier(environ.get("GITHUB_TOKEN", "")),
    }


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
        # least of all the M10 `verderer run` loop, which loads this every tick and would
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
            if not sub.active or key in state.delivered or not matches(sub, event):
                continue
            notifier = notifiers.get(sub.channel)
            if notifier is None:
                continue
            base = {"subscription": sub.name, "channel": sub.channel, "event": event["id"], "dest": sub.label}
            try:
                notifier.send(sub, event)
            except Exception as error:  # network/SMTP failure — leave undelivered for retry
                deliveries.append({**base, "error": str(error)})
                continue
            state.delivered.add(key)
            deliveries.append(base)
    return deliveries
