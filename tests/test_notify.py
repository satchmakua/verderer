"""M5c — push alerts: subscription matching, idempotent dispatch, and message building,
all offline via injectable senders."""

from pathlib import Path

from verderer.notify import (
    DispatchState,
    HttpWebhookNotifier,
    SmtpEmailNotifier,
    Subscription,
    build_email,
    dispatch,
    load_state,
    matches,
    save_state,
)

HIGH_NUMERIC = {
    "id": "a" * 64, "target_id": "epa-ghgrp", "diff_type": "NumericThresholdChange",
    "severity": "High", "detected_at": "2026-01-01T00:00:00Z", "evidence": {"from": "10 ppb", "to": "15 ppb"},
}
MED_TERM = {
    "id": "b" * 64, "target_id": "usgcrp", "diff_type": "TermSubstitution",
    "severity": "Medium", "detected_at": "2026-01-02T00:00:00Z", "evidence": {"term": "climate change"},
}


def test_matches_by_severity_target_and_type() -> None:
    high_only = Subscription("s", "webhook", "https://x", min_severity="High")
    assert matches(high_only, HIGH_NUMERIC)
    assert not matches(high_only, MED_TERM)  # Medium < High

    usgcrp_only = Subscription("s", "email", "a@x", min_severity="Low", targets=("usgcrp",))
    assert matches(usgcrp_only, MED_TERM)
    assert not matches(usgcrp_only, HIGH_NUMERIC)  # different target

    numeric_only = Subscription("s", "webhook", "https://x", diff_types=("NumericThresholdChange",))
    assert matches(numeric_only, HIGH_NUMERIC)
    assert not matches(numeric_only, MED_TERM)


def test_dispatch_sends_matching_events_and_is_idempotent() -> None:
    sent: list[tuple[str, dict]] = []

    class FakeWebhook:
        channel = "webhook"

        def send(self, sub: Subscription, event: dict) -> None:
            sent.append((sub.dest, event))

    subs = [
        Subscription("high", "webhook", "https://hook/high", min_severity="High"),
        Subscription("all", "webhook", "https://hook/all", min_severity="Info"),
    ]
    state = DispatchState()
    deliveries = dispatch([HIGH_NUMERIC, MED_TERM], subs, {"webhook": FakeWebhook()}, state)

    # "high" gets only the High event; "all" gets both -> 3 deliveries.
    assert len(deliveries) == 3
    assert len(sent) == 3
    assert ("https://hook/high", HIGH_NUMERIC) in sent

    # Re-running delivers nothing new (idempotent per subscription+event).
    again = dispatch([HIGH_NUMERIC, MED_TERM], subs, {"webhook": FakeWebhook()}, state)
    assert again == []


def test_failed_delivery_is_not_marked_and_retries() -> None:
    class Flaky:
        channel = "webhook"

        def __init__(self) -> None:
            self.calls = 0

        def send(self, sub: Subscription, event: dict) -> None:
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("network down")

    flaky = Flaky()
    subs = [Subscription("s", "webhook", "https://x", min_severity="Info")]
    state = DispatchState()
    first = dispatch([HIGH_NUMERIC], subs, {"webhook": flaky}, state)
    assert "error" in first[0]
    assert state.delivered == set()  # not marked -> will retry

    second = dispatch([HIGH_NUMERIC], subs, {"webhook": flaky}, state)
    assert second and "error" not in second[0]  # retried and succeeded


def test_corrupt_notify_state_fails_open(tmp_path: Path) -> None:
    # Regression (M10 review): the `verderer run` loop loads notify state every tick. A corrupt
    # file (a crash mid-write) must not raise — it would kill the watchdog and re-crash on
    # every restart. Fail open to an empty (nothing-delivered) state instead.
    (tmp_path / "notify-state.json").write_text("{ truncated", encoding="utf-8")
    state = load_state(tmp_path)
    assert state.delivered == set()


def test_notify_state_save_is_atomic(tmp_path: Path) -> None:
    state = DispatchState(delivered={"a:1", "b:2"})
    save_state(tmp_path, state)
    path = tmp_path / "notify-state.json"
    assert path.exists() and not (tmp_path / "notify-state.json.tmp").exists()
    assert load_state(tmp_path).delivered == {"a:1", "b:2"}  # round-trips


def test_webhook_notifier_posts_alert_payload() -> None:
    posted: list[tuple[str, dict]] = []
    notifier = HttpWebhookNotifier(poster=lambda url, payload: posted.append((url, payload)))
    notifier.send(Subscription("s", "webhook", "https://hook", min_severity="Info"), HIGH_NUMERIC)
    url, payload = posted[0]
    assert url == "https://hook"
    assert payload["schema"] == "verderer.alert/v1"
    assert payload["subscription"] == "s"
    assert payload["diff_type"] == "NumericThresholdChange"


def test_email_message_is_built_and_sent_via_injected_sender() -> None:
    captured: list = []
    notifier = SmtpEmailNotifier(sender=captured.append, from_addr="verderer@watch")
    notifier.send(Subscription("desk", "email", "editor@example.org", min_severity="Info"), HIGH_NUMERIC)
    msg = captured[0]
    assert msg["To"] == "editor@example.org"
    assert "NumericThresholdChange [High]" in msg["Subject"]
    assert "15 ppb" in msg.get_content()


def test_build_email_shape() -> None:
    msg = build_email(Subscription("s", "email", "to@x", min_severity="Info"), MED_TERM, from_addr="from@x")
    assert msg["From"] == "from@x"
    assert "usgcrp" in msg["Subject"]


# --- change-level alerts -------------------------------------------------------------------

CHANGE = {
    "id": "c" * 64,
    "target_id": "epa-drinking-water-mcl",
    "title": "EPA drinking water limits",
    "severity": "High",
    "diff_type": "NumericThresholdChange",
    "diff_types": ["NumericThresholdChange", "ContentEdit"],
    "detected_at": "2026-11-20T06:00:00Z",
    "headline": "Regulatory number changed: 0.010 mg/L → 0.015 mg/L",
    "points": ["In the passage “…action level”, the value changed from 0.010 mg/L to 0.015 mg/L (+50%)."],
    "findings": 2,
    "reverts": None,
    "url": "https://verderer.example/change/" + "c" * 64,
}


def test_an_env_destination_stays_out_of_the_file_and_is_inactive_until_set(tmp_path: Path) -> None:
    from verderer.notify import load_subscriptions

    config = tmp_path / "subscriptions.toml"
    config.write_text(
        '[[subscription]]\nname = "hook"\nchannel = "webhook"\ndest = "env:ALERT_HOOK"\nsince = "2026-11-17"\n',
        encoding="utf-8",
    )
    (unset,) = load_subscriptions(config, env={})
    assert not unset.active and unset.label == "env:ALERT_HOOK"
    (live,) = load_subscriptions(config, env={"ALERT_HOOK": "https://hooks.example/secret-token"})
    assert live.active and live.dest == "https://hooks.example/secret-token"
    assert live.label == "env:ALERT_HOOK"  # what gets printed never includes the secret

    sent: list[dict] = []

    class Hook:
        channel = "webhook"

        def send(self, sub: Subscription, event: dict) -> None:
            sent.append(event)

    assert dispatch([CHANGE], [unset], {"webhook": Hook()}, DispatchState()) == []  # inactive: skipped
    (delivery,) = dispatch([CHANGE], [live], {"webhook": Hook()}, DispatchState())
    assert delivery["dest"] == "env:ALERT_HOOK" and sent == [CHANGE]


def test_since_and_any_diff_type_filter_change_alerts() -> None:
    recent = Subscription("s", "webhook", "https://x", since="2026-11-17")
    assert matches(recent, CHANGE)
    assert not matches(recent, {**CHANGE, "detected_at": "2026-09-22T00:00:00Z"})  # history is not replayed
    # A change matches a type filter if any of its findings has that type.
    assert matches(Subscription("s", "webhook", "https://x", diff_types=("ContentEdit",)), CHANGE)
    assert not matches(Subscription("s", "webhook", "https://x", diff_types=("SchemaChange",)), CHANGE)


def test_a_change_alert_is_one_readable_message_on_every_channel() -> None:
    from verderer.notify import GithubIssueNotifier

    posted: list[tuple[str, dict]] = []
    HttpWebhookNotifier(poster=lambda url, payload: posted.append((url, payload))).send(
        Subscription("s", "webhook", "https://hook"), CHANGE
    )
    payload = posted[0][1]
    assert payload["schema"] == "verderer.alert/v2" and payload["headline"] == CHANGE["headline"]
    # Chat-style incoming webhooks read `text` (Slack, Mattermost) or `content` (Discord).
    assert payload["text"] == payload["content"]
    assert payload["text"].startswith("[High] EPA drinking water limits: Regulatory number changed")
    assert payload["text"].endswith(CHANGE["url"])

    message = build_email(Subscription("s", "email", "to@x"), CHANGE, from_addr="from@x")
    assert message["Subject"].startswith("[Verderer] [High] EPA drinking water limits")
    body = message.get_content()
    assert "(+50%)" in body and CHANGE["url"] in body and "best-effort" in body

    issues: list[tuple[str, dict]] = []
    GithubIssueNotifier(poster=lambda url, body: issues.append((url, body))).send(
        Subscription("s", "github-issue", "someone/somerepo"), CHANGE
    )
    url, issue = issues[0]
    assert url == "https://api.github.com/repos/someone/somerepo/issues"
    assert issue["title"].startswith("[High] EPA drinking water limits") and issue["labels"] == ["change-alert"]
    assert CHANGE["url"] in issue["body"]


def test_a_github_issue_needs_a_real_repository_and_a_token() -> None:
    import pytest

    from verderer.notify import GithubIssueNotifier

    with pytest.raises(ValueError):
        GithubIssueNotifier(poster=lambda *_: None).send(Subscription("s", "github-issue", "not-a-repo"), CHANGE)
    with pytest.raises(RuntimeError):  # no token: a failed delivery, retried later - never a silent drop
        GithubIssueNotifier(token="").send(Subscription("s", "github-issue", "someone/somerepo"), CHANGE)


def test_alerts_are_one_per_change_and_skip_error_page_churn(tmp_path: Path, ledger_built: None) -> None:
    from verderer.collectors.base import FetchResult
    from verderer.collectors.static import StaticCollector
    from verderer.config import Target
    from verderer.notify import alerts
    from verderer.pipeline import Verderer

    def page(*items: str) -> bytes:
        listed = "".join(f"<li>{item}</li>" for item in items)
        return f"<html><body><main><h1>Plan</h1><ul>{listed}</ul></main></body></html>".encode()

    responses = [
        (200, page("Climate change adaptation", "Community resilience grants", "Contact the office")),
        (200, page("Adaptation", "Community grants", "Contact the office")),  # two watched terms removed
        (403, b"<html>Access Denied. Reference #18.aaaa</html>"),
        (403, b"<html>Access Denied. Reference #18.bbbb</html>"),  # only the error page differs
    ]
    cursor = {"i": 0}

    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        status, body = responses[cursor["i"]]
        return FetchResult(url=url, status=status, headers={"content-type": "text/html"}, body=body)

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="The Plan", url="https://example.gov/plan")},
        terms=["climate change", "resilience"],
        collector=StaticCollector(fetcher=fetch),
    )
    for step in range(len(responses)):
        cursor["i"] = step
        verderer.observe("t")

    found = alerts(verderer, site_url="https://verderer.example/")
    # Two terms removed is ONE alert; the takedown is one more; the error-page churn is none.
    assert [a["severity"] for a in found] == ["High", "High"]
    first, second = found
    assert first["findings"] == 2 and first["title"] == "The Plan" and "2 watched terms removed" in first["headline"]
    assert first["url"] == f"https://verderer.example/change/{first['id']}"
    assert second["diff_types"] == ["Deletion"]


def test_repo_subscriptions_are_opt_in() -> None:
    from verderer.notify import load_subscriptions

    path = Path(__file__).resolve().parents[1] / "data" / "subscriptions.toml"
    subs = load_subscriptions(path, env={})
    assert {s.channel for s in subs} == {"webhook", "email", "github-issue"}
    # Nothing is sent anywhere until a destination is provided, and history is never replayed.
    assert all(not s.active and s.source.startswith("env:") and s.since for s in subs)
