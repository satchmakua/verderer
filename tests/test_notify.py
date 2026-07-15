"""M5c — push alerts: subscription matching, idempotent dispatch, and message building,
all offline via injectable senders."""

from pathlib import Path

from annals.notify import (
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
    # Regression (M10 review): the `annals run` loop loads notify state every tick. A corrupt
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
    assert payload["schema"] == "annals.alert/v1"
    assert payload["subscription"] == "s"
    assert payload["diff_type"] == "NumericThresholdChange"


def test_email_message_is_built_and_sent_via_injected_sender() -> None:
    captured: list = []
    notifier = SmtpEmailNotifier(sender=captured.append, from_addr="annals@watch")
    notifier.send(Subscription("desk", "email", "editor@example.org", min_severity="Info"), HIGH_NUMERIC)
    msg = captured[0]
    assert msg["To"] == "editor@example.org"
    assert "NumericThresholdChange [High]" in msg["Subject"]
    assert "15 ppb" in msg.get_content()


def test_build_email_shape() -> None:
    msg = build_email(Subscription("s", "email", "to@x", min_severity="Info"), MED_TERM, from_addr="from@x")
    assert msg["From"] == "from@x"
    assert "usgcrp" in msg["Subject"]


def test_load_subscriptions_from_repo_config() -> None:
    from annals.config import load_targets  # noqa: F401  (repo layout sanity)

    path = Path(__file__).resolve().parents[1] / "data" / "subscriptions.toml"
    from annals.notify import load_subscriptions

    subs = load_subscriptions(path)
    assert any(s.channel == "webhook" and s.min_severity == "High" for s in subs)
    assert any(s.channel == "email" for s in subs)
