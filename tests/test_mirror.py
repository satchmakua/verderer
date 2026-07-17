"""M14b-2 — checkpoint mirroring. Offline via an injected HTTP function: submissions hit the
right archive endpoints, receipts are honest, one mirror failing never blocks another, and the
Wayback round-trip compares bytes exactly (identity URL, no replay banner).
"""

from __future__ import annotations

from verderer.mirror import (
    MirrorReceipt,
    mirror_checkpoint,
    submit_software_heritage,
    submit_wayback,
    verify_wayback_copy,
)

CP_URL = "https://verderer.satchelhamilton.com/checkpoint"
REPO = "https://github.com/satchmakua/verderer"


def test_wayback_submission_hits_save_endpoint_and_reports_snapshot() -> None:
    seen: list[tuple[str, str]] = []

    def http(url: str, method: str) -> tuple[int, str, bytes]:
        seen.append((url, method))
        return 200, f"https://web.archive.org/web/20260717000000/{CP_URL}", b""

    receipt = submit_wayback(CP_URL, http)
    assert seen == [(f"https://web.archive.org/save/{CP_URL}", "GET")]
    assert receipt.ok and receipt.mirror == "wayback"
    assert "/web/20260717000000/" in receipt.location


def test_wayback_failure_is_an_honest_receipt_not_an_exception() -> None:
    def http(url: str, method: str) -> tuple[int, str, bytes]:
        raise ConnectionError("archive down")

    receipt = submit_wayback(CP_URL, http)
    assert not receipt.ok and "archive down" in receipt.detail


def test_software_heritage_submission_posts_save_code_now() -> None:
    seen: list[tuple[str, str]] = []

    def http(url: str, method: str) -> tuple[int, str, bytes]:
        seen.append((url, method))
        return 200, url, b"{}"

    receipt = submit_software_heritage(REPO, http)
    assert seen == [(f"https://archive.softwareheritage.org/api/1/origin/save/git/url/{REPO}/", "POST")]
    assert receipt.ok and REPO in receipt.location


def test_one_mirror_down_never_blocks_the_other() -> None:
    def http(url: str, method: str) -> tuple[int, str, bytes]:
        if "web.archive.org" in url:
            return 503, url, b""
        return 200, url, b"{}"

    receipts = mirror_checkpoint(CP_URL, REPO, http)
    assert [r.ok for r in receipts] == [False, True]  # fail-soft, both attempted
    assert all(isinstance(r, MirrorReceipt) for r in receipts)


def test_wayback_round_trip_compares_exact_bytes_via_identity_url() -> None:
    checkpoint = b"verderer.watchdog/m1-log\n3\nAAAA\n\n- sig\n"

    def http(url: str, method: str) -> tuple[int, str, bytes]:
        assert "0id_/" in url  # identity flag: original bytes, no replay rewriting
        return 200, url, checkpoint

    assert verify_wayback_copy(CP_URL, checkpoint, http) is True
    assert verify_wayback_copy(CP_URL, b"different", http) is False
