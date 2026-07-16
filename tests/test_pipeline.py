"""End-to-end M1 slice with a fake collector (no network): observe twice, detect a
term substitution, verify the ledger via the Rust trust core, then prove tampering is
caught. Skipped if the Rust binaries aren't built (see conftest `ledger_built`).
"""

import base64
from pathlib import Path

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.models import DiffType
from verderer.pipeline import Verderer

PAGE_BEFORE = b"<html><body><p>EPA works on climate change adaptation.</p></body></html>"
PAGE_AFTER = b"<html><body><p>EPA works on resilience adaptation.</p></body></html>"


def _make_verderer(tmp_path: Path, pages: list[bytes], cursor: dict[str, int]) -> Verderer:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        body = pages[min(cursor["i"], len(pages) - 1)]
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=body)

    return Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["climate change", "resilience"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def test_observe_diff_and_verify(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    verderer = _make_verderer(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)

    first = verderer.observe("t")
    assert first.is_first
    assert first.diffs == []

    cursor["i"] = 1
    second = verderer.observe("t")
    assert DiffType.TermSubstitution in {d.diff_type for d in second.diffs}

    ok, message = verderer.log.verify()
    assert ok, message
    assert len(verderer.log.public_key_hex) == 64  # an Ed25519 public key, hex-encoded


def test_inclusion_proof_round_trips(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    verderer = _make_verderer(tmp_path, [PAGE_BEFORE], cursor)
    verderer.observe("t")
    incl = verderer.log.inclusion(0)
    assert incl["tree_size"] >= 1
    assert incl["checkpoint"].startswith("verderer.watchdog/m1-log")
    assert isinstance(incl["proof"], list)


def test_offline_inclusion_verifies(tmp_path: Path, ledger_built: None) -> None:
    # Append a few leaves, then confirm leaf 0 verifies offline against the signed
    # checkpoint — the transferable proof the verifier checks without the live service.
    cursor = {"i": 0}
    verderer = _make_verderer(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    verderer.observe("t")

    ok, message = verderer.log.offline_verify(0)
    assert ok, message
    assert "included in tree size" in message


def test_tampering_breaks_verification(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    verderer = _make_verderer(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    verderer.observe("t")
    assert verderer.log.verify()[0]

    # Corrupt a stored leaf (re-encode a different record into line 0); the recomputed
    # root no longer matches the signed checkpoint.
    entries = tmp_path / "data" / "ledger" / "entries.b64"
    lines = entries.read_text(encoding="utf-8").splitlines()
    lines[0] = base64.b64encode(b'{"schema":"verderer.observation/v1","tampered":true}').decode()
    entries.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, _ = verderer.log.verify()
    assert not ok  # tampering with a stored leaf is detected


# --- M10: don't re-log a byte-identical observation (sustainable continuous operation) ---


def _status_verderer(tmp_path: Path, responses: list[tuple[int, bytes]], cursor: dict[str, int]) -> Verderer:
    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        status, body = responses[min(cursor["i"], len(responses) - 1)]
        return FetchResult(url=url, status=status, headers={}, body=body)

    return Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fake),
    )


def _obs_count(verderer: Verderer) -> int:
    return sum(1 for e in verderer.log.entries() if e.record.get("schema") == "verderer.observation/v1")


def test_identical_reobservation_is_not_relogged(tmp_path: Path, ledger_built: None) -> None:
    # A 404 (or any no-validator response) can't be spared by a conditional GET, so the
    # scheduler re-fetches it. Re-logging the byte-identical leaf every cycle would bloat the
    # ledger; instead the pipeline treats it like a 304 — no new leaf.
    cursor = {"i": 0}
    verderer = _status_verderer(tmp_path, [(404, b"<html>not found</html>")], cursor)
    first = verderer.observe("t")
    assert first.status == "observed" and first.is_first
    second = verderer.observe("t")
    assert second.status == "unchanged" and second.observation is None
    assert _obs_count(verderer) == 1  # the identical 404 was not re-logged


def test_status_flip_with_identical_body_is_logged(tmp_path: Path, ledger_built: None) -> None:
    # A 200 -> 451 (unavailable for legal reasons) with a byte-identical cached body is a
    # real change: it must be attested, not deduped away.
    cursor = {"i": 0}
    body = b"<html>same bytes different status</html>"
    verderer = _status_verderer(tmp_path, [(200, body), (451, body)], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    second = verderer.observe("t")
    assert second.status == "observed"
    assert _obs_count(verderer) == 2


def test_reappearance_after_404_is_logged_with_diff(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    live = b"<html>EPA works on climate change.</html>"
    verderer = _status_verderer(tmp_path, [(200, live), (404, b"<html>gone</html>"), (200, live)], cursor)
    verderer.observe("t")  # 200 live
    cursor["i"] = 1
    verderer.observe("t")  # 404 -> logged (content changed)
    cursor["i"] = 2
    third = verderer.observe("t")  # 200 live again -> logged (a reappearance, not a duplicate)
    assert third.status == "observed"
    assert _obs_count(verderer) == 3
    assert third.diffs  # the reappearance is a detected change
