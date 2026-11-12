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


# --- Status-aware diffing: availability is classified first, content only between served responses ---


def _diff_types(result: object) -> list[str]:
    return [str(d.diff_type) for d in result.diffs]  # type: ignore[attr-defined]


def test_takedown_is_one_deletion_not_a_list_of_vanished_terms(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    live = b"<html>EPA works on climate change.</html>"
    verderer = _status_verderer(tmp_path, [(200, live), (404, b"<html>not found</html>")], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    gone = verderer.observe("t")
    # The 404 body is the server's error page: its missing terms are not content findings.
    assert _diff_types(gone) == ["Deletion"]
    assert gone.diffs[0].severity == "High"
    assert gone.diffs[0].evidence == {"from_status": 200, "to_status": 404}


def test_status_flip_with_identical_body_is_a_deletion(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    body = b"<html>same bytes different status</html>"
    verderer = _status_verderer(tmp_path, [(200, body), (451, body)], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    flipped = verderer.observe("t")
    assert _diff_types(flipped) == ["Deletion"]
    assert flipped.diffs[0].evidence == {"from_status": 200, "to_status": 451}


def test_error_page_churn_is_attested_but_not_reported_as_content(tmp_path: Path, ledger_built: None) -> None:
    # A block page that rotates a reference number: every response is a distinct attested
    # observation, but the resource itself did not change — no finding, no alert.
    cursor = {"i": 0}
    pages = [(403, b"<html>Access Denied. Reference #18.aaaa</html>"), (403, b"<html>Access Denied. Reference #18.bbbb</html>")]
    verderer = _status_verderer(tmp_path, pages, cursor)
    verderer.observe("t")
    cursor["i"] = 1
    second = verderer.observe("t")
    assert second.status == "observed" and second.diffs == []
    assert _obs_count(verderer) == 2


def test_a_changed_refusal_is_flagged(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    verderer = _status_verderer(tmp_path, [(403, b"<html>denied</html>"), (404, b"<html>gone</html>")], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    changed = verderer.observe("t")
    assert _diff_types(changed) == ["MetadataChange"]
    assert changed.diffs[0].evidence == {"scope": "http_status", "from_status": 403, "to_status": 404}


def test_reappearance_unchanged_says_so(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    live = b"<html>EPA works on climate change.</html>"
    verderer = _status_verderer(tmp_path, [(200, live), (404, b"<html>gone</html>"), (200, live)], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    verderer.observe("t")
    cursor["i"] = 2
    back = verderer.observe("t")
    assert _diff_types(back) == ["Reappearance"]
    assert back.diffs[0].severity == "Medium"
    assert back.diffs[0].evidence == {"from_status": 404, "to_status": 200, "versus_last_served": "identical"}


def test_reappearance_altered_is_diffed_against_the_last_served_version(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    before = b"<html><p>EPA works on climate change.</p></html>"
    after = b"<html><p>EPA works on resilience.</p></html>"
    verderer = _status_verderer(tmp_path, [(200, before), (404, b"<html>gone</html>"), (200, after)], cursor)
    first = verderer.observe("t")
    cursor["i"] = 1
    verderer.observe("t")
    cursor["i"] = 2
    back = verderer.observe("t")
    assert _diff_types(back) == ["Reappearance", "TermSubstitution"]
    assert back.diffs[0].evidence["versus_last_served"] == "changed"
    removed = back.diffs[1]
    assert removed.severity == "High" and removed.evidence == {"term": "climate change", "from": 1, "to": 0}
    # Compared with what was last *served*, not with the error page in between.
    assert first.observation is not None
    assert removed.from_observation_hash == first.observation.raw_bytes_hash


def test_first_ever_served_response_after_errors_has_no_earlier_version(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    verderer = _status_verderer(tmp_path, [(404, b"<html>gone</html>"), (200, b"<html>hello</html>")], cursor)
    verderer.observe("t")
    cursor["i"] = 1
    back = verderer.observe("t")
    assert _diff_types(back) == ["Reappearance"]
    assert back.diffs[0].evidence["versus_last_served"] == "no_earlier_version"


def test_a_new_redirect_destination_is_flagged_alongside_the_content_change(tmp_path: Path, ledger_built: None) -> None:
    responses = [
        ("https://example.gov/t", b"<html><p>The original page about climate change.</p></html>"),
        ("https://example.gov/landing", b"<html><p>Welcome to the agency.</p></html>"),
    ]
    cursor = {"i": 0}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        final_url, body = responses[cursor["i"]]
        return FetchResult(url=final_url, status=200, headers={}, body=body)

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fake),
    )
    verderer.observe("t")
    cursor["i"] = 1
    moved = verderer.observe("t")
    assert _diff_types(moved) == ["MetadataChange", "TermSubstitution"]
    assert moved.diffs[0].evidence == {
        "scope": "final_url",
        "from_url": "https://example.gov/t",
        "to_url": "https://example.gov/landing",
    }


def test_a_dataset_that_404s_is_a_deletion_not_a_parse_failure(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    responses = [(200, b"year,co2\n2020,410\n2021,412\n"), (404, b"<html>not found</html>")]

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        status, body = responses[cursor["i"]]
        return FetchResult(url=url, status=status, headers={}, body=body)

    verderer = Verderer(
        tmp_path / "data",
        targets={"d": Target(id="d", title="D", url="https://example.gov/d.csv", kind="dataset")},
        terms=[],
        collector=StaticCollector(fetcher=fake),
    )
    verderer.observe("d")
    cursor["i"] = 1
    gone = verderer.observe("d")
    assert _diff_types(gone) == ["Deletion"]
