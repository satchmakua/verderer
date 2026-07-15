"""M13 — consistency-proof gossip. A client that saw an earlier signed checkpoint can
confirm, offline, that a later one is the *same* append-only log (never forked, shrank, or
rewrote). Ledger-backed, so these skip if the Rust kernel isn't built.
"""

from __future__ import annotations

import json
from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.pipeline import Druid, _checkpoint_size
from druid.web.export import export_site

PAGES = [
    b"<html><body><p>reporting threshold is 10 ppb</p></body></html>",
    b"<html><body><p>reporting threshold is 15 ppb</p></body></html>",
    b"<html><body><p>reporting threshold is 20 ppb</p></body></html>",
]


def _druid(tmp_path: Path, cursor: dict[str, int]) -> Druid:
    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=PAGES[min(cursor["i"], len(PAGES) - 1)])

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["threshold"],
        collector=StaticCollector(fetcher=fetch),
    )


def test_checkpoint_size_parses_the_note() -> None:
    cp = "druid.watchdog/m1-log\n42\nAAAA...\n\n— druid.watchdog/m1-log base64sig\n"
    assert _checkpoint_size(cp) == 42


def test_gossip_bundle_confirms_extension(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    druid = _druid(tmp_path, cursor)
    druid.observe("t")  # first observation -> the log grows
    old_cp = druid.log.signed_checkpoint()  # a client saves this
    old_size = _checkpoint_size(old_cp)

    cursor["i"] = 1
    druid.observe("t")  # more leaves (observation + a diff)
    cursor["i"] = 2
    druid.observe("t")

    bundle = druid.gossip_bundle(old_cp)
    assert bundle["schema"] == "druid.consistency/v1"
    assert bundle["from"] == old_size and bundle["to"] > old_size

    ok, message = druid.log.verify_consistency(
        bundle["old_checkpoint"], bundle["new_checkpoint"], bundle["proof"]
    )
    assert ok, message
    assert "CONSISTENT" in message and "extends" in message


def test_gossip_rejects_a_shrunk_or_forged_history(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    druid = _druid(tmp_path, cursor)
    druid.observe("t")
    old_cp = druid.log.signed_checkpoint()
    cursor["i"] = 1
    druid.observe("t")
    bundle = druid.gossip_bundle(old_cp)

    # Swapping old/new claims the (larger) new tree is extended by the (smaller) old one:
    # the log would have to have shrunk. Rejected.
    ok, message = druid.log.verify_consistency(
        bundle["new_checkpoint"], bundle["old_checkpoint"], bundle["proof"]
    )
    assert not ok and "INCONSISTENT" in message

    # A checkpoint whose signature is broken doesn't verify as a note at all.
    tampered = bundle["new_checkpoint"].replace("m1-log", "m1-XXX", 1)
    ok2, _ = druid.log.verify_consistency(bundle["old_checkpoint"], tampered, bundle["proof"])
    assert not ok2


def test_export_publishes_a_verifiable_consistency_chain(tmp_path: Path, ledger_built: None) -> None:
    cursor = {"i": 0}
    druid = _druid(tmp_path, cursor)
    druid.observe("t")

    # First export records the gossip baseline; there is no earlier checkpoint to link yet.
    first = export_site(druid, tmp_path / "site1")
    assert first["consistency"] == 0
    assert not (tmp_path / "site1" / "consistency.json").exists()

    # The log grows, then a second export publishes a consistency proof linking the two.
    cursor["i"] = 1
    druid.observe("t")
    second = export_site(druid, tmp_path / "site2")
    assert second["consistency"] == 1
    bundle = json.loads((tmp_path / "site2" / "consistency.json").read_text(encoding="utf-8"))
    assert bundle["schema"] == "druid.consistency/v1"

    # A client that downloaded only consistency.json can verify it offline.
    ok, message = druid.log.verify_consistency(
        bundle["old_checkpoint"], bundle["new_checkpoint"], bundle["proof"]
    )
    assert ok, message


def test_cmd_consistency_baseline_then_proves(tmp_path: Path, ledger_built: None) -> None:
    import argparse

    from druid.cli import cmd_consistency

    cursor = {"i": 0}
    _druid(tmp_path, cursor).observe("t")  # seed a ledger under tmp_path/data

    data_dir = tmp_path / "data"
    args = argparse.Namespace(
        data_dir=data_dir, targets=None, terms=None, output=tmp_path / "gossip.json"
    )
    # First run records a baseline.
    assert cmd_consistency(args) == 0
    assert (data_dir / "ledger" / "gossip-baseline-checkpoint").exists()

    # Grow the log, then a second run proves consistency and writes the bundle.
    _druid(tmp_path, {"i": 1}).observe("t")
    assert cmd_consistency(args) == 0
    assert (tmp_path / "gossip.json").exists()


def test_verify_consistency_binds_to_a_pinned_key(tmp_path: Path, ledger_built: None) -> None:
    # A gossip bundle verified under a WRONG pinned key must be rejected (an attacker's
    # self-consistent history under their own key proves nothing about Druid's real log).
    import argparse

    from druid.cli import cmd_verify_consistency

    cursor = {"i": 0}
    druid = _druid(tmp_path, cursor)
    druid.observe("t")
    old_cp = druid.log.signed_checkpoint()
    cursor["i"] = 1
    druid.observe("t")
    bundle = druid.gossip_bundle(old_cp)
    (tmp_path / "b.json").write_text(json.dumps(bundle), encoding="utf-8")

    # The real key verifies.
    ok_args = argparse.Namespace(path=tmp_path / "b.json", pubkey=druid.log.public_key_hex)
    assert cmd_verify_consistency(ok_args) == 0
    # A different pinned key is rejected before even running the proof.
    bad = "00" * 32
    assert cmd_verify_consistency(argparse.Namespace(path=tmp_path / "b.json", pubkey=bad)) == 1
