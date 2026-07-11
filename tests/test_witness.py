"""M8 — multi-party witnesses (C2SP tlog-cosignature). With a 2-of-3 witness set, a bundle
carrying a quorum of valid cosignatures verifies; one missing the quorum is rejected; a
cosignature from an unpinned witness does not count. Skipped if the Rust kernel is unbuilt.
"""

import json
import subprocess
from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.ledger.core import find_binary
from druid.pipeline import Druid
from druid.witness import generate_witness

PAGE = b"<html><body><p>EPA reporting threshold is 10 ppb.</p></body></html>"


def _make_druid(tmp_path: Path) -> Druid:
    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url="https://example.gov/t", status=200, headers={}, body=PAGE)

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=[],
        collector=StaticCollector(fetcher=fake),
    )


def _verify(bundle: dict, tmp_path: Path, name: str, extra: list[str]) -> subprocess.CompletedProcess[str]:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    return subprocess.run(
        [str(find_binary("druid-verify")), "bundle", str(path), *extra],
        capture_output=True,
        encoding="utf-8",
    )


def test_two_of_three_quorum(tmp_path: Path, ledger_built: None) -> None:
    druid = _make_druid(tmp_path)
    druid.observe("t")

    w1 = generate_witness("witness.one")
    w2 = generate_witness("witness.two")
    w3 = generate_witness("witness.three")  # a 3rd pinned witness who does NOT cosign
    pins = ["--witness", w1.pin(), "--witness", w2.pin(), "--witness", w3.pin()]

    # No cosignatures yet -> a 2-of-3 quorum is not met.
    bundle = druid.bundle("t")
    assert bundle["cosignatures"] == []
    r0 = _verify(bundle, tmp_path, "none", [*pins, "--quorum", "2"])
    assert r0.returncode != 0 and "quorum not met" in r0.stdout

    # One witness cosigns -> still short of a 2-of-3 quorum.
    druid.cosign(w1)
    bundle = druid.bundle("t")
    assert len(bundle["cosignatures"]) == 1
    r1 = _verify(bundle, tmp_path, "one", [*pins, "--quorum", "2"])
    assert r1.returncode != 0 and "quorum not met" in r1.stdout

    # A second witness cosigns -> quorum met, bundle validates.
    druid.cosign(w2)
    bundle = druid.bundle("t")
    assert len(bundle["cosignatures"]) == 2
    r2 = _verify(bundle, tmp_path, "two", [*pins, "--quorum", "2"])
    assert r2.returncode == 0, r2.stdout + r2.stderr
    assert "2/2 witness cosignature(s) verified" in r2.stdout


def test_unpinned_witness_does_not_count(tmp_path: Path, ledger_built: None) -> None:
    druid = _make_druid(tmp_path)
    druid.observe("t")

    pinned = generate_witness("witness.pinned")
    stranger = generate_witness("witness.stranger")  # cosigns, but the verifier doesn't pin it
    druid.cosign(pinned)
    druid.cosign(stranger)
    bundle = druid.bundle("t")
    assert len(bundle["cosignatures"]) == 2

    # Only the pinned witness counts; requiring 2 fails, requiring 1 passes.
    fail = _verify(bundle, tmp_path, "q2", ["--witness", pinned.pin(), "--quorum", "2"])
    assert fail.returncode != 0 and "quorum not met" in fail.stdout
    ok = _verify(bundle, tmp_path, "q1", ["--witness", pinned.pin(), "--quorum", "1"])
    assert ok.returncode == 0 and "1/1 witness cosignature(s) verified" in ok.stdout


def test_tampered_checkpoint_breaks_cosignature(tmp_path: Path, ledger_built: None) -> None:
    druid = _make_druid(tmp_path)
    druid.observe("t")
    w1 = generate_witness("witness.one")
    druid.cosign(w1)
    bundle = druid.bundle("t")

    # Flip a byte of the checkpoint the cosignature covers: inclusion fails first, and even
    # a cosignature would no longer match. The bundle must be rejected either way.
    chk = bundle["checkpoint"]
    bundle["checkpoint"] = chk.replace("m1-log\n1", "m1-log\n2", 1) if "m1-log\n1" in chk else chk[:-4] + "XXXX"
    bad = _verify(bundle, tmp_path, "tampered", ["--witness", w1.pin(), "--quorum", "1"])
    assert bad.returncode != 0 and "INVALID" in bad.stdout


def test_no_quorum_required_ignores_cosignatures(tmp_path: Path, ledger_built: None) -> None:
    # With no witnesses pinned and quorum 0, a bundle verifies as before (backward compat).
    druid = _make_druid(tmp_path)
    druid.observe("t")
    bundle = druid.bundle("t")
    ok = _verify(bundle, tmp_path, "plain", [])
    assert ok.returncode == 0 and "included offline" in ok.stdout


def test_witness_keys_are_distinct_and_stable(tmp_path: Path) -> None:
    from druid.witness import load_or_create_witness

    a = generate_witness("w")
    b = generate_witness("w")
    assert a.public_hex != b.public_hex  # independent keys
    assert len(a.public_hex) == 64 and len(a.seed_hex) == 64
    path = tmp_path / "w.json"
    first = load_or_create_witness(path, "w")
    again = load_or_create_witness(path, "w")
    assert first == again  # persisted + reloaded stably
