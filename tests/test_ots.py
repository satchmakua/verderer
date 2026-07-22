"""OpenTimestamps anchor tests (M13b) — against the real, Bitcoin-confirmed fixture.

`tests/fixtures/ots/` carries the live size-15 checkpoint, a genuine `.ots` proof upgraded
after Bitcoin confirmed it (blocks 959058 & 959061), those blocks' headers, and a proof
bundle that embeds the OTS anchor. Everything here verifies **offline** — no network, no
synthetic anchor — so a green test means the verifier agrees with the blockchain.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from verderer.anchors import verify_ots_offline
from verderer.ledger.core import find_binary

FIX = Path(__file__).parent / "fixtures" / "ots"
CHECKPOINT = (FIX / "checkpoint-15").read_text(encoding="utf-8")
OTS = (FIX / "checkpoint-15.ots").read_bytes()
HEADERS = {int(h): bytes.fromhex(x) for h, x in json.loads((FIX / "bitcoin-headers.json").read_text()).items()}

EARLIEST_BLOCK = "959058"


def test_confirmed_ots_anchor_verifies_offline(ledger_built: None) -> None:
    ok, message = verify_ots_offline(CHECKPOINT, OTS, HEADERS)
    assert ok, message
    assert "existed no later than 2026-07-21T21:09:36Z" in message
    assert EARLIEST_BLOCK in message  # the tightest bound is the earliest carried block


def test_forged_ots_proof_is_rejected(ledger_built: None) -> None:
    # Corrupt a byte on the shared prefix every Bitcoin path runs through.
    needle = bytes.fromhex("9e7360100716d07628e9ac17c27cfb22")
    at = OTS.find(needle)
    assert at > 0
    forged = bytearray(OTS)
    forged[at + 4] ^= 0x01
    ok, message = verify_ots_offline(CHECKPOINT, bytes(forged), HEADERS)
    assert not ok
    assert message.startswith("INVALID"), message


def test_confirmed_proof_without_header_is_unverified_not_invalid(ledger_built: None) -> None:
    ok, message = verify_ots_offline(CHECKPOINT, OTS, {})
    assert not ok
    assert message.startswith("UNVERIFIED"), message  # real proof, just nothing to bound offline


def test_wrong_checkpoint_is_rejected(ledger_built: None) -> None:
    ok, message = verify_ots_offline(CHECKPOINT + " ", OTS, HEADERS)
    assert not ok
    assert "does not commit" in message


def _verify_bundle(path: Path) -> tuple[int, str]:
    result = subprocess.run(
        [str(find_binary("verderer-verify")), "bundle", str(path)],
        capture_output=True,
    )
    return result.returncode, result.stdout.decode("utf-8", errors="replace").strip()


def test_bundle_carrying_ots_anchor_verifies_offline(ledger_built: None) -> None:
    code, message = _verify_bundle(FIX / "bundle-ots-15.json")
    assert code == 0, message
    assert "1 anchor(s) verified" in message
    assert "existed no later than 2026-07-21T21:09:36Z" in message


def test_bundle_with_tampered_ots_header_is_rejected(ledger_built: None, tmp_path: Path) -> None:
    bundle = json.loads((FIX / "bundle-ots-15.json").read_text(encoding="utf-8"))
    ots_anchor = next(a for a in bundle["anchors"] if a["type"] == "ots")
    # Flip a merkle-root byte in a carried header — only the OTS check can catch it.
    header = bytearray.fromhex(ots_anchor["headers"][EARLIEST_BLOCK])
    header[40] ^= 0x01
    ots_anchor["headers"][EARLIEST_BLOCK] = header.hex()
    tampered = tmp_path / "tampered.json"
    tampered.write_text(json.dumps(bundle), encoding="utf-8")
    code, message = _verify_bundle(tampered)
    assert code != 0
    assert "INVALID" in message or "merkle" in message


def test_producer_refuses_an_ots_proof_for_the_wrong_checkpoint(ledger_built: None, tmp_path: Path) -> None:
    # store_ots_anchor must reject a proof that does not commit to the ledger's checkpoint.
    from verderer.pipeline import Verderer

    verderer = Verderer(tmp_path / "data", targets={}, terms=[])
    verderer.log.append({"schema": "verderer.observation/v1", "target_id": "t", "raw_bytes_hash": "1220" + "00" * 32})
    with pytest.raises(ValueError, match="does not verify|does not commit"):
        verderer.store_ots_anchor(OTS, HEADERS)
