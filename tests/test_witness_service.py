"""M14c — the independently-run witness. It holds its own key and its own memory of the log,
pins the log key out-of-band, and needs no operator ledger. It cosigns only what it can
confirm extends what it last saw — and refuses (loudly) anything else. Ledger-backed, so
these skip if the Rust kernel isn't built.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.pipeline import Verderer
from verderer.witness import WitnessService, generate_witness

TARGET = {"t": Target(id="t", title="T", url="https://fixture.verderer.invalid/t")}


def _verderer(data: Path, body: bytes) -> Verderer:
    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=body)

    return Verderer(data, targets=TARGET, terms=[], collector=StaticCollector(fetcher=fetch))


def _service(tmp_path: Path, pubkey: str, name: str = "witness.acme") -> WitnessService:
    return WitnessService(generate_witness(name), pubkey, tmp_path / f"{name}.state")


def test_witness_cosigns_a_checkpoint_it_can_verify(tmp_path: Path, ledger_built: None) -> None:
    v = _verderer(tmp_path / "op", b"<p>a</p>")
    v.observe("t")
    service = _service(tmp_path, v.log.public_key_hex)

    result = service.observe(v.log.signed_checkpoint())
    assert result.status == "cosigned"
    assert result.cosignature and result.cosignature.startswith("—")
    assert result.size == 1
    # It remembers what it vouched for — its own independent memory of the log.
    assert service.last_accepted() == v.log.signed_checkpoint()


def test_witness_cosigns_a_genuine_extension(tmp_path: Path, ledger_built: None) -> None:
    state = {"b": b"<p>a</p>"}

    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=state["b"])

    v = Verderer(tmp_path / "op", targets=TARGET, terms=[], collector=StaticCollector(fetcher=fetch))
    v.observe("t")
    service = _service(tmp_path, v.log.public_key_hex)
    assert service.observe(v.log.signed_checkpoint()).status == "cosigned"

    state["b"] = b"<p>b</p>"
    v.observe("t")  # the log grows honestly
    bundle = v.gossip_bundle(service.last_accepted() or "")
    result = service.observe(bundle["new_checkpoint"], bundle["proof"])
    assert result.status == "cosigned", result.reason
    assert "extends" in result.reason


def test_witness_refuses_an_equivocating_log(tmp_path: Path, ledger_built: None) -> None:
    # The whole reason a witness exists: two different roots at the same size, signed by the
    # same key, is a split view. It must never vouch for it.
    v = _verderer(tmp_path / "op", b"<p>honest</p>")
    v.observe("t")
    service = _service(tmp_path, v.log.public_key_hex)
    assert service.observe(v.log.signed_checkpoint()).status == "cosigned"

    evil_dir = tmp_path / "evil"
    (evil_dir / "ledger").mkdir(parents=True)
    shutil.copy(tmp_path / "op" / "ledger" / "key.json", evil_dir / "ledger" / "key.json")
    evil = _verderer(evil_dir, b"<p>tampered</p>")  # same key, different content -> different root
    evil.observe("t")

    result = service.observe(evil.log.signed_checkpoint())
    assert result.status == "refused"
    assert "equivocated" in result.reason


def test_witness_refuses_a_log_signed_by_an_unpinned_key(tmp_path: Path, ledger_built: None) -> None:
    # A witness pins the log key out-of-band; an attacker's own log must not verify.
    v = _verderer(tmp_path / "op", b"<p>a</p>")
    v.observe("t")
    attacker = _verderer(tmp_path / "attacker", b"<p>a</p>")  # a different key
    attacker.observe("t")

    service = _service(tmp_path, v.log.public_key_hex)  # pinned to the REAL log
    result = service.observe(attacker.log.signed_checkpoint())
    assert result.status == "refused"


def test_unreadable_memory_fails_closed_not_back_to_bootstrap(tmp_path: Path, ledger_built: None) -> None:
    # Review regression (HIGH): if the witness's memory exists but can't be read, treating it
    # as "no memory" would drop to the bootstrap path (signature check only) and cosign a fork
    # it had already refused — then remember it. One I/O fault must not defeat the whole point.
    v = _verderer(tmp_path / "op", b"<p>honest</p>")
    v.observe("t")
    service = _service(tmp_path, v.log.public_key_hex)
    assert service.observe(v.log.signed_checkpoint()).status == "cosigned"

    evil_dir = tmp_path / "evil"
    (evil_dir / "ledger").mkdir(parents=True)
    shutil.copy(tmp_path / "op" / "ledger" / "key.json", evil_dir / "ledger" / "key.json")
    evil = _verderer(evil_dir, b"<p>tampered</p>")
    evil.observe("t")
    fork = evil.log.signed_checkpoint()

    # With its memory intact the witness refuses the fork...
    assert service.observe(fork).status == "refused"

    # ...and with its memory *unreadable* it must still refuse — never silently re-bootstrap.
    def boom(*_a: object, **_k: object) -> str:
        raise OSError("state file locked")

    original = Path.read_text
    Path.read_text = boom  # type: ignore[method-assign]
    try:
        result = service.observe(fork)
    finally:
        Path.read_text = original  # type: ignore[method-assign]
    assert result.status == "refused"
    assert "memory" in result.reason
    # The attacker's fork was not adopted as this witness's history.
    assert service.last_accepted() != fork


def test_ingest_rejects_a_vouch_for_a_stale_checkpoint(tmp_path: Path, ledger_built: None) -> None:
    # Review regression: a cosignature only means something about the checkpoint it covers.
    # If the log moves on before the operator files it, filing it anyway would yield a bundle
    # whose quorum can never hold. Reject loudly instead.
    import pytest

    state = {"b": b"<p>a</p>"}

    def fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=state["b"])

    v = Verderer(tmp_path / "op", targets=TARGET, terms=[], collector=StaticCollector(fetcher=fetch))
    v.observe("t")
    witness = generate_witness("witness.acme")
    vouch = WitnessService(witness, v.log.public_key_hex, tmp_path / "w.state").observe(v.log.signed_checkpoint())
    assert vouch.checkpoint is not None

    state["b"] = b"<p>b</p>"
    v.observe("t")  # the log moves on before the operator files the vouch
    with pytest.raises(ValueError, match="re-witness"):
        v.ingest_cosignature(vouch.cosignature or "", witness.name, covers=vouch.checkpoint)


def test_operator_ingests_an_independent_vouch_and_meets_quorum(tmp_path: Path, ledger_built: None) -> None:
    # End-to-end: the operator files a line produced by a witness whose key it never holds,
    # and a bundle then meets a quorum of 1 — but not 2.
    v = _verderer(tmp_path / "op", b"<p>a</p>")
    v.observe("t")
    witness = generate_witness("witness.acme")
    service = WitnessService(witness, v.log.public_key_hex, tmp_path / "w.state")
    vouch = service.observe(v.log.signed_checkpoint())
    assert vouch.status == "cosigned" and vouch.cosignature

    info = v.ingest_cosignature(vouch.cosignature, witness.name)
    assert info["cosignatures"] == 1
    bundle = v.bundle("t")
    assert len(bundle["cosignatures"]) == 1  # the bundle carries the independent vouch
