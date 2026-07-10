"""M2c — tile serving, end to end through the pipeline: appends publish C2SP tile
files; a verifier reconstructs an inclusion proof from the published tiles alone (no
supplied proof, no stored-hash file); a tampered tile is rejected; `export` ships the
checkpoint + tiles so the static site doubles as a tile server. Skipped if the Rust
kernel isn't built (see conftest `ledger_built`).
"""

from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.pipeline import Druid
from druid.web.export import export_site

PAGE_BEFORE = b"<html><body><p>EPA works on climate change adaptation.</p></body></html>"
PAGE_AFTER = b"<html><body><p>EPA works on resilience adaptation.</p></body></html>"


def _make_druid(tmp_path: Path, pages: list[bytes], cursor: dict[str, int]) -> Druid:
    def fake_fetch(url: str, *, timeout: float = 30.0) -> FetchResult:
        body = pages[min(cursor["i"], len(pages) - 1)]
        return FetchResult(url=url, status=200, headers={"content-type": "text/html"}, body=body)

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://example.gov/t")},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fake_fetch),
    )


def _observed_twice(tmp_path: Path) -> Druid:
    cursor = {"i": 0}
    druid = _make_druid(tmp_path, [PAGE_BEFORE, PAGE_AFTER], cursor)
    druid.observe("t")
    cursor["i"] = 1
    druid.observe("t")
    return druid


def test_appends_publish_tiles_and_proofs_reconstruct_from_tiles_alone(
    tmp_path: Path, ledger_built: None
) -> None:
    druid = _observed_twice(tmp_path)
    size = len(druid.log.entries())
    assert size >= 3  # two observations + at least one diff record

    tile = tmp_path / "data" / "ledger" / "tile" / "8" / "0" / "000.p" / str(size)
    assert tile.exists(), f"expected the level-0 partial at {tile}"

    # The canonical hash file is removed: the published tiles + checkpoint must suffice.
    (tmp_path / "data" / "ledger" / "hashes").unlink()
    for index in range(size):
        ok, message = druid.log.offline_verify_from_tiles(index)
        assert ok, message
        assert "via tiles alone" in message


def test_tampered_tile_is_rejected(tmp_path: Path, ledger_built: None) -> None:
    druid = _observed_twice(tmp_path)
    size = len(druid.log.entries())
    tile = tmp_path / "data" / "ledger" / "tile" / "8" / "0" / "000.p" / str(size)
    data = bytearray(tile.read_bytes())
    data[7] ^= 0x01
    tile.write_bytes(bytes(data))

    ok, message = druid.log.offline_verify_from_tiles(0)
    assert not ok
    assert "INVALID" in message


def test_emit_tiles_regenerates_a_pre_tile_ledger(tmp_path: Path, ledger_built: None) -> None:
    import shutil

    druid = _observed_twice(tmp_path)
    shutil.rmtree(tmp_path / "data" / "ledger" / "tile")
    assert not druid.log.offline_verify_from_tiles(0)[0]

    info = druid.log.emit_tiles()
    assert info["height"] == 8
    assert info["tiles"] >= 1
    ok, message = druid.log.offline_verify_from_tiles(0)
    assert ok, message


def test_export_ships_checkpoint_and_tiles(tmp_path: Path, ledger_built: None) -> None:
    druid = _observed_twice(tmp_path)
    out = tmp_path / "site"
    info = export_site(druid, out)
    assert info["tiles"] >= 1
    assert (out / "checkpoint").read_text(encoding="utf-8").startswith("druid.watchdog/m1-log")
    size = len(druid.log.entries())
    assert (out / "tile" / "8" / "0" / "000.p" / str(size)).exists()
