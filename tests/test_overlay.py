"""M7 — federated overlay + verification badging. A resource in both a third-party archive
and Druid is badged druid-attested with a downloadable proof bundle; a third-party-only
copy shows no badge. A fake `ArchiveSource` keeps the harvest offline; `WaybackSource`
parsing of real CDX rows is checked directly.
"""

import json
from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.overlay import OverlayCapture, WaybackSource, build_overlay, write_overlay
from druid.pipeline import Druid

TARGET_URL = "https://www.example.gov/ghg"
SIBLING_URL = "https://example.gov/other-page"  # archived by a third party, never observed by Druid


class FakeSource:
    name = "wayback"

    def __init__(self, by_query: dict[str, list[OverlayCapture]]) -> None:
        self._by_query = by_query

    def captures(self, url: str) -> list[OverlayCapture]:
        return self._by_query.get(url, [])


def _cap(url: str, ts: str) -> OverlayCapture:
    return OverlayCapture(source="wayback", url=url, timestamp=ts, archive_url=f"http://web.archive.org/web/{ts}/{url}")


def _druid(tmp_path: Path) -> Druid:
    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=TARGET_URL, status=200, headers={}, body=b"<html>ghg</html>")

    return Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url=TARGET_URL)},
        terms=[],
        collector=StaticCollector(fetcher=fake),
    )


def test_attested_resource_is_badged_and_third_party_only_is_not(tmp_path: Path, ledger_built: None) -> None:
    druid = _druid(tmp_path)
    druid.observe("t")  # Druid now attests TARGET_URL

    # The archive returns a capture of the observed URL AND of a sibling Druid never saw.
    source = FakeSource(
        {TARGET_URL: [_cap("http://example.gov/ghg", "20250101000000"), _cap(SIBLING_URL, "20250102000000")]}
    )
    overlay = build_overlay(druid, [source], query_urls=[TARGET_URL])

    by_url = {r["url"]: r for r in overlay["resources"]}
    # The observed resource (matched across scheme/www) is attested + carries a bundle ref.
    attested = next(r for r in overlay["resources"] if r["attested"])
    assert attested["badge"] == "druid-attested"
    # The bundle is keyed on the specific attested leaf, so it proves exactly this hash.
    assert attested["druid"]["bundle"] == f"bundles/{attested['druid']['index']}.json"
    assert attested["druid"]["observations"] == 1
    assert attested["external"] and attested["external"][0]["source"] == "wayback"

    # The third-party-only sibling is present but unbadged.
    sibling = by_url[SIBLING_URL]
    assert sibling["attested"] is False and sibling["badge"] is None and sibling["druid"] is None
    assert sibling["external"][0]["captures"][0]["archive_url"].startswith("http://web.archive.org/web/")

    assert overlay["attested_count"] == 1
    assert overlay["schema"] == "druid.overlay/v1"


def test_write_overlay_emits_index_and_downloadable_bundle(tmp_path: Path, ledger_built: None) -> None:
    druid = _druid(tmp_path)
    druid.observe("t")
    source = FakeSource({TARGET_URL: [_cap("http://example.gov/ghg", "20250101000000")]})

    out = tmp_path / "site"
    info = write_overlay(druid, out, [source], query_urls=[TARGET_URL])
    assert info["attested"] == 1 and info["bundles"] == 1

    overlay = json.loads((out / "overlay.json").read_text(encoding="utf-8"))
    assert overlay["schema"] == "druid.overlay/v1"
    att = next(r for r in overlay["resources"] if r["attested"])
    bundle = json.loads((out / att["druid"]["bundle"]).read_text(encoding="utf-8"))
    assert bundle["schema"] == "druid.proofbundle/v1"  # a real, self-verifying proof bundle
    assert bundle["observation"]["url"] == TARGET_URL
    # The invariant: the shipped bundle proves exactly the hash the row advertises.
    assert bundle["observation"]["raw_bytes_hash"] == att["druid"]["content_hash"]


def test_attested_only_resource_appears_without_any_archive(tmp_path: Path, ledger_built: None) -> None:
    # A Druid-attested resource that no third party archived is still in the overlay,
    # badged, with an empty external list.
    druid = _druid(tmp_path)
    druid.observe("t")
    overlay = build_overlay(druid, [FakeSource({})], query_urls=[TARGET_URL])
    assert len(overlay["resources"]) == 1
    assert overlay["resources"][0]["attested"] and overlay["resources"][0]["external"] == []


def test_every_attested_bundle_proves_its_advertised_hash(tmp_path: Path, ledger_built: None) -> None:
    # A curated target whose URL moved over time (observed at two URLs) yields two attested
    # resources. Each row's bundle must prove *that row's* URL + hash — never the other's.
    url1, url2 = "https://www.epa.gov/climate", "https://www.epa.gov/climate-change"
    bodies = {url1: b"<html>v1</html>", url2: b"<html>v2 changed</html>"}

    def fetch_for(url: str):
        def fake(u: str, *, timeout: float = 30.0) -> FetchResult:
            return FetchResult(url=url, status=200, headers={}, body=bodies[url])

        return fake

    data = tmp_path / "data"
    Druid(data, targets={"t": Target(id="t", title="T", url=url1)}, terms=[],
          collector=StaticCollector(fetcher=fetch_for(url1))).observe("t")
    druid = Druid(data, targets={"t": Target(id="t", title="T", url=url2)}, terms=[],
                  collector=StaticCollector(fetcher=fetch_for(url2)))
    druid.observe("t")  # same ledger now holds observations of url1 (v1) and url2 (v2)

    # Third parties archived each URL under an equivalent-but-different form (http, slash).
    source = FakeSource({
        url1: [_cap("http://www.epa.gov/climate/", "20240101000000")],
        url2: [_cap("http://epa.gov/climate-change", "20250101000000")],
    })
    out = tmp_path / "site"
    write_overlay(druid, out, [source], query_urls=[url1, url2])
    overlay = json.loads((out / "overlay.json").read_text(encoding="utf-8"))

    attested = [r for r in overlay["resources"] if r["attested"]]
    assert len(attested) == 2  # two distinct URL resources, both attested
    for row in attested:
        bundle = json.loads((out / row["druid"]["bundle"]).read_text(encoding="utf-8"))
        # No overclaim: the downloadable proof attests exactly this resource's URL + hash —
        # and the URL shown is the one Druid observed, not a third party's capture form.
        assert bundle["observation"]["url"] == row["url"]
        assert bundle["observation"]["raw_bytes_hash"] == row["druid"]["content_hash"]
        assert row["external"]  # the archive form still surfaces as a third-party capture


def test_wayback_source_skips_ragged_cdx_rows() -> None:
    # A short/truncated data row must be skipped, never abort the whole harvest.
    rows = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["com,epa)/x", "20200101000000"],  # ragged: fewer columns than the header
        ["gov,epa)/ghg", "20250101120000", "http://epa.gov/ghg", "text/html", "200", "AB", "12"],
    ]
    caps = WaybackSource(fetcher=lambda url, prefix, limit: rows).captures("http://epa.gov/ghg")
    assert len(caps) == 1 and caps[0].url == "http://epa.gov/ghg"


def test_wayback_source_parses_cdx_rows() -> None:
    # Real CDX shape: row 0 is the field header, then one row per capture.
    rows = [
        ["urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"],
        ["gov,epa)/ghg", "20250101120000", "http://epa.gov/ghg", "text/html", "200", "ABCD", "1234"],
    ]
    source = WaybackSource(fetcher=lambda url, prefix, limit: rows)
    caps = source.captures("http://epa.gov/ghg")
    assert len(caps) == 1
    assert caps[0].url == "http://epa.gov/ghg" and caps[0].status == "200" and caps[0].mime == "text/html"
    assert caps[0].archive_url == "http://web.archive.org/web/20250101120000/http://epa.gov/ghg"


def test_wayback_source_empty_result() -> None:
    assert WaybackSource(fetcher=lambda url, prefix, limit: []).captures("x") == []
