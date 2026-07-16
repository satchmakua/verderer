"""L3 embedding triage (M6): a reworded passage is surfaced for review; a near-duplicate
is not. A deterministic bag-of-words fake embedder stands in for the real model, so the
suite needs no `sentence-transformers`.
"""

import hashlib
import re
from pathlib import Path

from verderer.collectors.base import FetchResult
from verderer.collectors.static import StaticCollector
from verderer.config import Target
from verderer.differ.embedding import embedding_triage
from verderer.models import DiffType
from verderer.pipeline import Verderer


class BagEmbedder:
    """A stable bag-of-words vector: overlapping vocabulary -> high cosine, disjoint -> low.
    Enough to exercise the alignment + banding logic without a real embedding model."""

    DIM = 128

    def embed(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]

    def _vec(self, text: str) -> list[float]:
        v = [0.0] * self.DIM
        for word in re.findall(r"[a-z]+", text.lower()):
            idx = int(hashlib.md5(word.encode()).hexdigest(), 16) % self.DIM
            v[idx] += 1.0
        return v


def _triage(prev: str, curr: str) -> list:
    return embedding_triage(
        prev, curr, BagEmbedder(), target_id="t", detected_at="2026-01-01T00:00:00Z", from_hash="a", to_hash="b"
    )


PREV = (
    "The agency remains firmly committed to aggressively reducing nationwide greenhouse pollution. "
    "Reporting is required for all large facilities every calendar year."
)
CURR_REWORDED = (
    "The agency remains open to reviewing facility emissions nationwide where feasible. "
    "Reporting is required for all large facilities every calendar year."
)


def test_reworded_passage_is_surfaced_for_review() -> None:
    diffs = _triage(PREV, CURR_REWORDED)
    reworded = [d for d in diffs if d.diff_type is DiffType.ContentEdit and d.evidence.get("change") == "reworded"]
    assert reworded, [d.evidence for d in diffs]
    ev = reworded[0].evidence
    assert reworded[0].layer == "L3-embedding" and reworded[0].severity == "Medium"
    assert "committed" in ev["from"] and "reviewing" in ev["to"]
    assert 0.0 <= ev["similarity"] < 0.85  # semantically distant enough to review


def test_unchanged_text_is_quiet() -> None:
    assert _triage(PREV, PREV) == []


def test_near_duplicate_is_not_a_review_finding() -> None:
    # A light edit (same vocabulary, one clause reordered) must not surface as a ContentEdit
    # rewrite — at most a low-severity cosmetic note.
    prev = "Every covered facility in the program must report its emissions to the agency."
    curr = "Every covered facility in the program must report to the agency its emissions."
    diffs = _triage(prev, curr)
    assert not any(d.diff_type is DiffType.ContentEdit for d in diffs)


def test_pipeline_uses_l3_when_embedder_present(tmp_path: Path, ledger_built: None) -> None:
    # A change that L1 term-watch and L2 numeric-watch do NOT explain: the reworded passage
    # is surfaced by L3 as a ContentEdit for review (no watched term, no number moved).
    pages = {"i": 0, "bodies": [PREV.encode(), CURR_REWORDED.encode()]}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=pages["bodies"][pages["i"]])

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://e.gov/t")},
        terms=["climate change"],  # not present -> L1 finds nothing
        collector=StaticCollector(fetcher=fake),
        embedder=BagEmbedder(),
    )
    assert verderer.observe("t").is_first
    pages["i"] = 1
    diffs = verderer.observe("t").diffs
    l3 = [d for d in diffs if d.layer == "L3-embedding" and d.diff_type is DiffType.ContentEdit]
    assert l3, [d.evidence for d in diffs]


def test_embedder_still_flags_a_pure_deletion(tmp_path: Path, ledger_built: None) -> None:
    # L3 inspects added/reworded passages, so a pure sentence deletion produces no L3
    # finding. The coarse floor must still fire — enabling the embedder must never *lose*
    # a signal the no-embedder path would have caught.
    before = (
        "Regional trends vary across the country. We remain committed to reducing facility "
        "emissions nationwide. Annual reporting continues for all covered facilities."
    )
    after = (  # middle sentence deleted; no watched term, no number
        "Regional trends vary across the country. Annual reporting continues for all covered facilities."
    )
    pages = {"i": 0, "bodies": [before.encode(), after.encode()]}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=pages["bodies"][pages["i"]])

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://e.gov/t")},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fake),
        embedder=BagEmbedder(),
    )
    verderer.observe("t")
    pages["i"] = 1
    diffs = verderer.observe("t").diffs
    assert [d for d in diffs if d.diff_type is DiffType.ContentEdit], "a deletion must still be flagged"


def test_pipeline_without_embedder_keeps_coarse_fallback(tmp_path: Path, ledger_built: None) -> None:
    pages = {"i": 0, "bodies": [PREV.encode(), CURR_REWORDED.encode()]}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=pages["bodies"][pages["i"]])

    verderer = Verderer(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://e.gov/t")},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fake),
    )
    verderer.observe("t")
    pages["i"] = 1
    diffs = verderer.observe("t").diffs
    assert [d for d in diffs if d.layer == "L0-normalize"]  # coarse fallback, no embedder
