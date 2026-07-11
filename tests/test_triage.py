"""L5 reviewer summaries (M6): drafts land in a review sidecar, never in the ledger, and
the summarizer is injectable so no API call or network is made. A fake Anthropic client
also verifies the request shape without the SDK.
"""

import hashlib
import re
from pathlib import Path

from druid.collectors.base import FetchResult
from druid.collectors.static import StaticCollector
from druid.config import Target
from druid.pipeline import Druid
from druid.triage import REVIEW_SCHEMA, claude_summarizer, summarize_event

PREV = (
    "The agency remains firmly committed to aggressively reducing nationwide greenhouse pollution. "
    "Reporting is required for all large facilities every calendar year."
)
CURR_REWORDED = (
    "The agency remains open to reviewing facility emissions nationwide where feasible. "
    "Reporting is required for all large facilities every calendar year."
)


class BagEmbedder:
    """A stable bag-of-words vector (overlap -> high cosine), so tests need no model."""

    DIM = 128

    def embed(self, texts: list[str]) -> list[list[float]]:
        out = []
        for text in texts:
            v = [0.0] * self.DIM
            for word in re.findall(r"[a-z]+", text.lower()):
                v[int(hashlib.md5(word.encode()).hexdigest(), 16) % self.DIM] += 1.0
            out.append(v)
        return out


def _druid_with_reworded_event(tmp_path: Path) -> Druid:
    pages = {"i": 0, "bodies": [PREV.encode(), CURR_REWORDED.encode()]}

    def fake(url: str, *, timeout: float = 30.0) -> FetchResult:
        return FetchResult(url=url, status=200, headers={}, body=pages["bodies"][pages["i"]])

    druid = Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://e.gov/t")},
        terms=["climate change"],
        collector=StaticCollector(fetcher=fake),
        embedder=BagEmbedder(),
    )
    druid.observe("t")
    pages["i"] = 1
    druid.observe("t")
    return druid


def test_summarize_event_writes_sidecar_not_ledger(tmp_path: Path, ledger_built: None) -> None:
    druid = _druid_with_reworded_event(tmp_path)
    entries_before = len(druid.log.entries())

    def fake_summarizer(before: str, after: str, *, context: str = "") -> str:
        assert "committed" in before and "reviewing" in after
        return "The passage weakens a firm commitment into a voluntary consideration."

    review = summarize_event(druid, "t", fake_summarizer)
    assert review is not None
    assert review["schema"] == REVIEW_SCHEMA
    assert "voluntary consideration" in review["summary"]
    assert "Not attested" in review["disclaimer"]

    # The trust core is untouched: the summary is a sidecar file, no new ledger leaf.
    assert len(druid.log.entries()) == entries_before
    sidecars = list((tmp_path / "data" / "review").glob("*.json"))
    assert len(sidecars) == 1
    assert "voluntary consideration" in sidecars[0].read_text(encoding="utf-8")
    assert druid.log.verify()[0]  # ledger still verifies


def test_summarize_event_none_when_no_rework(tmp_path: Path, ledger_built: None) -> None:
    druid = Druid(
        tmp_path / "data",
        targets={"t": Target(id="t", title="T", url="https://e.gov/t")},
        terms=[],
        collector=StaticCollector(fetcher=lambda u, *, timeout=30.0: FetchResult(u, 200, {}, PREV.encode())),
        embedder=BagEmbedder(),
    )
    druid.observe("t")  # only one observation -> no diff at all
    assert summarize_event(druid, "t", lambda b, a, *, context="": "x") is None


class _FakeBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeMessage:
    def __init__(self, text: str) -> None:
        self.content = [_FakeBlock(text)]


class _FakeMessages:
    def __init__(self, record: dict) -> None:
        self._record = record

    def create(self, **kwargs: object) -> _FakeMessage:
        self._record.update(kwargs)
        return _FakeMessage("weakened commitment to a voluntary measure")


class _FakeAnthropic:
    def __init__(self) -> None:
        self.captured: dict = {}
        self.messages = _FakeMessages(self.captured)


def test_claude_summarizer_builds_a_correct_request() -> None:
    # Verify the Messages API usage (model, system, single user turn) without the SDK or
    # a billable call, by injecting a fake client.
    client = _FakeAnthropic()
    summarize = claude_summarizer("claude-opus-4-8", client=client)
    out = summarize("BEFORE text", "AFTER text", context="target t")

    assert out == "weakened commitment to a voluntary measure"
    assert client.captured["model"] == "claude-opus-4-8"
    assert client.captured["max_tokens"] == 1024
    assert "reviewer" in client.captured["system"].lower()
    messages = client.captured["messages"]
    assert len(messages) == 1 and messages[0]["role"] == "user"
    assert "BEFORE text" in messages[0]["content"] and "AFTER text" in messages[0]["content"]
