"""L5 — LLM-assisted change summaries (DESIGN §6.2, M6). **For reviewers only.**

A plain-language draft of *what changed and whether it plausibly alters meaning*, to help
a human reviewer triage an L3-surfaced rewrite faster. It is a drafting aid and **never an
authority**: the summary is written to a review sidecar (`druid-data/review/`), clearly
labelled best-effort, and is **never** placed in a ledger leaf — the trust core neither
sees nor attests it. The summarizer is injected behind the :class:`Summarizer` port so
tests need no API and no network; the default calls Claude (an optional `triage` extra).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from .models import DiffType
from .pipeline import Druid

REVIEW_SCHEMA = "druid.review/v1"
DISCLAIMER = (
    "Best-effort LLM draft for a human reviewer. Not attested, not in the ledger, "
    "never a verified fact about the source. See DESIGN 4.2 / 6.2."
)

_SYSTEM = (
    "You help a human reviewer triage changes to U.S. government environmental web pages. "
    "Given the BEFORE and AFTER of a passage, write 2-4 plain sentences: what changed, and "
    "whether it plausibly alters the meaning or policy (e.g. a commitment weakened, a "
    "requirement softened, a scope narrowed). Be factual and specific; quote short phrases. "
    "Do not speculate about motive. You are a drafting aid, not an authority."
)


class Summarizer(Protocol):
    def __call__(self, before: str, after: str, *, context: str = "") -> str: ...


def claude_summarizer(model: str = "claude-opus-4-8", *, client: Any = None) -> Summarizer:
    """The default :class:`Summarizer`: a single Claude Messages call (optional `triage`
    extra — `anthropic`). `client` is injectable for testing; by default a live
    `anthropic.Anthropic()` is constructed lazily (resolves credentials from the env or an
    `ant auth login` profile). A live call is billable and hits the network."""

    def summarize(before: str, after: str, *, context: str = "") -> str:
        api = client
        if api is None:
            import anthropic  # lazy: optional dep

            api = anthropic.Anthropic()
        user = (
            (f"Context: {context}\n\n" if context else "")
            + f"BEFORE:\n{before}\n\nAFTER:\n{after}\n\n"
            + "Summarize the change for a reviewer."
        )
        message = api.messages.create(
            model=model,
            max_tokens=1024,
            system=_SYSTEM,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(block.text for block in message.content if block.type == "text").strip()

    return summarize


def _latest_reworded_event(druid: Druid, target_id: str) -> dict[str, Any] | None:
    """The most recent L3 rewrite (a `ContentEdit` carrying before/after passages) for a
    target — the thing a reviewer most wants explained."""
    latest: dict[str, Any] | None = None
    for row in druid.timeline():
        if (
            row.get("schema") == "druid.diff/v1"
            and row.get("target_id") == target_id
            and row.get("diff_type") == str(DiffType.ContentEdit)
            and "to" in row.get("evidence", {})
        ):
            latest = row
    return latest


def _review_dir(druid: Druid) -> Path:
    return druid.data_dir / "review"


def summarize_event(druid: Druid, target_id: str, summarizer: Summarizer) -> dict[str, Any] | None:
    """Draft a reviewer summary for the latest L3 rewrite of `target_id` and persist it to
    the review sidecar. Returns the review record, or None if there is nothing to explain.

    The sidecar lives outside the ledger by design: re-running re-drafts it, and nothing
    here is ever attested."""
    event = _latest_reworded_event(druid, target_id)
    if event is None:
        return None
    evidence = event["evidence"]
    before, after = evidence.get("from", ""), evidence.get("to", "")
    summary = summarizer(before, after, context=f"target {target_id}")
    review = {
        "schema": REVIEW_SCHEMA,
        "target_id": target_id,
        "to_observation_hash": event.get("to_observation_hash"),
        "detected_at": event.get("detected_at"),
        "before": before,
        "after": after,
        "summary": summary,
        "disclaimer": DISCLAIMER,
    }
    review_dir = _review_dir(druid)
    review_dir.mkdir(parents=True, exist_ok=True)
    key = f"{event.get('to_observation_hash', 'unknown')[:18]}.json"
    (review_dir / key).write_text(json.dumps(review, indent=2), encoding="utf-8")
    return review
