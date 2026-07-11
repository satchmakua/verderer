"""L3 — embedding similarity triage (DESIGN §6.2, M6). **Triage, not truth.**

Layers L1/L2 are high-precision but narrow: they catch a *watched term* moving or a
*regulatory number* changing. A passage can be rewritten to mean something materially
different — "remains committed to reducing emissions" becoming "will consider voluntary
approaches" — without tripping either. L3 embeds the changed passages and scores each
against its closest prior passage: a semantically distant rewrite ranks up for human
review as a `ContentEdit`; a near-identical edit is cosmetic and stays quiet.

This is explicitly a **signal, not a verified property** (DESIGN §6.2): the score is a
best-effort heuristic, stored alongside the attested record like every other diff label,
never inside a ledger leaf. The embedder is injected behind the :class:`Embedder` port so
tests need no model; the default drives `sentence-transformers` (an optional `triage`
extra, lazily imported).
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Protocol

from ..models import DiffRecord, DiffType, Severity

# Similarity bands (cosine, 0..1). Above COSMETIC: near-identical, not worth flagging.
# Below REWRITE: meaning plausibly shifted -> surface for review. In between: a minor edit.
# Below ADDED_FLOOR: too distant to claim a specific origin -> treat as new content.
COSMETIC_SIM = 0.97
REWRITE_SIM = 0.85
ADDED_FLOOR = 0.35

_SENTENCE = re.compile(r"(?<=[.!?])\s+")


class Embedder(Protocol):
    def embed(self, texts: list[str]) -> list[Sequence[float]]:
        """Return one embedding vector per input text (order-preserving)."""
        ...


def sentence_transformer_embedder(model_name: str = "all-MiniLM-L6-v2") -> Embedder:
    """The default :class:`Embedder`: a `sentence-transformers` model (optional `triage`
    extra, lazily loaded so the dependency is needed only when actually triaging)."""

    class _STEmbedder:
        def __init__(self) -> None:
            from sentence_transformers import SentenceTransformer  # lazy: optional dep

            self._model = SentenceTransformer(model_name)

        def embed(self, texts: list[str]) -> list[Sequence[float]]:
            return [list(map(float, v)) for v in self._model.encode(texts, normalize_embeddings=False)]

    return _STEmbedder()


def _segment(text: str) -> list[str]:
    # L0 normalisation collapses whitespace to a single line, so segment on sentence
    # boundaries. Keep only substantive segments (a few words) to avoid noise.
    segments = [s.strip() for s in _SENTENCE.split(text) if s.strip()]
    return [s for s in segments if len(s.split()) >= 4]


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(x * x for x in b) ** 0.5
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def _best_match(vec: Sequence[float], prev_vecs: list[Sequence[float]]) -> tuple[float, int | None]:
    best_sim, best_idx = -1.0, None
    for idx, pv in enumerate(prev_vecs):
        sim = _cosine(vec, pv)
        if sim > best_sim:
            best_sim, best_idx = sim, idx
    return (best_sim, best_idx) if best_idx is not None else (0.0, None)


def embedding_triage(
    prev_text: str,
    curr_text: str,
    embedder: Embedder,
    *,
    target_id: str,
    detected_at: str,
    from_hash: str | None,
    to_hash: str,
    rewrite_threshold: float = REWRITE_SIM,
    cosmetic_threshold: float = COSMETIC_SIM,
) -> list[DiffRecord]:
    def record(diff_type: DiffType, severity: Severity, evidence: dict) -> DiffRecord:
        return DiffRecord(
            target_id=target_id,
            from_observation_hash=from_hash,
            to_observation_hash=to_hash,
            detected_at=detected_at,
            diff_type=diff_type,
            severity=severity,
            layer="L3-embedding",
            evidence=evidence,
        )

    prev_segs = _segment(prev_text)
    curr_segs = _segment(curr_text)
    prev_set = set(prev_segs)
    changed = [s for s in curr_segs if s not in prev_set]
    if not changed:
        return []

    prev_vecs = list(embedder.embed(prev_segs)) if prev_segs else []
    changed_vecs = embedder.embed(changed)

    diffs: list[DiffRecord] = []
    for seg, vec in zip(changed, changed_vecs, strict=False):
        sim, idx = _best_match(vec, prev_vecs)
        if idx is None or sim < ADDED_FLOOR:
            # No close prior counterpart: new content, surfaced for review (no false origin).
            diffs.append(
                record(DiffType.ContentEdit, "Medium", {"change": "new_passage", "passage": seg, "similarity": round(sim, 3)})
            )
        elif sim < rewrite_threshold:
            # Aligned to a prior passage but semantically distant: a meaningful rewrite.
            diffs.append(
                record(
                    DiffType.ContentEdit,
                    "Medium",
                    {"change": "reworded", "from": prev_segs[idx], "to": seg, "similarity": round(sim, 3)},
                )
            )
        elif sim < cosmetic_threshold:
            diffs.append(
                record(DiffType.CosmeticOnly, "Low", {"from": prev_segs[idx], "to": seg, "similarity": round(sim, 3)})
            )
        # sim >= cosmetic_threshold: near-identical, not worth flagging.
    return diffs
