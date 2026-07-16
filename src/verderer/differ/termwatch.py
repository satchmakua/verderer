"""L1 — term watch (cheap, high-precision).

A curated dictionary of sensitive terms whose appearance, disappearance, or count
change is flagged. This catches the documented manipulations (terminology swaps,
definition narrowing) with near-zero false positives. Disappearance of a watched term
is treated as the higher-severity signal.
"""

from __future__ import annotations

from ..models import DiffRecord, DiffType, Severity


def count_terms(text: str, terms: list[str]) -> dict[str, int]:
    lowered = text.lower()
    return {term: lowered.count(term) for term in terms}


def term_watch(
    prev_text: str,
    curr_text: str,
    terms: list[str],
    *,
    target_id: str,
    detected_at: str,
    from_hash: str | None,
    to_hash: str,
) -> list[DiffRecord]:
    before = count_terms(prev_text, terms)
    after = count_terms(curr_text, terms)
    diffs: list[DiffRecord] = []
    for term in terms:
        if before[term] == after[term]:
            continue
        disappeared = before[term] > 0 and after[term] == 0
        severity: Severity = "High" if disappeared else "Medium"
        diffs.append(
            DiffRecord(
                target_id=target_id,
                from_observation_hash=from_hash,
                to_observation_hash=to_hash,
                detected_at=detected_at,
                diff_type=DiffType.TermSubstitution,
                severity=severity,
                layer="L1-termwatch",
                evidence={"term": term, "from": before[term], "to": after[term]},
            )
        )
    return diffs
