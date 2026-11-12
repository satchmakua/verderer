"""Status watch (DESIGN §6.1 taxonomy — `Deletion`, `Reappearance`): classify a change in a
resource's *availability* from the attested response metadata alone.

The content layers (L1 term-watch, L2 numeric, the structure diff) compare page text. That is
only meaningful when both responses actually carried the resource: an error response's body is
the server's error page, not the resource's content. Diffing it reports a takedown as a list of
"watched term removed" findings, and reports a block page's rotating reference number as a
content edit on every single fetch. So this layer runs first and decides from the two statuses:

* served -> not served                         `Deletion` (High) — it stopped being served.
* not served -> served                         `Reappearance` (Medium) — it is served again.
* not served -> not served, another status     `MetadataChange` (Medium) — still unavailable,
                                               but the refusal itself changed (403 -> 404).
* not served -> not served, same status        nothing — the error page changed, the resource
                                               did not.
* served -> served                             nothing here; the content layers compare bodies.

Independently, a change in the *final* URL (the address the fetch ended at after redirects) is
flagged as a `MetadataChange`: a page quietly replaced by a redirect is a common soft removal.

Best-effort interpretation like every differ layer — stored alongside the attested
observations, never inside them. The statuses and URLs are attested (they are fields of the
observation leaves); only the label and severity are interpretation.
"""

from __future__ import annotations

from ..models import DiffRecord, DiffType, Observation, Severity

LAYER = "L0-status"

# How a reappearing resource compares with the last version that was actually served.
SAME_AS_LAST_SERVED = "identical"
DIFFERS_FROM_LAST_SERVED = "changed"
NO_EARLIER_VERSION = "no_earlier_version"


def is_served(status: int) -> bool:
    """Whether a response carried the resource itself (2xx) rather than an error or a refusal.
    Redirects are followed by the collectors, so a 3xx seen here is a terminal non-answer."""
    return 200 <= status < 300


def status_watch(
    previous: Observation,
    current: Observation,
    *,
    detected_at: str,
    versus_last_served: str | None = None,
) -> list[DiffRecord]:
    """Availability findings for the transition `previous` -> `current` (possibly none).

    `versus_last_served` annotates a `Reappearance` with how the returned content compares to
    the last served version — the caller knows, this layer only records it.
    """

    def record(diff_type: DiffType, severity: Severity, evidence: dict[str, object]) -> DiffRecord:
        return DiffRecord(
            target_id=current.target_id,
            from_observation_hash=previous.raw_bytes_hash,
            to_observation_hash=current.raw_bytes_hash,
            detected_at=detected_at,
            diff_type=diff_type,
            severity=severity,
            layer=LAYER,
            evidence=evidence,
        )

    diffs: list[DiffRecord] = []
    statuses: dict[str, object] = {"from_status": previous.http_status, "to_status": current.http_status}
    was_served, now_served = is_served(previous.http_status), is_served(current.http_status)
    if was_served and not now_served:
        diffs.append(record(DiffType.Deletion, "High", statuses))
    elif now_served and not was_served:
        evidence = dict(statuses)
        if versus_last_served is not None:
            evidence["versus_last_served"] = versus_last_served
        diffs.append(record(DiffType.Reappearance, "Medium", evidence))
    elif not now_served and previous.http_status != current.http_status:
        diffs.append(record(DiffType.MetadataChange, "Medium", {"scope": "http_status", **statuses}))

    if previous.url != current.url:
        diffs.append(
            record(
                DiffType.MetadataChange,
                "Medium",
                {"scope": "final_url", "from_url": previous.url, "to_url": current.url},
            )
        )
    return diffs
