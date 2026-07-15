"""The records that become ledger leaves (DESIGN §6.1).

Both ``Observation`` (a faithful, attested record) and ``DiffRecord`` (the differ's
best-effort interpretation) are logged. The interpretation is timestamped and
tamper-evident, but explicitly labelled best-effort and stored *alongside*, never
inside, the attested observation. Re-classification appends a new record; nothing is
ever mutated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import StrEnum
from typing import Any, Literal

Severity = Literal["Info", "Low", "Medium", "High"]


@dataclass(frozen=True, slots=True)
class Observation:
    """One faithful fetch. Hashes reference blobs in the store; bytes are never inline."""

    target_id: str
    url: str
    collector_type: str
    collector_version: str
    fetched_at: str  # RFC3339 UTC, collector wall clock
    http_status: int
    raw_bytes_hash: str  # multihash of the response body
    response_headers_hash: str  # multihash of canonically-serialised headers
    schema: str = "annals.observation/v1"
    rendered_dom_hash: str | None = None  # render collector: the post-JS DOM
    captured_requests_hash: str | None = None  # render collector: manifest of the page's own API/data calls
    tls_cert_chain_hash: str | None = None
    warc_record_hash: str | None = None

    def to_record(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_record(cls, rec: dict[str, Any]) -> Observation:
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in rec.items() if k in names})


class DiffType(StrEnum):
    Deletion = "Deletion"
    TermSubstitution = "TermSubstitution"
    NumericThresholdChange = "NumericThresholdChange"
    SchemaChange = "SchemaChange"
    DistributionalShift = "DistributionalShift"
    MetadataChange = "MetadataChange"
    ContentEdit = "ContentEdit"
    Reappearance = "Reappearance"
    CosmeticOnly = "CosmeticOnly"


@dataclass(frozen=True, slots=True)
class DiffRecord:
    """The differ's classified, severity-scored interpretation of a change."""

    target_id: str
    from_observation_hash: str | None
    to_observation_hash: str
    detected_at: str
    diff_type: DiffType
    severity: Severity
    layer: str
    evidence: dict[str, Any]
    schema: str = "annals.diff/v1"

    def to_record(self) -> dict[str, Any]:
        rec = asdict(self)
        rec["diff_type"] = str(self.diff_type)  # plain str for stable JSON
        return rec
