"""The observation pipeline — the application service that wires the ports together.

    collect → store bytes → diff vs. the previous observation → append leaves

The trust-core writes (store + ledger) stay free of the differ's heuristics; diff
records are appended as their own leaves *alongside* the observation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .collectors.base import Collector
from .collectors.static import StaticCollector
from .config import Target
from .differ.normalize import normalize_bytes
from .differ.termwatch import term_watch
from .ledger.log import SignedLog
from .models import DiffRecord, DiffType, Observation
from .store import ContentAddressedStore


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True, slots=True)
class ObserveResult:
    observation: Observation
    diffs: list[DiffRecord]
    is_first: bool


class Druid:
    def __init__(
        self,
        data_dir: Path,
        *,
        targets: dict[str, Target],
        terms: list[str],
        collector: Collector | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.store = ContentAddressedStore(self.data_dir / "blobs")
        self.log = SignedLog(self.data_dir / "ledger")
        self.targets = targets
        self.terms = terms
        self.collector: Collector = collector or StaticCollector()

    def _latest_observation_for(self, target_id: str) -> Observation | None:
        latest: dict | None = None
        for entry in self.log.entries():
            record = entry.record
            if record.get("schema") == "druid.observation/v1" and record.get("target_id") == target_id:
                latest = record
        return Observation.from_record(latest) if latest is not None else None

    def observe(self, target_id: str) -> ObserveResult:
        target = self.targets[target_id]
        previous = self._latest_observation_for(target_id)
        observation, body = self.collector.collect(target)
        self.store.put(body)

        diffs: list[DiffRecord] = []
        if previous is not None and previous.raw_bytes_hash != observation.raw_bytes_hash:
            diffs = self._diff(previous, observation, body)

        # The attested observation is logged first, then its interpretation.
        self.log.append(observation.to_record())
        for diff in diffs:
            self.log.append(diff.to_record())

        return ObserveResult(observation=observation, diffs=diffs, is_first=previous is None)

    def _diff(self, previous: Observation, observation: Observation, body: bytes) -> list[DiffRecord]:
        prev_text = normalize_bytes(self.store.get(previous.raw_bytes_hash))
        curr_text = normalize_bytes(body)
        now = _utc_now()
        diffs = term_watch(
            prev_text,
            curr_text,
            self.terms,
            target_id=observation.target_id,
            detected_at=now,
            from_hash=previous.raw_bytes_hash,
            to_hash=observation.raw_bytes_hash,
        )
        if not diffs and prev_text != curr_text:
            diffs.append(
                DiffRecord(
                    target_id=observation.target_id,
                    from_observation_hash=previous.raw_bytes_hash,
                    to_observation_hash=observation.raw_bytes_hash,
                    detected_at=now,
                    diff_type=DiffType.ContentEdit,
                    severity="Medium",
                    layer="L0-normalize",
                    evidence={"note": "normalised content changed; no watched term moved"},
                )
            )
        return diffs

    def timeline(self) -> list[dict]:
        return [entry.record for entry in self.log.entries()]
