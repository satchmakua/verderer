"""The observation pipeline — the application service that wires the ports together.

    collect → store bytes → diff vs. the previous observation → append leaves

The trust-core writes (store + ledger) stay free of the differ's heuristics; diff
records are appended as their own leaves *alongside* the observation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from .anchors import Anchorer, anchored_hash
from .collectors.base import Collector
from .collectors.static import StaticCollector
from .config import Target
from .differ.normalize import normalize_bytes
from .differ.termwatch import term_watch
from .ledger.core import Ledger
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
        self.log = Ledger(self.data_dir / "ledger")
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

    def _anchors_dir(self) -> Path:
        return self.data_dir / "ledger" / "anchors"

    def anchor(self, anchorer: Anchorer) -> dict:
        """Anchor the current signed checkpoint with a TSA and store the token (M2b).

        Anchor *after* logging observations: the token commits to the current checkpoint,
        so a bundle for a leaf includes the anchor only when its checkpoint still matches.
        """
        checkpoint = self.log.signed_checkpoint()
        digest = anchored_hash(checkpoint)
        token = anchorer.anchor(digest)
        adir = self._anchors_dir()
        adir.mkdir(parents=True, exist_ok=True)
        (adir / f"{digest.hex()}.{anchorer.name}.der").write_bytes(token)
        # Stash a self-hosted root to pin when verifying (real TSA roots ship in the verifier).
        root = anchorer.root_pem()
        if root:
            (self.data_dir / "ledger" / f"{anchorer.name}-root.pem").write_text(root, encoding="utf-8")
        return {"tsa": anchorer.name, "anchored_hash": digest.hex(), "token_bytes": len(token)}

    def _anchors_for(self, checkpoint: str) -> list[dict]:
        digest = anchored_hash(checkpoint).hex()
        adir = self._anchors_dir()
        if not adir.exists():
            return []
        anchors: list[dict] = []
        for path in sorted(adir.glob(f"{digest}.*.der")):
            tsa_name = path.name[len(digest) + 1 : -4]
            anchors.append(
                {
                    "type": "rfc3161",
                    "anchored_hash": digest,
                    "tsa_name": tsa_name,
                    "token": base64.b64encode(path.read_bytes()).decode(),
                }
            )
        return anchors

    def bundle(self, target_id: str, index: int | None = None) -> dict:
        """Assemble a self-verifying `druid.proofbundle/v1` for an observation (DESIGN §6.4).

        Picks the latest observation leaf for `target_id` (or the leaf at ledger `index`),
        and packages: the observation record, the raw response bytes (the artifact), the
        Merkle inclusion proof, and the signed checkpoint + pinned public key. The bundle
        verifies offline via `druid-verify bundle` — trusting neither the source nor Druid.
        """
        observations = [
            entry
            for entry in self.log.entries()
            if entry.record.get("schema") == "druid.observation/v1"
            and entry.record.get("target_id") == target_id
        ]
        if not observations:
            raise ValueError(f"no observation logged for target {target_id}")
        if index is None:
            leaf = observations[-1]
        else:
            match = next((e for e in observations if e.index == index), None)
            if match is None:
                raise ValueError(f"ledger index {index} is not an observation of {target_id}")
            leaf = match

        incl = self.log.inclusion(leaf.index)
        raw_hash = leaf.record["raw_bytes_hash"]
        raw_bytes = self.store.get(raw_hash)
        return {
            "schema": "druid.proofbundle/v1",
            "origin": "druid.watchdog/m1-log",
            "observation": leaf.record,
            "artifacts": [
                {
                    "hash": raw_hash,
                    "media_type": "application/octet-stream",
                    "bytes_b64": base64.b64encode(raw_bytes).decode(),
                }
            ],
            "leaf": {"index": leaf.index, "record_b64": self.log.entry_b64(leaf.index), "leaf_hash": incl["leaf_hash"]},
            "inclusion_proof": {"tree_size": incl["tree_size"], "proof": incl["proof"]},
            "checkpoint": incl["checkpoint"],
            "pubkey_hex": self.log.public_key_hex,
            "anchors": self._anchors_for(incl["checkpoint"]),
        }
