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
from .collectors.render import RenderCollector
from .collectors.static import StaticCollector
from .config import Target
from .differ.dataset import dataset_diff
from .differ.embedding import Embedder, embedding_triage
from .differ.normalize import normalize_bytes
from .differ.numeric import numeric_watch
from .differ.termwatch import term_watch
from .ledger.core import Ledger
from .models import DiffRecord, DiffType, Observation
from .store import ContentAddressedStore
from .witness import Witness


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
        collectors: dict[str, Collector] | None = None,
        embedder: Embedder | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.store = ContentAddressedStore(self.data_dir / "blobs")
        self.log = Ledger(self.data_dir / "ledger")
        self.targets = targets
        self.terms = terms
        # Optional L3 (embedding triage): when provided, it interprets a text change that
        # L1/L2 didn't explain; when absent, the pipeline keeps the coarse ContentEdit
        # fallback. A best-effort reviewer signal, never in a leaf.
        self.embedder = embedder
        # `collector` forces one collector for every target (tests, single-collector runs);
        # otherwise dispatch on `target.collector` against a registry keyed by type name.
        self._forced_collector = collector
        self.collectors: dict[str, Collector] = collectors or {
            "static": StaticCollector(),
            "render": RenderCollector(),
        }

    def _collector_for(self, target: Target) -> Collector:
        if self._forced_collector is not None:
            return self._forced_collector
        try:
            return self.collectors[target.collector]
        except KeyError:
            raise ValueError(
                f"target {target.id} wants collector {target.collector!r}, "
                f"which is not registered ({sorted(self.collectors)})"
            ) from None

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
        collected = self._collector_for(target).collect(target)
        observation, body = collected.observation, collected.body
        self.store.put(body)
        # Store any side artifacts (a render collector's captured API/data calls). They
        # are already referenced by hash in the observation record; storing them makes
        # those references resolvable and independently verifiable.
        for artifact in collected.side_artifacts:
            self.store.put(artifact)

        diffs: list[DiffRecord] = []
        if previous is not None and previous.raw_bytes_hash != observation.raw_bytes_hash:
            diffs = self._diff(target, previous, observation, body)

        # The attested observation is logged first, then its interpretation.
        self.log.append(observation.to_record())
        for diff in diffs:
            self.log.append(diff.to_record())

        return ObserveResult(observation=observation, diffs=diffs, is_first=previous is None)

    def _diff(
        self, target: Target, previous: Observation, observation: Observation, body: bytes
    ) -> list[DiffRecord]:
        now = _utc_now()
        if target.kind == "dataset":
            # L4 — tabular schema + distributional diff over the raw bytes.
            return dataset_diff(
                self.store.get(previous.raw_bytes_hash),
                body,
                target_id=observation.target_id,
                detected_at=now,
                from_hash=previous.raw_bytes_hash,
                to_hash=observation.raw_bytes_hash,
            )
        prev_text = normalize_bytes(self.store.get(previous.raw_bytes_hash))
        curr_text = normalize_bytes(body)
        diffs = term_watch(
            prev_text,
            curr_text,
            self.terms,
            target_id=observation.target_id,
            detected_at=now,
            from_hash=previous.raw_bytes_hash,
            to_hash=observation.raw_bytes_hash,
        )
        diffs += numeric_watch(
            prev_text,
            curr_text,
            target_id=observation.target_id,
            detected_at=now,
            from_hash=previous.raw_bytes_hash,
            to_hash=observation.raw_bytes_hash,
        )
        if not diffs and prev_text != curr_text:
            if self.embedder is not None:
                # L3 ranks reworded passages for review; it inspects only added/reworded
                # passages, so it can be silent on a pure deletion or a change confined to
                # very short sentences.
                diffs += embedding_triage(
                    prev_text,
                    curr_text,
                    self.embedder,
                    target_id=observation.target_id,
                    detected_at=now,
                    from_hash=previous.raw_bytes_hash,
                    to_hash=observation.raw_bytes_hash,
                )
            if not diffs:
                # Floor: a normalised text change that no layer itemised must still be
                # flagged, never dropped — enabling L3 must not lose signal L0 would catch.
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

    def _cosignatures_dir(self) -> Path:
        return self.data_dir / "ledger" / "cosignatures"

    def cosign(self, witness: Witness) -> dict:
        """Have `witness` co-sign the current checkpoint and store the cosignature (M8).

        Like anchoring, cosign *after* logging: the cosignature covers the current
        checkpoint, so a bundle for a leaf carries it only while that checkpoint matches.
        Cosignatures are keyed by the checkpoint digest; one per witness name (latest wins).
        """
        checkpoint = self.log.signed_checkpoint()
        line = self.log.cosign(witness.name, witness.seed_hex)
        digest = anchored_hash(checkpoint).hex()
        cdir = self._cosignatures_dir()
        cdir.mkdir(parents=True, exist_ok=True)
        path = cdir / f"{digest}.txt"
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        lines = [entry for entry in lines if not entry.startswith(f"— {witness.name} ")]
        lines.append(line)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return {"witness": witness.name, "checkpoint_hash": digest, "cosignatures": len(lines)}

    def _cosignatures_for(self, checkpoint: str) -> list[str]:
        path = self._cosignatures_dir() / f"{anchored_hash(checkpoint).hex()}.txt"
        if not path.exists():
            return []
        return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

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
            "cosignatures": self._cosignatures_for(incl["checkpoint"]),
        }
