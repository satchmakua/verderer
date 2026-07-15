"""The observation pipeline — the application service that wires the ports together.

    collect → store bytes → diff vs. the previous observation → append leaves

The trust-core writes (store + ledger) stay free of the differ's heuristics; diff
records are appended as their own leaves *alongside* the observation.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from .anchors import Anchorer, anchored_hash
from .collectors.base import Capture, Collector
from .collectors.render import RenderCollector, playwright_engine
from .collectors.static import StaticCollector, httpx_fetcher
from .config import Target
from .differ.dataset import dataset_diff
from .differ.embedding import Embedder, embedding_triage
from .differ.normalize import normalize_for_diff
from .differ.numeric import numeric_watch
from .differ.structure import structure_watch
from .differ.termwatch import term_watch
from .ledger.core import Ledger
from .models import DiffRecord, DiffType, Observation
from .politeness import CollectionSkipped, NotModified, PolitenessPolicy
from .store import ContentAddressedStore
from .witness import Witness


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _checkpoint_size(checkpoint: str) -> int:
    """The tree size a signed checkpoint commits to — line 2 of the C2SP note body
    (origin / size / root). Parsed, not trusted; the Rust verifier checks the signature."""
    return int(checkpoint.splitlines()[1])


def _same_content(previous: Observation, observation: Observation) -> bool:
    """Whether ``observation`` is byte-for-byte identical to the last one — the attested
    artifact bytes, the HTTP status, and (render collector) the captured-requests manifest
    all match. Used to suppress re-logging an unchanged observation when a conditional GET
    could not (no validator), so a continuously-running ledger doesn't grow without change.
    A status flip (200→451/404) or a captured-requests change is *not* identical and is
    logged."""
    return (
        previous.http_status == observation.http_status
        and previous.raw_bytes_hash == observation.raw_bytes_hash
        and previous.captured_requests_hash == observation.captured_requests_hash
    )


@dataclass(frozen=True, slots=True)
class ObserveResult:
    """The outcome of one ``observe`` call. ``status`` distinguishes a new attested
    observation (``observed``) from a polite no-op — ``unchanged`` (a conditional-GET
    ``304``) or ``skipped`` (robots.txt disallowed the URL). ``observation`` is ``None``
    for the no-op outcomes (nothing was fetched or logged)."""

    observation: Observation | None
    diffs: list[DiffRecord]
    is_first: bool
    status: str = "observed"  # "observed" | "unchanged" | "skipped"
    reason: str = ""


class Annals:
    def __init__(
        self,
        data_dir: Path,
        *,
        targets: dict[str, Target],
        terms: list[str],
        collector: Collector | None = None,
        collectors: dict[str, Collector] | None = None,
        embedder: Embedder | None = None,
        politeness: PolitenessPolicy | None = None,
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
        self.politeness: PolitenessPolicy | None = politeness
        if collector is None and collectors is None:
            # Default (production) collectors are polite by construction (M9): one shared
            # policy coordinates robots.txt, per-host rate-limiting/backoff, and
            # conditional GET across the static + render seams, persisting validators under
            # the data dir. Injected collectors opt in explicitly (or stay bare for tests).
            if self.politeness is None:
                self.politeness = PolitenessPolicy(state_path=self.data_dir / "politeness-state.json")
            self.collectors: dict[str, Collector] = {
                "static": StaticCollector(fetcher=self.politeness.fetcher(httpx_fetcher)),
                "render": RenderCollector(engine=self.politeness.engine(playwright_engine)),
            }
        else:
            self.collectors = collectors or {}

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
            if record.get("schema") == "annals.observation/v1" and record.get("target_id") == target_id:
                latest = record
        return Observation.from_record(latest) if latest is not None else None

    def observe(self, target_id: str) -> ObserveResult:
        target = self.targets[target_id]
        previous = self._latest_observation_for(target_id)
        is_first = previous is None
        if is_first and self.politeness is not None:
            # No attested baseline for this target yet: force an unconditional fetch so a
            # stale or cross-target conditional validator cannot produce a spurious 304 that
            # silently suppresses the baseline. (Validators are URL-keyed courtesy state; the
            # ledger baseline is target-keyed — this reconciles the two.)
            self.politeness.forget(target.url)
        try:
            collected = self._collector_for(target).collect(target)
        except NotModified:
            # Conditional GET said 304: the bytes match the last observation, so there is
            # nothing new to attest. A polite no-op — no leaf, no diff.
            if is_first:
                # A 304 with no baseline is a validator/ledger desync the pipeline could not
                # pre-empt (e.g. an injected collector whose policy the pipeline does not
                # own). Never record it as a clean "unchanged" — that would be a silent
                # missing baseline, the exact blind spot a watchdog must not have. Fail loud.
                raise RuntimeError(
                    f"conditional GET returned 304 for {target_id} but no baseline observation "
                    f"exists (stale validator); clear annals-data/politeness-state.json and re-observe"
                ) from None
            return ObserveResult(
                observation=None, diffs=[], is_first=False, status="unchanged", reason="304 Not Modified"
            )
        except CollectionSkipped as skip:
            # robots.txt disallowed this URL for our UA — we never fetched it.
            return ObserveResult(
                observation=None, diffs=[], is_first=is_first, status="skipped", reason=str(skip)
            )
        observation, body = collected.observation, collected.body
        if previous is not None and _same_content(previous, observation):
            # Byte-identical to this target's last attested observation, but the conditional
            # GET couldn't spare the fetch (the response carried no validator — a 404, or a
            # server that sends no ETag). Nothing new to attest: the existing leaf already
            # commits to exactly these bytes+status, the blob is already stored, and
            # re-logging identical leaves every scheduler cycle would bloat the ledger
            # without adding evidence. Freshness (that we re-checked) lives in the scheduler
            # state, not the ledger — the same outcome as a 304.
            return ObserveResult(
                observation=None, diffs=[], is_first=False, status="unchanged",
                reason="content identical to last observation",
            )
        self.store.put(body)
        # Store any side artifacts (a render collector's captured API/data calls). They
        # are already referenced by hash in the observation record; storing them makes
        # those references resolvable and independently verifiable.
        for artifact in collected.side_artifacts:
            self.store.put(artifact)

        # Archive the fetch as a standards WARC (M11): a faithful, interoperable capture of
        # the request + response, stored content-addressed and attested in the leaf via
        # warc_record_hash — so the raw artifact is recoverable from a WARC any archive
        # replays. Built after the dedup check (which never sees warc_record_hash), so a
        # byte-identical re-observation never builds or stores a redundant WARC.
        if collected.capture is not None:
            observation = self._archive_warc(observation, body, collected.capture)

        diffs: list[DiffRecord] = []
        if previous is not None and previous.raw_bytes_hash != observation.raw_bytes_hash:
            diffs = self._diff(target, previous, observation, body)

        # The attested observation is logged first, then its interpretation.
        self.log.append(observation.to_record())
        for diff in diffs:
            self.log.append(diff.to_record())

        return ObserveResult(observation=observation, diffs=diffs, is_first=is_first, status="observed")

    def _archive_warc(self, observation: Observation, body: bytes, capture: Capture) -> Observation:
        """Build the WARC for this observation, store it content-addressed, and return the
        observation carrying its ``warc_record_hash``. The WARC's archived payload hashes to
        ``raw_bytes_hash`` (the same bytes), so the artifact is recoverable from the WARC.

        Best-effort: WARC is an interop/archival feature *layered on* the trust core, never a
        prerequisite for it. If archiving fails (e.g. a pathological URL warcio can't encode),
        the observation is still attested — just without a ``warc_record_hash`` — rather than
        losing the observation entirely (which, under the M10 scheduler, would retry-loop the
        target forever and blind the watchdog to it)."""
        from .warc import build_warc  # lazy: warcio only loads when actually archiving

        try:
            warc_bytes = build_warc(
                target_uri=capture.target_uri,
                fetched_at=capture.fetched_at,
                payload=body,
                record_type=capture.record_type,
                status=capture.status,
                response_headers=capture.response_headers,
                content_type=capture.content_type,
            )
        except Exception:
            return observation  # attest without a WARC rather than dropping the observation
        warc_hash = self.store.put(warc_bytes)
        return replace(observation, warc_record_hash=warc_hash)

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
        prev_body = self.store.get(previous.raw_bytes_hash)
        # M12: normalize AND noise-suppress (timestamps/nonces/session ids) before diffing, so
        # a re-render that changed nothing meaningful doesn't false-fire. Attested bytes untouched.
        prev_text = normalize_for_diff(prev_body)
        curr_text = normalize_for_diff(body)
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
            # M12: localise the change to the block it happened in (a table cell, a heading,
            # a list item) — in place of the coarse floor — when the semantic layers didn't
            # itemise it. Declines (returns []) if the change is too broad to localise.
            diffs += structure_watch(
                prev_body,
                body,
                target_id=observation.target_id,
                detected_at=now,
                from_hash=previous.raw_bytes_hash,
                to_hash=observation.raw_bytes_hash,
            )
            if not diffs and self.embedder is not None:
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

    def gossip_bundle(self, old_checkpoint: str) -> dict:
        """A self-contained `annals.consistency/v1` proving the current checkpoint extends the
        client's earlier `old_checkpoint` (M13 gossip). It carries both signed checkpoints and
        a C2SP consistency proof, so `annals-verify consistency` confirms — offline — that the
        log never forked, shrank, or rewrote history between them."""
        new_checkpoint = self.log.signed_checkpoint()
        old_size = _checkpoint_size(old_checkpoint)
        new_size = _checkpoint_size(new_checkpoint)
        proof = self.log.consistency_proof(old_size, new_size)
        return {
            "schema": "annals.consistency/v1",
            "origin": "annals.watchdog/m1-log",
            "from": old_size,
            "to": new_size,
            "old_checkpoint": old_checkpoint,
            "new_checkpoint": new_checkpoint,
            "proof": proof,
            "pubkey_hex": self.log.public_key_hex,
        }

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
        """Assemble a self-verifying `annals.proofbundle/v1` for an observation (DESIGN §6.4).

        Picks the latest observation leaf for `target_id` (or the leaf at ledger `index`),
        and packages: the observation record, the raw response bytes (the artifact), the
        Merkle inclusion proof, and the signed checkpoint + pinned public key. The bundle
        verifies offline via `annals-verify bundle` — trusting neither the source nor Annals.
        """
        observations = [
            entry
            for entry in self.log.entries()
            if entry.record.get("schema") == "annals.observation/v1"
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
            "schema": "annals.proofbundle/v1",
            "origin": "annals.watchdog/m1-log",
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
