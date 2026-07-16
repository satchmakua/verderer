"""`verderer-witness` — an independently-deployable witness (M14c, DESIGN §4).

A third party runs this. It is *not* part of the operator's deployment: it holds its own key,
keeps its own memory of the log, pins the log's public key out-of-band, and needs no access to
the operator's ledger — only the checkpoint (and consistency proof) it fetches from wherever
the log is published.

    verderer-witness --checkpoint https://site/checkpoint --proof https://site/consistency.json \
                     --pubkey <log-pubkey-hex> --key-file ./witness.json --name witness.acme

It prints a C2SP cosignature line when the checkpoint checks out, and **refuses** — loudly,
with a reason, exit 1 — when it doesn't. The operator collects the line (`verderer cosign
--ingest`) so proof bundles carry it and a verifier can require a quorum. That is what turns
M8's in-process demo into real multi-party gossip: forging the record now requires an
independent party to vouch for a history that doesn't check out.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .witness import WitnessService, load_or_create_witness

USER_AGENT = "VerdererWitness/0.0 (+https://github.com/satchmakua/Verderer) independent-witness"


def _read(source: str) -> str:
    """Fetch a checkpoint/proof from a URL or a local path — a witness reads the *published*
    log, wherever it lives; it never reaches into the operator's ledger."""
    if source.startswith(("http://", "https://")):
        import httpx  # lazy: a file-based witness needs no HTTP client

        response = httpx.get(source, timeout=30.0, follow_redirects=True, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        return response.text
    return Path(source).read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="verderer-witness",
        description="An independent witness: verify a Verderer checkpoint extends what you last saw, then cosign it.",
    )
    parser.add_argument("--checkpoint", required=True, help="path or URL of the log's signed checkpoint")
    parser.add_argument("--pubkey", required=True, help="the log's public key (hex), pinned out-of-band")
    parser.add_argument("--key-file", type=Path, required=True, help="this witness's own key (created if absent)")
    parser.add_argument("--name", default="witness.local", help="this witness's name (what a verifier pins)")
    parser.add_argument("--state", type=Path, default=None, help="where this witness remembers the last checkpoint it accepted")
    parser.add_argument(
        "--proof", default=None, help="path or URL of a consistency proof (verderer.consistency/v1) for this step"
    )
    args = parser.parse_args(argv)

    witness = load_or_create_witness(args.key_file, args.name)
    state = args.state or args.key_file.with_suffix(".state")
    service = WitnessService(witness, args.pubkey, state)

    try:
        checkpoint = _read(args.checkpoint)
    except Exception as error:  # unreachable log / bad path — report, never cosign
        print(f"could not fetch the checkpoint: {error}")
        return 1
    proof = None
    if args.proof:
        try:
            proof = json.loads(_read(args.proof)).get("proof")
        except Exception as error:
            print(f"could not fetch the consistency proof: {error}")
            return 1

    result = service.observe(checkpoint, proof)
    if result.status == "cosigned":
        print(f"cosigned checkpoint at tree size {result.size} ({result.reason})")
        print(result.cosignature)
        print(f"  pin this witness when verifying: --witness {witness.pin()}")
        return 0
    print(f"REFUSED to cosign: {result.reason}")
    print("  this witness will not vouch for a log it cannot confirm extends what it last saw")
    return 1
