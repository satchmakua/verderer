"""The ``druid`` command line — the M0 surface over the pipeline.

    druid targets                 list the curated targets
    druid observe <target_id>     observe one target now (fetch, store, diff, log)
    druid log                     print the observation / diff timeline
    druid verify                  recompute the ledger chain and check the signed head

Global options (before the subcommand): --data-dir, --targets, --terms.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

from .config import load_targets, load_terms
from .ledger.core import LedgerBinaryNotFound, find_binary
from .pipeline import Druid

DEFAULT_DATA_DIR = Path("druid-data")


def _repo_data_dir() -> Path:
    # In M0 (editable install) the curated data lives at the repo root, beside src/.
    return Path(__file__).resolve().parents[2] / "data"


def _build(args: argparse.Namespace) -> Druid:
    data = _repo_data_dir()
    targets = load_targets(args.targets or data / "targets.toml")
    terms = load_terms(args.terms or data / "terms.toml")
    return Druid(args.data_dir, targets=targets, terms=terms)


def cmd_targets(args: argparse.Namespace) -> int:
    druid = _build(args)
    for target in druid.targets.values():
        print(f"{target.id:24} {target.url}")
    return 0


def cmd_observe(args: argparse.Namespace) -> int:
    druid = _build(args)
    if args.target_id not in druid.targets:
        print(f"unknown target: {args.target_id} (try `druid targets`)")
        return 2
    try:
        result = druid.observe(args.target_id)
    except Exception as error:  # network/parse failures should not crash the CLI
        print(f"observe failed for {args.target_id}: {error}")
        return 1
    obs = result.observation
    tag = "first observation" if result.is_first else f"{len(result.diffs)} change(s)"
    print(f"observed {obs.target_id} [{obs.http_status}] {obs.url}")
    print(f"  content {obs.raw_bytes_hash[:18]}…  at {obs.fetched_at}  ({tag})")
    for diff in result.diffs:
        print(f"  ! {diff.diff_type} [{diff.severity}] {diff.evidence}")
    return 0


def cmd_log(args: argparse.Namespace) -> int:
    druid = _build(args)
    rows = druid.timeline()
    if not rows:
        print("(empty record — run `druid observe <target>`)")
        return 0
    for row in rows:
        if row.get("schema") == "druid.observation/v1":
            when, tid = row["fetched_at"], row["target_id"]
            print(f"OBS  {when}  {tid:22} [{row['http_status']}] {row['raw_bytes_hash'][:14]}…")
        else:
            when, tid = row["detected_at"], row["target_id"]
            print(f"DIFF {when}  {tid:22} {row['diff_type']} [{row['severity']}] {row.get('evidence')}")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    druid = _build(args)
    ok, message = druid.log.verify()
    print(("VALID   " if ok else "INVALID ") + message)
    print(f"log public key: {druid.log.public_key_hex}")
    return 0 if ok else 1


def cmd_bundle(args: argparse.Namespace) -> int:
    druid = _build(args)
    try:
        bundle = druid.bundle(args.target_id, args.index)
    except Exception as error:
        print(f"bundle failed: {error}")
        return 1
    text = json.dumps(bundle, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"wrote proof bundle -> {args.output} ({len(text)} bytes); verify with `druid verify-bundle {args.output}`")
    else:
        print(text)
    return 0


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    try:
        verifier = find_binary("druid-verify")
    except LedgerBinaryNotFound as error:
        print(str(error))
        return 1
    result = subprocess.run([str(verifier), "bundle", str(args.path)], capture_output=True, encoding="utf-8")
    print((result.stdout or result.stderr).strip())
    return 0 if result.returncode == 0 else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="druid", description="A verifiable watchdog for public environmental data.")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="where blobs + ledger live")
    parser.add_argument("--targets", type=Path, default=None, help="override targets.toml")
    parser.add_argument("--terms", type=Path, default=None, help="override terms.toml")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("targets", help="list curated targets")
    observe = sub.add_parser("observe", help="observe one target now")
    observe.add_argument("target_id")
    sub.add_parser("log", help="print the observation / diff timeline")
    sub.add_parser("verify", help="verify the ledger chain and signed head")
    bundle = sub.add_parser("bundle", help="export a self-verifying proof bundle for a target")
    bundle.add_argument("target_id")
    bundle.add_argument("--index", type=int, default=None, help="ledger index of a specific observation leaf")
    bundle.add_argument("-o", "--output", type=Path, default=None, help="write the bundle to a file")
    verify_bundle = sub.add_parser("verify-bundle", help="verify a downloaded proof bundle offline")
    verify_bundle.add_argument("path", type=Path)

    args = parser.parse_args(argv)
    dispatch = {
        "targets": cmd_targets,
        "observe": cmd_observe,
        "log": cmd_log,
        "verify": cmd_verify,
        "bundle": cmd_bundle,
        "verify-bundle": cmd_verify_bundle,
    }
    return dispatch[args.cmd](args)
