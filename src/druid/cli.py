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


def _build(args: argparse.Namespace, *, embedder: object = None) -> Druid:
    data = _repo_data_dir()
    targets = load_targets(args.targets or data / "targets.toml")
    terms = load_terms(args.terms or data / "terms.toml")
    return Druid(args.data_dir, targets=targets, terms=terms, embedder=embedder)  # type: ignore[arg-type]


def cmd_targets(args: argparse.Namespace) -> int:
    druid = _build(args)
    for target in druid.targets.values():
        print(f"{target.id:24} {target.url}")
    return 0


def cmd_observe(args: argparse.Namespace) -> int:
    embedder = None
    if getattr(args, "embed", False):
        from .differ.embedding import sentence_transformer_embedder

        embedder = sentence_transformer_embedder()  # heavy: loads the model (triage extra)
    druid = _build(args, embedder=embedder)
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


def cmd_anchor(args: argparse.Namespace) -> int:
    from .anchors import HttpTsaAnchorer, OpensslTsaAnchorer

    druid = _build(args)
    if not druid.log.entries():
        print("nothing to anchor — run `druid observe <target>` first")
        return 1
    names = [n.strip() for n in args.tsa.split(",") if n.strip()]
    succeeded = 0
    for name in names:
        try:
            if name == "dev":
                anchorer: object = OpensslTsaAnchorer(args.data_dir / "anchors" / "dev-tsa")
            else:
                anchorer = HttpTsaAnchorer(name)
            info = druid.anchor(anchorer)  # type: ignore[arg-type]
            print(f"anchored via {name}: token {info['token_bytes']} bytes")
            succeeded += 1
        except Exception as error:  # network / openssl / unknown TSA — report, keep going
            print(f"  {name}: FAILED ({error})")
    if succeeded == 0:
        print("no anchors succeeded (real TSAs need network; try `--tsa dev` for the offline self-hosted TSA)")
        return 1
    print(f"bundles now embed {succeeded} anchor(s). DigiCert/FreeTSA verify by default;")
    print("  a self-hosted `dev` anchor needs `--root druid-data/ledger/dev-tsa-root.pem`.")
    return 0


def cmd_tiles(args: argparse.Namespace) -> int:
    druid = _build(args)
    if not druid.log.entries():
        print("nothing to tile — run `druid observe <target>` first")
        return 1
    info = druid.log.emit_tiles()
    print(f"published {info['tiles']} tile file(s) at height {info['height']} under {args.data_dir / 'ledger' / 'tile'}")
    print("  verifiers can now recompute inclusion proofs from the tile files alone")
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from .triage import claude_summarizer, summarize_event

    druid = _build(args)
    if args.target_id not in druid.targets:
        print(f"unknown target: {args.target_id} (try `druid targets`)")
        return 2
    try:
        review = summarize_event(druid, args.target_id, claude_summarizer(args.model))
    except Exception as error:  # missing anthropic / no credentials / network
        print(f"triage failed: {error}")
        print("  (needs the `triage` extra + Claude credentials; this makes a billable API call)")
        return 1
    if review is None:
        print(f"no reworded (L3 ContentEdit) change to summarize for {args.target_id}")
        print("  observe with `--embed` across a reworded change first")
        return 0
    print(f"reviewer summary for {args.target_id} (best-effort, NOT attested):")
    print(f"  {review['summary']}")
    print(f"  saved to {args.data_dir / 'review'}/  ({review['disclaimer']})")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .web.export import export_site

    druid = _build(args)
    info = export_site(druid, args.out, base_url=args.base_url)
    print(
        f"exported public record -> {info['out']}: {info['targets']} target(s), "
        f"{info['events']} event(s), {info['tiles']} tile file(s)"
    )
    print("  record.json + feed.xml (+ per-target feeds/); subscribe to feed.xml for alerts")
    print("  checkpoint + tile/ published: verifiers can recompute proofs from the tiles alone")
    return 0


def cmd_notify(args: argparse.Namespace) -> int:
    from .notify import (
        HttpWebhookNotifier,
        Notifier,
        SmtpEmailNotifier,
        dispatch,
        events,
        load_state,
        load_subscriptions,
        matches,
        save_state,
    )

    druid = _build(args)
    subs_path = args.subscriptions or _repo_data_dir() / "subscriptions.toml"
    subscriptions = load_subscriptions(subs_path)
    evs = events(druid)
    state = load_state(args.data_dir)

    if args.dry_run:
        pending = [
            (s.name, s.channel, e["id"])
            for e in evs
            for s in subscriptions
            if matches(s, e) and f"{s.name}:{e['id']}" not in state.delivered
        ]
        print(f"{len(pending)} pending delivery(ies) across {len(subscriptions)} subscription(s):")
        for name, channel, eid in pending[:30]:
            print(f"  {channel:8} {name:24} <- {eid[:16]}")
        return 0

    notifiers: dict[str, Notifier] = {
        "webhook": HttpWebhookNotifier(),
        "email": SmtpEmailNotifier(args.smtp_host, args.smtp_port, args.email_from),
    }
    deliveries = dispatch(evs, subscriptions, notifiers, state)
    save_state(args.data_dir, state)
    sent = [d for d in deliveries if "error" not in d]
    failed = [d for d in deliveries if "error" in d]
    print(f"delivered {len(sent)} alert(s); {len(failed)} failed (will retry)")
    for d in sent[:30]:
        print(f"  {d['channel']:8} {d['subscription']:24} -> {d['dest']}")
    for d in failed[:10]:
        print(f"  FAILED {d['channel']} {d['subscription']} -> {d['dest']}: {d['error']}")
    return 1 if failed and not sent else 0


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    try:
        verifier = find_binary("druid-verify")
    except LedgerBinaryNotFound as error:
        print(str(error))
        return 1
    cmd = [str(verifier), "bundle", str(args.path)]
    for root in args.root or []:
        cmd += ["--root", str(root)]
    result = subprocess.run(cmd, capture_output=True, encoding="utf-8")
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
    observe.add_argument("--embed", action="store_true", help="enable L3 embedding triage (needs the `triage` extra)")
    sub.add_parser("log", help="print the observation / diff timeline")
    sub.add_parser("verify", help="verify the ledger chain and signed head")
    anchor = sub.add_parser("anchor", help="anchor the current checkpoint with independent TSAs")
    anchor.add_argument(
        "--tsa", default="digicert,freetsa",
        help="comma-separated TSAs: digicert, freetsa, sectigo (real, need network), or dev (self-hosted, offline)",
    )
    bundle = sub.add_parser("bundle", help="export a self-verifying proof bundle for a target")
    bundle.add_argument("target_id")
    bundle.add_argument("--index", type=int, default=None, help="ledger index of a specific observation leaf")
    bundle.add_argument("-o", "--output", type=Path, default=None, help="write the bundle to a file")
    verify_bundle = sub.add_parser("verify-bundle", help="verify a downloaded proof bundle offline")
    verify_bundle.add_argument("path", type=Path)
    verify_bundle.add_argument("--root", type=Path, action="append", help="pinned TSA root PEM (repeatable) to verify anchors")
    triage = sub.add_parser("triage", help="draft a plain-language reviewer summary of a reworded change (L5)")
    triage.add_argument("target_id")
    triage.add_argument("--model", default="claude-opus-4-8", help="Claude model for the summary")
    sub.add_parser("tiles", help="(re)publish the C2SP tile files for the current ledger")
    export = sub.add_parser("export", help="export the public record (record.json + RSS feeds) for the site")
    export.add_argument("--out", type=Path, default=Path("site-data"), help="output directory")
    export.add_argument("--base-url", default="https://druid.example", help="public base URL for feed links")
    notify = sub.add_parser("notify", help="deliver new diff events to webhook/email subscriptions")
    notify.add_argument("--subscriptions", type=Path, default=None, help="override subscriptions.toml")
    notify.add_argument("--dry-run", action="store_true", help="show pending deliveries without sending")
    notify.add_argument("--smtp-host", default="localhost", help="SMTP host for email subscriptions")
    notify.add_argument("--smtp-port", type=int, default=25, help="SMTP port")
    notify.add_argument("--email-from", default="druid@localhost", help="From: address for email alerts")

    args = parser.parse_args(argv)
    dispatch = {
        "targets": cmd_targets,
        "observe": cmd_observe,
        "log": cmd_log,
        "verify": cmd_verify,
        "anchor": cmd_anchor,
        "bundle": cmd_bundle,
        "verify-bundle": cmd_verify_bundle,
        "triage": cmd_triage,
        "tiles": cmd_tiles,
        "export": cmd_export,
        "notify": cmd_notify,
    }
    return dispatch[args.cmd](args)
