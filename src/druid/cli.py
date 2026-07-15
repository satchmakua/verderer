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
from typing import TYPE_CHECKING

from .config import load_targets, load_terms
from .ledger.core import LedgerBinaryNotFound, find_binary
from .pipeline import Druid, _checkpoint_size

if TYPE_CHECKING:
    from .scheduler import TickResult

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
    if result.status == "unchanged":
        detail = f" ({result.reason})" if result.reason else ""
        print(f"{args.target_id}: unchanged{detail} - no new observation logged")
        return 0
    if result.status == "skipped":
        print(f"{args.target_id}: skipped - {result.reason}")
        return 0
    obs = result.observation
    assert obs is not None  # status == "observed" always carries an observation
    tag = "first observation" if result.is_first else f"{len(result.diffs)} change(s)"
    print(f"observed {obs.target_id} [{obs.http_status}] {obs.url}")
    print(f"  content {obs.raw_bytes_hash[:18]}...  at {obs.fetched_at}  ({tag})")
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
            print(f"OBS  {when}  {tid:22} [{row['http_status']}] {row['raw_bytes_hash'][:14]}...")
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


def cmd_overlay(args: argparse.Namespace) -> int:
    from .overlay import ArchiveSource, WaybackSource, write_overlay

    druid = _build(args)
    sources: list[ArchiveSource] = []
    for name in (n.strip() for n in args.sources.split(",") if n.strip()):
        if name == "wayback":
            sources.append(WaybackSource(match_prefix=args.prefix))
        else:
            print(f"unknown source: {name} (known: wayback)")
            return 2
    try:
        info = write_overlay(druid, args.out, sources)
    except Exception as error:  # network / archive API failure — report, don't crash
        print(f"overlay build failed: {error}")
        return 1
    print(
        f"built overlay -> {info['out']}: {info['resources']} resource(s) across {info['sources']}, "
        f"{info['attested']} druid-attested ({info['bundles']} bundle(s) written)"
    )
    print("  attested resources carry a downloadable proof bundle; third-party-only copies do not")
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    from .web.export import export_site

    druid = _build(args)
    info = export_site(druid, args.out, base_url=args.base_url)
    print(
        f"exported public record -> {info['out']}: {info['targets']} target(s), "
        f"{info['events']} event(s), {info['tiles']} tile file(s), {info['warcs']} WARC(s)"
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


def _build_notify_fn(args: argparse.Namespace):  # type: ignore[no-untyped-def]
    """Wire the real M5c notify pipeline as a scheduler seam: (druid) -> deliveries."""
    from .notify import (
        HttpWebhookNotifier,
        Notifier,
        SmtpEmailNotifier,
        dispatch,
        events,
        load_state,
        load_subscriptions,
        save_state,
    )

    subs_path = args.subscriptions or _repo_data_dir() / "subscriptions.toml"
    subscriptions = load_subscriptions(subs_path)
    notifiers: dict[str, Notifier] = {
        "webhook": HttpWebhookNotifier(),
        "email": SmtpEmailNotifier(args.smtp_host, args.smtp_port, args.email_from),
    }

    def notify_fn(druid: Druid) -> list[dict[str, object]]:
        state = load_state(args.data_dir)
        deliveries = dispatch(events(druid), subscriptions, notifiers, state)
        save_state(args.data_dir, state)
        return deliveries

    return notify_fn


def _print_tick(r: TickResult) -> None:
    print(
        f"due {r.due_count}: {len(r.observed)} observed, {len(r.unchanged)} unchanged, "
        f"{len(r.skipped)} skipped, {len(r.errored)} error(s); "
        f"{r.diffs} new diff(s), {r.deliveries} alert(s) sent"
    )
    for tid in r.observed:
        print(f"  observed  {tid}")
    for tid in r.unchanged:
        print(f"  unchanged {tid}")
    for tid in r.skipped:
        print(f"  skipped   {tid} (robots)")
    for err in r.errored:
        print(f"  ERROR     {err}")
    if r.notify_error:
        print(f"  notify failed (observation unaffected, will retry): {r.notify_error}")


def cmd_run(args: argparse.Namespace) -> int:
    from .scheduler import Scheduler

    druid = _build(args)
    notify_fn = None if args.no_notify else _build_notify_fn(args)
    scheduler = Scheduler(druid, notify=notify_fn)
    if args.once:
        _print_tick(scheduler.run_due())
        return 0
    print(f"druid run: watching {len(druid.targets)} target(s) on their cadence; Ctrl-C to stop")
    try:
        scheduler.run_forever(poll_cap=args.poll)
    except KeyboardInterrupt:
        print("stopped")
    return 0


def cmd_cosign(args: argparse.Namespace) -> int:
    from .witness import load_or_create_witness

    druid = _build(args)
    if not druid.log.entries():
        print("nothing to cosign — run `druid observe <target>` first")
        return 1
    witness = load_or_create_witness(args.key_file, args.name)
    try:
        info = druid.cosign(witness)
    except Exception as error:
        print(f"cosign failed: {error}")
        return 1
    print(f"witness {witness.name} cosigned checkpoint {info['checkpoint_hash'][:16]} ({info['cosignatures']} total)")
    print(f"  pin it when verifying: --witness {witness.pin()}")
    return 0


def cmd_consistency(args: argparse.Namespace) -> int:
    """Gossip: prove the current checkpoint extends a previously-recorded one (M13).

    Records a baseline the first time; on later runs it proves — offline — that the log has
    only *grown* from that baseline (never forked/shrank/rewrote) and advances the baseline.
    """
    druid = _build(args)
    if not druid.log.entries():
        print("nothing to gossip - run `druid observe <target>` first")
        return 1
    # A distinct marker from the export chain (each tool keeps its own gossip baseline).
    marker = args.data_dir / "ledger" / "gossip-baseline-checkpoint"
    current = druid.log.signed_checkpoint()
    previous_size = None
    if marker.exists():
        try:
            previous_size = _checkpoint_size(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError, IndexError):
            previous_size = None  # a corrupt marker -> re-record a fresh baseline below
    if previous_size is None:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(current, encoding="utf-8")
        print(f"recorded gossip baseline at tree size {_checkpoint_size(current)}")
        return 0
    previous = marker.read_text(encoding="utf-8")
    if previous_size >= _checkpoint_size(current):
        print(f"no new entries since the baseline (size {previous_size}) - nothing to prove")
        return 0
    bundle = druid.gossip_bundle(previous)
    ok, message = druid.log.verify_consistency(bundle["old_checkpoint"], bundle["new_checkpoint"], bundle["proof"])
    if args.output:
        args.output.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
        print(f"wrote gossip bundle -> {args.output}")
    print(message)
    if ok:
        marker.write_text(current, encoding="utf-8")  # advance the gossip baseline
    return 0 if ok else 1


def cmd_verify_consistency(args: argparse.Namespace) -> int:
    """Verify a downloaded `druid.consistency/v1` bundle offline — the log never forked.

    Soundness note: pin Druid's public key with `--pubkey` (obtained from a trusted channel).
    A gossip proof is only meaningful against a *pinned* key — verifying a bundle under the key
    it carries proves it is internally consistent, not that it is Druid's real log (an attacker
    can fabricate a self-consistent history under their own key)."""
    try:
        verifier = find_binary("druid-verify")
    except LedgerBinaryNotFound as error:
        print(str(error))
        return 1
    bundle = json.loads(args.path.read_text(encoding="utf-8"))
    bundle_key = str(bundle.get("pubkey_hex", ""))
    if args.pubkey:
        if bundle_key and bundle_key != args.pubkey:
            print(f"INCONSISTENT bundle is signed by {bundle_key[:16]}..., not the pinned key {args.pubkey[:16]}...")
            return 1
        key = args.pubkey
    else:
        key = bundle_key
        print(
            "warning: no --pubkey pinned - this proves the bundle is internally consistent, NOT "
            "that it is Druid's real log. Pin Druid's key with --pubkey for a trust decision."
        )
    payload = {
        "old_checkpoint": bundle["old_checkpoint"],
        "new_checkpoint": bundle["new_checkpoint"],
        "proof": bundle["proof"],
        "pubkey_hex": key,
    }
    result = subprocess.run(
        [str(verifier), "consistency"], input=json.dumps(payload).encode("utf-8"), capture_output=True
    )
    print((result.stdout or result.stderr).decode(errors="replace").strip())
    return 0 if result.returncode == 0 else 1


def cmd_verify_bundle(args: argparse.Namespace) -> int:
    try:
        verifier = find_binary("druid-verify")
    except LedgerBinaryNotFound as error:
        print(str(error))
        return 1
    cmd = [str(verifier), "bundle", str(args.path)]
    for root in args.root or []:
        cmd += ["--root", str(root)]
    for witness in args.witness or []:
        cmd += ["--witness", witness]
    if args.quorum:
        cmd += ["--quorum", str(args.quorum)]
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
    cosign = sub.add_parser("cosign", help="have a witness co-sign the current checkpoint (M8)")
    cosign.add_argument("--name", required=True, help="witness name (a stable identifier)")
    cosign.add_argument("--key-file", type=Path, required=True, help="witness key file (created if absent)")
    consistency = sub.add_parser("consistency", help="gossip: prove the current checkpoint extends a recorded one (M13)")
    consistency.add_argument("-o", "--output", type=Path, default=None, help="write the gossip bundle to a file")
    verify_consistency = sub.add_parser(
        "verify-consistency", help="verify a downloaded druid.consistency/v1 gossip bundle offline"
    )
    verify_consistency.add_argument("path", type=Path)
    verify_consistency.add_argument(
        "--pubkey", default=None, help="pin Druid's public key (hex) - required for a real trust decision"
    )
    verify_bundle = sub.add_parser("verify-bundle", help="verify a downloaded proof bundle offline")
    verify_bundle.add_argument("path", type=Path)
    verify_bundle.add_argument("--root", type=Path, action="append", help="pinned TSA root PEM (repeatable) to verify anchors")
    verify_bundle.add_argument("--witness", action="append", help="pinned witness name:pubkeyhex (repeatable, M8)")
    verify_bundle.add_argument("--quorum", type=int, default=0, help="required number of witness cosignatures (M8)")
    triage = sub.add_parser("triage", help="draft a plain-language reviewer summary of a reworded change (L5)")
    triage.add_argument("target_id")
    triage.add_argument("--model", default="claude-opus-4-8", help="Claude model for the summary")
    overlay = sub.add_parser("overlay", help="build the federated overlay index (third-party archives + attested badges)")
    overlay.add_argument("--out", type=Path, default=Path("site-data"), help="output directory")
    overlay.add_argument("--sources", default="wayback", help="comma-separated archive sources (known: wayback)")
    overlay.add_argument("--prefix", action="store_true", help="Wayback prefix match (harvest sibling resources)")
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
    run = sub.add_parser("run", help="continuously re-observe due targets on their cadence + fire alerts (M10)")
    run.add_argument("--once", action="store_true", help="process exactly the due set once and exit (cron/systemd)")
    run.add_argument("--poll", type=float, default=300.0, help="max seconds to sleep between wakeups in the loop")
    run.add_argument("--no-notify", action="store_true", help="observe + diff but do not fire the alert pipeline")
    run.add_argument("--subscriptions", type=Path, default=None, help="override subscriptions.toml")
    run.add_argument("--smtp-host", default="localhost", help="SMTP host for email subscriptions")
    run.add_argument("--smtp-port", type=int, default=25, help="SMTP port")
    run.add_argument("--email-from", default="druid@localhost", help="From: address for email alerts")

    args = parser.parse_args(argv)
    dispatch = {
        "targets": cmd_targets,
        "observe": cmd_observe,
        "log": cmd_log,
        "verify": cmd_verify,
        "anchor": cmd_anchor,
        "bundle": cmd_bundle,
        "verify-bundle": cmd_verify_bundle,
        "cosign": cmd_cosign,
        "triage": cmd_triage,
        "overlay": cmd_overlay,
        "tiles": cmd_tiles,
        "export": cmd_export,
        "notify": cmd_notify,
        "run": cmd_run,
        "consistency": cmd_consistency,
        "verify-consistency": cmd_verify_consistency,
    }
    return dispatch[args.cmd](args)
