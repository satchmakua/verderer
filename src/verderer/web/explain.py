"""A plain-language reading of the public record (DESIGN §6.5).

The ledger says *what was observed*; the differ says *what kind of change that was*, in a
terse typed vocabulary (``TermSubstitution {"term": "climate change", "from": 2, "to": 0}``).
This module turns both into sentences a reader can act on, and derives the views a reader
actually needs: what state each source is in, the findings grouped into one *change* per
observed transition, the net effect of a change the differ reported position by position, and
whether a change was later reversed.

Everything here is presentation. These are pure functions over record views that are already
built — no I/O, no hashing, no signatures — and nothing they produce is attested or ever
appended to the ledger. The integrity/interpretation boundary of DESIGN §2 stays visible in the
output: every derived field sits beside the attested ones, never in place of them.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from http import HTTPStatus
from typing import Any

from ..differ.numeric import relative_change
from ..differ.status import is_served

SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3}

# The published curation criteria (the `[tag]` prefixes in data/targets.toml), for readers.
CRITERIA_TAGS: dict[str, str] = {
    "mandate": "Congressionally mandated or regulatory content",
    "threshold": "Carries numeric regulatory thresholds",
    "history": "Documented history of alteration or removal",
    "removed": "Already gone when added to the watch list; watched for reappearance",
    "traffic": "Heavily relied on by the public or by scientists",
}

# How many consecutive failed checks before a source that used to answer is called out as
# not responding (one failed check is routinely a network blip).
FAILING_AFTER = 2

_TEXT_CAP = 220
# How resolvers on different platforms word "this domain does not exist".
_DNS_FAILURES = (
    "name or service not known",
    "getaddrinfo",
    "nodename nor servname",
    "name resolution",
    "no address associated",
    "name does not resolve",
)
_TAG = re.compile(r"^\s*((?:\[[a-z-]+\]\s*)+)(.*)$", re.DOTALL)
_BLOCK = re.compile(r"^(?:table\[(\d+)\]\.row\[(\d+)\]\.col\[(\d+)\]|(li|h[1-6])\[(\d+)\])$")

# Findings are ranked for a change's headline: what a reader most needs to see first.
_KIND_PRIORITY = [
    "removed",
    "number_changed",
    "term_removed",
    "column_removed",
    "sheet_removed",
    "member_removed",
    "variable_removed",
    "rows_changed",
    "distribution_shifted",
    "reappeared",
    "redirect_changed",
    "status_changed",
    "term_added",
    "term_reduced",
    "term_increased",
    "column_retyped",
    "column_added",
    "sheet_added",
    "member_added",
    "variable_added",
    "metadata_changed",
    "text_removed",
    "text_added",
    "text_edited",
    "passage_added",
    "page_edited",
    "cosmetic",
    "error_page_churn",
    "other",
]
_PRIORITY = {kind: rank for rank, kind in enumerate(_KIND_PRIORITY)}
_TEXT_KINDS = {"text_edited", "text_added", "text_removed"}


# --- small helpers -------------------------------------------------------------------------


def _clip(value: object, cap: int = _TEXT_CAP) -> str:
    text = " ".join(str(value).split())
    return text if len(text) <= cap else text[: cap - 1].rstrip() + "…"


def _quoted(value: object, cap: int = _TEXT_CAP) -> str:
    return f"“{_clip(value, cap)}”"


def _int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _percent(fraction: float | None) -> str:
    if fraction is None:
        return ""
    return f" ({fraction * 100:+.0f}%)" if abs(fraction) >= 0.005 else ""


def status_phrase(status: object) -> str:
    """``403`` -> ``"HTTP 403 Forbidden"``; an unknown code is still named."""
    code = _int(status)
    if code is None:
        return "an unknown status"
    try:
        return f"HTTP {code} {HTTPStatus(code).phrase}"
    except ValueError:
        return f"HTTP {code}"


def to_ascii(text: str) -> str:
    """The same sentence for an ASCII-only channel (the CLI: piped Windows stdout cannot
    encode the typographic quotes and arrows these explanations use)."""
    table = {
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
        "→": "->",
        "…": "...",
        "—": "-",
        "–": "-",
        "×": "x",
        "−": "-",
    }
    out = "".join(table.get(ch, ch) for ch in text)
    return out.encode("ascii", "replace").decode("ascii")


def describe_block(path: object) -> str:
    """A structural path from the structure diff, in words: ``li[4]`` -> ``list item 5``."""
    match = _BLOCK.match(str(path))
    if match is None:
        return str(path)
    if match.group(1) is not None:
        table, row, col = (int(match.group(i)) + 1 for i in (1, 2, 3))
        return f"table {table}, row {row}, column {col}"
    name, index = match.group(4), int(match.group(5)) + 1
    return f"list item {index}" if name == "li" else f"heading {index} ({name})"


def word_diff(before: str, after: str, *, context: int = 12) -> dict[str, str]:
    """Where two versions of a passage differ: the words they share at each end are context,
    what sits between is what changed. Word-level, so a one-character edit in a long sentence
    is shown as exactly that, not as two near-identical paragraphs."""
    a, b = before.split(), after.split()
    head = 0
    while head < len(a) and head < len(b) and a[head] == b[head]:
        head += 1
    tail = 0
    while tail < len(a) - head and tail < len(b) - head and a[len(a) - 1 - tail] == b[len(b) - 1 - tail]:
        tail += 1
    lead, trail = a[:head], a[len(a) - tail :] if tail else []
    return {
        "before": ("… " if len(lead) > context else "") + " ".join(lead[-context:]),
        "removed": _clip(" ".join(a[head : len(a) - tail]), 400),
        "added": _clip(" ".join(b[head : len(b) - tail]), 400),
        "after": " ".join(trail[:context]) + (" …" if len(trail) > context else ""),
    }


def parse_criteria(criteria: str) -> tuple[list[str], str]:
    """Split a target's published criteria into its ``[tag]`` prefixes and the prose."""
    match = _TAG.match(criteria or "")
    if match is None:
        return [], (criteria or "").strip()
    return re.findall(r"\[([a-z-]+)\]", match.group(1)), match.group(2).strip()


# --- one finding ---------------------------------------------------------------------------


def _where(evidence: Mapping[str, Any], subject: str) -> str:
    """`` (in <sheet/archive member>)`` when a dataset finding is scoped to part of a file."""
    parts = [str(evidence[key]) for key in ("member", "scope") if evidence.get(key) and key != subject]
    return f" (in {', '.join(parts)})" if parts else ""


def _stat_changes(before: object, after: object) -> str:
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        return f"{_clip(before, 80)} → {_clip(after, 80)}"
    moved = [
        f"{key} {before[key]:.4g} → {after[key]:.4g}"
        for key in before
        if key in after
        and isinstance(before[key], (int, float))
        and isinstance(after[key], (int, float))
        and before[key] != after[key]
    ]
    return "; ".join(moved[:4]) or "summary statistics moved"


def _explain_term(e: Mapping[str, Any]) -> dict[str, Any]:
    term, before, after = _quoted(e.get("term"), 80), _int(e.get("from")), _int(e.get("to"))
    if before is None or after is None:
        return {"kind": "other", "title": f"Watched term count changed: {term}", "summary": _clip(dict(e))}
    if before > 0 and after == 0:
        return {
            "kind": "term_removed",
            "title": f"Watched term removed: {term}",
            "summary": f"{term} appeared {_plural(before, 'time')} in the previous version and is now gone.",
        }
    if before == 0 and after > 0:
        return {
            "kind": "term_added",
            "title": f"Watched term appeared: {term}",
            "summary": f"{term} was absent from the previous version and now appears {_plural(after, 'time')}.",
        }
    if after < before:
        return {
            "kind": "term_reduced",
            "title": f"Fewer mentions of {term}",
            "summary": f"Mentions of {term} fell from {before} to {after}.",
        }
    return {
        "kind": "term_increased",
        "title": f"More mentions of {term}",
        "summary": f"Mentions of {term} rose from {before} to {after}.",
    }


def _explain_number(e: Mapping[str, Any]) -> dict[str, Any]:
    before, after = _clip(e.get("from"), 60), _clip(e.get("to"), 60)
    change = _percent(relative_change(before, after))
    return {
        "kind": "number_changed",
        "title": f"Regulatory number changed: {before} → {after}",
        "summary": (
            f"In the passage {_quoted('…' + _clip(e.get('context', ''), 120))}, the value changed "
            f"from {before} to {after}{change}."
        ),
    }


def _explain_content(e: Mapping[str, Any], served: bool) -> dict[str, Any]:
    if not served:
        return {
            "kind": "error_page_churn",
            "title": "Error page changed",
            "summary": (
                "The server answered with an error page both times, and only the wording of that "
                "error page differs. The resource itself was not served, so this says nothing "
                "about its content."
            ),
        }
    if "block" in e:
        where = describe_block(e["block"])
        if e.get("change") == "added":
            return {"kind": "text_added", "title": f"Text added ({where})", "summary": f"New text: {_quoted(e.get('to', ''))}"}
        if e.get("change") == "removed":
            return {
                "kind": "text_removed",
                "title": f"Text removed ({where})",
                "summary": f"Removed text: {_quoted(e.get('from', ''))}",
            }
        before, after = str(e.get("from", "")), str(e.get("to", ""))
        return {
            "kind": "text_edited",
            "title": f"Text edited ({where})",
            "summary": f"{_quoted(before)} became {_quoted(after)}",
            "diff": word_diff(before, after),
        }
    if "passage" in e:
        return {
            "kind": "passage_added",
            "title": "New or reworded passage",
            "summary": f"A passage with no close match in the previous version: {_quoted(e['passage'])}",
        }
    return {
        "kind": "page_edited",
        "title": "Page text changed",
        "summary": (
            "The text of the page changed, but no watched term or regulatory number moved and the "
            "edit was too broad to pin to a single passage."
        ),
    }


def _explain_schema(e: Mapping[str, Any]) -> dict[str, Any]:
    change = str(e.get("change", ""))
    subject, _, verb = change.partition("_")
    name = _quoted(e.get(subject, "?"), 100)
    nouns = {"column": "Column", "sheet": "Sheet", "member": "File in the archive", "variable": "Variable"}
    if subject not in nouns or verb not in {"removed", "added", "retyped"}:
        return {"kind": "other", "title": "Dataset structure changed", "summary": _clip(dict(e))}
    where = _where(e, subject)
    if verb == "retyped":
        return {
            "kind": change,
            "title": f"{nouns[subject]} type changed: {name}",
            "summary": f"{name} changed type from {_clip(e.get('from'), 40)} to {_clip(e.get('to'), 40)}{where}.",
        }
    return {
        "kind": change,
        "title": f"{nouns[subject]} {verb}: {name}",
        "summary": (
            f"The dataset no longer contains {name}{where}."
            if verb == "removed"
            else f"The dataset now contains {name}{where}, which the previous version did not."
        ),
    }


def _explain_shift(e: Mapping[str, Any]) -> dict[str, Any]:
    if e.get("change") == "row_count":
        before, after = _int(e.get("from")), _int(e.get("to"))
        change = _percent((after - before) / before) if before and after is not None else ""
        return {
            "kind": "rows_changed",
            "title": f"Row count changed: {e.get('from')} → {e.get('to')}",
            "summary": f"The dataset went from {e.get('from')} rows to {e.get('to')}{change}{_where(e, '')}.",
        }
    subject = "column" if "column" in e else "variable"
    name = _quoted(e.get(subject, "?"), 100)
    return {
        "kind": "distribution_shifted",
        "title": f"Values shifted in {name}",
        "summary": (
            f"The numbers in {name} changed in aggregate{_where(e, subject)}: {_stat_changes(e.get('from'), e.get('to'))}."
        ),
    }


def _explain_metadata(e: Mapping[str, Any]) -> dict[str, Any]:
    scope = e.get("scope")
    if scope == "http_status":
        return {
            "kind": "status_changed",
            "title": f"Still unavailable, differently: HTTP {e.get('from_status')} → {e.get('to_status')}",
            "summary": (
                f"The address was already not being served; its answer changed from "
                f"{status_phrase(e.get('from_status'))} to {status_phrase(e.get('to_status'))}."
            ),
        }
    if scope == "final_url":
        return {
            "kind": "redirect_changed",
            "title": "Now resolves to a different address",
            "summary": (
                f"Requests used to end at {_clip(e.get('from_url'), 160)}; they now end at {_clip(e.get('to_url'), 160)}."
            ),
        }
    if "note" in e:
        return {"kind": "metadata_changed", "title": "Dataset could not be compared", "summary": _clip(e["note"]) + "."}
    parts = []
    for key, label in (("removed", "removed"), ("added", "added")):
        if e.get(key):
            parts.append(f"{label}: {_clip(', '.join(map(str, e[key])), 120)}")
    if isinstance(e.get("changed"), Mapping) and e["changed"]:
        parts.append(f"changed: {_clip(', '.join(map(str, e['changed'])), 120)}")
    area = "the file's global attributes" if scope == "global_attrs" else f"{str(scope or 'metadata').removeprefix('var:')}"
    return {
        "kind": "metadata_changed",
        "title": f"Metadata changed ({area})",
        "summary": f"Attributes of {area} changed — {'; '.join(parts) or 'see the evidence'}.",
    }


def explain_event(event: Mapping[str, Any], *, to_status: int | None = None) -> dict[str, Any]:
    """One finding, in plain language: ``{"kind", "title", "summary"}`` (plus a word-level
    ``diff`` for an edited passage). ``to_status`` is the HTTP status of the observation the
    finding leads to, when known — it distinguishes an edit to a page from an edit to an error
    page. Total: unknown types and malformed evidence still get an honest generic reading."""
    raw_evidence = event.get("evidence")
    e: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    diff_type = str(event.get("diff_type", ""))
    served = to_status is None or is_served(to_status)
    try:
        if diff_type == "TermSubstitution":
            return _explain_term(e)
        if diff_type == "NumericThresholdChange":
            return _explain_number(e)
        if diff_type == "ContentEdit":
            return _explain_content(e, served)
        if diff_type == "CosmeticOnly":
            return {
                "kind": "cosmetic",
                "title": "Minor rewording",
                "summary": f"{_quoted(e.get('from', ''))} was reworded as {_quoted(e.get('to', ''))}",
            }
        if diff_type == "SchemaChange":
            return _explain_schema(e)
        if diff_type == "DistributionalShift":
            return _explain_shift(e)
        if diff_type == "MetadataChange":
            return _explain_metadata(e)
        if diff_type == "Deletion":
            return {
                "kind": "removed",
                "title": f"No longer served: HTTP {e.get('from_status')} → {e.get('to_status')}",
                "summary": (
                    f"The address answered normally ({status_phrase(e.get('from_status'))}) and now "
                    f"returns {status_phrase(e.get('to_status'))}."
                ),
            }
        if diff_type == "Reappearance":
            versus = {
                "identical": " Its content is byte-identical to the last version that was served.",
                "changed": (
                    " Its content differs from the last version that was served; the other findings in this change say how."
                ),
                "no_earlier_version": " No earlier served version is on record to compare it with.",
            }.get(str(e.get("versus_last_served")), "")
            return {
                "kind": "reappeared",
                "title": f"Served again: HTTP {e.get('from_status')} → {e.get('to_status')}",
                "summary": (
                    f"The address was returning {status_phrase(e.get('from_status'))} and is being "
                    f"served again ({status_phrase(e.get('to_status'))}).{versus}"
                ),
            }
    except Exception:  # a malformed leaf must never break the public record
        pass
    detail = "; ".join(f"{key}: {_clip(value, 80)}" for key, value in e.items())
    return {"kind": "other", "title": diff_type or "Change detected", "summary": detail or "No further detail was recorded."}


# --- a source's current state --------------------------------------------------------------


def _same_address(a: str, b: str) -> bool:
    def norm(url: str) -> str:
        return re.sub(r"^https?://(www\.)?", "", url.strip().lower()).rstrip("/")

    return norm(a) == norm(b)


def _failure_reason(error: str) -> str:
    """A scheduler error message, classified. Distinguishes the source failing from the
    collector failing — the difference between "the site is gone" and "the tool is broken"."""
    text = error.lower()
    if not text:
        return ""
    if any(marker in text for marker in _DNS_FAILURES):
        return "its domain name no longer resolves (DNS lookup fails)"
    if "certificate" in text or "ssl" in text or "tls" in text:
        return "the TLS handshake fails"
    if "timed out" in text or "timeout" in text:
        return "the connection times out"
    if "refused" in text:
        return "the connection is refused"
    if "playwright" in text or "chromium" in text or "browser" in text:
        return (
            "the rendering collector is not available where the watchdog runs (a collector fault, not evidence about the source)"
        )
    return f"the fetch fails ({_clip(error, 140)})"


def target_state(
    target_url: str,
    observations: Sequence[Mapping[str, Any]],
    monitor: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """The reader-facing state of one source, derived from its latest attested observation
    and the scheduler's own account of recent checks. ``code`` is one of ``live``,
    ``blocked``, ``gone``, ``error``, ``failing``, ``unreachable``, ``excluded``, ``pending``.

    The status and final URL come from attested leaves; the liveness (``failing`` /
    ``unreachable``) comes from operator-reported scheduler state and is labelled as such
    wherever it is shown — a fetch that got no answer leaves nothing to attest."""
    monitor = monitor or {}
    failures = _int(monitor.get("consecutive_failures")) or 0
    reason = _failure_reason(str(monitor.get("last_error") or ""))
    because = f" — {reason}" if reason else ""

    if not observations:
        if monitor.get("last_status") == "error" or failures:
            return {
                "code": "unreachable",
                "label": "Unreachable",
                "detail": (
                    f"No response has ever been received: {_plural(failures, 'consecutive check')} "
                    f"failed{because}. There is nothing to attest until the address answers."
                ),
                "http_status": None,
                "final_url": None,
                "since": None,
            }
        if monitor.get("last_status") == "skipped":
            return {
                "code": "excluded",
                "label": "Not collected",
                "detail": "The site's robots.txt disallows this address, so it is not fetched.",
                "http_status": None,
                "final_url": None,
                "since": None,
            }
        return {
            "code": "pending",
            "label": "Awaiting first check",
            "detail": "No observation has been recorded yet.",
            "http_status": None,
            "final_url": None,
            "since": None,
        }

    latest = observations[-1]
    status = _int(latest.get("http_status")) or 0
    final_url = str(latest.get("url") or "")
    redirected = bool(final_url) and not _same_address(final_url, target_url)
    via = f" after redirecting to {final_url}" if redirected else ""

    if is_served(status):
        code, label = "live", "Live"
        detail = f"Answering normally ({status_phrase(status)})."
        if redirected:
            detail += f" Requests are redirected to {final_url}, so that is the page being recorded."
    elif status in (401, 403, 429, 451):
        code, label = "blocked", "Blocked"
        detail = (
            f"The server refuses the collector ({status_phrase(status)}){via}. The refusal is what "
            "is attested; the page's actual content is not being observed, and other visitors "
            "may be served something different."
        )
    elif status in (404, 410):
        code, label = "gone", "Gone"
        detail = (
            f"The address returns {status_phrase(status)}{via}. The absence is attested, and the "
            "watch continues for a reappearance."
        )
    else:
        code, label = "error", "Erroring"
        detail = f"The address returns {status_phrase(status)}{via}."

    # How long it has been in this state: walk back while the status holds.
    since = latest.get("fetched_at")
    for earlier in reversed(observations[:-1]):
        if _int(earlier.get("http_status")) != status:
            break
        since = earlier.get("fetched_at")

    if monitor.get("last_status") == "error" and failures >= FAILING_AFTER:
        code, label = "failing", "Not responding"
        detail = (
            f"It last answered on {str(latest.get('fetched_at'))[:10]} ({status_phrase(status)}); the "
            f"last {_plural(failures, 'check')} got no response{because}."
        )
    return {
        "code": code,
        "label": label,
        "detail": detail,
        "http_status": status,
        "final_url": final_url if redirected else None,
        "since": since,
    }


# --- findings grouped into changes ---------------------------------------------------------


def _net_text_changes(findings: Sequence[Mapping[str, Any]]) -> tuple[list[str], list[str]] | None:
    """The net effect of a run of positional text findings.

    The structure diff addresses blocks by position, so one list item inserted or removed
    re-indexes everything after it and is reported as a cascade of "edits" (item 5 became old
    item 6, item 6 became old item 7, ...). Comparing the two sides as multisets cancels the
    shuffle and leaves what was actually removed and added. Returns ``None`` when netting
    doesn't shorten the account (the edits were genuinely independent)."""
    before: Counter[str] = Counter()
    after: Counter[str] = Counter()
    for finding in findings:
        evidence = finding.get("evidence") or {}
        if isinstance(evidence.get("from"), str):
            before[evidence["from"]] += 1
        if isinstance(evidence.get("to"), str):
            after[evidence["to"]] += 1
    removed, added = list((before - after).elements()), list((after - before).elements())
    if len(removed) + len(added) >= len(findings):
        return None
    return removed, added


def _signature(findings: Sequence[Mapping[str, Any]]) -> Counter[tuple[Any, ...]] | None:
    """What a change did, in a form that can be compared with its exact opposite. ``None`` if
    any finding has no well-defined inverse (a broad "page text changed" does not)."""
    deltas: Counter[tuple[Any, ...]] = Counter()
    texts = []
    for finding in findings:
        kind, evidence = finding["explain"]["kind"], finding.get("evidence") or {}
        if kind.startswith("term_"):
            deltas[("term", evidence.get("term"), evidence.get("from"), evidence.get("to"))] += 1
        elif kind == "number_changed":
            deltas[("number", evidence.get("context"), evidence.get("from"), evidence.get("to"))] += 1
        elif kind in ("removed", "reappeared", "status_changed"):
            deltas[("status", evidence.get("from_status"), evidence.get("to_status"))] += 1
        elif kind == "redirect_changed":
            deltas[("url", evidence.get("from_url"), evidence.get("to_url"))] += 1
        elif kind in _TEXT_KINDS:
            texts.append(finding)
        else:
            return None
    before: Counter[str] = Counter()
    after: Counter[str] = Counter()
    for finding in texts:
        evidence = finding.get("evidence") or {}
        if isinstance(evidence.get("from"), str):
            before[evidence["from"]] += 1
        if isinstance(evidence.get("to"), str):
            after[evidence["to"]] += 1
    for text in (before - after).elements():
        deltas[("text", text, None)] += 1
    for text in (after - before).elements():
        deltas[("text", None, text)] += 1
    return deltas or None


def _inverse(signature: Counter[tuple[Any, ...]]) -> Counter[tuple[Any, ...]]:
    return Counter({(*delta[:-2], delta[-1], delta[-2]): count for delta, count in signature.items()})


def _headline(findings: Sequence[Mapping[str, Any]], net: tuple[list[str], list[str]] | None) -> str:
    ranked = sorted(findings, key=lambda f: _PRIORITY.get(f["explain"]["kind"], len(_PRIORITY)))
    top = ranked[0]["explain"]
    if top["kind"] in ("term_removed", "term_added"):
        terms = [_quoted((f.get("evidence") or {}).get("term"), 60) for f in ranked if f["explain"]["kind"] == top["kind"]]
        if len(terms) > 1:
            verb = "removed" if top["kind"] == "term_removed" else "appeared"
            rest = len(findings) - len(terms)
            return f"{len(terms)} watched terms {verb}: {', '.join(terms)}" + (f" (+{rest} more)" if rest else "")
    if top["kind"] in _TEXT_KINDS and net is not None:
        removed, added = net
        if removed and not added:
            return f"Text removed: {_quoted(removed[0], 120)}" + (f" (+{len(removed) - 1} more)" if len(removed) > 1 else "")
        if added and not removed:
            return f"Text added: {_quoted(added[0], 120)}" + (f" (+{len(added) - 1} more)" if len(added) > 1 else "")
        return f"Text changed: {_plural(len(removed), 'passage')} removed, {len(added)} added"
    if top["kind"] in _TEXT_KINDS and len(findings) > 1:
        return f"Text edited in {len(findings)} places"
    others = len(findings) - 1
    return top["title"] + (f" (+{others} more finding{'s' if others > 1 else ''})" if others else "")


def _points(findings: Sequence[Mapping[str, Any]], net: tuple[list[str], list[str]] | None, cap: int = 8) -> list[str]:
    """The change as a short list of sentences, most important first, cascades netted."""
    ranked = sorted(findings, key=lambda f: _PRIORITY.get(f["explain"]["kind"], len(_PRIORITY)))
    points: list[str] = []
    text_findings = [f for f in ranked if f["explain"]["kind"] in _TEXT_KINDS]
    for finding in ranked:
        if finding["explain"]["kind"] in _TEXT_KINDS and net is not None:
            continue
        points.append(finding["explain"]["summary"])
    if net is not None:
        removed, added = net
        points += [f"Removed: {_quoted(text)}" for text in removed]
        points += [f"Added: {_quoted(text)}" for text in added]
        points.append(
            f"(The differ reported this as {len(text_findings)} position-by-position edits because "
            "the surrounding list shifted; this is their net effect.)"
        )
    if len(points) > cap:
        points = points[: cap - 1] + [f"…and {len(points) - cap + 1} more findings."]
    return points


def build_changes(
    events: Sequence[dict[str, Any]],
    observations: Mapping[str, Sequence[Mapping[str, Any]]],
) -> list[dict[str, Any]]:
    """Group findings into one *change* per observed transition, oldest first.

    ``events`` are the record's event views in ledger order (each gains an ``explain`` entry
    and a ``change_id``); ``observations`` maps a target id to its observation views, oldest
    first. Findings from one transition share a destination hash and a detection time; a
    change's permanent id is the leaf hash of its first finding."""

    def before_or_at(target_id: str, content_hash: object, moment: str) -> Mapping[str, Any] | None:
        found = None
        for obs in observations.get(target_id, ()):
            if obs.get("content_hash") == content_hash and str(obs.get("fetched_at") or "") <= moment:
                found = obs
        return found

    def endpoint(obs: Mapping[str, Any] | None) -> dict[str, Any] | None:
        if obs is None:
            return None
        return {
            "observation_id": obs.get("id"),
            "observed_at": obs.get("fetched_at"),
            "http_status": obs.get("http_status"),
            "url": obs.get("url"),
            "content_hash": obs.get("content_hash"),
            "warc": obs.get("warc"),
        }

    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for event in events:
        key = (event.get("target_id"), event.get("to_hash"), event.get("detected_at"))
        groups.setdefault(key, []).append(event)

    changes: list[dict[str, Any]] = []
    for (target_id, to_hash, detected_at), findings in groups.items():
        moment = str(detected_at or "")
        to_obs = before_or_at(str(target_id), to_hash, moment)
        to_status = _int(to_obs.get("http_status")) if to_obs else None
        for finding in findings:
            finding["explain"] = explain_event(finding, to_status=to_status)
            finding["change_id"] = findings[0].get("id")
        # The version this one is compared with: the immediately preceding observation, taken
        # from the availability finding when there is one (content findings after a
        # reappearance point further back, at the last version that was served).
        status_finding = next((f for f in findings if f.get("layer") == "L0-status"), findings[0])
        from_obs = before_or_at(
            str(target_id), status_finding.get("from_hash"), str(to_obs.get("fetched_at")) if to_obs else moment
        )

        text_findings = [f for f in findings if f["explain"]["kind"] in _TEXT_KINDS]
        net = _net_text_changes(text_findings) if len(text_findings) >= 3 else None
        kinds = sorted({f["explain"]["kind"] for f in findings}, key=lambda k: _PRIORITY.get(k, len(_PRIORITY)))
        severity = max((str(f.get("severity")) for f in findings), key=lambda s: SEVERITY_RANK.get(s, -1))
        if all(kind == "error_page_churn" for kind in kinds):
            category = "churn"
        elif severity == "High":
            category = "notable"
        else:
            category = "routine"
        changes.append(
            {
                "id": findings[0].get("id"),
                "target_id": target_id,
                "detected_at": detected_at,
                "severity": severity,
                "category": category,
                "kinds": kinds,
                "diff_types": sorted({str(f.get("diff_type")) for f in findings}),
                "headline": _headline(findings, net),
                "points": _points(findings, net),
                "netted": net is not None,
                "event_ids": [f.get("id") for f in findings],
                "from": endpoint(from_obs),
                "to": endpoint(to_obs),
                "reverted_by": None,
                "reverts": None,
            }
        )

    # Link a change to the one that exactly undid it (same source, next meaningful change).
    by_event = {event.get("id"): event for event in events}
    last_by_target: dict[Any, tuple[dict[str, Any], Counter[tuple[Any, ...]] | None]] = {}
    for change in changes:
        if change["category"] == "churn":
            continue
        signature = _signature([by_event[event_id] for event_id in change["event_ids"]])
        previous = last_by_target.get(change["target_id"])
        if previous is not None and signature is not None and previous[1] is not None and _inverse(previous[1]) == signature:
            previous[0]["reverted_by"] = change["id"]
            change["reverts"] = previous[0]["id"]
        last_by_target[change["target_id"]] = (change, signature)
    return changes
