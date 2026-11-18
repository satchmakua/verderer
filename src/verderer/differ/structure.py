"""Structure-aware diff (DESIGN §6.2, M12): localise a change to the block it happened in.

L0 flattens a page to one string, which is right for term/numeric watching but *smears* a
single table-cell edit into anonymous flat-text noise — you can tell the page changed, not
*where*. This layer preserves the block structure L0 discards — **headings, list items, and
table cells (with coordinates)** — and diffs block-by-block, so a one-cell edit is reported
as exactly that cell, `from` -> `to`.

It runs in the differ's fallback position: after the semantic layers (L1 term-watch, L2
numeric) have had their say, to give a *localised* account of a change they didn't itemise —
in place of the coarse "the page changed" floor. If the change is too broad to localise (a
structural overhaul re-indexes everything), it declines and lets the floor summarise. Block
text is noise-suppressed like the flat text, so a rotating token in a cell doesn't false-fire.
"""

from __future__ import annotations

import re
from dataclasses import replace

from bs4 import BeautifulSoup

from ..models import DiffRecord, DiffType
from .normalize import _STRIP_TAGS, _WHITESPACE, suppress_noise
from .numeric import quantities_in, same_dimension, values_differ

# Above this many changed/added/removed blocks it isn't a *localised* edit — the structure was
# reshuffled (a row inserted re-indexes the tail), so positional block paths over-report.
# Decline and let the coarse floor give one honest "content changed" instead of a flood.
_MAX_LOCALISED = 20
_EVIDENCE_CAP = 300  # trim a cell's text in evidence so a huge cell can't bloat a leaf


def _text(node: object) -> str:
    return suppress_noise(_WHITESPACE.sub(" ", node.get_text(" ")).strip())  # type: ignore[attr-defined]


def extract_blocks(html: str) -> dict[str, str]:
    """Map a structural path -> its (noise-suppressed) text. Paths are positional and stable
    for an edit that doesn't change the structure: ``h2[0]``, ``table[0].row[2].col[1]``,
    ``li[3]``."""
    soup = BeautifulSoup(html, "html.parser")
    # Strip the same page chrome L0 strips (nav/header/footer/aside/form/…) so a rotating
    # nav/footer block isn't localized as a spurious ContentEdit — the layers must agree.
    for tag in soup(_STRIP_TAGS):
        tag.decompose()

    blocks: dict[str, str] = {}
    heading_counts: dict[str, int] = {}
    for heading in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]):
        level = heading.name
        index = heading_counts.get(level, 0)
        heading_counts[level] = index + 1
        text = _text(heading)
        if text:
            blocks[f"{level}[{index}]"] = text

    for t, table in enumerate(soup.find_all("table")):
        for r, row in enumerate(table.find_all("tr")):
            for c, cell in enumerate(row.find_all(["td", "th"])):
                blocks[f"table[{t}].row[{r}].col[{c}]"] = _text(cell)

    for i, item in enumerate(soup.find_all("li")):
        text = _text(item)
        if text:
            blocks[f"li[{i}]"] = text

    return blocks


def structure_watch(
    prev_body: bytes,
    curr_body: bytes,
    *,
    target_id: str,
    detected_at: str,
    from_hash: str | None,
    to_hash: str,
) -> list[DiffRecord]:
    prev = extract_blocks(prev_body.decode("utf-8", errors="replace"))
    curr = extract_blocks(curr_body.decode("utf-8", errors="replace"))

    def rec(evidence: dict[str, object]) -> DiffRecord:
        return DiffRecord(
            target_id=target_id,
            from_observation_hash=from_hash,
            to_observation_hash=to_hash,
            detected_at=detected_at,
            diff_type=DiffType.ContentEdit,
            severity="Medium",
            layer="L0-structure",
            evidence=evidence,
        )

    changed: list[DiffRecord] = []
    for path, curr_text in curr.items():
        prev_text = prev.get(path)
        if prev_text is not None and prev_text != curr_text:
            changed.append(rec({"block": path, "from": prev_text[:_EVIDENCE_CAP], "to": curr_text[:_EVIDENCE_CAP]}))
    added = [rec({"block": p, "change": "added", "to": t[:_EVIDENCE_CAP]}) for p, t in curr.items() if p not in prev]
    removed = [rec({"block": p, "change": "removed", "from": t[:_EVIDENCE_CAP]}) for p, t in prev.items() if p not in curr]

    localised = changed + added + removed
    if len(localised) > _MAX_LOCALISED:
        return []  # too broad to localise usefully — defer to the coarse floor
    return localised


_CELL = re.compile(r"^table\[(\d+)\]\.row\[(\d+)\]\.col\[(\d+)\]$")


def table_numeric_watch(
    prev_body: bytes,
    curr_body: bytes,
    *,
    target_id: str,
    detected_at: str,
    from_hash: str | None,
    to_hash: str,
    already: frozenset[tuple[str, str]] = frozenset(),
) -> list[DiffRecord]:
    """L2 for tables: a regulatory value in a table cell is named by its row and column, not
    by a keyword beside it ("PFHxS | 10 ppt" under a "Final MCL" header), so the flat-text
    numeric watch never sees it as regulatory. This reports a cell whose quantity moved as a
    `NumericThresholdChange`, with the row label and column header as its context.

    Positional paths lie when a row is inserted (every later row shifts), so a cell is only
    compared when its table kept the same number of rows and its row label and column header
    (when the table has one) are unchanged. `already` holds (from, to) pairs the flat-text watch reported, so one change
    is not logged twice.
    """
    prev = extract_blocks(prev_body.decode("utf-8", errors="replace"))
    curr = extract_blocks(curr_body.decode("utf-8", errors="replace"))

    def rows(blocks: dict[str, str]) -> dict[int, int]:
        count: dict[int, int] = {}
        for path in blocks:
            match = _CELL.match(path)
            if match:
                table, row = int(match.group(1)), int(match.group(2))
                count[table] = max(count.get(table, 0), row + 1)
        return count

    prev_rows, curr_rows = rows(prev), rows(curr)
    found: list[DiffRecord] = []
    for path, curr_text in curr.items():
        match = _CELL.match(path)
        prev_text = prev.get(path)
        if match is None or prev_text is None or prev_text == curr_text:
            continue
        table, row, col = (int(g) for g in match.groups())
        if prev_rows.get(table) != curr_rows.get(table):
            continue
        label_path = f"table[{table}].row[{row}].col[0]"
        if col > 0 and prev.get(label_path) != curr.get(label_path):
            continue
        # The first row is a header only if its cell in this column is words, not a value:
        # a table with no header row starts straight in with data.
        header_path = f"table[{table}].row[0].col[{col}]"
        header = curr.get(header_path, "") if row > 0 else ""
        if header and quantities_in(header):
            header = ""
        if header and prev.get(header_path) != header:
            continue
        before, after = quantities_in(prev_text), quantities_in(curr_text)
        if not before or len(before) != len(after):
            continue
        label = curr.get(label_path, "") if col > 0 else ""
        context = " - ".join(part for part in (label, header) if part)[:_EVIDENCE_CAP]
        for old, new in zip(before, after, strict=True):
            if not same_dimension(old, new) or not values_differ(old, new):
                continue
            if (old.raw.lower(), new.raw.lower()) in already:
                continue
            found.append(
                DiffRecord(
                    target_id=target_id,
                    from_observation_hash=from_hash,
                    to_observation_hash=to_hash,
                    detected_at=detected_at,
                    diff_type=DiffType.NumericThresholdChange,
                    severity="High",
                    layer="L2-table",
                    evidence={"context": context, "unit": new.unit, "from": old.raw, "to": new.raw, "block": path},
                )
            )
    if len(found) > _MAX_LOCALISED:
        # A re-based table is one event, not a flood of leaves: keep the first cells and say
        # how many more moved.
        extra = len(found) - _MAX_LOCALISED
        found = found[:_MAX_LOCALISED]
        found[-1] = replace(found[-1], evidence={**found[-1].evidence, "also_changed": extra})
    return found
