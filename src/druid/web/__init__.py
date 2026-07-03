"""The public record (DESIGN §7): a browsable, append-only timeline built from the
ledger, plus subscribable RSS/Atom alert feeds. This package produces the *data* (a
JSON export + feeds); the Astro site renders it (kept read-only + static-leaning, which
is Astro's sweet spot). Nothing here touches the trust core — it only reads attested
records and the differ's (labelled) interpretations.
"""
