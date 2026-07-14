"""L0 — structural normalisation.

Strip page chrome (nav/footer/scripts/styles), extract the main text, and normalise
whitespace, so a downstream diff catches *real* text change instead of byte noise
(rotating banners, session tokens, timestamps).

M12 adds **noise suppression** for `normalize_for_diff`: redact the per-render volatility a
rendered DOM carries — ISO timestamps, session/trace ids, CSP nonces, and other long random
tokens — *before diffing*, so a re-render that changed nothing meaningful doesn't false-fire a
diff. This affects only the differ's interpretation; the attested bytes (`raw_bytes_hash`, the
WARC) keep the real, unredacted content — the trust core is untouched.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

_STRIP_TAGS = ["script", "style", "nav", "footer", "header", "aside", "form", "noscript", "svg"]
_WHITESPACE = re.compile(r"\s+")

# ISO 8601 date-times ("2026-07-12T14:31:40Z", "2026-07-12 14:31").
_ISO_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
# Long random tokens: a hex string >= 24, or a base64url-ish run >= 24 that contains a digit
# (so real long words — which have no digits — are left alone). Catches nonces / session ids /
# trace ids / CSRF tokens that leak into the rendered text.
_HEX_TOKEN = re.compile(r"\b[0-9a-fA-F]{24,}\b")
_MIXED_TOKEN = re.compile(r"\b(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{24,}\b")


def normalize_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(_STRIP_TAGS):
        tag.decompose()
    return _WHITESPACE.sub(" ", soup.get_text(" ")).strip()


def normalize_bytes(body: bytes) -> str:
    return normalize_html(body.decode("utf-8", errors="replace"))


def suppress_noise(text: str) -> str:
    """Redact per-render volatility (timestamps, nonces, session/trace ids) so a re-render
    that changed nothing meaningful doesn't produce a diff. Best-effort and diff-only."""
    text = _ISO_TIMESTAMP.sub("<ts>", text)
    text = _HEX_TOKEN.sub("<token>", text)
    text = _MIXED_TOKEN.sub("<token>", text)
    return text


def normalize_for_diff(body: bytes) -> str:
    """Normalise **and** noise-suppress — what the differ compares. The attested bytes are
    never touched by this; only the interpretation is."""
    return suppress_noise(normalize_bytes(body))
