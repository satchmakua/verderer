"""L0 — structural normalisation.

Strip page chrome (nav/footer/scripts/styles), extract the main text, and normalise
whitespace, so a downstream diff catches *real* text change instead of byte noise
(rotating banners, session tokens, timestamps).
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

_STRIP_TAGS = ["script", "style", "nav", "footer", "header", "aside", "form", "noscript", "svg"]
_WHITESPACE = re.compile(r"\s+")


def normalize_html(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(_STRIP_TAGS):
        tag.decompose()
    return _WHITESPACE.sub(" ", soup.get_text(" ")).strip()


def normalize_bytes(body: bytes) -> str:
    return normalize_html(body.decode("utf-8", errors="replace"))
