"""Checkpoint mirroring (DESIGN §6.3, M14b-2): make the signed checkpoint survivable.

A checkpoint only constrains the operator if copies exist *outside the operator's control* —
otherwise a compromised Verderer could quietly rewrite history and republish. This module
submits the live checkpoint (and the site around it) to **independent public archives**:

* **Wayback Machine** (Save Page Now): archives the exact `checkpoint` URL — a third party
  can later fetch the bytes from `web.archive.org` and compare/verify signatures.
* **Software Heritage** (Save Code Now): archives the whole git repository — including the
  `gh-pages` branch that carries every published checkpoint, tile, bundle, and WARC.

This is a *redundancy* layer, not the trust core: a mirror stores bytes whose integrity is
already self-evident (the checkpoint is Ed25519-signed; blobs are content-addressed). Mirrors
add survivability and independent timestamps, never authority. Submissions are polite,
fail-soft (one mirror down never blocks another), and injectable for offline tests.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

USER_AGENT = "VerdererWatchdog/0.1 (+https://github.com/satchmakua/verderer) checkpoint-mirror"

# (url, method) -> (status_code, final_url, body). Injectable so tests never touch the network.
HttpFn = Callable[[str, str], tuple[int, str, bytes]]


def _httpx_request(url: str, method: str = "GET") -> tuple[int, str, bytes]:
    import httpx  # lazy: offline tests inject a fake

    with httpx.Client(follow_redirects=True, timeout=90.0, headers={"User-Agent": USER_AGENT}) as client:
        response = client.request(method, url)
        return response.status_code, str(response.url), response.content


@dataclass(frozen=True, slots=True)
class MirrorReceipt:
    mirror: str  # "wayback" | "software-heritage"
    submitted: str  # what we asked it to preserve
    ok: bool
    location: str = ""  # where the archived copy lives (when the mirror reports one)
    detail: str = ""


def submit_wayback(target_url: str, http: HttpFn = _httpx_request) -> MirrorReceipt:
    """Ask the Wayback Machine to capture `target_url` now (Save Page Now).

    A bare GET of `https://web.archive.org/save/<url>` is the documented no-auth path; the
    response redirects to (or names) the new snapshot. SPN can also queue the capture — a
    2xx/3xx without a snapshot URL still means "accepted", so that is reported ok with the
    generic `/web/<url>` locator a reader can resolve later.
    """
    save_url = f"https://web.archive.org/save/{target_url}"
    try:
        status, final_url, _body = http(save_url, "GET")
    except Exception as error:
        return MirrorReceipt(mirror="wayback", submitted=target_url, ok=False, detail=str(error))
    if status >= 400:
        return MirrorReceipt(mirror="wayback", submitted=target_url, ok=False, detail=f"HTTP {status}")
    location = final_url if "/web/" in final_url else f"https://web.archive.org/web/{target_url}"
    return MirrorReceipt(mirror="wayback", submitted=target_url, ok=True, location=location, detail=f"HTTP {status}")


def submit_software_heritage(repo_url: str, http: HttpFn = _httpx_request) -> MirrorReceipt:
    """Ask Software Heritage to archive the git repository (Save Code Now, no auth).

    SWH archives every branch — including `gh-pages`, which carries the published checkpoints,
    tiles, bundles, and WARCs — into a globally deduplicated, independently operated archive.
    """
    api = f"https://archive.softwareheritage.org/api/1/origin/save/git/url/{repo_url}/"
    try:
        status, _final, _body = http(api, "POST")
    except Exception as error:
        return MirrorReceipt(mirror="software-heritage", submitted=repo_url, ok=False, detail=str(error))
    if status >= 400:
        return MirrorReceipt(mirror="software-heritage", submitted=repo_url, ok=False, detail=f"HTTP {status}")
    return MirrorReceipt(
        mirror="software-heritage",
        submitted=repo_url,
        ok=True,
        location=f"https://archive.softwareheritage.org/browse/origin/directory/?origin_url={repo_url}",
        detail=f"HTTP {status}",
    )


def verify_wayback_copy(target_url: str, expected: bytes, http: HttpFn = _httpx_request) -> bool:
    """Fetch the newest Wayback snapshot of `target_url` and compare it byte-for-byte.

    Uses the `id_` (identity) flag so Wayback serves the original bytes without its replay
    banner/rewriting — required for a signed checkpoint to survive the round trip intact.
    """
    snapshot = f"https://web.archive.org/web/0id_/{target_url}"
    try:
        status, _final, body = http(snapshot, "GET")
    except Exception:
        return False
    return status == 200 and body == expected


def mirror_checkpoint(
    checkpoint_url: str,
    repo_url: str,
    http: HttpFn = _httpx_request,
) -> list[MirrorReceipt]:
    """Submit the published checkpoint to every mirror. Fail-soft per mirror."""
    return [
        submit_wayback(checkpoint_url, http),
        submit_software_heritage(repo_url, http),
    ]
