"""External anchoring (DESIGN §6.3, M2b): bind a signed checkpoint to a time via an
RFC 3161 timestamp token, verifiable offline by the Rust `druid-verify`.

**Honesty (M2b-1).** This ships a *self-hosted* dev TSA — an RFC 3161 responder backed
by openssl, whose key Druid generates and holds in the gitignored data dir. It proves
the mechanism (and verifies offline end to end), but a self-hosted TSA is **not** an
independent anchor: Druid could forge its own timestamps, so it is no defence against
Adversary B. Independent third-party TSAs (DigiCert / FreeTSA, over HTTP) are M2b-2. An
anchor's time bound is only as trustworthy as the pinned TSA — do not overclaim.

Anchorers are a port (like collectors): injectable, so tests and future TSAs slot in.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Protocol

# Independent, unauthenticated third-party TSAs (M2b-2). The DigiCert + FreeTSA roots
# ship pinned in the Rust verifier, so their anchors verify with no `--root`.
KNOWN_TSAS: dict[str, str] = {
    "digicert": "http://timestamp.digicert.com",
    "freetsa": "https://freetsa.org/tsr",
    "sectigo": "http://timestamp.sectigo.com",
}


class AnchorError(RuntimeError):
    pass


def _openssl() -> str:
    exe = shutil.which("openssl")
    if not exe:
        raise AnchorError("openssl not found on PATH (needed to build/parse RFC 3161 tokens)")
    return exe


def _run_openssl(openssl: str, *args: str) -> None:
    result = subprocess.run([openssl, *args], capture_output=True)
    if result.returncode != 0:
        raise AnchorError(f"openssl {args[0]} failed: {result.stderr.decode(errors='replace').strip()}")


class Anchorer(Protocol):
    name: str

    def anchor(self, digest: bytes) -> bytes:
        """Return a raw RFC 3161 TimeStampToken (DER) committing to `digest`."""
        ...

    def root_pem(self) -> str:
        """The TSA root certificate to pin when verifying tokens from this anchorer."""
        ...


def anchored_hash(checkpoint: str) -> bytes:
    """The bytes an anchor commits to: SHA-256 of the signed-checkpoint text."""
    return hashlib.sha256(checkpoint.encode("utf-8")).digest()


class OpensslTsaAnchorer:
    """A self-hosted RFC 3161 TSA backed by openssl. Keys live under `tsa_dir` (keep it
    out of version control — `druid-data/` is gitignored). NOT an independent anchor."""

    name = "dev-tsa"

    def __init__(self, tsa_dir: Path) -> None:
        self.dir = Path(tsa_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.openssl = _openssl()
        self._ensure_tsa()

    def _run(self, *args: str) -> None:
        _run_openssl(self.openssl, *args)

    def _p(self, name: str) -> str:
        return (self.dir / name).as_posix()  # forward slashes: safe in openssl configs

    def _ensure_tsa(self) -> None:
        if (self.dir / "root.pem").exists():
            return
        self._run(
            "req", "-x509", "-newkey", "rsa:2048", "-keyout", self._p("ca.key"), "-out", self._p("root.pem"),
            "-days", "3650", "-nodes", "-subj", "/CN=Druid self-hosted dev TSA root",
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        )
        self._run(
            "req", "-newkey", "rsa:2048", "-keyout", self._p("tsa.key"), "-out", self._p("tsa.csr"),
            "-nodes", "-subj", "/CN=Druid self-hosted dev TSA",
        )
        (self.dir / "eku.ext").write_text("extendedKeyUsage=critical,timeStamping\nkeyUsage=critical,digitalSignature\n")
        self._run(
            "x509", "-req", "-in", self._p("tsa.csr"), "-CA", self._p("root.pem"), "-CAkey", self._p("ca.key"),
            "-CAcreateserial", "-days", "3650", "-out", self._p("tsa.crt"), "-extfile", self._p("eku.ext"),
        )
        (self.dir / "serial").write_text("01\n")
        (self.dir / "tsa.cnf").write_text(
            "[tsa]\ndefault_tsa = tc\n[tc]\n"
            f"serial = {self._p('serial')}\ncrypto_device = builtin\n"
            f"signer_cert = {self._p('tsa.crt')}\ncerts = {self._p('root.pem')}\nsigner_key = {self._p('tsa.key')}\n"
            "default_policy = 1.3.6.1.4.1.99999.1\nsigner_digest = sha256\ndigests = sha256, sha512\n"
            "accuracy = secs:1\nordering = yes\ntsa_name = yes\ness_cert_id_chain = no\n"
        )

    def anchor(self, digest: bytes) -> bytes:
        self._run("ts", "-query", "-digest", digest.hex(), "-sha256", "-cert", "-out", self._p("req.tsq"))
        self._run(
            "ts", "-reply", "-config", self._p("tsa.cnf"), "-queryfile", self._p("req.tsq"),
            "-token_out", "-out", self._p("token.der"),
        )
        return (self.dir / "token.der").read_bytes()

    def root_pem(self) -> str:
        return (self.dir / "root.pem").read_text(encoding="utf-8")


class HttpTsaAnchorer:
    """Submit to a real, independent RFC 3161 TSA over HTTP (M2b-2) — the anchor that
    gives a *trustworthy* time bound. Best-effort: needs network. Polite by construction
    (identifiable UA, bounded timeout). The DigiCert/FreeTSA roots ship pinned in the
    verifier, so these anchors verify with no `--root`."""

    def __init__(self, name: str, url: str | None = None, timeout: float = 30.0) -> None:
        resolved = url or KNOWN_TSAS.get(name)
        if not resolved:
            raise AnchorError(f"unknown TSA '{name}' — pass an explicit url")
        self.name = name
        self.url: str = resolved
        self.timeout = timeout
        self.openssl = _openssl()

    def anchor(self, digest: bytes) -> bytes:
        import httpx

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            query = tmp_dir / "req.tsq"
            response = tmp_dir / "resp.tsr"
            token = tmp_dir / "token.der"
            _run_openssl(
                self.openssl, "ts", "-query", "-digest", digest.hex(), "-sha256", "-cert",
                "-out", query.as_posix(),
            )
            reply = httpx.post(
                self.url,
                content=query.read_bytes(),
                timeout=self.timeout,
                headers={
                    "Content-Type": "application/timestamp-query",
                    "User-Agent": "DruidWatchdog/0.0 (+https://github.com/satchmakua/Druid) polite-anchor",
                },
            )
            reply.raise_for_status()
            response.write_bytes(reply.content)
            _run_openssl(self.openssl, "ts", "-reply", "-in", response.as_posix(), "-token_out", "-out", token.as_posix())
            return token.read_bytes()

    def root_pem(self) -> str:
        return ""  # the verifier ships DigiCert/FreeTSA roots pinned; nothing to stash
