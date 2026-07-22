//! Offline verification of OpenTimestamps (OTS) proofs (Verderer M13b / M2b-3).
//!
//! An OTS `.ots` proof commits a file's SHA-256 digest — via a chain of {append, prepend,
//! sha256} operations — into the **merkle root of a Bitcoin block**. A *confirmed* proof
//! carries a `BitcoinBlockHeaderAttestation(height)`: apply the ops to the digest and you
//! obtain the merkle root of the block at `height`. Paired with that block's 80-byte header
//! (which the proof bundle carries, so the check needs no network), this bounds time —
//! "the digest existed no later than the block's timestamp" — the maximally
//! adversary-resistant anchor (DESIGN §4.2).
//!
//! **What is proven offline, and the one residual assumption.** The verifier proves, from
//! bytes alone: (a) the proof commits *this* checkpoint's digest, (b) the op chain lands in
//! the carried header's merkle-root field, and (c) that header carries valid proof-of-work.
//! The single remaining assumption — that the carried header is a block on Bitcoin's *main
//! chain* (not a privately-mined fork) — is checkable by anyone in seconds against the block
//! hash this verifier reports, from any independent source. This mirrors the RFC 3161 anchor
//! model (ADR-0005): report what is cryptographically checkable, name the residual trust, and
//! never overclaim. A proof that mis-binds or a header that fails PoW/merkle is *tamper* and
//! rejects; a real-but-unbounded proof (pending, or its block's header not carried) is
//! reported "present, not verified" and claims no time bound.
//!
//! No bespoke crypto: SHA-256 and byte concatenation only. We implement exactly the three ops
//! a Bitcoin OTS path uses and reject any other tag rather than risk mis-reading a hostile
//! proof.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// `\x00OpenTimestamps\x00\x00Proof\x00` + a random 8-byte magic (the detached-file header).
const HEADER_MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
/// 8-byte attestation type tags (opentimestamps `core/notary.py`).
const ATT_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const ATT_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];
/// Op tags we support (the whole Bitcoin OTS path).
const OP_SHA256: u8 = 0x08;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
/// OTS spec caps an intermediate message at 4096 bytes; a Bitcoin path stays far under.
const MAX_MSG_LEN: usize = 4096;
/// A Bitcoin OTS path is ~50 ops; bound total work so a hostile proof can't fan out.
const MAX_OPS: usize = 10_000;

/// Non-fatal discriminants (the ADR-0005 "present but not verified" cases). Everything else a
/// `verify_ots` `Err` reports is tamper and must reject the bundle.
pub const ERR_OTS_PENDING: &str = "ots: no Bitcoin attestation yet (pending calendar confirmation)";
pub const ERR_OTS_NO_HEADER: &str =
    "ots: Bitcoin attestation present but its block header is not carried";

/// The time bound a confirmed OTS anchor yields.
#[derive(Debug, Clone)]
pub struct OtsBound {
    /// Bitcoin block height the checkpoint is committed into.
    pub height: u32,
    /// Canonical (big-endian display) block hash — check it against any explorer to confirm
    /// the header is main-chain.
    pub block_hash_hex: String,
    /// The block header's `nTime` — the upper time bound (Unix seconds).
    pub unix_time: u32,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn peek(&self) -> Result<u8, String> {
        self.b
            .get(self.i)
            .copied()
            .ok_or_else(|| "ots: truncated proof".into())
    }
    fn u8(&mut self) -> Result<u8, String> {
        let v = self.peek()?;
        self.i += 1;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.i.checked_add(n).ok_or("ots: length overflow")?;
        let s = self.b.get(self.i..end).ok_or("ots: truncated proof")?;
        self.i = end;
        Ok(s)
    }
    fn expect(&mut self, tag: &[u8]) -> Result<(), String> {
        if self.take(tag.len())? == tag {
            Ok(())
        } else {
            Err("ots: bad magic / not an OpenTimestamps proof".into())
        }
    }
    /// OTS varuint: little-endian base-128, high bit = continuation.
    fn varuint(&mut self) -> Result<u64, String> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let byte = self.u8()?;
            if shift >= 64 {
                return Err("ots: varuint too large".into());
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
    fn varbytes(&mut self) -> Result<&'a [u8], String> {
        let n = self.varuint()? as usize;
        self.take(n)
    }
}

/// Verify an OTS proof over `expected_digest` against carried Bitcoin block `headers`
/// (height -> raw 80-byte header). Returns the tightest (earliest) confirmed time bound.
///
/// `Err(ERR_OTS_PENDING | ERR_OTS_NO_HEADER)` are the non-fatal "no bound to claim" cases;
/// any other `Err` is tamper evidence.
pub fn verify_ots(
    expected_digest: &[u8],
    ots: &[u8],
    headers: &BTreeMap<u32, [u8; 80]>,
) -> Result<OtsBound, String> {
    let mut c = Cursor { b: ots, i: 0 };
    c.expect(HEADER_MAGIC)?;
    if c.varuint()? != 1 {
        return Err("ots: unsupported major version".into());
    }
    if c.u8()? != OP_SHA256 {
        return Err("ots: file-hash op is not sha256".into());
    }
    let file_digest = c.take(32)?;
    if file_digest != expected_digest {
        return Err("ots: proof does not commit to this checkpoint".into());
    }

    // Walk the timestamp tree, collecting every Bitcoin (height, merkle-root) commitment.
    let mut commits: Vec<(u32, [u8; 32])> = Vec::new();
    let mut pending = false;
    let mut budget = MAX_OPS;
    eval(
        &mut c,
        file_digest.to_vec(),
        &mut commits,
        &mut pending,
        &mut budget,
    )?;

    if commits.is_empty() {
        return Err(if pending {
            ERR_OTS_PENDING.into()
        } else {
            "ots: no attestation in proof".to_string()
        });
    }

    // Verify each commitment whose block header we carry; keep the tightest bound.
    let mut best: Option<OtsBound> = None;
    for (height, root) in &commits {
        let Some(header) = headers.get(height) else {
            continue;
        };
        let (block_hash_hex, unix_time) = verify_block(header, root)?;
        let bound = OtsBound {
            height: *height,
            block_hash_hex,
            unix_time,
        };
        best = Some(match best {
            Some(cur) if cur.unix_time <= bound.unix_time => cur,
            _ => bound,
        });
    }
    best.ok_or_else(|| ERR_OTS_NO_HEADER.to_string())
}

/// Recursive-descent evaluator over the C2SP/OTS timestamp serialization. A node is a series
/// of branches, each a fork off the *same* message: non-final branches are `\xff`-prefixed,
/// the last is bare. A branch is either an attestation (`\x00` + 8-byte tag + varbytes) or an
/// operation (tag + operands) whose child subtree follows.
fn eval(
    c: &mut Cursor,
    msg: Vec<u8>,
    commits: &mut Vec<(u32, [u8; 32])>,
    pending: &mut bool,
    budget: &mut usize,
) -> Result<(), String> {
    loop {
        if *budget == 0 {
            return Err("ots: proof exceeds operation budget".into());
        }
        *budget -= 1;

        let final_branch = c.peek()? != 0xff;
        if !final_branch {
            c.u8()?; // consume the 0xff fork marker
        }
        let tag = c.u8()?;
        if tag == 0x00 {
            let att_tag = c.take(8)?;
            let payload = c.varbytes()?;
            if att_tag == ATT_BITCOIN {
                let height = Cursor { b: payload, i: 0 }.varuint()? as u32;
                let root: [u8; 32] = msg
                    .as_slice()
                    .try_into()
                    .map_err(|_| "ots: Bitcoin attestation on a non-32-byte message".to_string())?;
                commits.push((height, root));
            } else if att_tag == ATT_PENDING {
                *pending = true;
            }
            // Unknown attestation types: payload already skipped; ignore.
        } else {
            let child = apply_op(tag, &msg, c)?;
            eval(c, child, commits, pending, budget)?;
        }

        if final_branch {
            return Ok(());
        }
    }
}

fn apply_op(tag: u8, msg: &[u8], c: &mut Cursor) -> Result<Vec<u8>, String> {
    let out = match tag {
        OP_SHA256 => Sha256::digest(msg).to_vec(),
        OP_APPEND => {
            let arg = c.varbytes()?;
            [msg, arg].concat()
        }
        OP_PREPEND => {
            let arg = c.varbytes()?;
            [arg, msg].concat()
        }
        other => return Err(format!("ots: unsupported op 0x{other:02x}")),
    };
    if out.len() > MAX_MSG_LEN {
        return Err("ots: intermediate message exceeds the length cap".into());
    }
    Ok(out)
}

/// Verify a raw 80-byte Bitcoin header commits to `expected_root` and carries valid PoW.
/// Returns (canonical block hash hex, nTime). Header layout (all little-endian):
/// version(4) | prev(32) | merkle_root(32) | time(4) | bits(4) | nonce(4).
fn verify_block(header: &[u8; 80], expected_root: &[u8; 32]) -> Result<(String, u32), String> {
    if &header[36..68] != expected_root.as_slice() {
        return Err("ots: block header merkle root does not match the proof".into());
    }
    // Block id = double-SHA-256(header), interpreted little-endian; displayed big-endian.
    let once = Sha256::digest(header.as_slice());
    let twice = Sha256::digest(once);
    let mut be = [0u8; 32]; // big-endian == the displayed block hash
    for (i, byte) in twice.iter().rev().enumerate() {
        be[i] = *byte;
    }
    // Proof-of-work: the big-endian block hash must be <= the target encoded by nBits.
    let bits = u32::from_le_bytes(header[72..76].try_into().unwrap());
    let target = compact_to_target(bits)?;
    if be > target {
        return Err("ots: block header fails proof-of-work".into());
    }
    let unix_time = u32::from_le_bytes(header[68..72].try_into().unwrap());
    let block_hash_hex = be.iter().map(|b| format!("{b:02x}")).collect();
    Ok((block_hash_hex, unix_time))
}

/// Decode Bitcoin's compact "nBits" into a 32-byte big-endian target.
fn compact_to_target(bits: u32) -> Result<[u8; 32], String> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 {
        return Err("ots: negative nBits".into());
    }
    let mut target = [0u8; 32];
    if exponent <= 3 {
        // Mantissa shifted down into the low bytes.
        let m = mantissa >> (8 * (3 - exponent as u32));
        target[29] = (m >> 16) as u8;
        target[30] = (m >> 8) as u8;
        target[31] = m as u8;
    } else {
        // The three mantissa bytes sit at big-endian offset (32 - exponent).
        let idx = 32usize
            .checked_sub(exponent)
            .ok_or("ots: nBits exponent too large")?;
        if idx + 3 > 32 {
            return Err("ots: nBits exponent out of range".into());
        }
        target[idx] = (mantissa >> 16) as u8;
        target[idx + 1] = (mantissa >> 8) as u8;
        target[idx + 2] = mantissa as u8;
    }
    Ok(target)
}

/// Format Unix seconds as ISO-8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`), so an OTS bound sorts and
/// reads alongside RFC 3161 `genTime`s. Pure civil-date arithmetic (Howard Hinnant's
/// `civil_from_days`), no dependency.
pub fn unix_to_iso8601(secs: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hh:02}:{mm:02}:{ss:02}Z")
}
