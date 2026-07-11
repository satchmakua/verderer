//! Druid's trust core (M1).
//!
//! A tamper-evident append-only Merkle log built on the [`tlog_tiles`] crate's
//! implementation of the C2SP tlog algorithms, with C2SP signed checkpoints (Ed25519
//! signed notes) and an independent offline verifier. See `DESIGN.md` §4.
//!
//! Storage in a ledger directory:
//! - `entries.b64` — one base64 line per record (the exact leaf bytes).
//! - `hashes`      — the flat stored-hash file (the canonical tlog backing store).
//! - `checkpoint`  — the current signed checkpoint (a signed note).
//! - `key.json`    — the Ed25519 log key (local; the public half is what verifiers pin).
//!
//! Heuristic-free by construction: this crate deals only in bytes, hashes, and
//! signatures.

mod cosignature;
mod note;
mod rfc3161;

pub use cosignature::{cosig_key_id, cosign_line, verify_cosign_line};
pub use ed25519_dalek::VerifyingKey;
pub use note::{key_id, sign_note, verify_note, NoteError};
pub use rfc3161::{verify_rfc3161_token, AnchorInfo, ERR_UNTRUSTED_ROOT};

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tlog_tiles::{
    check_record, prove_record, prove_tree, record_hash, stored_hash_index, stored_hashes,
    tree_hash, Checkpoint, Error as TlogError, Hash, HashReader, RecordProof, Tile, TileHashReader,
    TileReader, TreeProof,
};

/// The checkpoint origin and note key name. A stable, schema-less identifier.
pub const ORIGIN: &str = "druid.watchdog/m1-log";

/// The C2SP tlog-tiles tile height: tiles of 2^8 = 256 hashes (M2c).
pub const TILE_HEIGHT: u8 = 8;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|e| e.to_string())
}

/// The sha2-256 multihash of `data` (`"1220"` + hex digest), matching the Python store.
fn multihash_sha256(data: &[u8]) -> String {
    format!("1220{}", hex::encode(Sha256::digest(data)))
}

/// Parse a hex-encoded Ed25519 public key (used to pin the log key and witness keys).
pub fn vk_from_hex(h: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(h).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "bad public key length")?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
}

/// Produce a C2SP tlog-cosignature line for a checkpoint (M8 witness tooling). `seed_hex`
/// is the witness's 32-byte Ed25519 seed; `timestamp` is Unix seconds.
pub fn cosign_checkpoint(
    checkpoint: &str,
    name: &str,
    seed_hex: &str,
    timestamp: u64,
) -> Result<String, String> {
    let sep = checkpoint.find("\n\n").ok_or("malformed checkpoint")?;
    let note_body = &checkpoint[..=sep];
    let bytes = hex::decode(seed_hex).map_err(|e| e.to_string())?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "bad key length")?;
    Ok(cosign_line(
        note_body,
        name,
        &SigningKey::from_bytes(&seed),
        timestamp,
    ))
}

/// Parse a checkpoint body (`origin\nsize\nbase64(root)\n`) into its parts. We parse
/// it ourselves rather than via strict `Checkpoint::from_bytes` so verification does
/// not depend on exact trailing-line framing.
fn parse_body(body: &str) -> Result<(String, u64, Hash), String> {
    let mut lines = body.lines();
    let origin = lines.next().ok_or("empty checkpoint")?.to_string();
    let size: u64 = lines
        .next()
        .ok_or("no size line")?
        .parse()
        .map_err(|_| "bad size")?;
    let root = Hash::parse_hash(lines.next().ok_or("no root line")?).map_err(|e| e.to_string())?;
    Ok((origin, size, root))
}

/// A [`HashReader`] backed by the flat `hashes` file (32 bytes per stored hash).
pub struct FileHashReader {
    path: PathBuf,
}

impl HashReader for FileHashReader {
    fn read_hashes(&self, indexes: &[u64]) -> Result<Vec<Hash>, TlogError> {
        if indexes.is_empty() {
            return Ok(Vec::new());
        }
        let mut file =
            File::open(&self.path).map_err(|e| TlogError::InvalidInput(e.to_string()))?;
        let mut out = Vec::with_capacity(indexes.len());
        for &index in indexes {
            file.seek(SeekFrom::Start(index * 32))
                .map_err(|e| TlogError::InvalidInput(e.to_string()))?;
            let mut buf = [0u8; 32];
            file.read_exact(&mut buf)
                .map_err(|e| TlogError::InvalidInput(e.to_string()))?;
            out.push(Hash(buf));
        }
        Ok(out)
    }
}

pub struct AppendResult {
    pub index: u64,
    pub leaf_hash: Hash,
    pub size: u64,
    pub checkpoint: String,
}

pub struct InclusionResult {
    pub index: u64,
    pub leaf_hash: Hash,
    pub tree_size: u64,
    pub proof: RecordProof,
    pub checkpoint: String,
}

pub struct Ledger {
    dir: PathBuf,
}

impl Ledger {
    pub fn open(dir: impl Into<PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn hashes_path(&self) -> PathBuf {
        self.dir.join("hashes")
    }
    fn entries_path(&self) -> PathBuf {
        self.dir.join("entries.b64")
    }
    fn checkpoint_path(&self) -> PathBuf {
        self.dir.join("checkpoint")
    }
    fn key_path(&self) -> PathBuf {
        self.dir.join("key.json")
    }

    fn reader(&self) -> FileHashReader {
        FileHashReader {
            path: self.hashes_path(),
        }
    }

    /// Number of records in the log (one base64 line per record).
    pub fn size(&self) -> u64 {
        match std::fs::read(self.entries_path()) {
            Ok(bytes) => bytes.iter().filter(|&&c| c == b'\n').count() as u64,
            Err(_) => 0,
        }
    }

    /// The raw leaf bytes of record `n`.
    pub fn entry_bytes(&self, n: u64) -> Result<Vec<u8>, String> {
        let data = std::fs::read_to_string(self.entries_path()).map_err(|e| e.to_string())?;
        let line = data
            .lines()
            .nth(n as usize)
            .ok_or("record index out of range")?;
        b64_decode(line)
    }

    fn load_or_create_key(&self) -> Result<SigningKey, String> {
        let path = self.key_path();
        if path.exists() {
            let value: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let priv_hex = value["private_hex"]
                .as_str()
                .ok_or("key.json missing private_hex")?;
            let bytes = hex::decode(priv_hex).map_err(|e| e.to_string())?;
            let seed: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| "bad private key length")?;
            Ok(SigningKey::from_bytes(&seed))
        } else {
            let mut seed = [0u8; 32];
            getrandom::getrandom(&mut seed).map_err(|e| e.to_string())?;
            let signing = SigningKey::from_bytes(&seed);
            let value = serde_json::json!({
                "name": ORIGIN,
                "private_hex": hex::encode(seed),
                "public_hex": hex::encode(signing.verifying_key().to_bytes()),
            });
            std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap())
                .map_err(|e| e.to_string())?;
            Ok(signing)
        }
    }

    /// The log's public key (read from `key.json`).
    pub fn public_key(&self) -> Result<VerifyingKey, String> {
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(self.key_path()).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        vk_from_hex(
            value["public_hex"]
                .as_str()
                .ok_or("key.json missing public_hex")?,
        )
    }

    /// Publish the C2SP tile files for the growth from `old_size` to `new_size` (M2c).
    ///
    /// Tiles land under `<ledger>/tile/<h>/<l>/<n>[.p/<w>]` — the C2SP tlog-tiles path
    /// scheme, so the ledger directory doubles as a static tile server layout (serve it
    /// from a CDN/R2 and verifiers can fetch tiles directly). Per the spec, stale
    /// partials MAY be dropped: writing a wider partial removes narrower ones, and a
    /// completed full tile removes its `.p/` directory. `write_tiles(0, size)`
    /// regenerates everything (idempotent — the migration path for pre-tile ledgers).
    pub fn write_tiles(&self, old_size: u64, new_size: u64) -> Result<usize, String> {
        let reader = self.reader();
        let tiles = Tile::new_tiles(TILE_HEIGHT, old_size, new_size);
        for tile in &tiles {
            let data = tile.read_data(&reader).map_err(|e| e.to_string())?;
            let path = self.dir.join(tile.path());
            let parent = path.parent().ok_or("tile path has no parent")?;
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            std::fs::write(&path, &data).map_err(|e| e.to_string())?;
            if tile.width() == 1 << TILE_HEIGHT {
                // Full tile: its partials are obsolete.
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                let _ = std::fs::remove_dir_all(parent.join(format!("{name}.p")));
            } else {
                // Growing partial: drop the narrower ones it supersedes.
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let stale = entry
                            .file_name()
                            .to_str()
                            .and_then(|n| n.parse::<u32>().ok())
                            .is_some_and(|w| w < tile.width());
                        if stale {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }
        }
        Ok(tiles.len())
    }

    /// Append a record, update the Merkle store, and write a fresh signed checkpoint.
    pub fn append(&self, record: &[u8]) -> Result<AppendResult, String> {
        let key = self.load_or_create_key()?;
        let n = self.size();
        let new_hashes = stored_hashes(n, record, &self.reader()).map_err(|e| e.to_string())?;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.hashes_path())
                .map_err(|e| e.to_string())?;
            for hash in &new_hashes {
                file.write_all(&hash.0).map_err(|e| e.to_string())?;
            }
            file.sync_all().ok();
        }
        {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.entries_path())
                .map_err(|e| e.to_string())?;
            file.write_all(b64_encode(record).as_bytes())
                .map_err(|e| e.to_string())?;
            file.write_all(b"\n").map_err(|e| e.to_string())?;
            file.sync_all().ok();
        }
        let size = n + 1;
        let root = tree_hash(size, &self.reader()).map_err(|e| e.to_string())?;
        let body = String::from_utf8(
            Checkpoint::new(ORIGIN, size, root, "")
                .map_err(|_| "malformed checkpoint")?
                .to_bytes(),
        )
        .map_err(|e| e.to_string())?;
        let checkpoint = sign_note(&body, ORIGIN, &key);
        std::fs::write(self.checkpoint_path(), &checkpoint).map_err(|e| e.to_string())?;
        // Publish the tiles this append grew (M2c). The hash file is already durable, so
        // a failure here leaves a consistent log; `write_tiles(0, size)` re-emits.
        self.write_tiles(n, size)?;
        Ok(AppendResult {
            index: n,
            leaf_hash: record_hash(record),
            size,
            checkpoint,
        })
    }

    pub fn signed_checkpoint(&self) -> Result<String, String> {
        std::fs::read_to_string(self.checkpoint_path()).map_err(|e| e.to_string())
    }

    /// An inclusion proof for record `n` against the current tree.
    pub fn inclusion(&self, n: u64) -> Result<InclusionResult, String> {
        let size = self.size();
        if n >= size {
            return Err("index out of range".into());
        }
        let proof = prove_record(size, n, &self.reader()).map_err(|e| e.to_string())?;
        let leaf_hash = record_hash(&self.entry_bytes(n)?);
        Ok(InclusionResult {
            index: n,
            leaf_hash,
            tree_size: size,
            proof,
            checkpoint: self.signed_checkpoint()?,
        })
    }

    /// A consistency proof that the size-`new` tree extends the size-`old` tree.
    pub fn consistency(&self, old: u64, new: u64) -> Result<TreeProof, String> {
        prove_tree(new, old, &self.reader()).map_err(|e| e.to_string())
    }

    /// The Merkle root over the first `size` records (the prefix tree).
    pub fn root(&self, size: u64) -> Result<Hash, String> {
        tree_hash(size, &self.reader()).map_err(|e| e.to_string())
    }

    /// Recompute the whole log and check it against its signed checkpoint. Catches
    /// tampering of either a stored leaf (entry) or a stored hash.
    pub fn verify_log(&self) -> Result<String, String> {
        let size = self.size();
        let body = verify_note(&self.signed_checkpoint()?, ORIGIN, &self.public_key()?)
            .map_err(|e| e.to_string())?;
        let (origin, cp_size, cp_root) = parse_body(&body)?;
        if origin != ORIGIN {
            return Err(format!("unexpected origin {origin}"));
        }
        if cp_size != size {
            return Err(format!("checkpoint size {cp_size} != {size} entries"));
        }
        let reader = self.reader();
        for n in 0..size {
            let leaf = record_hash(&self.entry_bytes(n)?);
            let stored = reader
                .read_hashes(&[stored_hash_index(0, n)])
                .map_err(|e| e.to_string())?;
            if stored[0].0 != leaf.0 {
                return Err(format!("entry {n} hash mismatch (tampered?)"));
            }
        }
        let root = tree_hash(size, &reader).map_err(|e| e.to_string())?;
        if root.0 != cp_root.0 {
            return Err("recomputed root != signed checkpoint root".into());
        }
        Ok(format!("{size} entries, root {}", hex::encode(root.0)))
    }
}

/// A [`TileReader`] over a directory laid out in the C2SP tile path scheme (M2c) —
/// the shape of a ledger dir, a synced R2 bucket, or files fetched from a CDN.
///
/// Lookup per tile: the exact path first (`…/000.p/11` or `…/000`), then the full
/// tile, then any wider partial — both fallbacks sliced down to the requested width
/// (a reader may legitimately hold a newer, wider file than the one asked for).
pub struct DirTileReader {
    base: PathBuf,
}

impl DirTileReader {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn read_one(&self, tile: &Tile) -> Result<Vec<u8>, TlogError> {
        let want = tile.width() as usize * 32;
        let exact = self.base.join(tile.path());
        if let Ok(data) = std::fs::read(&exact) {
            if data.len() >= want {
                return Ok(data[..want].to_vec());
            }
        }
        if tile.width() < 1 << tile.height() {
            let full = Tile::new(
                tile.height(),
                tile.level(),
                tile.level_index(),
                1 << tile.height(),
                false,
            );
            let full_path = self.base.join(full.path());
            if let Ok(data) = std::fs::read(&full_path) {
                if data.len() >= want {
                    return Ok(data[..want].to_vec());
                }
            }
            let partials = full_path.parent().map(|p| {
                let name = full_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default();
                p.join(format!("{name}.p"))
            });
            if let Some(dir) = partials {
                if let Ok(entries) = std::fs::read_dir(dir) {
                    for entry in entries.flatten() {
                        let wide_enough = entry
                            .file_name()
                            .to_str()
                            .and_then(|n| n.parse::<u32>().ok())
                            .is_some_and(|w| w >= tile.width());
                        if wide_enough {
                            if let Ok(data) = std::fs::read(entry.path()) {
                                if data.len() >= want {
                                    return Ok(data[..want].to_vec());
                                }
                            }
                        }
                    }
                }
            }
        }
        Err(TlogError::InvalidInput(format!(
            "tile {} not found under {}",
            tile.path(),
            self.base.display()
        )))
    }
}

impl TileReader for DirTileReader {
    fn height(&self) -> u8 {
        TILE_HEIGHT
    }

    fn read_tiles(&self, tiles: &[Tile]) -> Result<Vec<Vec<u8>>, TlogError> {
        tiles.iter().map(|t| self.read_one(t)).collect()
    }

    fn save_tiles(&self, _tiles: &[Tile], _data: &[Vec<u8>]) {}
}

/// Verify a record against a signed checkpoint using **only published tile files** —
/// no supplied proof, no stored-hash file, no live service (M2c's acceptance property).
///
/// The inclusion proof is *reconstructed* from the tiles via [`TileHashReader`], which
/// authenticates every tile against the checkpoint's signed root before use — so a
/// tampered or substituted tile is rejected, and trust still reduces to the checkpoint
/// signature alone.
pub fn verify_inclusion_from_tiles(
    record: &[u8],
    index: u64,
    tiles_base: &std::path::Path,
    signed_checkpoint: &str,
    public_hex: &str,
) -> Result<String, String> {
    let vk = vk_from_hex(public_hex)?;
    let body = verify_note(signed_checkpoint, ORIGIN, &vk).map_err(|e| e.to_string())?;
    let (_origin, size, root) = parse_body(&body)?;
    let reader = DirTileReader::new(tiles_base);
    let tile_hashes = TileHashReader::new(size, Hash(root.0), &reader);
    let proof = prove_record(size, index, &tile_hashes).map_err(|e| e.to_string())?;
    let leaf = record_hash(record);
    check_record(&proof, size, Hash(root.0), index, leaf).map_err(|e| e.to_string())?;
    Ok(format!(
        "record {index} included in tree size {size} via tiles alone, root {}",
        hex::encode(root.0)
    ))
}

/// Offline inclusion verification — no ledger directory, no live service. Given a
/// record, its index + inclusion proof, and a signed checkpoint, confirm the record
/// is included under the checkpoint's signed root. The foundation of the M2 proof bundle.
pub fn verify_inclusion(
    record: &[u8],
    index: u64,
    proof: &RecordProof,
    signed_checkpoint: &str,
    public_hex: &str,
) -> Result<String, String> {
    let vk = vk_from_hex(public_hex)?;
    let body = verify_note(signed_checkpoint, ORIGIN, &vk).map_err(|e| e.to_string())?;
    let (_origin, size, root) = parse_body(&body)?;
    let leaf = record_hash(record);
    check_record(proof, size, Hash(root.0), index, Hash(leaf.0)).map_err(|e| e.to_string())?;
    Ok(format!(
        "record {index} included in tree size {size}, root {}",
        hex::encode(root.0)
    ))
}

fn parse_proof(value: &serde_json::Value) -> Vec<Hash> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str())
                .filter_map(|h| hex::decode(h).ok())
                .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .map(Hash)
                .collect()
        })
        .unwrap_or_default()
}

/// Verify a `druid.proofbundle/v1` fully offline (DESIGN §6.4): the artifact bytes hash
/// to the observation's referenced content, the leaf is exactly that observation, and the
/// leaf is included under a validly-signed checkpoint. Trust routes through nothing live.
///
/// Any RFC 3161 `anchors` are verified against `roots_pem` (the TSA roots the caller
/// pins). Aggregation follows the C2SP witness model (ADR-0005): an internally-consistent
/// anchor whose TSA root isn't pinned is reported "present but not verified" and claims
/// no time bound; any other token failure is tamper-evidence and rejects the bundle.
///
/// `witnesses` are pinned C2SP tlog-cosignature keys (name, public key); when `quorum > 0`
/// the bundle's `cosignatures` must include valid cosignatures from at least `quorum`
/// distinct pinned witnesses over this checkpoint, or the bundle is rejected (M8).
pub fn verify_bundle(
    json: &str,
    roots_pem: &[String],
    witnesses: &[(String, ed25519_dalek::VerifyingKey)],
    quorum: usize,
) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if v["schema"] != "druid.proofbundle/v1" {
        return Err("unexpected bundle schema".into());
    }

    // The leaf is the canonical observation bytes; its hash must match what's claimed.
    let record_b64 = v["leaf"]["record_b64"]
        .as_str()
        .ok_or("missing leaf.record_b64")?;
    let leaf_bytes = B64.decode(record_b64).map_err(|e| e.to_string())?;
    let claimed = v["leaf"]["leaf_hash"]
        .as_str()
        .ok_or("missing leaf.leaf_hash")?;
    if hex::encode(record_hash(&leaf_bytes).0) != claimed {
        return Err("leaf_hash does not match the leaf bytes".into());
    }

    // The observation references its content by hash; an artifact must supply those bytes.
    let observation: serde_json::Value =
        serde_json::from_slice(&leaf_bytes).map_err(|e| e.to_string())?;
    let raw_hash = observation["raw_bytes_hash"]
        .as_str()
        .ok_or("observation missing raw_bytes_hash")?;
    let artifacts = v["artifacts"].as_array().ok_or("missing artifacts")?;
    let mut matched_raw = false;
    for artifact in artifacts {
        let hash = artifact["hash"].as_str().ok_or("artifact missing hash")?;
        let bytes = B64
            .decode(
                artifact["bytes_b64"]
                    .as_str()
                    .ok_or("artifact missing bytes_b64")?,
            )
            .map_err(|e| e.to_string())?;
        if multihash_sha256(&bytes) != hash {
            return Err(format!("artifact bytes do not hash to {hash}"));
        }
        if hash == raw_hash {
            matched_raw = true;
        }
    }
    if !matched_raw {
        return Err("no artifact provides the observation's raw_bytes_hash".into());
    }

    // The leaf is included under the signed checkpoint.
    let index = v["leaf"]["index"].as_u64().ok_or("missing leaf.index")?;
    let proof = parse_proof(&v["inclusion_proof"]["proof"]);
    let checkpoint = v["checkpoint"].as_str().ok_or("missing checkpoint")?;
    let pubkey = v["pubkey_hex"].as_str().ok_or("missing pubkey_hex")?;
    verify_inclusion(&leaf_bytes, index, &proof, checkpoint, pubkey)?;

    // External anchors bind the checkpoint to a time. Each token must commit to the hash
    // of the very checkpoint bytes in this bundle.
    let roots: Vec<&str> = roots_pem.iter().map(String::as_str).collect();
    let anchored_hash = Sha256::digest(checkpoint.as_bytes());
    let empty: Vec<serde_json::Value> = Vec::new();
    let anchors = v["anchors"].as_array().unwrap_or(&empty);
    let mut verified = 0usize;
    let mut unverified = 0usize; // present but uncheckable: unpinned TSA root or unsupported type
    let mut earliest: Option<String> = None; // ISO-8601 sorts chronologically
    for anchor in anchors {
        if anchor["type"] != "rfc3161" {
            unverified += 1;
            continue;
        }
        let token = B64
            .decode(anchor["token"].as_str().ok_or("anchor missing token")?)
            .map_err(|e| e.to_string())?;
        if roots.is_empty() {
            unverified += 1;
            continue;
        }
        match verify_rfc3161_token(&token, anchored_hash.as_slice(), &roots) {
            Ok(info) => {
                verified += 1;
                earliest = Some(match earliest {
                    Some(current) if current <= info.gen_time => current,
                    _ => info.gen_time,
                });
            }
            // An internally-consistent token from a TSA we don't pin proves nothing but
            // spoils nothing — the C2SP witness model: report it, ignore it, let the
            // inclusion proof and the other anchors stand. Every other failure means
            // the bundle carries a corrupt or mismatched token and is rejected.
            Err(e) if e == rfc3161::ERR_UNTRUSTED_ROOT => unverified += 1,
            Err(e) => return Err(format!("anchor verification failed: {e}")),
        }
    }
    let mut anchor_note = String::new();
    if verified > 0 {
        // The tightest bound is the earliest genTime across independent anchors.
        anchor_note = format!(
            "; {verified} anchor(s) verified - existed no later than {}",
            earliest.unwrap_or_default()
        );
    }
    if unverified > 0 {
        anchor_note.push_str(&format!(
            "; {unverified} anchor(s) present but not verified (no pinned root for that TSA)"
        ));
    }

    // Witness cosignatures (M8): each is a C2SP cosignature line over the checkpoint's note
    // body. Count distinct pinned witnesses that validly cosigned; require a quorum.
    let sep = checkpoint.find("\n\n").ok_or("malformed checkpoint")?;
    let note_body = &checkpoint[..=sep]; // note text incl. its trailing newline
    let cosigs = v["cosignatures"].as_array().unwrap_or(&empty);
    let mut cosigned: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for cosig in cosigs {
        let line = cosig.as_str().ok_or("cosignature must be a string line")?;
        for (name, wpub) in witnesses {
            if verify_cosign_line(note_body, line, name, wpub).is_ok() {
                cosigned.insert(name.as_str());
                break;
            }
        }
    }
    if cosigned.len() < quorum {
        return Err(format!(
            "witness quorum not met: {} of {quorum} required cosignature(s) from pinned witnesses",
            cosigned.len()
        ));
    }
    let cosig_note = if quorum > 0 {
        format!(
            "; {}/{quorum} witness cosignature(s) verified",
            cosigned.len()
        )
    } else if !cosigned.is_empty() {
        format!("; {} witness cosignature(s) present", cosigned.len())
    } else {
        String::new()
    };

    let url = observation["url"].as_str().unwrap_or("?");
    Ok(format!(
        "bundle OK: {} artifact(s) match; observation of {url} included offline{anchor_note}{cosig_note}",
        artifacts.len()
    ))
}
