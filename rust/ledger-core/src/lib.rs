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

mod note;

pub use note::{key_id, sign_note, verify_note, NoteError};

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tlog_tiles::{
    check_record, prove_record, prove_tree, record_hash, stored_hash_index, stored_hashes,
    tree_hash, Checkpoint, Error as TlogError, Hash, HashReader, RecordProof, TreeProof,
};

/// The checkpoint origin and note key name. A stable, schema-less identifier.
pub const ORIGIN: &str = "druid.watchdog/m1-log";

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s.trim()).map_err(|e| e.to_string())
}

fn vk_from_hex(h: &str) -> Result<VerifyingKey, String> {
    let bytes = hex::decode(h).map_err(|e| e.to_string())?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "bad public key length")?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string())
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
