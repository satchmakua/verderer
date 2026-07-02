//! `druid-verify` — the independent verifier.
//!
//!   druid-verify log       --dir D   recompute the whole log vs. its signed checkpoint
//!   druid-verify inclusion           (JSON bundle on stdin) verify a record offline
//!
//! The `inclusion` mode takes no directory and contacts no service: it is the offline,
//! transferable check at the heart of Druid's value (DESIGN §6.4). stdin JSON:
//!   {"record_b64": "...", "index": N, "proof": ["<hex>", ...],
//!    "checkpoint": "<signed note>", "pubkey_hex": "<hex>"}

use std::io::Read;

use base64::Engine;
use ledger_core::{verify_bundle, verify_inclusion, Ledger};
use tlog_tiles::Hash;

fn opt(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("log") => {
            let Some(dir) = opt(&args, "--dir") else {
                eprintln!("--dir is required");
                return 2;
            };
            let ledger = match Ledger::open(&dir) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            };
            match ledger.verify_log() {
                Ok(msg) => {
                    println!("VALID {msg}");
                    0
                }
                Err(e) => {
                    println!("INVALID {e}");
                    1
                }
            }
        }
        Some("inclusion") => {
            let mut s = String::new();
            if std::io::stdin().read_to_string(&mut s).is_err() {
                eprintln!("failed to read JSON from stdin");
                return 1;
            }
            let value: serde_json::Value = match serde_json::from_str(&s) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            };
            let b64 = base64::engine::general_purpose::STANDARD;
            let record = match b64.decode(value["record_b64"].as_str().unwrap_or("")) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            };
            let index = value["index"].as_u64().unwrap_or(u64::MAX);
            let proof: Vec<Hash> = value["proof"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .filter_map(|h| hex::decode(h).ok())
                        .filter_map(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                        .map(Hash)
                        .collect()
                })
                .unwrap_or_default();
            let checkpoint = value["checkpoint"].as_str().unwrap_or("");
            let pubkey = value["pubkey_hex"].as_str().unwrap_or("");
            match verify_inclusion(&record, index, &proof, checkpoint, pubkey) {
                Ok(msg) => {
                    println!("VALID {msg}");
                    0
                }
                Err(e) => {
                    println!("INVALID {e}");
                    1
                }
            }
        }
        Some("bundle") => {
            // druid-verify bundle <file.json> [--root <tsa_root.pem>]...
            // Verify a downloaded proof bundle offline; pinned TSA roots verify any anchors.
            let Some(path) = args.get(1).filter(|a| !a.starts_with("--")) else {
                eprintln!("usage: druid-verify bundle <file.json> [--root <tsa_root.pem>]...");
                return 2;
            };
            // Ship the independent third-party TSA roots we trust by default (M2b-2);
            // --root adds more (e.g. a self-hosted dev TSA).
            let mut roots: Vec<String> = vec![
                include_str!("../../roots/digicert_g4.crt").to_string(),
                include_str!("../../roots/freetsa.crt").to_string(),
            ];
            let mut i = 2;
            while i < args.len() {
                if args[i] == "--root" {
                    match args.get(i + 1).map(std::fs::read_to_string) {
                        Some(Ok(pem)) => roots.push(pem),
                        _ => {
                            eprintln!("--root needs a readable PEM file");
                            return 2;
                        }
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            let json = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return 1;
                }
            };
            match verify_bundle(&json, &roots) {
                Ok(msg) => {
                    println!("VALID {msg}");
                    0
                }
                Err(e) => {
                    println!("INVALID {e}");
                    1
                }
            }
        }
        _ => {
            eprintln!(
                "usage: druid-verify log --dir D | druid-verify inclusion (JSON on stdin) | druid-verify bundle <file.json>"
            );
            2
        }
    }
}
