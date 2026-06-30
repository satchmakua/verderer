//! `druid-ledger` — the writer the Python pipeline shells out to over stdio.
//!
//!   druid-ledger append      --dir D            (record bytes on stdin) -> JSON
//!   druid-ledger inclusion   --dir D --index N  -> JSON {index, leaf_hash, tree_size, proof, checkpoint}
//!   druid-ledger consistency --dir D --from M --to N -> JSON {from, to, proof}
//!   druid-ledger checkpoint  --dir D            -> the signed checkpoint text
//!   druid-ledger pubkey      --dir D            -> the log public key (hex)

use std::io::Read;

use ledger_core::Ledger;

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
    let cmd = args.first().cloned().unwrap_or_default();
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

    match cmd.as_str() {
        "append" => {
            let mut buf = Vec::new();
            if std::io::stdin().read_to_end(&mut buf).is_err() {
                eprintln!("failed to read record from stdin");
                return 1;
            }
            match ledger.append(&buf) {
                Ok(r) => {
                    let out = serde_json::json!({
                        "index": r.index,
                        "leaf_hash": hex::encode(r.leaf_hash.0),
                        "size": r.size,
                        "checkpoint": r.checkpoint,
                    });
                    println!("{out}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "inclusion" => {
            let Some(n) = opt(&args, "--index").and_then(|s| s.parse::<u64>().ok()) else {
                eprintln!("--index N is required");
                return 2;
            };
            match ledger.inclusion(n) {
                Ok(r) => {
                    let proof: Vec<String> = r.proof.iter().map(|h| hex::encode(h.0)).collect();
                    let out = serde_json::json!({
                        "index": r.index,
                        "leaf_hash": hex::encode(r.leaf_hash.0),
                        "tree_size": r.tree_size,
                        "proof": proof,
                        "checkpoint": r.checkpoint,
                    });
                    println!("{out}");
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "consistency" => {
            let from = opt(&args, "--from")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let to = opt(&args, "--to")
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or_else(|| ledger.size());
            match ledger.consistency(from, to) {
                Ok(proof) => {
                    let proof: Vec<String> = proof.iter().map(|h| hex::encode(h.0)).collect();
                    println!(
                        "{}",
                        serde_json::json!({"from": from, "to": to, "proof": proof})
                    );
                    0
                }
                Err(e) => {
                    eprintln!("{e}");
                    1
                }
            }
        }
        "checkpoint" => match ledger.signed_checkpoint() {
            Ok(text) => {
                print!("{text}");
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        "pubkey" => match ledger.public_key() {
            Ok(vk) => {
                println!("{}", hex::encode(vk.to_bytes()));
                0
            }
            Err(e) => {
                eprintln!("{e}");
                1
            }
        },
        other => {
            eprintln!("unknown command: {other}");
            2
        }
    }
}
