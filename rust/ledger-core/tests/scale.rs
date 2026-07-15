//! Scale tests for the trust core (M14): the Merkle log's invariants must hold — and hold
//! cheaply — at a realistic operating size. A watchdog that runs for years accumulates a
//! large log; inclusion and consistency proofs must stay O(log n) and every leaf must remain
//! verifiable against the signed checkpoint.
//!
//! `scale_log_invariants_hold` runs in the normal suite at a modest size (regression guard).
//! `scale_100k_leaf_log` is `#[ignore]`d (run with `cargo test -- --ignored`) — it proves the
//! ROADMAP's 100k-leaf invariants without slowing every build. The scale signal is *structural*
//! (proofs verify + stay O(log n)), never wall-clock — a suspended/loaded box must not flake it.

use std::time::Instant;

use ledger_core::{verify_consistency, verify_inclusion, Ledger};
use tlog_tiles::{check_tree, Hash};

fn build_log(n: u64) -> (tempfile::TempDir, Ledger) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path()).unwrap();
    for i in 0..n {
        ledger.append(format!("leaf-{i}").as_bytes()).unwrap();
    }
    (dir, ledger)
}

/// Inclusion + consistency proofs hold across the whole range, and stay O(log n). Each
/// inclusion proof is verified against the *signed checkpoint*, so this confirms the leaves
/// are committed under the signed root without an O(n) full re-read (`verify_log`, which
/// re-reads every stored hash, is exercised at a modest size in `scale_log_invariants_hold`).
fn assert_invariants_at_scale(ledger: &Ledger, n: u64) {
    let pubkey = hex::encode(ledger.public_key().unwrap().to_bytes());
    assert_eq!(ledger.size(), n);

    // Spot-check inclusion proofs across the range (first, last, and a spread between).
    for &idx in &[0, 1, n / 3, n / 2, (2 * n) / 3, n - 2, n - 1] {
        let incl = ledger.inclusion(idx).unwrap();
        let record = format!("leaf-{idx}");
        let out = verify_inclusion(
            record.as_bytes(),
            idx,
            &incl.proof,
            &incl.checkpoint,
            &pubkey,
        )
        .unwrap_or_else(|e| panic!("leaf {idx} should verify: {e}"));
        assert!(out.contains(&format!("tree size {n}")), "{out}");
        // A wrong record at the same index must not verify.
        assert!(verify_inclusion(b"forged", idx, &incl.proof, &incl.checkpoint, &pubkey).is_err());
    }

    // A consistency proof between an interior prefix and the full tree holds; the proof is
    // O(log n) — bound its length so a regression to a linear proof is caught.
    let old = n / 2;
    let old_root = ledger.root(old).unwrap();
    let new_root = ledger.root(n).unwrap();
    let proof = ledger.consistency(old, n).unwrap();
    check_tree(&proof, n, Hash(new_root.0), old, Hash(old_root.0))
        .expect("consistency must hold at scale");
    assert!(
        proof.len() <= 2 * (64 - n.leading_zeros() as usize) + 4,
        "consistency proof of {} hashes is not O(log n) for n={n}",
        proof.len()
    );
}

#[test]
fn scale_log_invariants_hold() {
    let n = 2_000u64;
    let (_dir, ledger) = build_log(n);
    // At a modest size, exercise the O(n) full re-verification too...
    ledger
        .verify_log()
        .expect("the whole log must verify against its signed checkpoint");
    // ...and the O(log n) proof invariants that must also hold at 100k.
    assert_invariants_at_scale(&ledger, n);
}

#[test]
#[ignore = "expensive: run with `cargo test -- --ignored` for the 100k-leaf scale proof"]
fn scale_100k_leaf_log() {
    let n = 100_000u64;
    let start = Instant::now();
    let (_dir, ledger) = build_log(n);
    let append_secs = start.elapsed().as_secs_f64();

    let verify_start = Instant::now();
    // The scale property is *structural*, not wall-clock: at 100k leaves every proof still
    // verifies against the signed checkpoint and stays O(log n) (bounded + asserted inside).
    // Timings are printed for information only — never asserted, since a test box can sleep /
    // be suspended / be under load, which would count into elapsed time and flake the test.
    assert_invariants_at_scale(&ledger, n);
    let verify_secs = verify_start.elapsed().as_secs_f64();
    println!("100k-leaf log: appended in {append_secs:.1}s, verified + proof-checked in {verify_secs:.1}s");

    // Gossip across the whole life of the log: the final checkpoint extends an early one.
    let early_cp = {
        let d = tempfile::tempdir().unwrap();
        std::fs::copy(_dir.path().join("key.json"), d.path().join("key.json")).unwrap();
        let l = Ledger::open(d.path()).unwrap();
        for i in 0..10u64 {
            l.append(format!("leaf-{i}").as_bytes()).unwrap();
        }
        l.signed_checkpoint().unwrap()
    };
    let new_cp = ledger.signed_checkpoint().unwrap();
    let proof = ledger.consistency(10, n).unwrap();
    let pubkey = hex::encode(ledger.public_key().unwrap().to_bytes());
    let msg =
        verify_consistency(&early_cp, &new_cp, &proof, &pubkey).expect("gossip must hold at scale");
    assert!(msg.contains("extends size 10"), "{msg}");
}
