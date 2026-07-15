//! Integration tests for the trust core: the Merkle log, signed checkpoints,
//! inclusion + consistency proofs, offline verification, and tamper detection.

use base64::Engine;
use ledger_core::{verify_consistency, verify_inclusion, Ledger};
use tlog_tiles::{check_tree, Hash};

fn temp_ledger() -> (tempfile::TempDir, Ledger) {
    let dir = tempfile::tempdir().unwrap();
    let ledger = Ledger::open(dir.path()).unwrap();
    (dir, ledger)
}

#[test]
fn append_grows_the_tree_and_verifies() {
    let (_dir, ledger) = temp_ledger();
    for i in 0..5u8 {
        ledger.append(format!("record-{i}").as_bytes()).unwrap();
    }
    assert_eq!(ledger.size(), 5);
    let msg = ledger.verify_log().expect("log should verify");
    assert!(msg.starts_with("5 entries"), "{msg}");
}

#[test]
fn inclusion_proof_verifies_offline() {
    let (_dir, ledger) = temp_ledger();
    for i in 0..6u8 {
        ledger.append(format!("entry {i}").as_bytes()).unwrap();
    }
    let incl = ledger.inclusion(3).unwrap();
    let pubkey = hex::encode(ledger.public_key().unwrap().to_bytes());
    // The verifier needs only the record bytes, the proof, the signed checkpoint, and the key.
    let out = verify_inclusion(b"entry 3", 3, &incl.proof, &incl.checkpoint, &pubkey).unwrap();
    assert!(out.contains("included in tree size 6"), "{out}");

    // A wrong record at the same index must not verify.
    assert!(verify_inclusion(b"entry X", 3, &incl.proof, &incl.checkpoint, &pubkey).is_err());
}

#[test]
fn consistency_proof_holds_between_two_sizes() {
    let (_dir, ledger) = temp_ledger();
    for i in 0..7u8 {
        ledger.append(format!("r{i}").as_bytes()).unwrap();
    }
    // Prefix roots are stable under append, so we can read both from the final tree.
    let old_root = ledger.root(4).unwrap();
    let new_root = ledger.root(7).unwrap();
    let proof = ledger.consistency(4, 7).unwrap();
    check_tree(&proof, 7, Hash(new_root.0), 4, Hash(old_root.0)).expect("consistency must hold");
}

// --- M13: gossip — verify one signed checkpoint extends another, offline ---

#[test]
fn verify_consistency_confirms_an_extension_offline() {
    let (_dir, ledger) = temp_ledger();
    for i in 0..4u8 {
        ledger.append(format!("r{i}").as_bytes()).unwrap();
    }
    let old_cp = ledger.signed_checkpoint().unwrap(); // a client saw this earlier (size 4)
    for i in 4..7u8 {
        ledger.append(format!("r{i}").as_bytes()).unwrap();
    }
    let new_cp = ledger.signed_checkpoint().unwrap(); // the current checkpoint (size 7)
    let proof = ledger.consistency(4, 7).unwrap();
    let pubkey = hex::encode(ledger.public_key().unwrap().to_bytes());

    let msg = verify_consistency(&old_cp, &new_cp, &proof, &pubkey).expect("should be consistent");
    assert!(msg.contains("extends size 4"), "{msg}");

    // A shorter tree claiming to be extended by a longer one it doesn't match: the log shrank.
    let shrunk = verify_consistency(&new_cp, &old_cp, &proof, &pubkey);
    assert!(shrunk.is_err() && shrunk.unwrap_err().contains("shrank"));

    // A forged proof (one that bridges a different prefix) can't connect these two roots.
    let wrong_proof = ledger.consistency(2, 7).unwrap();
    assert!(verify_consistency(&old_cp, &new_cp, &wrong_proof, &pubkey).is_err());
}

#[test]
fn verify_consistency_catches_an_equivocating_operator() {
    // Two checkpoints of the SAME size with DIFFERENT roots, signed by the same key — a
    // split-view / equivocating log. Gossip must catch it (this is the M8-complement).
    let dir_a = tempfile::tempdir().unwrap();
    let a = Ledger::open(dir_a.path()).unwrap();
    for i in 0..4u8 {
        a.append(format!("a{i}").as_bytes()).unwrap();
    }
    let cp_a = a.signed_checkpoint().unwrap();

    // A second log with the SAME signing key but different entries -> same size, different root.
    let dir_b = tempfile::tempdir().unwrap();
    std::fs::copy(dir_a.path().join("key.json"), dir_b.path().join("key.json")).unwrap();
    let b = Ledger::open(dir_b.path()).unwrap();
    for i in 0..4u8 {
        b.append(format!("b{i}").as_bytes()).unwrap();
    }
    let cp_b = b.signed_checkpoint().unwrap();

    let pubkey = hex::encode(a.public_key().unwrap().to_bytes());
    let no_proof: Vec<Hash> = Vec::new(); // same-size equivocation is decided without a proof
    let result = verify_consistency(&cp_a, &cp_b, &no_proof, &pubkey);
    assert!(
        result.is_err() && result.unwrap_err().contains("equivocated"),
        "same-size different-root checkpoints must be caught as equivocation"
    );
}

#[test]
fn tampering_an_entry_breaks_verification() {
    let (dir, ledger) = temp_ledger();
    for i in 0..4u8 {
        ledger.append(format!("payload {i}").as_bytes()).unwrap();
    }
    assert!(ledger.verify_log().is_ok());

    // Corrupt one stored leaf line; the recomputed root no longer matches the signature.
    let entries = dir.path().join("entries.b64");
    let text = std::fs::read_to_string(&entries).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    lines[1] = base64::engine::general_purpose::STANDARD.encode(b"payload TAMPERED");
    std::fs::write(&entries, lines.join("\n") + "\n").unwrap();

    assert!(
        ledger.verify_log().is_err(),
        "tampered entry must fail verification"
    );
}
