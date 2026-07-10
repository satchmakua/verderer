//! M2c — tile serving. The acceptance property: a verifier reconstructs an inclusion
//! proof **from published tile files alone** (no stored-hash file, no supplied proof),
//! with every tile authenticated against the signed checkpoint root before use.

use ledger_core::{verify_inclusion_from_tiles, Ledger, TILE_HEIGHT};

fn build_log(dir: &std::path::Path, n: usize) -> (Ledger, Vec<Vec<u8>>, String, String) {
    let ledger = Ledger::open(dir).expect("open ledger");
    let mut records = Vec::new();
    let mut checkpoint = String::new();
    for i in 0..n {
        let record = format!("{{\"record\":{i}}}").into_bytes();
        checkpoint = ledger.append(&record).expect("append").checkpoint;
        records.push(record);
    }
    let pubkey = hex::encode(ledger.public_key().expect("pubkey").to_bytes());
    (ledger, records, checkpoint, pubkey)
}

#[test]
fn append_publishes_tiles_and_proof_reconstructs_from_tiles_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ledger, records, checkpoint, pubkey) = build_log(tmp.path(), 5);

    // The level-0 partial for a 5-leaf tree is published at the C2SP path.
    let tile = tmp
        .path()
        .join("tile")
        .join(format!("{TILE_HEIGHT}"))
        .join("0")
        .join("000.p")
        .join("5");
    assert!(tile.exists(), "expected tile file at {}", tile.display());

    // The canonical backing store is *removed*: tiles + checkpoint must suffice.
    std::fs::remove_file(tmp.path().join("hashes")).unwrap();
    std::fs::remove_file(tmp.path().join("entries.b64")).unwrap();

    for (i, record) in records.iter().enumerate() {
        let msg = verify_inclusion_from_tiles(record, i as u64, tmp.path(), &checkpoint, &pubkey)
            .expect("verify from tiles alone");
        assert!(msg.contains("via tiles alone"), "got: {msg}");
    }
}

#[test]
fn multi_tile_log_verifies_and_full_tiles_obsolete_partials() {
    let tmp = tempfile::tempdir().unwrap();
    // 600 leaves: two full level-0 tiles + a partial, and a level-1 partial.
    let (_ledger, records, checkpoint, pubkey) = build_log(tmp.path(), 600);

    let level0 = tmp
        .path()
        .join("tile")
        .join(format!("{TILE_HEIGHT}"))
        .join("0");
    assert!(level0.join("000").exists(), "full tile 000");
    assert!(level0.join("001").exists(), "full tile 001");
    assert!(
        level0.join("002.p").join("88").exists(),
        "partial tile 002.p/88"
    );
    assert!(
        !level0.join("000.p").exists(),
        "full tile obsoletes its partials"
    );
    let level1 = tmp
        .path()
        .join("tile")
        .join(format!("{TILE_HEIGHT}"))
        .join("1");
    assert!(level1.join("000.p").join("2").exists(), "level-1 partial");

    std::fs::remove_file(tmp.path().join("hashes")).unwrap();
    for i in [0usize, 255, 256, 300, 599] {
        verify_inclusion_from_tiles(&records[i], i as u64, tmp.path(), &checkpoint, &pubkey)
            .unwrap_or_else(|e| panic!("record {i} must verify from tiles: {e}"));
    }
}

#[test]
fn tampered_tile_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ledger, records, checkpoint, pubkey) = build_log(tmp.path(), 5);

    let tile = tmp
        .path()
        .join("tile")
        .join(format!("{TILE_HEIGHT}"))
        .join("0")
        .join("000.p")
        .join("5");
    let mut data = std::fs::read(&tile).unwrap();
    data[7] ^= 0x01;
    std::fs::write(&tile, &data).unwrap();

    let err = verify_inclusion_from_tiles(&records[0], 0, tmp.path(), &checkpoint, &pubkey)
        .expect_err("a tampered tile must be rejected");
    assert!(!err.is_empty());
}

#[test]
fn wrong_record_is_rejected_via_tiles() {
    let tmp = tempfile::tempdir().unwrap();
    let (_ledger, _records, checkpoint, pubkey) = build_log(tmp.path(), 5);
    let err = verify_inclusion_from_tiles(b"not the record", 0, tmp.path(), &checkpoint, &pubkey)
        .expect_err("a record not in the tree must be rejected");
    assert!(!err.is_empty());
}

#[test]
fn regenerate_tiles_for_a_pre_tile_ledger() {
    let tmp = tempfile::tempdir().unwrap();
    let (ledger, records, checkpoint, pubkey) = build_log(tmp.path(), 5);

    // Simulate a pre-M2c ledger: tiles never published.
    std::fs::remove_dir_all(tmp.path().join("tile")).unwrap();
    assert!(verify_inclusion_from_tiles(&records[0], 0, tmp.path(), &checkpoint, &pubkey).is_err());

    let count = ledger.write_tiles(0, ledger.size()).expect("regenerate");
    assert!(count >= 1);
    verify_inclusion_from_tiles(&records[0], 0, tmp.path(), &checkpoint, &pubkey)
        .expect("verifies after regeneration");
}
