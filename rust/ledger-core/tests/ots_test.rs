//! Offline OpenTimestamps verifier tests against a **real, Bitcoin-confirmed** fixture (M13b).
//!
//! `tests/fixtures/ots/` holds the exact bytes of Verderer's live size-15 checkpoint, a real
//! `.ots` proof stamped over it and upgraded once the calendars' aggregation tx confirmed on
//! Bitcoin (blocks 959058 & 959061), and those two blocks' 80-byte headers. No network, no
//! synthetic anchor — the proof is genuine, so a passing test means the offline verifier
//! agrees with the Bitcoin blockchain.

use std::collections::BTreeMap;

use ledger_core::{verify_ots, ERR_OTS_NO_HEADER};
use sha2::{Digest, Sha256};

const CHECKPOINT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/ots/checkpoint-15"
));
const OTS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/ots/checkpoint-15.ots"
));
const HEADERS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/ots/bitcoin-headers.json"
));

// The earliest confirmed block the checkpoint is committed into (its nTime is the bound).
const EARLIEST_HEIGHT: u32 = 959_058;
const EARLIEST_NTIME: u32 = 1_784_668_176;
const EARLIEST_HASH: &str = "00000000000000000000e54f9fb3a4221154f8571dfc31cf5c3a98cf262db90e";

fn digest() -> [u8; 32] {
    Sha256::digest(CHECKPOINT).into()
}

fn headers() -> BTreeMap<u32, [u8; 80]> {
    let v: serde_json::Value = serde_json::from_str(HEADERS_JSON).unwrap();
    let mut out = BTreeMap::new();
    for (height, hex_val) in v.as_object().unwrap() {
        let bytes = hex::decode(hex_val.as_str().unwrap()).unwrap();
        out.insert(
            height.parse().unwrap(),
            <[u8; 80]>::try_from(bytes.as_slice()).unwrap(),
        );
    }
    out
}

#[test]
fn real_proof_yields_the_bitcoin_time_bound() {
    let bound = verify_ots(&digest(), OTS, &headers()).expect("real confirmed proof must verify");
    // The tightest bound is the earliest carried block.
    assert_eq!(bound.height, EARLIEST_HEIGHT);
    assert_eq!(bound.unix_time, EARLIEST_NTIME);
    assert_eq!(bound.block_hash_hex, EARLIEST_HASH);
}

#[test]
fn tightest_bound_holds_when_only_the_later_block_is_carried() {
    // Drop the earliest header; the proof still verifies against the remaining block.
    let mut h = headers();
    h.remove(&EARLIEST_HEIGHT);
    let bound = verify_ots(&digest(), OTS, &h).expect("later block alone still bounds time");
    assert_eq!(bound.height, 959_061);
    assert!(bound.unix_time > EARLIEST_NTIME);
}

#[test]
fn wrong_checkpoint_is_rejected() {
    let mut other = CHECKPOINT.to_vec();
    other.push(b' '); // any different bytes -> different digest
    let err = verify_ots(&Sha256::digest(&other), OTS, &headers()).unwrap_err();
    assert!(err.contains("does not commit"), "got: {err}");
    assert_ne!(err, ERR_OTS_NO_HEADER);
}

#[test]
fn tampering_the_winning_path_is_rejected() {
    // Flip a byte inside the first op-argument, which is on the shared prefix of every path.
    let needle = hex::decode("9e7360100716d07628e9ac17c27cfb22").unwrap();
    let at = OTS
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("shared arg present");
    let mut forged = OTS.to_vec();
    forged[at + 4] ^= 0x01;
    let err = verify_ots(&digest(), &forged, &headers()).unwrap_err();
    assert!(err.contains("merkle root does not match"), "got: {err}");
}

#[test]
fn tampering_a_block_header_merkle_root_is_rejected() {
    let mut h = headers();
    h.get_mut(&EARLIEST_HEIGHT).unwrap()[40] ^= 0x01; // a merkle-root byte (header[36..68])
    let err = verify_ots(&digest(), OTS, &h).unwrap_err();
    assert!(err.contains("merkle root does not match"), "got: {err}");
}

#[test]
fn a_header_with_broken_proof_of_work_is_rejected() {
    // Keep the merkle root intact but corrupt the nonce, so only the PoW gate can catch it.
    let mut h = headers();
    h.get_mut(&EARLIEST_HEIGHT).unwrap()[78] ^= 0xff; // nonce is header[76..80]
    let err = verify_ots(&digest(), OTS, &h).unwrap_err();
    assert!(err.contains("proof-of-work"), "got: {err}");
}

#[test]
fn confirmed_proof_without_a_carried_header_is_unverified_not_tamper() {
    // Real proof, but we carry no block header: nothing to bound offline. Non-fatal.
    let err = verify_ots(&digest(), OTS, &BTreeMap::new()).unwrap_err();
    assert_eq!(err, ERR_OTS_NO_HEADER);
}

#[test]
fn garbage_is_rejected_without_panicking() {
    assert!(verify_ots(&digest(), b"not an ots proof", &headers()).is_err());
    assert!(verify_ots(&digest(), &[], &headers()).is_err());
    // A valid header but truncated proof body.
    assert!(verify_ots(&digest(), &OTS[..50], &headers()).is_err());
}
