//! Offline RFC 3161 verifier tests against committed fixtures (no network at test time).
//! Fixtures live at repo `tests/fixtures/rfc3161/`: a self-issued TSA we pin (+ an
//! "untrusted" one whose token must be rejected), and **real** tokens from the
//! independent DigiCert and FreeTSA TSAs — the real-world proof the verifier handles
//! production chains (multi-cert, RSA-4096, cross-signed roots).

use ledger_core::verify_rfc3161_token;
use sha2::{Digest, Sha256};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/rfc3161/");

macro_rules! bytes {
    ($name:expr) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/fixtures/rfc3161/",
            $name
        ))
    };
}

const CHECKPOINT: &[u8] = bytes!("checkpoint.bin");
const TOKEN_VALID: &[u8] = bytes!("token_valid.der");
const TOKEN_UNTRUSTED: &[u8] = bytes!("token_untrusted.der");
const ROOT_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/rfc3161/tsa_root.crt"
));

const CHECKPOINT_REAL: &[u8] = bytes!("checkpoint_real.bin");
const TOKEN_DIGICERT: &[u8] = bytes!("token_digicert.der");
const TOKEN_FREETSA: &[u8] = bytes!("token_freetsa.der");
const DIGICERT_ROOT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/rfc3161/digicert_g4_root.crt"
));
const FREETSA_ROOT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/rfc3161/freetsa_root.crt"
));

fn anchored_hash() -> [u8; 32] {
    Sha256::digest(CHECKPOINT).into()
}

fn real_hash() -> [u8; 32] {
    Sha256::digest(CHECKPOINT_REAL).into()
}

#[test]
fn real_digicert_token_verifies_against_pinned_root() {
    let info = verify_rfc3161_token(TOKEN_DIGICERT, &real_hash(), &[DIGICERT_ROOT])
        .expect("real DigiCert token must verify against the pinned DigiCert root");
    assert!(
        info.gen_time.starts_with("2026-"),
        "genTime = {}",
        info.gen_time
    );
    assert!(info.tsa.contains("DigiCert"), "tsa = {}", info.tsa);
}

#[test]
fn real_freetsa_token_verifies_against_pinned_root() {
    let info = verify_rfc3161_token(TOKEN_FREETSA, &real_hash(), &[FREETSA_ROOT])
        .expect("real FreeTSA token must verify against the pinned FreeTSA root");
    assert!(
        info.tsa.to_lowercase().contains("freetsa"),
        "tsa = {}",
        info.tsa
    );
}

#[test]
fn real_token_rejected_under_the_other_operators_root() {
    // Independence: a DigiCert token must not chain to FreeTSA's root, and vice versa.
    assert!(verify_rfc3161_token(TOKEN_DIGICERT, &real_hash(), &[FREETSA_ROOT]).is_err());
    assert!(verify_rfc3161_token(TOKEN_FREETSA, &real_hash(), &[DIGICERT_ROOT]).is_err());
}

#[test]
fn real_token_binds_its_hash() {
    let mut h = real_hash();
    h[5] ^= 0xff;
    assert!(verify_rfc3161_token(TOKEN_DIGICERT, &h, &[DIGICERT_ROOT]).is_err());
}

#[test]
fn valid_token_verifies_and_reports_gentime() {
    let _ = FIX;
    let info = verify_rfc3161_token(TOKEN_VALID, &anchored_hash(), &[ROOT_PEM])
        .expect("valid token must verify");
    assert!(
        info.gen_time.starts_with("2026-"),
        "genTime = {}",
        info.gen_time
    );
    assert!(!info.tsa.is_empty());
}

#[test]
fn wrong_anchored_hash_is_rejected() {
    let mut h = anchored_hash();
    h[0] ^= 0xff;
    let err = verify_rfc3161_token(TOKEN_VALID, &h, &[ROOT_PEM]).unwrap_err();
    assert!(err.contains("messageImprint"), "got: {err}");
}

#[test]
fn tampered_token_is_rejected() {
    let mut t = TOKEN_VALID.to_vec();
    let mid = t.len() / 2;
    t[mid] ^= 0x01; // a single-byte flip somewhere in the token body
    assert!(verify_rfc3161_token(&t, &anchored_hash(), &[ROOT_PEM]).is_err());
}

#[test]
fn untrusted_tsa_root_is_rejected() {
    let err = verify_rfc3161_token(TOKEN_UNTRUSTED, &anchored_hash(), &[ROOT_PEM]).unwrap_err();
    assert!(err.contains("chain"), "got: {err}");
}
