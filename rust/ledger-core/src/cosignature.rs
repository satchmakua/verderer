//! C2SP tlog-cosignature (https://c2sp.org/tlog-cosignature) over Ed25519 — M8.
//!
//! An independent **witness** observes a log's checkpoint and co-signs it, so a verifier
//! can require a *quorum* of witness cosignatures and stop trusting the log operator alone
//! (defends against a split-view / equivocating log). A cosignature is a signed-note
//! signature line whose payload is `keyID(4) || timestamp(8, big-endian) || Ed25519 sig
//! (64)` — 76 bytes — over the message:
//!
//! ```text
//! cosignature/v1
//! time <unix-seconds>
//! <checkpoint note body>
//! ```
//!
//! The witness key ID uses algorithm byte **0x04** (Ed25519 cosignature), distinct from
//! the log's 0x01: `SHA-256(name || 0x0A || 0x04 || pubkey)[:4]`. No bespoke crypto — this
//! is the published C2SP spec on the same `ed25519-dalek` primitive as `note.rs`.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

const COSIG_ALG: u8 = 0x04;

/// The 4-byte key ID for an Ed25519 cosignature (witness) key.
pub fn cosig_key_id(name: &str, public: &VerifyingKey) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0x0A, COSIG_ALG]);
    hasher.update(public.to_bytes());
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// The exact bytes a witness signs for `note_body` (the checkpoint text, ending in `\n`).
fn cosig_message(note_body: &str, timestamp: u64) -> Vec<u8> {
    format!("cosignature/v1\ntime {timestamp}\n{note_body}").into_bytes()
}

/// Produce a cosignature signature line for a checkpoint body: `— name base64(keyID ||
/// timestamp || signature)`. `note_body` must be the checkpoint text (ending in `\n`).
pub fn cosign_line(note_body: &str, name: &str, key: &SigningKey, timestamp: u64) -> String {
    let signature = key.sign(&cosig_message(note_body, timestamp));
    let mut blob = Vec::with_capacity(4 + 8 + 64);
    blob.extend_from_slice(&cosig_key_id(name, &key.verifying_key()));
    blob.extend_from_slice(&timestamp.to_be_bytes());
    blob.extend_from_slice(&signature.to_bytes());
    format!("\u{2014} {name} {}", B64.encode(&blob))
}

/// Verify one cosignature line against `note_body` and a pinned witness key. On success
/// returns the cosignature's timestamp (Unix seconds).
pub fn verify_cosign_line(
    note_body: &str,
    line: &str,
    name: &str,
    public: &VerifyingKey,
) -> Result<u64, String> {
    let prefix = format!("\u{2014} {name} ");
    let rest = line
        .strip_prefix(&prefix)
        .ok_or("cosignature line name does not match")?;
    let blob = B64.decode(rest.trim()).map_err(|e| e.to_string())?;
    if blob.len() != 76 {
        return Err(format!(
            "cosignature blob is {} bytes, expected 76",
            blob.len()
        ));
    }
    if blob[..4] != cosig_key_id(name, public) {
        return Err("cosignature key ID does not match the pinned witness key".into());
    }
    let timestamp = u64::from_be_bytes(blob[4..12].try_into().map_err(|_| "bad timestamp")?);
    let sig_bytes: [u8; 64] = blob[12..76]
        .try_into()
        .map_err(|_| "bad signature length")?;
    let signature = Signature::from_bytes(&sig_bytes);
    public
        .verify(&cosig_message(note_body, timestamp), &signature)
        .map_err(|_| "cosignature signature verification failed".to_string())?;
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wkey(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    const BODY: &str = "annals.watchdog/m1-log\n4\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n";

    #[test]
    fn cosign_then_verify_roundtrips() {
        let k = wkey(11);
        let line = cosign_line(BODY, "witness.a", &k, 1_700_000_000);
        let ts = verify_cosign_line(BODY, &line, "witness.a", &k.verifying_key()).unwrap();
        assert_eq!(ts, 1_700_000_000);
    }

    #[test]
    fn wrong_witness_key_is_rejected() {
        let line = cosign_line(BODY, "witness.a", &wkey(11), 1_700_000_000);
        let other = wkey(99).verifying_key();
        assert!(verify_cosign_line(BODY, &line, "witness.a", &other).is_err());
    }

    #[test]
    fn tampered_body_is_rejected() {
        let k = wkey(11);
        let line = cosign_line(BODY, "witness.a", &k, 1_700_000_000);
        let other_body = "annals.watchdog/m1-log\n5\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n";
        assert!(verify_cosign_line(other_body, &line, "witness.a", &k.verifying_key()).is_err());
    }

    #[test]
    fn wrong_name_is_rejected() {
        let k = wkey(11);
        let line = cosign_line(BODY, "witness.a", &k, 1_700_000_000);
        assert!(verify_cosign_line(BODY, &line, "witness.b", &k.verifying_key()).is_err());
    }
}
