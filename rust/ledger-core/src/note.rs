//! C2SP signed notes (https://c2sp.org/signed-note) over Ed25519.
//!
//! A signed note is `text` (ending in a newline) + a blank line + one or more
//! signature lines `"\u{2014} " + name + " " + base64(keyID || signature)`. The
//! Ed25519 signature is computed over the note text including its final newline but
//! not the separating blank line. The 4-byte key ID is
//! `SHA-256(name || 0x0A || 0x01 || pubkey)[:4]`.

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, PartialEq, Eq)]
pub enum NoteError {
    Malformed,
    NoSignature,
    BadSignature,
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NoteError::Malformed => write!(f, "malformed signed note"),
            NoteError::NoSignature => write!(f, "no signature for the expected key"),
            NoteError::BadSignature => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for NoteError {}

/// The 4-byte Ed25519 key ID for a note key.
pub fn key_id(name: &str, public: &VerifyingKey) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0x0A, 0x01]); // newline, then the Ed25519 algorithm byte
    hasher.update(public.to_bytes());
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Produce a signed note: `text` + blank line + one Ed25519 signature line.
/// `text` must end in a newline (a checkpoint body does).
pub fn sign_note(text: &str, name: &str, key: &SigningKey) -> String {
    let signature = key.sign(text.as_bytes());
    let id = key_id(name, &key.verifying_key());
    let mut blob = Vec::with_capacity(4 + 64);
    blob.extend_from_slice(&id);
    blob.extend_from_slice(&signature.to_bytes());
    format!("{text}\n\u{2014} {name} {}\n", B64.encode(&blob))
}

/// Verify a signed note against the expected key name and public key. On success
/// returns the note text (including its final newline) — the bytes that were signed.
pub fn verify_note(note: &str, name: &str, public: &VerifyingKey) -> Result<String, NoteError> {
    let sep = note.find("\n\n").ok_or(NoteError::Malformed)?;
    let text = &note[..=sep]; // text including its trailing newline
    let sigs = &note[sep + 2..]; // signature lines, after the blank line
    let want_id = key_id(name, public);
    let prefix = format!("\u{2014} {name} ");
    for line in sigs.lines() {
        let Some(rest) = line.strip_prefix(&prefix) else {
            continue;
        };
        let blob = B64.decode(rest.trim()).map_err(|_| NoteError::Malformed)?;
        if blob.len() != 68 || blob[..4] != want_id {
            continue; // a signature, but not by the key we were asked to verify
        }
        // A signature by the expected key: from here, a failure is a bad signature.
        let sig_bytes: [u8; 64] = blob[4..].try_into().map_err(|_| NoteError::Malformed)?;
        let signature = Signature::from_bytes(&sig_bytes);
        return public
            .verify(text.as_bytes(), &signature)
            .map(|()| text.to_string())
            .map_err(|_| NoteError::BadSignature);
    }
    Err(NoteError::NoSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let text = "verderer.watchdog/m1-log\n3\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n";
        let note = sign_note(text, "verderer.watchdog/m1-log", &key());
        let got = verify_note(&note, "verderer.watchdog/m1-log", &key().verifying_key()).unwrap();
        assert_eq!(got, text);
    }

    #[test]
    fn wrong_key_fails() {
        let text = "origin\n1\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n";
        let note = sign_note(text, "origin", &key());
        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(
            verify_note(&note, "origin", &other),
            Err(NoteError::NoSignature)
        );
    }

    #[test]
    fn tampered_text_fails() {
        let text = "origin\n1\nTszzRgjTG6xce+z2AG31kAXYKBgQVtCSCE40HmuwBb0=\n";
        let note = sign_note(text, "origin", &key());
        let tampered = note.replacen("origin\n1", "origin\n2", 1);
        assert_eq!(
            verify_note(&tampered, "origin", &key().verifying_key()),
            Err(NoteError::BadSignature)
        );
    }
}
