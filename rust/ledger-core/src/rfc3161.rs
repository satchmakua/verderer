//! Offline verification of RFC 3161 timestamp tokens (Verderer M2b anchoring).
//!
//! An RFC 3161 TimeStampToken is a CMS `SignedData` whose eContent is a `TSTInfo`. It
//! binds "a TSA (identified by a cert chaining to a pinned root) asserts that the bytes
//! with hash `h` existed at `genTime`". Combined with Verderer's checkpoint signature, an
//! anchored bundle proves *checkpoint root R existed no later than genTime* — an UPPER
//! time bound, contingent on trusting the pinned TSA. We use ≥2 independent TSAs so the
//! claim degrades gracefully (DESIGN §4.2). No interpretation enters here — bytes,
//! hashes, signatures, and a genTime only.
//!
//! Built on the der-0.7 RustCrypto generation (cms 0.2, x509-cert 0.2, x509-tsp 0.1,
//! rsa 0.9, ecdsa 0.16). This is pinned-root verification, not full RFC 5280 path
//! validation (no revocation, name constraints, or policy) — appropriate for a small
//! set of explicitly pinned TSAs, and stated as a known limit.
//! TODO(der-0.8): migrate when cms 0.3 + x509-cert 0.3 ship stable.

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier as Oid;
use der::asn1::OctetString;
use der::{Decode, DecodePem, Encode};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier as _;
use sha2::{Digest, Sha256};
use x509_cert::ext::pkix::ExtendedKeyUsage;
use x509_cert::Certificate;
use x509_tsp::TstInfo;

const ID_SIGNED_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: Oid = Oid::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_MESSAGE_DIGEST: Oid = Oid::new_unwrap("1.2.840.113549.1.9.4");
const ID_CONTENT_TYPE: Oid = Oid::new_unwrap("1.2.840.113549.1.9.3");
const ID_KP_TIMESTAMPING: Oid = Oid::new_unwrap("1.3.6.1.5.5.7.3.8");
const RSA_ENCRYPTION: Oid = Oid::new_unwrap("1.2.840.113549.1.1.1"); // digest carried separately
const SHA256_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.11");
const SHA384_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.12");
const SHA512_WITH_RSA: Oid = Oid::new_unwrap("1.2.840.113549.1.1.13");
const ECDSA_WITH_SHA256: Oid = Oid::new_unwrap("1.2.840.10045.4.3.2");
const ECDSA_WITH_SHA384: Oid = Oid::new_unwrap("1.2.840.10045.4.3.3");
const ECDSA_WITH_SHA512: Oid = Oid::new_unwrap("1.2.840.10045.4.3.4");
// The ECDSA signature OID gives the *digest*; the *curve* comes from the public key.
const PRIME256V1: Oid = Oid::new_unwrap("1.2.840.10045.3.1.7");
const SECP384R1: Oid = Oid::new_unwrap("1.3.132.0.34");
const SECP521R1: Oid = Oid::new_unwrap("1.3.132.0.35");
const SHA256_OID: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.1");
const SHA384_OID: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.2");
const SHA512_OID: Oid = Oid::new_unwrap("2.16.840.1.101.3.4.2.3");

#[derive(Clone, Copy)]
enum DigestKind {
    S256,
    S384,
    S512,
}

/// What an anchor proves, extracted from a verified token. Facts only.
#[derive(Debug, Clone)]
pub struct AnchorInfo {
    pub gen_time: String, // TSTInfo.genTime as YYYY-MM-DDTHH:MM:SSZ (the upper time bound)
    pub policy: String,   // TSTInfo.policy OID (informational)
    pub tsa: String,      // signer cert subject (informational)
}

fn dn_der(name: &x509_cert::name::Name) -> Vec<u8> {
    name.to_der().unwrap_or_default()
}

fn digest_from_oid(oid: &Oid) -> Option<DigestKind> {
    if *oid == SHA256_OID {
        Some(DigestKind::S256)
    } else if *oid == SHA384_OID {
        Some(DigestKind::S384)
    } else if *oid == SHA512_OID {
        Some(DigestKind::S512)
    } else {
        None
    }
}

fn digest_bytes(dg: DigestKind, data: &[u8]) -> Vec<u8> {
    match dg {
        DigestKind::S256 => Sha256::digest(data).to_vec(),
        DigestKind::S384 => sha2::Sha384::digest(data).to_vec(),
        DigestKind::S512 => sha2::Sha512::digest(data).to_vec(),
    }
}

fn rsa_verify(spki_der: &[u8], dg: DigestKind, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let pk = rsa::RsaPublicKey::from_public_key_der(spki_der).map_err(|e| e.to_string())?;
    let s = rsa::pkcs1v15::Signature::try_from(sig).map_err(|e| e.to_string())?;
    let ok = match dg {
        DigestKind::S256 => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(pk).verify(msg, &s),
        DigestKind::S384 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(pk).verify(msg, &s),
        DigestKind::S512 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha512>::new(pk).verify(msg, &s),
    };
    ok.map_err(|_| "RSA signature invalid".to_string())
}

/// Verify an RSA (PKCS#1 v1.5) or ECDSA signature over `msg` using a DER SubjectPublicKeyInfo.
/// `digest_alg` supplies the hash when `sig_alg` is the generic `rsaEncryption` OID (as RFC 3161
/// tokens use — the digest lives in `SignerInfo.digestAlgorithm`).
fn verify_sig(
    spki_der: &[u8],
    sig_alg: &Oid,
    digest_alg: Option<&Oid>,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    if *sig_alg == SHA256_WITH_RSA {
        rsa_verify(spki_der, DigestKind::S256, msg, sig)
    } else if *sig_alg == SHA384_WITH_RSA {
        rsa_verify(spki_der, DigestKind::S384, msg, sig)
    } else if *sig_alg == SHA512_WITH_RSA {
        rsa_verify(spki_der, DigestKind::S512, msg, sig)
    } else if *sig_alg == RSA_ENCRYPTION {
        let dg = digest_alg
            .and_then(digest_from_oid)
            .ok_or("rsaEncryption without a known digest algorithm")?;
        rsa_verify(spki_der, dg, msg, sig)
    } else if *sig_alg == ECDSA_WITH_SHA256 {
        ecdsa_verify(spki_der, DigestKind::S256, msg, sig)
    } else if *sig_alg == ECDSA_WITH_SHA384 {
        ecdsa_verify(spki_der, DigestKind::S384, msg, sig)
    } else if *sig_alg == ECDSA_WITH_SHA512 {
        ecdsa_verify(spki_der, DigestKind::S512, msg, sig)
    } else {
        Err(format!("unsupported signature algorithm {sig_alg}"))
    }
}

/// Verify an ECDSA signature. The digest comes from the signature algorithm; the curve
/// comes from the public key (they are independent — e.g. FreeTSA signs with a P-384 key
/// and SHA-512). We hash to a prehash and let ECDSA reduce it to the curve's field size.
fn ecdsa_verify(spki_der: &[u8], dg: DigestKind, msg: &[u8], sig: &[u8]) -> Result<(), String> {
    use ecdsa::signature::hazmat::PrehashVerifier;

    let spki = spki::SubjectPublicKeyInfoRef::from_der(spki_der).map_err(|e| e.to_string())?;
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or("unaligned EC public key")?;
    let curve = spki
        .algorithm
        .parameters_oid()
        .map_err(|_| "EC key without a named curve".to_string())?;
    let prehash = digest_bytes(dg, msg);

    if curve == PRIME256V1 {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| e.to_string())?;
        let s: p256::ecdsa::Signature = ecdsa::der::Signature::<p256::NistP256>::from_der(sig)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "bad ECDSA sig".to_string())?;
        vk.verify_prehash(&prehash, &s)
            .map_err(|_| "ECDSA P-256 signature invalid".to_string())
    } else if curve == SECP384R1 {
        let vk = p384::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| e.to_string())?;
        let s: p384::ecdsa::Signature = ecdsa::der::Signature::<p384::NistP384>::from_der(sig)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "bad ECDSA sig".to_string())?;
        vk.verify_prehash(&prehash, &s)
            .map_err(|_| "ECDSA P-384 signature invalid".to_string())
    } else if curve == SECP521R1 {
        let vk = p521::ecdsa::VerifyingKey::from_sec1_bytes(point).map_err(|e| e.to_string())?;
        let s: p521::ecdsa::Signature = ecdsa::der::Signature::<p521::NistP521>::from_der(sig)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "bad ECDSA sig".to_string())?;
        vk.verify_prehash(&prehash, &s)
            .map_err(|_| "ECDSA P-521 signature invalid".to_string())
    } else {
        Err(format!("unsupported EC curve {curve}"))
    }
}

/// Verify that `child` was signed by `issuer` (over the TBSCertificate).
fn cert_signed_by(child: &Certificate, issuer: &Certificate) -> Result<(), String> {
    let tbs = child.tbs_certificate.to_der().map_err(|e| e.to_string())?;
    let spki = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| e.to_string())?;
    let sig = child
        .signature
        .as_bytes()
        .ok_or("unaligned cert signature")?;
    verify_sig(&spki, &child.signature_algorithm.oid, None, &tbs, sig)
}

/// True iff `leaf` chains to one of the pinned roots by verifying each signature link.
/// A pinned root is matched by exact DER equality; intermediates come from the token.
fn chains_to_pinned(leaf: &Certificate, all: &[Certificate], pinned: &[Certificate]) -> bool {
    let is_pinned = |c: &Certificate| pinned.iter().any(|p| p.to_der().ok() == c.to_der().ok());
    let mut node = leaf.clone();
    for _ in 0..8 {
        if is_pinned(&node) {
            return true; // a pinned root reached (self-issued roots are pinned directly)
        }
        // Directly issued by a pinned root?
        if let Some(root) = pinned.iter().find(|r| {
            dn_der(&r.tbs_certificate.subject) == dn_der(&node.tbs_certificate.issuer)
                && cert_signed_by(&node, r).is_ok()
        }) {
            let _ = root;
            return true;
        }
        // Otherwise step up through an intermediate present in the token.
        let issuer = all.iter().find(|c| {
            c.to_der().ok() != node.to_der().ok()
                && dn_der(&c.tbs_certificate.subject) == dn_der(&node.tbs_certificate.issuer)
                && cert_signed_by(&node, c).is_ok()
        });
        match issuer {
            Some(i) => node = i.clone(),
            None => return false,
        }
    }
    false
}

fn has_timestamping_eku(cert: &Certificate) -> bool {
    let Some(exts) = &cert.tbs_certificate.extensions else {
        return false;
    };
    let eku_oid = Oid::new_unwrap("2.5.29.37"); // id-ce-extKeyUsage
    for ext in exts {
        if ext.extn_id == eku_oid {
            if let Ok(eku) = ExtendedKeyUsage::from_der(ext.extn_value.as_bytes()) {
                return eku.0.contains(&ID_KP_TIMESTAMPING);
            }
        }
    }
    false
}

fn gen_time_string(tst: &TstInfo) -> String {
    let dt = tst.gen_time.to_date_time();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minutes(),
        dt.seconds()
    )
}

fn attr_value<'a>(
    attrs: &'a cms::signed_data::SignedAttributes,
    oid: &Oid,
) -> Option<&'a der::Any> {
    attrs
        .iter()
        .find(|a| a.oid == *oid)
        .and_then(|a| a.values.iter().next())
}

/// The one non-fatal failure mode: the token is internally consistent (imprint, digests,
/// signature, EKU all check out) but its signer chains to no pinned root. Callers
/// aggregating anchors treat this like an unknown C2SP witness cosignature — reported,
/// not trusted, not fatal — while every other failure is evidence of tampering.
pub const ERR_UNTRUSTED_ROOT: &str = "signer cert does not chain to a pinned TSA root";

/// Verify an RFC 3161 timestamp token offline and return what it proves.
///
/// * `token_der` — the raw TimeStampToken (CMS SignedData) DER.
/// * `expected_hash` — the bytes the token must commit to (the SHA-256 of the anchored data).
/// * `roots_pem` — the pinned TSA root certificates (PEM).
pub fn verify_rfc3161_token(
    token_der: &[u8],
    expected_hash: &[u8],
    roots_pem: &[&str],
) -> Result<AnchorInfo, String> {
    let pinned: Vec<Certificate> = roots_pem
        .iter()
        .map(|pem| Certificate::from_pem(pem).map_err(|e| format!("bad pinned root: {e}")))
        .collect::<Result<_, _>>()?;
    if pinned.is_empty() {
        return Err("no pinned TSA roots".into());
    }

    let ci = ContentInfo::from_der(token_der).map_err(|e| format!("not a CMS token: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err("token is not CMS SignedData".into());
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| format!("bad SignedData: {e}"))?;

    // eContent must be a TSTInfo.
    if sd.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err("eContent is not a TSTInfo".into());
    }
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or("empty eContent")?;
    let tst_bytes = econtent.value(); // OCTET STRING content = DER TSTInfo
    let tst = TstInfo::from_der(tst_bytes).map_err(|e| format!("bad TSTInfo: {e}"))?;

    // BIND: the token must commit to exactly our hash.
    if tst.message_imprint.hashed_message.as_bytes() != expected_hash {
        return Err("messageImprint does not match the anchored hash".into());
    }

    // The single signer + its signed attributes.
    let si: &SignerInfo = sd.signer_infos.0.as_ref().first().ok_or("no SignerInfo")?;
    let signed_attrs = si.signed_attrs.as_ref().ok_or("token has no signedAttrs")?;

    // Cross-check the signed attributes before trusting the signature.
    // The messageDigest attribute is digest(eContent) under the SignerInfo digest
    // algorithm (SHA-256/384/512 — DigiCert uses 256, FreeTSA 512).
    let signer_digest =
        digest_from_oid(&si.digest_alg.oid).ok_or("unknown SignerInfo digest algorithm")?;
    let md = attr_value(signed_attrs, &ID_MESSAGE_DIGEST).ok_or("no messageDigest attr")?;
    let md_octets = md.decode_as::<OctetString>().map_err(|e| e.to_string())?;
    if md_octets.as_bytes() != digest_bytes(signer_digest, tst_bytes).as_slice() {
        return Err("messageDigest attr != hash(eContent)".into());
    }
    let ct = attr_value(signed_attrs, &ID_CONTENT_TYPE).ok_or("no contentType attr")?;
    if ct.decode_as::<Oid>().map_err(|e| e.to_string())? != ID_CT_TST_INFO {
        return Err("contentType attr != id-ct-TSTInfo".into());
    }

    // Collect the certs the token carries.
    let certs: Vec<Certificate> = match &sd.certificates {
        Some(set) => set
            .0
            .iter()
            .filter_map(|c| match c {
                cms::cert::CertificateChoices::Certificate(cert) => Some(cert.clone()),
                _ => None,
            })
            .collect(),
        None => Vec::new(),
    };

    // Identify the signer (leaf) cert from the SignerIdentifier.
    let leaf = match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(iss) => certs.iter().find(|c| {
            dn_der(&c.tbs_certificate.issuer) == dn_der(&iss.issuer)
                && c.tbs_certificate.serial_number == iss.serial_number
        }),
        SignerIdentifier::SubjectKeyIdentifier(_) => certs.first(),
    }
    .ok_or("signer certificate not found in token")?;

    // Verify the signature over the DER SET OF signed attributes (RFC 5652 §5.4).
    let attrs_der = signed_attrs.to_der().map_err(|e| e.to_string())?;
    let leaf_spki = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| e.to_string())?;
    verify_sig(
        &leaf_spki,
        &si.signature_algorithm.oid,
        Some(&si.digest_alg.oid),
        &attrs_der,
        si.signature.as_bytes(),
    )?;

    // The signer must be a timestamping cert that chains to a pinned root...
    if !has_timestamping_eku(leaf) {
        return Err("signer cert lacks the id-kp-timeStamping EKU".into());
    }
    if !chains_to_pinned(leaf, &certs, &pinned) {
        return Err(ERR_UNTRUSTED_ROOT.into());
    }

    // ...and its validity window must contain genTime (NOT verify-time: RFC 3161 tokens
    // stay valid past cert expiry).
    let gen = tst.gen_time.to_unix_duration();
    let nb = leaf.tbs_certificate.validity.not_before.to_unix_duration();
    let na = leaf.tbs_certificate.validity.not_after.to_unix_duration();
    if gen < nb || gen > na {
        return Err("genTime is outside the signer cert validity window".into());
    }

    Ok(AnchorInfo {
        gen_time: gen_time_string(&tst),
        policy: tst.policy.to_string(),
        tsa: format!("{}", leaf.tbs_certificate.subject),
    })
}
