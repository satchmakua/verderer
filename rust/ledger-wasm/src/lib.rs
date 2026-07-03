//! WASM bindings for Druid's offline proof-bundle verifier (M5b).
//!
//! Compiles [`ledger_core::verify_bundle`] to WebAssembly so the public site can verify a
//! downloaded `druid.proofbundle/v1` **in the browser**, trusting neither the government
//! nor Druid's servers. Ships the same pinned DigiCert + FreeTSA roots as the native
//! `druid-verify`, so real-TSA-anchored bundles verify with nothing extra.

use wasm_bindgen::prelude::*;

/// Verify a proof-bundle JSON string. Returns a message beginning with `VALID` or
/// `INVALID` (the caller checks the prefix and shows a green check / red cross).
#[wasm_bindgen]
pub fn verify_bundle(json: &str) -> String {
    let roots = [
        include_str!("../../ledger-core/roots/digicert_g4.crt").to_string(),
        include_str!("../../ledger-core/roots/freetsa.crt").to_string(),
    ];
    match ledger_core::verify_bundle(json, &roots) {
        Ok(message) => format!("VALID {message}"),
        Err(error) => format!("INVALID {error}"),
    }
}
