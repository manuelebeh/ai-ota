//! Shared helpers for the golden-fixture generator and parity tests.

use ota_package::ParsedPackage;
use serde_json::json;

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The canonical parsed representation of a package, used to compare the Rust parser's
/// output against the Python parser's output for the same fixture — both are checked
/// against this same JSON shape, which is the parity contract.
pub fn expected_json(parsed: &ParsedPackage) -> serde_json::Value {
    let manifest = serde_json::to_value(&parsed.manifest).unwrap_or(serde_json::Value::Null);
    let chunks: Vec<_> = parsed
        .chunk_index
        .0
        .iter()
        .map(|entry| {
            json!({
                "offset": entry.offset,
                "length": entry.length,
                "sha256": hex(&entry.sha256),
            })
        })
        .collect();
    let tlv_tags: Vec<_> = parsed.tlv_sections.iter().map(|s| s.tag).collect();

    json!({
        "version_major": parsed.header.version_major,
        "version_minor": parsed.header.version_minor,
        "manifest": manifest,
        "chunks": chunks,
        "tlv_tags": tlv_tags,
        "signature_alg": parsed.signature.alg,
    })
}
