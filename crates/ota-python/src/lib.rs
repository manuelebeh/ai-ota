// pyo3's `#[pyfunction]`/`#[pymodule]` macros (as of 0.22) generate argument-extraction
// code that calls an unsafe function without an explicit `unsafe` block; that's macro
// codegen we don't control, not unsafe code we wrote, so the workspace-wide
// `unsafe_op_in_unsafe_fn = deny` lint is relaxed for this crate only.
// Same reasoning for `useless_conversion`: pyo3's generated `#[pyfunction]` wrapper
// performs a `From<PyErr> for PyErr` no-op conversion internally.
#![allow(unsafe_op_in_unsafe_fn, clippy::useless_conversion)]

//! PyO3 bindings exposing `ota-package`'s read path to the Python SDK.
//!
//! Deliberately minimal: the native module returns a JSON string, and
//! `python/ai_ota/packaging.py` turns it into a plain Python dict. This keeps the Rust
//! side a thin wrapper around `ota_package::parse`, and keeps the shape returned here
//! identical to the JSON shape `ota-package`'s own Rust tests check golden fixtures
//! against (see `crates/ota-package/tests/common/mod.rs`), which is how the Rust and
//! Python parity tests end up checking the same contract.

use ota_package::ParsedPackage;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::json;
use std::fs;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn to_json(parsed: &ParsedPackage) -> serde_json::Value {
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

/// Reads and structurally validates the `.otapkg` at `path`, returning its parsed
/// representation as a JSON string. Raises `ValueError` on any I/O or format error.
#[pyfunction]
fn parse_package_json(path: &str) -> PyResult<String> {
    let bytes =
        fs::read(path).map_err(|e| PyValueError::new_err(format!("reading {path}: {e}")))?;
    let parsed = ota_package::parse(&bytes).map_err(|e| PyValueError::new_err(e.to_string()))?;
    serde_json::to_string(&to_json(&parsed)).map_err(|e| PyValueError::new_err(e.to_string()))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_package_json, m)?)?;
    Ok(())
}
