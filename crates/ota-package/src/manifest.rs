//! The manifest: canonical CBOR map embedded in the `manifest` section.
//! See `docs/reference/formats/manifest-format.md` and `docs/reference/schemas/manifest.schema.json`.

use serde::{Deserialize, Serialize};

use crate::PackageError;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    /// Content-addressed identity, computed and overwritten by [`crate::PackageBuilder`]
    /// as `sha256(chunk_index)` — callers building a manifest by hand may leave this empty.
    #[serde(default)]
    pub package_id: String,
    pub created_at: String,
    pub target_platform: String,
    #[serde(default)]
    pub chunk_count: u32,
    #[serde(default)]
    pub total_payload_size: u64,
    pub model: ModelInfo,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub provenance: Option<Provenance>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub base: Option<BaseReference>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelInfo {
    pub quantization: String,
    pub tensors: Vec<TensorInfo>,
    pub opset: String,
    pub arena_bytes: u64,
    pub latency_estimate_ms: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TensorInfo {
    pub name: String,
    pub dtype: String,
    pub shape: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sparsity: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Provenance {
    pub training_run_id: String,
    pub dataset_hash: String,
    pub git_commit: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaseReference {
    pub package_id: String,
    pub base_manifest_hash: String,
    pub base_total_hash: String,
}

impl Manifest {
    pub fn to_cbor(&self) -> Result<Vec<u8>, PackageError> {
        let mut out = Vec::new();
        ciborium::ser::into_writer(self, &mut out)
            .map_err(|e| PackageError::CborEncode(e.to_string()))?;
        Ok(out)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, PackageError> {
        ciborium::de::from_reader(bytes).map_err(|e| PackageError::Cbor(e.to_string()))
    }
}
