//! Regenerates the golden `.otapkg` v1 fixtures under `tests/golden/v1/`.
//!
//! These fixtures are committed to the repo; this test is `#[ignore]`d so normal
//! `cargo test` runs don't regenerate them. Run deliberately after a format change:
//!
//! ```sh
//! cargo test -p ota-package --test generate_golden -- --ignored
//! ```
//!
//! See `tests/golden/v1/README.md` for the test-only signing key used here.

#[path = "common/mod.rs"]
mod common;

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use ota_package::{
    BaseReference, Manifest, ModelInfo, PackageBuilder, Provenance, TensorInfo, TlvSection,
};

const TEST_SEED: [u8; 32] = [7u8; 32];
const GOLDEN_DIR: &str = "tests/golden/v1";

fn base_manifest() -> Manifest {
    Manifest {
        package_id: String::new(), // overwritten by PackageBuilder
        created_at: "2026-01-01T00:00:00Z".to_string(),
        target_platform: "stm32h7".to_string(),
        chunk_count: 0,
        total_payload_size: 0,
        model: ModelInfo {
            quantization: "int8".to_string(),
            tensors: vec![TensorInfo {
                name: "conv1".to_string(),
                dtype: "int8".to_string(),
                shape: vec![1, 3, 3, 8],
                sparsity: None,
            }],
            opset: "tflite-micro-2.x".to_string(),
            arena_bytes: 16384,
            latency_estimate_ms: 12.5,
        },
        license: None,
        provenance: None,
        base: None,
    }
}

fn write_fixture(name: &str, bytes: &[u8]) {
    let dir = Path::new(GOLDEN_DIR);
    fs::create_dir_all(dir).expect("create golden fixture dir");
    let path = dir.join(format!("{name}.otapkg"));
    fs::write(&path, bytes).expect("write fixture bytes");

    let parsed = ota_package::parse(bytes).expect("generated fixture must parse");
    let expected = common::expected_json(&parsed);
    let expected_path = dir.join(format!("{name}.expected.json"));
    fs::write(
        &expected_path,
        serde_json::to_string_pretty(&expected).expect("serialize expected json"),
    )
    .expect("write expected json");

    assert!(
        bytes.len() < 4096,
        "{name}.otapkg is {} bytes, must stay under 4 KiB",
        bytes.len()
    );
}

#[test]
#[ignore = "run manually with --ignored to regenerate committed fixtures"]
fn generate_minimal() {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let bytes = PackageBuilder::new(base_manifest())
        .with_payload_chunked(b"tiny single-chunk model payload", 64)
        .build_and_sign(&signing_key)
        .expect("build_and_sign");
    write_fixture("minimal", &bytes);
}

#[test]
#[ignore = "run manually with --ignored to regenerate committed fixtures"]
fn generate_delta() {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let mut manifest = base_manifest();
    manifest.base = Some(BaseReference {
        package_id: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        base_manifest_hash:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string(),
        base_total_hash: "sha256:3333333333333333333333333333333333333333333333333333333333333333"
            .to_string(),
    });
    let bytes = PackageBuilder::new(manifest)
        .with_payload_chunked(
            b"delta patch bytes against a previously installed base package",
            32,
        )
        .build_and_sign(&signing_key)
        .expect("build_and_sign");
    write_fixture("delta", &bytes);
}

#[test]
#[ignore = "run manually with --ignored to regenerate committed fixtures"]
fn generate_full() {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let mut manifest = base_manifest();
    manifest.license = Some("Apache-2.0".to_string());
    manifest.provenance = Some(Provenance {
        training_run_id: "run-2026-01-01-001".to_string(),
        dataset_hash: "sha256:4444444444444444444444444444444444444444444444444444444444444444"
            .to_string(),
        git_commit: "a1b2c3d4e5f60718293a4b5c6d7e8f9011223344".to_string(),
    });
    manifest.base = Some(BaseReference {
        package_id: "sha256:5555555555555555555555555555555555555555555555555555555555555555"
            .to_string(),
        base_manifest_hash:
            "sha256:6666666666666666666666666666666666666666666666666666666666666666".to_string(),
        base_total_hash: "sha256:7777777777777777777777777777777777777777777777777777777777777777"
            .to_string(),
    });
    manifest.model.tensors.push(TensorInfo {
        name: "depthwise2".to_string(),
        dtype: "int8".to_string(),
        shape: vec![1, 3, 3, 16],
        sparsity: Some(0.4),
    });

    let bytes = PackageBuilder::new(manifest)
        .with_payload_chunked(
            b"full-featured fixture payload with every optional field populated",
            24,
        )
        .add_tlv(TlvSection {
            tag: ota_package::tlv::TAG_PROVENANCE,
            value: b"cbor-ish provenance blob placeholder".to_vec(),
        })
        .build_and_sign(&signing_key)
        .expect("build_and_sign");
    write_fixture("full", &bytes);
}
