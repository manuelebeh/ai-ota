use ed25519_dalek::SigningKey;
use ota_package::{Manifest, ModelInfo, PackageBuilder};

/// Fixed 32-byte seed, test-only: not a real secret, only used to make this
/// test's signature deterministic and reproducible.
const TEST_SEED: [u8; 32] = [7u8; 32];

fn test_manifest() -> Manifest {
    Manifest {
        package_id: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        created_at: "2026-01-01T00:00:00Z".to_string(),
        target_platform: "stm32h7".to_string(),
        chunk_count: 0,
        total_payload_size: 0,
        model: ModelInfo {
            quantization: "int8".to_string(),
            tensors: vec![],
            opset: "tflite-micro-2.x".to_string(),
            arena_bytes: 16384,
            latency_estimate_ms: 12.5,
        },
        license: None,
        provenance: None,
        base: None,
    }
}

#[test]
fn build_parse_and_verify_round_trip() {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let bytes = PackageBuilder::new(test_manifest())
        .with_payload_chunked(b"hello world, this is a fake model payload", 16)
        .build_and_sign(&signing_key)
        .expect("build_and_sign should succeed");

    let verifying_key = signing_key.verifying_key();
    let parsed = ota_package::verify(&bytes, &verifying_key).expect("verify should succeed");

    assert_eq!(parsed.manifest.target_platform, "stm32h7");
    assert!(parsed.manifest.chunk_count > 0);
    assert_eq!(parsed.chunks.len(), parsed.chunk_index.0.len());
}

#[test]
fn tampered_payload_fails_verification() {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let mut bytes = PackageBuilder::new(test_manifest())
        .with_payload_chunked(b"hello world, this is a fake model payload", 16)
        .build_and_sign(&signing_key)
        .expect("build_and_sign should succeed");

    // Flip a byte inside the payload region (after the fixed header, manifest and
    // chunk index, well before the trailer) to simulate corruption/tampering.
    let flip_at = bytes.len() / 2;
    bytes[flip_at] ^= 0xFF;

    let verifying_key = signing_key.verifying_key();
    assert!(ota_package::verify(&bytes, &verifying_key).is_err());
}

#[test]
fn wrong_major_version_is_rejected() {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let mut bytes = PackageBuilder::new(test_manifest())
        .with_payload_chunked(b"payload", 16)
        .build_and_sign(&signing_key)
        .expect("build_and_sign should succeed");

    bytes[4] = 2; // version_major = 2

    assert!(matches!(
        ota_package::reader::parse(&bytes),
        Err(ota_package::PackageError::UnsupportedVersion(2))
    ));
}
