//! Parses every committed golden fixture and asserts the result matches its
//! `<name>.expected.json` — the same contract the Python binding is checked against in
//! `python/tests/unit/test_golden_fixtures.py`, giving cross-language parity transitively.

#[path = "common/mod.rs"]
mod common;

use std::fs;

const FIXTURES: &[&str] = &["minimal", "delta", "full"];
const GOLDEN_DIR: &str = "tests/golden/v1";

#[test]
fn golden_fixtures_parse_and_match_expected_json() {
    for name in FIXTURES {
        let path = format!("{GOLDEN_DIR}/{name}.otapkg");
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));

        let parsed = ota_package::parse(&bytes).unwrap_or_else(|e| panic!("parsing {path}: {e}"));
        let actual = common::expected_json(&parsed);

        let expected_path = format!("{GOLDEN_DIR}/{name}.expected.json");
        let expected_raw = fs::read_to_string(&expected_path)
            .unwrap_or_else(|e| panic!("reading {expected_path}: {e}"));
        let expected: serde_json::Value = serde_json::from_str(&expected_raw)
            .unwrap_or_else(|e| panic!("parsing {expected_path}: {e}"));

        assert_eq!(
            actual, expected,
            "{name}: parsed output does not match {expected_path}"
        );
    }
}

#[test]
fn golden_fixtures_are_under_size_cap() {
    for name in FIXTURES {
        let path = format!("{GOLDEN_DIR}/{name}.otapkg");
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        assert!(
            bytes.len() < 4096,
            "{name}.otapkg is {} bytes, must stay under 4 KiB",
            bytes.len()
        );
    }
}
