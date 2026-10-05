# `.otapkg` v1 golden fixtures

Three committed `.otapkg` files, each under 4 KiB, implementing the acceptance criteria of
ADR 0001 / issue #2:

| File | Covers |
|---|---|
| `minimal.otapkg` | smallest valid package: one chunk, no delta reference, no optional TLV sections |
| `delta.otapkg` | manifest has a populated `base` delta reference |
| `full.otapkg` | every optional manifest field populated, plus a `provenance` TLV section |

Each `<name>.otapkg` has a matching `<name>.expected.json` — the canonical parsed
representation (header version, manifest, chunk hashes, TLV tags, signature algorithm).
Both the Rust parity test (`tests/golden.rs`) and the Python parity test
(`python/tests/unit/test_golden_fixtures.py`) parse the `.otapkg` independently and assert
their output matches this same JSON, which is how cross-language parsing parity is checked
without running both languages in one process.

## Regenerating

These files are generated, not handcrafted, by `tests/generate_golden.rs`:

```sh
cargo test -p ota-package --test generate_golden -- --ignored
```

Run this after any change to the wire format and commit the resulting files.

## The signing key

The fixtures are signed with a **fixed, hardcoded, test-only** Ed25519 seed
(`[7u8; 32]` in `tests/generate_golden.rs` and `tests/common/mod.rs`'s callers). This is
**not a secret** — it exists solely so the fixtures' signature bytes are deterministic and
reproducible across regenerations and across machines. It must never be used to sign a real
`.otapkg` release. The corresponding public key is derivable from the seed by anyone (it is
public by construction); it is not checked in separately since every test that needs it
derives it from `SigningKey::from_bytes(&TEST_SEED).verifying_key()`.
