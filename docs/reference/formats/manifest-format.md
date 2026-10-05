# `.otapkg` v1 — manifest format

> _Statut : stable (v1.0)_ · _Propriétaire : Emmanuel Ebeh (@manuelebeh)_ · Chemin : `docs/reference/formats/manifest-format.md`

The manifest is a canonical CBOR map (RFC 8949 §4.2) embedded in the `manifest` section of a `.otapkg` file (see [package-format.md](package-format.md)). This document lists every field. The machine-readable form is [`../schemas/manifest.schema.json`](../schemas/manifest.schema.json); this document is the human-readable companion and the two must stay in sync (enforced in CI via `check-jsonschema`).

The Python SDK never exposes raw CBOR to users — `ai_ota.packaging.inspect()` returns a plain Python `dict` with these same keys.

## Required fields

| Field | Type | Semantics |
|---|---|---|
| `package_id` | string | `"sha256:<hex>"` — content-addressed identity of this package, computed as the SHA-256 of the `chunk_index` bytes alone (deliberately *not* including the manifest itself, since the manifest contains `package_id` — hashing the chunk index avoids that circularity while still changing whenever the payload layout or content changes) |
| `created_at` | string | RFC 3339 UTC timestamp of when the package was built |
| `target_platform` | string | free-text target identifier, e.g. `"stm32h7"`, `"esp32c3"`, `"jetson-orin"` — matched against device capability reports, not validated by the format itself |
| `chunk_count` | integer | must equal the number of records in `chunk_index` |
| `total_payload_size` | integer | sum of all chunk lengths, in bytes |
| `model` | map | model metadata, see below |

### `model` map

| Field | Type | Semantics |
|---|---|---|
| `quantization` | string | e.g. `"int8"`, `"int4"`, `"fp16"`, `"none"` |
| `tensors` | array of maps | one entry per tensor: `{"name": string, "dtype": string, "shape": [int], "sparsity": float?}` |
| `opset` | string | inference runtime op-set version this model targets, e.g. `"tflite-micro-2.x"` |
| `arena_bytes` | integer | inference arena size required at runtime (TFLM/CMSIS-NN), used for the target-fit check in ADR 0009 |
| `latency_estimate_ms` | number | best-effort latency estimate on the stated `target_platform` |

## Optional fields

| Field | Type | Semantics |
|---|---|---|
| `license` | string | SPDX identifier or free text |
| `provenance` | map | `{"training_run_id": string, "dataset_hash": string, "git_commit": string}` — duplicate of TLV tag `0x0002` for consumers that only parse the manifest |
| `base` | map | delta reference, see below; absent for a full (non-delta) package |

### `base` map (delta reference)

Present only when this package's `payload` encodes a patch against a previously installed package, not a full image.

| Field | Type | Semantics |
|---|---|---|
| `package_id` | string | `package_id` of the base package this delta applies to |
| `base_manifest_hash` | string | `"sha256:<hex>"` of the base package's `manifest \|\| chunk_index` bytes |
| `base_total_hash` | string | `"sha256:<hex>"` of the base package's full reconstructed payload |

A device checks its currently-installed package against `base.package_id` and `base.base_manifest_hash` **before** attempting to apply the delta; on mismatch it rejects the delta and falls back to requesting a full package. See ADR 0001, "Delta reference semantics."

## Unknown fields

A v1.0 parser **ignores** any manifest key it does not recognize. This is how `version_minor` bumps add fields without breaking older parsers (see ADR 0001, "Version compatibility").

## See also

- [package-format.md](package-format.md) — the byte container this manifest lives inside.
- [../schemas/manifest.md](../schemas/manifest.md) and [`manifest.schema.json`](../schemas/manifest.schema.json) — the JSON Schema.
- [ADR 0001](../../engineering/architecture/adr/0001-package-format.md) — design rationale.
