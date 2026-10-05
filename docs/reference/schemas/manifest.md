# `.otapkg` v1 manifest — JSON Schema

> _Statut : stable (v1.0)_ · _Propriétaire : Emmanuel Ebeh (@manuelebeh)_ · Chemin : `docs/reference/schemas/manifest.md`

This is the machine-readable JSON Schema for the `.otapkg` v1 manifest, kept in sync with the human-readable field table in [`../formats/manifest-format.md`](../formats/manifest-format.md). The manifest itself is encoded as CBOR on disk (see [`../formats/package-format.md`](../formats/package-format.md)); this schema validates its JSON representation — the same shape `ota-cli package inspect --format json` and `ai_ota.packaging.inspect()` produce.

The schema file lives at [`manifest.schema.json`](manifest.schema.json) and is validated in CI with [`check-jsonschema`](https://check-jsonschema.readthedocs.io/) against the manifest extracted from every golden fixture in `crates/ota-package/tests/golden/v1/`.

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": ".otapkg v1 manifest",
  "required": [
    "package_id", "created_at", "target_platform",
    "chunk_count", "total_payload_size", "model"
  ],
  "properties": {
    "package_id": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
    "created_at": { "type": "string", "format": "date-time" },
    "target_platform": { "type": "string" },
    "chunk_count": { "type": "integer", "minimum": 1 },
    "total_payload_size": { "type": "integer", "minimum": 0 },
    "license": { "type": "string" },
    "model": {
      "type": "object",
      "required": ["quantization", "tensors", "opset", "arena_bytes", "latency_estimate_ms"]
    },
    "provenance": { "type": "object" },
    "base": {
      "type": "object",
      "required": ["package_id", "base_manifest_hash", "base_total_hash"]
    }
  }
}
```

See [`manifest.schema.json`](manifest.schema.json) for the complete, authoritative schema — the snippet above is a trimmed overview for readability.

## See also

- [`../formats/manifest-format.md`](../formats/manifest-format.md) — field-by-field semantics.
- [`../formats/package-format.md`](../formats/package-format.md) — the binary container.
- [ADR 0001](../../engineering/architecture/adr/0001-package-format.md) — design rationale.
