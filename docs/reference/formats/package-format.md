# `.otapkg` v1 — normative byte-level format

> _Statut : stable (v1.0)_ · _Propriétaire : Emmanuel Ebeh (@manuelebeh)_ · Chemin : `docs/reference/formats/package-format.md`

This document is the **normative** byte-level specification for the `.otapkg` v1 container. It implements the decision recorded in [ADR 0001](../../engineering/architecture/adr/0001-package-format.md). Every claim here is testable against the golden fixtures in `crates/ota-package/tests/golden/v1/`.

All multi-byte integers are little-endian unless noted. All offsets are absolute from the start of the file unless the field says "in record" or "in TLV".

## File layout

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| 0 | 4 | `magic` | bytes | ASCII `"OTAP"` (`0x4F 0x54 0x41 0x50`) |
| 4 | 1 | `version_major` | u8 | `1` |
| 5 | 1 | `version_minor` | u8 | `0` for this revision |
| 6 | 2 | `flags` | u16 | reserved, must be `0` |
| 8 | 4 | `header_crc32` | u32 | CRC32 (IEEE 802.3 polynomial) over the raw bytes of `manifest` concatenated with `chunk_index` (not including their length prefixes) |
| 12 | 4 | `manifest_len` | u32 | byte length of the `manifest` section, must be ≤ `MAX_MANIFEST_LEN` (4096) |
| 16 | `manifest_len` | `manifest` | CBOR | canonical CBOR map, see [manifest-format.md](manifest-format.md) |
| 16 + manifest_len | 4 | `chunk_index_len` | u32 | byte length of `chunk_index`, must be a multiple of 44 |
| … | `chunk_index_len` | `chunk_index` | records | `chunk_index_len / 44` chunk records, see below |
| … | Σ(`chunk[i].length`) | `payload` | bytes | raw chunk bytes, concatenated in index order |
| … | 2 | `tlv_section_count` | u16 | number of TLV sections that follow, may be `0` |
| … | varies | `tlv_sections` | TLV | `tlv_section_count` repeated TLV records, see below |
| … | 4 | `signature_len` | u32 | byte length of `signature` |
| … | `signature_len` | `signature` | block | see below |
| … | 4 | `trailer_crc32` | u32 | CRC32 over every preceding byte of the file (offset 0 up to, but not including, this field) |
| … | 8 | `trailer_magic` | bytes | ASCII `"OTAPEND!"` |

A conformant parser reads fields strictly in this order and never seeks backward except to re-read a section it already bounded (e.g. re-reading `manifest` bytes to feed the CRC after having already read `manifest_len`).

## Chunk index record (44 bytes)

Repeated back to back inside `chunk_index`, one per payload chunk, in the order chunks appear in `payload`.

| Offset in record | Size | Field | Type | Notes |
|---|---|---|---|---|
| 0 | 8 | `offset` | u64 | byte offset of this chunk relative to the start of `payload` |
| 8 | 4 | `length` | u32 | chunk length in bytes |
| 12 | 32 | `sha256` | bytes | SHA-256 of the chunk's plaintext bytes |

`chunk_count = chunk_index_len / 44`. Chunks are contiguous and in ascending `offset` order; there is no gap or overlap between `chunk[i].offset + chunk[i].length` and `chunk[i+1].offset`.

## TLV section

| Offset in TLV | Size | Field | Type |
|---|---|---|---|
| 0 | 2 | `tag` | u16 |
| 2 | 4 | `len` | u32 |
| 6 | `len` | `value` | bytes, tag-specific |

### Tag registry (v1.0)

| Tag | Name | Value encoding |
|---|---|---|
| `0x0001` | `delta_reference_hint` | CBOR map, mirrors manifest `base` object, for transports that frame on TLVs instead of parsing the manifest |
| `0x0002` | `provenance` | CBOR map: training run id, dataset hash, git commit of the training code |
| `0x0003` | `quantization_detail` | CBOR map: per-tensor quantization scheme detail beyond the manifest summary |

**Unknown tags (anything not in this table, or a future tag unknown to an older parser) MUST be skipped using `len` and parsing continues with the next TLV.** This is the sole forward-compatibility mechanism for optional sections.

## Signature block

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| 0 | 1 | `alg` | u8 | `1` = Ed25519 (only defined value in v1.0) |
| 1 | 32 | `pubkey_id` | bytes | SHA-256 of the signer's raw public key, used to look up the verification key |
| 33 | `signature_len - 33` | `sig` | bytes | the signature itself (64 bytes for Ed25519) |

The signed message is **exactly** `manifest || chunk_index` — the raw section bytes, without their length prefixes, header, payload, TLVs, or trailer. This is what lets a device authenticate every chunk hash before reading any payload byte (see "Streaming validation" in ADR 0001).

## Validation algorithm (reference pseudocode)

```text
read 16-byte header
assert magic == "OTAP"
assert version_major == 1          # hard reject otherwise, parsing stops here
assert manifest_len <= MAX_MANIFEST_LEN
manifest_bytes = read(manifest_len)
assert crc32(manifest_bytes || chunk_index_bytes) == header_crc32
chunk_index_bytes = read(chunk_index_len)
assert chunk_index_len % 44 == 0
manifest = cbor_decode(manifest_bytes)   # unknown map keys ignored
chunk_index = parse_records(chunk_index_bytes)

verify_ed25519(signature.sig, pubkey_for(signature.pubkey_id), message = manifest_bytes || chunk_index_bytes)
# --> decision point: package is authentic, device may begin staging

for chunk in chunk_index:
    bytes = read(chunk.length)          # streamed, not buffered whole
    assert sha256(bytes) == chunk.sha256
    stage(bytes, chunk.offset)

read tlv_section_count, then tlv_sections, skipping unknown tags by len
assert crc32(bytes[0 .. trailer_crc32_offset]) == trailer_crc32
assert trailer_magic == "OTAPEND!"
```

## Worked example

`crates/ota-package/tests/golden/v1/minimal.otapkg` is the smallest valid package: one 64-byte chunk, no delta reference, no optional TLV sections. Its parsed representation is checked into [`minimal.expected.json`](../../../crates/ota-package/tests/golden/v1/minimal.expected.json) next to it — read that file for a concrete field-by-field example rather than a hand-maintained hex dump here, since the fixture and its expected output are generated together and kept in sync by the Rust/Python parity tests.

## See also

- [ADR 0001: `.otapkg` v1 package format](../../engineering/architecture/adr/0001-package-format.md) — the design rationale, RAM budget, and alternatives.
- [manifest-format.md](manifest-format.md) — every manifest field.
- [../schemas/manifest.md](../schemas/manifest.md) — JSON Schema for the manifest.
