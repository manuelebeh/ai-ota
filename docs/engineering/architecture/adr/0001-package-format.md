# ADR 0001: `.otapkg` v1 package format

> _Statut : **Proposed**_ · _Propriétaire : Emmanuel Ebeh (@manuelebeh)_ · Chemin : `docs/engineering/architecture/adr/0001-package-format.md`

## Status

**Proposed.** Promotes to **Accepted** after a 7-day review window with no unaddressed objections from embedded and ML stakeholders. Before that promotion, the risk mitigation below (a 1-week parser spike on real STM32H7 hardware) must have run — this ADR does not claim that spike happened.

## Context

Every component in `ai-ota` — `ota-package` (Rust), the firmware bootloader (Rust, `no_std`), the Python SDK (PyO3 wrapper), and the server (registry + validation) — parses or emits the same binary artifact: the package. Without a frozen, versioned, byte-exact format:

1. **The four implementations will diverge.** Every divergence between parsers is a device that bricks.
2. **The MCU constraint is not negotiable.** The format must be parseable and verifiable on a Cortex-M with ~64 KB RAM, no heap, and power that can drop mid-read.
3. **Delta updates depend on it.** A delta is "patch from base package to target package." Base/target identity, chunking, and hashing must be defined once, by the format, not invented per delta engine.
4. **Security depends on it.** Signatures, anti-rollback, replay protection, and manifest binding all need byte ranges the format guarantees.
5. **Registry, CDN, and resume need it.** Chunk boundaries and manifest fields determine how a device resumes a transfer after a dropped connection.

No code touching the package path should be written before this ADR is accepted.

### Out of scope (follow-up ADRs/issues)

- A/B partition layout (where the package is written) — see ADR 0003.
- Signing scheme details (algorithm choice, key rotation) — see ADR 0004.
- Delta algorithm (zstd, bsdiff, MCU patcher) — see ADR 0002.
- Transport framing (MQTT, CoAP, BLE chunking) — see ADR 0005.
- Server-side registry storage format.
- `.otapkg` MIME type / IANA extension registration.
- Encrypted packages (confidentiality is not a v0.1 requirement).

## Decision

Define `.otapkg` v1 as a flat binary container: a fixed 16-byte header, then length-prefixed sections in a fixed order, then a trailer. Every section length is explicit up front so a streaming parser never has to seek backward or buffer more than one section at a time.

### Byte layout

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| 0 | 4 | `magic` | bytes | ASCII `"OTAP"` |
| 4 | 1 | `version_major` | u8 | `1` for this ADR |
| 5 | 1 | `version_minor` | u8 | `0` initially, additive bumps only |
| 6 | 2 | `flags` | u16 LE | reserved, must be `0` in v1.0 |
| 8 | 4 | `header_crc32` | u32 LE | CRC32 (IEEE) over `manifest \|\| chunk_index` bytes |
| 12 | 4 | `manifest_len` | u32 LE | length in bytes of the CBOR manifest that follows |
| 16 | `manifest_len` | `manifest` | CBOR | canonical CBOR (RFC 8949 §4.2), see `manifest-format.md` |
| — | 4 | `chunk_index_len` | u32 LE | length in bytes of the chunk index that follows |
| — | `chunk_index_len` | `chunk_index` | records | repeated fixed 44-byte records, see below |
| — | Σ chunk lengths | `payload` | bytes | raw payload chunks, back to back, in index order |
| — | 2 | `tlv_section_count` | u16 LE | number of optional TLV sections that follow |
| — | varies | `tlv_sections` | TLV | repeated `{tag:u16, len:u32, value}`, see below |
| — | 4 | `signature_len` | u32 LE | length in bytes of the signature block |
| — | `signature_len` | `signature` | block | `{alg:u8, pubkey_id:[u8;32], sig:bytes}`, see below |
| — | 4 | `trailer_crc32` | u32 LE | CRC32 over the entire file except this field and the next |
| — | 8 | `trailer_magic` | bytes | ASCII `"OTAPEND!"` |

**Chunk index record** (44 bytes, repeated `chunk_count` times):

| Offset in record | Size | Field | Type |
|---|---|---|---|
| 0 | 8 | `offset` | u64 LE — byte offset of this chunk within `payload` |
| 8 | 4 | `length` | u32 LE |
| 12 | 32 | `sha256` | bytes — SHA-256 of the chunk's plaintext bytes |

**TLV section** (variable length, repeated `tlv_section_count` times):

| Offset in TLV | Size | Field | Type |
|---|---|---|---|
| 0 | 2 | `tag` | u16 LE — see tag registry below |
| 2 | 4 | `len` | u32 LE |
| 6 | `len` | `value` | bytes — tag-specific encoding |

Known tags (v1.0): `0x0001` delta-reference hint (duplicates/extends the manifest `base` object for transports that frame on TLVs), `0x0002` provenance blob, `0x0003` quantization detail blob. **A parser that does not recognize a tag MUST skip it using `len` and continue** — this is the forward-compatibility mechanism for v1.x.

**Signature block**:

| Offset | Size | Field | Type |
|---|---|---|---|
| 0 | 1 | `alg` | u8 — `1` = Ed25519 (only value defined in v1.0) |
| 1 | 32 | `pubkey_id` | bytes — SHA-256 of the signer's public key, for key lookup/rotation |
| 33 | remaining | `sig` | bytes — signature over `manifest \|\| chunk_index` (exactly those two sections' raw bytes, header and trailer excluded) |

### RAM budget: ≤ 16 KB to parse and verify

The streaming parse/verify path on an MCU needs, at any one instant:

| Component | Bytes (worst case) |
|---|---|
| Fixed header | 16 |
| Manifest buffer (capped, see `MAX_MANIFEST_LEN`) | 4096 |
| Chunk index: one record at a time, streamed from flash | 44 |
| One payload read buffer | 4096 |
| SHA-256 streaming hasher state | ~200 |
| Ed25519 verify working set (signature + pubkey + scratch) | ~400 |
| Misc (section-length cursors, CRC32 state) | ~100 |
| **Total** | **~8950** |

This leaves headroom under the 16 KB budget. `MAX_MANIFEST_LEN = 4096` is a hard constant enforced before any manifest bytes are read into the buffer — a `manifest_len` exceeding it is rejected immediately. The 4 KB payload read buffer is a design choice, not a format requirement; a device with less RAM may use a smaller read buffer and read more times, at a performance cost, without changing the format.

If a future revision pushes this number over 16 KB, the alternative is to move the manifest to a separate, index-addressable section the device can skip-parse field by field instead of buffering it whole — this is *not* adopted in v1.0 because manifests are small (ML metadata, not tensors) and buffering one is simpler.

### Streaming validation semantics

A device can decide **"this package is valid and I will stage it"** at this exact point in the byte stream: *immediately after reading `signature` and verifying it against `manifest || chunk_index`* — before reading a single payload byte. At that point every chunk's SHA-256 commitment in the chunk index is authenticated transitively through the signature. The device then streams `payload`, hashing each chunk as it arrives and comparing against the chunk index entry; a mismatch on chunk *N* aborts staging of chunk *N* without invalidating chunks `0..N-1` already staged (the commit/journal semantics of partially-staged chunks are ADR 0005's concern, not this one — this ADR only guarantees the per-chunk hash is independently checkable).

### Version compatibility

- A v1 parser **hard-rejects** any package whose `version_major != 1` immediately after reading the header, before touching `manifest_len` or any later field. It does not attempt a partial parse of an incompatible major version.
- Within v1, `version_minor` bumps are **additive-only**: new optional manifest fields and new TLV tags. A v1.0 parser reading a v1.3 package skips unknown manifest fields (CBOR maps are self-describing) and unknown TLV tags (skipped by `len`), and succeeds.
- v1.0 packages remain parseable by any later v1.x parser, by construction (additive-only evolution).
- v2 (a new major version) is free to break format compatibility; this ADR makes no promise about v1 parsers reading v2 packages, nor v2 parsers reading v1 packages — that is v2's ADR to decide.

### Delta reference semantics

The manifest may contain an optional `base` object:

```json
{
  "package_id": "sha256:...",
  "base_manifest_hash": "sha256:...",
  "base_total_hash": "sha256:..."
}
```

A delta package is a normal `.otapkg` whose `payload` happens to encode a patch instead of full tensor bytes (the patch *algorithm* is ADR 0002's concern). It still carries the **target's** full manifest and the **target's** signature — verification is always performed against the target, never the base. Before attempting to reconstruct payload bytes from a delta, the device checks that its currently-installed package's identity matches `base.package_id` and `base.base_manifest_hash`; on mismatch, it must reject the delta and fall back to requesting a full package. This keeps "can I even apply this delta" a cheap, local, pre-verification check, separate from cryptographic verification of the target package itself.

## Alternatives considered

1. **Reuse SWUpdate's `.swu` (cpio-based).** Rejected: cpio has no streaming-verify story, isn't `no_std`-friendly, and has no explicit AI-model metadata concept.
2. **Reuse RAUC's `.raucb` (squashfs + manifest).** Rejected: requires buffering/mounting a full image; not viable on a bare-metal MCU with no filesystem.
3. **Reuse Mender's artifact format (tar + JSON header).** Rejected: tar's sequential-but-unindexed layout and JSON's non-canonical encoding complicate both streaming resume and deterministic signing; no native delta/chunk-index concept at the format level.
4. **Protobuf-based manifest instead of CBOR.** Rejected: requires a schema compiler/codegen toolchain on the MCU side; CBOR's deterministic encoding (RFC 8949 §4.2) is enough, and the team already uses CBOR elsewhere in the stack.
5. **Flat fixed-size C struct header with no TLV extensibility.** Rejected: can't evolve the format without breaking binary layout; TLV sections give room for optional/vendor extensions without a major version bump.
6. **Single whole-file signature (no separate manifest+chunk-index signature).** Rejected: forces buffering the entire payload before any staging decision can be made, which violates the MCU streaming requirement directly.
7. **JSON manifest instead of CBOR.** Rejected: `no_std` JSON parsers handling floats/escapes correctly are heavier than CBOR parsers; JSON has no standard canonical form, which complicates deterministic signing (CBOR's canonical encoding is defined by the spec).

## Risks & trade-offs

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Format is designed before real MCU testing, then needs a v2 before v0.1 ships | High | High | Prototype the parser on real STM32H7 hardware before marking this ADR Accepted. A 1-week bench spike is cheaper than a format rewrite. |
| CBOR manifest is unfamiliar to ML engineers and slows adoption | Medium | Low | The Python SDK never exposes raw CBOR — it presents a Python dict (`ai_ota.packaging.inspect()`). Only embedded engineers see CBOR directly, and they already know it. |
| RAM budget target (≤16 KB) is too aggressive, forcing a design that's slow on MPU targets | Medium | Medium | The parse path (streaming, constant RAM) is separate from the verify path (buffers one chunk at a time). Both are documented independently; an MPU target is free to use larger buffers without changing the format. |
| Chunk size tuned for one transport hurts another (a size fine for HTTPS is terrible for BLE) | High | Medium | Chunk size is a per-transport *framing* concern, not a format concern. The format defines a chunk index; transports (ADR 0005) decide how to send each chunk. |
| Delta reference creates a package that can't be verified standalone | High | High | A delta package still carries the target's full manifest and signature (see "Delta reference semantics" above) — verification is always against the target, never the base. |

## Non-goals

- Deciding the signing algorithm beyond "v1.0 defines `alg=1` as Ed25519." Key rotation and additional algorithms are ADR 0004.
- Deciding the delta algorithm. This ADR defines how a delta *references* a base package; ADR 0002 defines how the delta is computed and applied.
- Deciding transport framing. This ADR defines chunk boundaries; ADR 0005 defines how chunks are framed over MQTT/CoAP/BLE.
- Deciding partition layout. This ADR defines the package; ADR 0003 defines where it's written.
- Registry design (server-side storage) and `.otapkg` MIME/extension registration with IANA.
- Encrypted packages — confidentiality is not a v0.1 requirement; if it becomes one, it's a separate ADR.

## Comparison table

| Criterion | `.swu` (SWUpdate) | `.raucb` (RAUC) | `.mender` | `.otapkg` (proposed) |
|---|---|---|---|---|
| `no_std` compatible | ❌ | ❌ | ❌ | ✅ |
| Streaming verify | ⚠️ | ⚠️ | ❌ | ✅ |
| Manifest encoding | cpio | custom | JSON | CBOR |
| Delta support | ✅ | ✅ | ⚠️ | ✅ |
| MCU RAM budget | n/a | n/a | n/a | ≤16 KB |
| Explicit AI-model semantics | ❌ | ❌ | ❌ | ✅ |

## Definition of Done

- [x] Acceptance criteria are fully met (byte-level spec, RAM budget, streaming/versioning/delta semantics, ≥5 alternatives).
- [x] Documentation updated: `docs/reference/formats/package-format.md`, `docs/reference/formats/manifest-format.md`, `docs/reference/schemas/manifest.schema.json`.
- [x] Tests added: golden fixtures + Rust/Python parity tests + RAM-budget test (see `crates/ota-package`).
- [ ] Safety review completed — pending the 7-day review window and the STM32H7 bench spike noted above; required before Status moves to Accepted.
