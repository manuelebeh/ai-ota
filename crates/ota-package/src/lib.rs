//! The versioned `.otapkg` v1 container format (read/write/validate).
//!
//! Implements ADR 0001 (`docs/engineering/architecture/adr/0001-package-format.md`).
//! See `docs/reference/formats/package-format.md` for the normative byte layout.

pub mod builder;
pub mod chunk;
pub mod header;
pub mod manifest;
pub mod reader;
pub mod tlv;

pub use builder::PackageBuilder;
pub use chunk::{ChunkEntry, ChunkIndex};
pub use header::{Header, HEADER_LEN, MAX_MANIFEST_LEN};
pub use manifest::{BaseReference, Manifest, ModelInfo, Provenance, TensorInfo};
pub use reader::{parse, verify, ParsedPackage, Signature};
pub use tlv::TlvSection;

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("truncated input: need at least {needed} bytes, got {got}")]
    Truncated { needed: usize, got: usize },
    #[error("bad magic bytes, this is not a .otapkg file")]
    BadMagic,
    #[error("unsupported format major version {0}, this parser only supports v1")]
    UnsupportedVersion(u8),
    #[error("manifest is {0} bytes, exceeds the {1}-byte RAM budget cap")]
    ManifestTooLarge(u32, u32),
    #[error("header CRC32 mismatch: manifest/chunk-index bytes were corrupted")]
    HeaderCrcMismatch,
    #[error("trailer CRC32 mismatch: file was corrupted or truncated")]
    TrailerCrcMismatch,
    #[error("bad trailer magic, file was truncated or corrupted")]
    BadTrailerMagic,
    #[error("chunk index length {0} is not a multiple of 44 bytes")]
    BadChunkIndexLen(u32),
    #[error("too many TLV sections ({0}) to fit in a u16 count")]
    TooManyTlvSections(usize),
    #[error("TLV value too large ({0} bytes) to fit in a u32 length")]
    TlvValueTooLarge(usize),
    #[error("CBOR decode error: {0}")]
    Cbor(String),
    #[error("CBOR encode error: {0}")]
    CborEncode(String),
    #[error("signature verification failed")]
    SignatureInvalid,
    #[error("unsupported signature algorithm id {0}")]
    UnsupportedSigAlg(u8),
    #[error("chunk {index} hash mismatch")]
    ChunkHashMismatch { index: usize },
    #[error("too many chunks ({0}) to fit in a u32 count")]
    TooManyChunks(usize),
    #[error("chunk {index} is too large ({len} bytes) to fit in a u32 length")]
    ChunkTooLarge { index: usize, len: usize },
}
