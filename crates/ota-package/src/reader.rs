//! Parsing and verification of a `.otapkg` v1 byte stream.
//!
//! `parse` reads and structurally validates a package (header/manifest/chunk-index/
//! trailer CRCs, magic, version) without touching the cryptography. `verify` additionally
//! checks the Ed25519 signature over `manifest || chunk_index` and every chunk's SHA-256 —
//! this is the "decision point" from ADR 0001: the signature check happens before any
//! payload byte is trusted, so a caller could stage chunks as they stream in rather than
//! requiring the whole file in memory, as this in-memory reference implementation does.

use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use signature::Verifier;

use crate::chunk::ChunkIndex;
use crate::header::{Header, HEADER_LEN, TRAILER_MAGIC};
use crate::manifest::Manifest;
use crate::tlv::{self, TlvSection};
use crate::PackageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub alg: u8,
    pub pubkey_id: [u8; 32],
    pub sig: Vec<u8>,
}

pub struct ParsedPackage {
    pub header: Header,
    pub manifest: Manifest,
    pub manifest_raw: Vec<u8>,
    pub chunk_index: ChunkIndex,
    pub chunk_index_raw: Vec<u8>,
    pub chunks: Vec<Vec<u8>>,
    pub tlv_sections: Vec<TlvSection>,
    pub signature: Signature,
}

fn need(bytes: &[u8], at: usize, len: usize) -> Result<(), PackageError> {
    if bytes.len() < at + len {
        Err(PackageError::Truncated {
            needed: at + len,
            got: bytes.len(),
        })
    } else {
        Ok(())
    }
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, PackageError> {
    need(bytes, at, 4)?;
    Ok(u32::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
    ]))
}

/// Structurally parses and validates a `.otapkg` v1 byte slice: header, magic, version,
/// manifest/chunk-index CRC, chunk-index shape, trailer CRC and magic. Does not check the
/// cryptographic signature or per-chunk hashes — use [`verify`] for that.
pub fn parse(bytes: &[u8]) -> Result<ParsedPackage, PackageError> {
    let header = Header::from_bytes(bytes)?;
    let mut cursor = HEADER_LEN;

    let manifest_len = header.manifest_len as usize;
    need(bytes, cursor, manifest_len)?;
    let manifest_raw = bytes[cursor..cursor + manifest_len].to_vec();
    cursor += manifest_len;

    let chunk_index_len = read_u32(bytes, cursor)? as usize;
    cursor += 4;
    need(bytes, cursor, chunk_index_len)?;
    let chunk_index_raw = bytes[cursor..cursor + chunk_index_len].to_vec();
    cursor += chunk_index_len;

    let mut header_hasher = crc32fast::Hasher::new();
    header_hasher.update(&manifest_raw);
    header_hasher.update(&chunk_index_raw);
    if header_hasher.finalize() != header.header_crc32 {
        return Err(PackageError::HeaderCrcMismatch);
    }

    let manifest = Manifest::from_cbor(&manifest_raw)?;
    let chunk_index = ChunkIndex::from_bytes(&chunk_index_raw)?;

    let mut chunks = Vec::with_capacity(chunk_index.0.len());
    for entry in &chunk_index.0 {
        let len = entry.length as usize;
        need(bytes, cursor, len)?;
        chunks.push(bytes[cursor..cursor + len].to_vec());
        cursor += len;
    }

    let (tlv_sections, consumed) = tlv::decode_sections(&bytes[cursor..])?;
    cursor += consumed;

    let signature_len = read_u32(bytes, cursor)? as usize;
    cursor += 4;
    need(bytes, cursor, signature_len)?;
    if signature_len < 33 {
        return Err(PackageError::Truncated {
            needed: cursor + 33,
            got: bytes.len(),
        });
    }
    let sig_block = &bytes[cursor..cursor + signature_len];
    let alg = sig_block[0];
    let mut pubkey_id = [0u8; 32];
    pubkey_id.copy_from_slice(&sig_block[1..33]);
    let sig = sig_block[33..].to_vec();
    cursor += signature_len;

    let trailer_start = cursor;
    need(bytes, cursor, 12)?;
    let trailer_crc32 = read_u32(bytes, cursor)?;
    cursor += 4;
    if bytes[cursor..cursor + 8] != TRAILER_MAGIC {
        return Err(PackageError::BadTrailerMagic);
    }
    cursor += 8;

    if cursor != bytes.len() {
        return Err(PackageError::Truncated {
            needed: cursor,
            got: bytes.len(),
        });
    }

    let mut trailer_hasher = crc32fast::Hasher::new();
    trailer_hasher.update(&bytes[0..trailer_start]);
    if trailer_hasher.finalize() != trailer_crc32 {
        return Err(PackageError::TrailerCrcMismatch);
    }

    Ok(ParsedPackage {
        header,
        manifest,
        manifest_raw,
        chunk_index,
        chunk_index_raw,
        chunks,
        tlv_sections,
        signature: Signature {
            alg,
            pubkey_id,
            sig,
        },
    })
}

/// Parses `bytes`, then verifies the Ed25519 signature over `manifest || chunk_index` and
/// every chunk's SHA-256 against its chunk-index entry.
pub fn verify(bytes: &[u8], pubkey: &VerifyingKey) -> Result<ParsedPackage, PackageError> {
    let parsed = parse(bytes)?;

    if parsed.signature.alg != 1 {
        return Err(PackageError::UnsupportedSigAlg(parsed.signature.alg));
    }
    let sig_bytes: [u8; 64] = parsed
        .signature
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| PackageError::SignatureInvalid)?;
    let signature = EdSignature::from_bytes(&sig_bytes);

    let mut message = Vec::with_capacity(parsed.manifest_raw.len() + parsed.chunk_index_raw.len());
    message.extend_from_slice(&parsed.manifest_raw);
    message.extend_from_slice(&parsed.chunk_index_raw);
    pubkey
        .verify(&message, &signature)
        .map_err(|_| PackageError::SignatureInvalid)?;

    for (i, (entry, chunk)) in parsed
        .chunk_index
        .0
        .iter()
        .zip(parsed.chunks.iter())
        .enumerate()
    {
        let digest: [u8; 32] = Sha256::digest(chunk).into();
        if digest != entry.sha256 {
            return Err(PackageError::ChunkHashMismatch { index: i });
        }
    }

    Ok(parsed)
}
