//! Assembles a manifest and chunks into a signed `.otapkg` v1 byte stream.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

use crate::chunk::{ChunkEntry, ChunkIndex};
use crate::header::{Header, MAX_MANIFEST_LEN, TRAILER_MAGIC};
use crate::manifest::Manifest;
use crate::tlv::{self, TlvSection};
use crate::PackageError;

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub struct PackageBuilder {
    manifest: Manifest,
    chunks: Vec<Vec<u8>>,
    tlv_sections: Vec<TlvSection>,
}

impl PackageBuilder {
    pub fn new(manifest: Manifest) -> Self {
        Self {
            manifest,
            chunks: Vec::new(),
            tlv_sections: Vec::new(),
        }
    }

    pub fn add_chunk(mut self, data: Vec<u8>) -> Self {
        self.chunks.push(data);
        self
    }

    pub fn add_tlv(mut self, section: TlvSection) -> Self {
        self.tlv_sections.push(section);
        self
    }

    /// Splits `payload` into chunks of at most `chunk_size` bytes and adds them in order.
    pub fn with_payload_chunked(mut self, payload: &[u8], chunk_size: usize) -> Self {
        for part in payload.chunks(chunk_size.max(1)) {
            self.chunks.push(part.to_vec());
        }
        self
    }

    /// Finalizes the manifest's `chunk_count`/`total_payload_size`, encodes everything,
    /// signs `manifest || chunk_index` with `signing_key`, and returns the full byte stream.
    pub fn build_and_sign(mut self, signing_key: &SigningKey) -> Result<Vec<u8>, PackageError> {
        let chunk_count = u32::try_from(self.chunks.len())
            .map_err(|_| PackageError::TooManyChunks(self.chunks.len()))?;

        let mut chunk_entries = Vec::with_capacity(self.chunks.len());
        let mut offset: u64 = 0;
        let mut total_payload_size: u64 = 0;
        for (i, chunk) in self.chunks.iter().enumerate() {
            let length = u32::try_from(chunk.len()).map_err(|_| PackageError::ChunkTooLarge {
                index: i,
                len: chunk.len(),
            })?;
            let sha256: [u8; 32] = Sha256::digest(chunk).into();
            chunk_entries.push(ChunkEntry {
                offset,
                length,
                sha256,
            });
            offset += u64::from(length);
            total_payload_size += u64::from(length);
        }

        self.manifest.chunk_count = chunk_count;
        self.manifest.total_payload_size = total_payload_size;

        // package_id is the SHA-256 of the chunk index alone (not manifest || chunk_index):
        // the manifest contains package_id, so hashing the manifest into its own identity
        // would be circular. The chunk index already captures payload identity.
        let chunk_index_raw_for_id = ChunkIndex(chunk_entries.clone()).to_bytes();
        let package_id_hash: [u8; 32] = Sha256::digest(&chunk_index_raw_for_id).into();
        self.manifest.package_id = format!("sha256:{}", hex(&package_id_hash));

        let manifest_raw = self.manifest.to_cbor()?;
        if manifest_raw.len() > MAX_MANIFEST_LEN as usize {
            return Err(PackageError::ManifestTooLarge(
                manifest_raw.len() as u32,
                MAX_MANIFEST_LEN,
            ));
        }
        let chunk_index_raw = ChunkIndex(chunk_entries).to_bytes();

        let mut header_hasher = crc32fast::Hasher::new();
        header_hasher.update(&manifest_raw);
        header_hasher.update(&chunk_index_raw);
        let header = Header::new(header_hasher.finalize(), manifest_raw.len() as u32);

        let mut message = Vec::with_capacity(manifest_raw.len() + chunk_index_raw.len());
        message.extend_from_slice(&manifest_raw);
        message.extend_from_slice(&chunk_index_raw);
        let signature = signing_key.sign(&message);
        let pubkey_id: [u8; 32] = Sha256::digest(signing_key.verifying_key().as_bytes()).into();

        let mut out = Vec::new();
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&manifest_raw);
        out.extend_from_slice(
            &u32::try_from(chunk_index_raw.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&chunk_index_raw);
        for chunk in &self.chunks {
            out.extend_from_slice(chunk);
        }
        out.extend_from_slice(&tlv::encode_sections(&self.tlv_sections)?);

        let sig_bytes = signature.to_bytes();
        let mut sig_block = Vec::with_capacity(33 + sig_bytes.len());
        sig_block.push(1u8); // alg = Ed25519, the only value defined in v1.0
        sig_block.extend_from_slice(&pubkey_id);
        sig_block.extend_from_slice(&sig_bytes);
        out.extend_from_slice(
            &u32::try_from(sig_block.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&sig_block);

        let trailer_crc32 = crc32fast::hash(&out);
        out.extend_from_slice(&trailer_crc32.to_le_bytes());
        out.extend_from_slice(&TRAILER_MAGIC);

        Ok(out)
    }
}
