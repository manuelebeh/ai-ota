//! Chunk index: fixed 44-byte records describing each payload chunk.
//! See `docs/reference/formats/package-format.md`.

use crate::PackageError;

pub const CHUNK_RECORD_LEN: usize = 44;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkEntry {
    pub offset: u64,
    pub length: u32,
    pub sha256: [u8; 32],
}

impl ChunkEntry {
    pub fn to_bytes(&self) -> [u8; CHUNK_RECORD_LEN] {
        let mut buf = [0u8; CHUNK_RECORD_LEN];
        buf[0..8].copy_from_slice(&self.offset.to_le_bytes());
        buf[8..12].copy_from_slice(&self.length.to_le_bytes());
        buf[12..44].copy_from_slice(&self.sha256);
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, PackageError> {
        if buf.len() < CHUNK_RECORD_LEN {
            return Err(PackageError::Truncated {
                needed: CHUNK_RECORD_LEN,
                got: buf.len(),
            });
        }
        let offset = u64::from_le_bytes(
            buf[0..8]
                .try_into()
                .map_err(|_| PackageError::BadChunkIndexLen(buf.len() as u32))?,
        );
        let length = u32::from_le_bytes(
            buf[8..12]
                .try_into()
                .map_err(|_| PackageError::BadChunkIndexLen(buf.len() as u32))?,
        );
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&buf[12..44]);
        Ok(Self {
            offset,
            length,
            sha256,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkIndex(pub Vec<ChunkEntry>);

impl ChunkIndex {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() * CHUNK_RECORD_LEN);
        for entry in &self.0 {
            out.extend_from_slice(&entry.to_bytes());
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, PackageError> {
        if !buf.len().is_multiple_of(CHUNK_RECORD_LEN) {
            return Err(PackageError::BadChunkIndexLen(
                u32::try_from(buf.len()).unwrap_or(u32::MAX),
            ));
        }
        let (records, _) = buf.as_chunks::<CHUNK_RECORD_LEN>();
        let mut entries = Vec::with_capacity(records.len());
        for chunk in records {
            entries.push(ChunkEntry::from_bytes(chunk)?);
        }
        Ok(Self(entries))
    }
}
