//! Fixed 16-byte `.otapkg` v1 header. See `docs/reference/formats/package-format.md`.

use crate::PackageError;

pub const MAGIC: [u8; 4] = *b"OTAP";
pub const TRAILER_MAGIC: [u8; 8] = *b"OTAPEND!";
pub const VERSION_MAJOR: u8 = 1;
pub const VERSION_MINOR: u8 = 0;
pub const HEADER_LEN: usize = 16;
/// Hard RAM-budget constant from ADR 0001: a manifest larger than this is rejected
/// before any of its bytes are read into the parse buffer.
pub const MAX_MANIFEST_LEN: u32 = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version_major: u8,
    pub version_minor: u8,
    pub flags: u16,
    pub header_crc32: u32,
    pub manifest_len: u32,
}

impl Header {
    pub fn new(header_crc32: u32, manifest_len: u32) -> Self {
        Self {
            version_major: VERSION_MAJOR,
            version_minor: VERSION_MINOR,
            flags: 0,
            header_crc32,
            manifest_len,
        }
    }

    #[must_use]
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = self.version_major;
        buf[5] = self.version_minor;
        buf[6..8].copy_from_slice(&self.flags.to_le_bytes());
        buf[8..12].copy_from_slice(&self.header_crc32.to_le_bytes());
        buf[12..16].copy_from_slice(&self.manifest_len.to_le_bytes());
        buf
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, PackageError> {
        if buf.len() < HEADER_LEN {
            return Err(PackageError::Truncated {
                needed: HEADER_LEN,
                got: buf.len(),
            });
        }
        if buf[0..4] != MAGIC {
            return Err(PackageError::BadMagic);
        }
        let version_major = buf[4];
        if version_major != VERSION_MAJOR {
            return Err(PackageError::UnsupportedVersion(version_major));
        }
        let version_minor = buf[5];
        let flags = u16::from_le_bytes([buf[6], buf[7]]);
        let header_crc32 = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let manifest_len = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]);
        if manifest_len > MAX_MANIFEST_LEN {
            return Err(PackageError::ManifestTooLarge(
                manifest_len,
                MAX_MANIFEST_LEN,
            ));
        }
        Ok(Self {
            version_major,
            version_minor,
            flags,
            header_crc32,
            manifest_len,
        })
    }
}
