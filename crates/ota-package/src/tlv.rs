//! Optional TLV sections. An unrecognized tag MUST be skipped using its length —
//! this is the v1.x forward-compatibility mechanism. See ADR 0001.

use crate::PackageError;

pub const TAG_DELTA_REFERENCE_HINT: u16 = 0x0001;
pub const TAG_PROVENANCE: u16 = 0x0002;
pub const TAG_QUANTIZATION_DETAIL: u16 = 0x0003;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvSection {
    pub tag: u16,
    pub value: Vec<u8>,
}

/// Encodes `tlv_section_count` (u16) followed by each `{tag:u16, len:u32, value}` record.
pub fn encode_sections(sections: &[TlvSection]) -> Result<Vec<u8>, PackageError> {
    let count = u16::try_from(sections.len())
        .map_err(|_| PackageError::TooManyTlvSections(sections.len()))?;
    let mut out = Vec::new();
    out.extend_from_slice(&count.to_le_bytes());
    for section in sections {
        out.extend_from_slice(&section.tag.to_le_bytes());
        let len = u32::try_from(section.value.len())
            .map_err(|_| PackageError::TlvValueTooLarge(section.value.len()))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&section.value);
    }
    Ok(out)
}

/// Decodes the `tlv_section_count`-prefixed TLV list starting at `buf[0]`.
/// Returns the decoded sections and the number of bytes consumed.
pub fn decode_sections(buf: &[u8]) -> Result<(Vec<TlvSection>, usize), PackageError> {
    if buf.len() < 2 {
        return Err(PackageError::Truncated {
            needed: 2,
            got: buf.len(),
        });
    }
    let count = u16::from_le_bytes([buf[0], buf[1]]);
    let mut cursor = 2usize;
    let mut sections = Vec::with_capacity(count as usize);
    for _ in 0..count {
        if buf.len() < cursor + 6 {
            return Err(PackageError::Truncated {
                needed: cursor + 6,
                got: buf.len(),
            });
        }
        let tag = u16::from_le_bytes([buf[cursor], buf[cursor + 1]]);
        let len = u32::from_le_bytes([
            buf[cursor + 2],
            buf[cursor + 3],
            buf[cursor + 4],
            buf[cursor + 5],
        ]) as usize;
        cursor += 6;
        if buf.len() < cursor + len {
            return Err(PackageError::Truncated {
                needed: cursor + len,
                got: buf.len(),
            });
        }
        let value = buf[cursor..cursor + len].to_vec();
        cursor += len;
        // Unknown tags are kept in the decoded list (the caller may ignore them);
        // the point of TLV is that decoding never fails on an unrecognized tag.
        sections.push(TlvSection { tag, value });
    }
    Ok((sections, cursor))
}
