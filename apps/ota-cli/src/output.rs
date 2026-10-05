//! Shared text/JSON rendering for `ota-cli package inspect`.

use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
}

#[derive(Serialize)]
pub struct HeaderReport {
    pub version_major: u8,
    pub version_minor: u8,
    pub flags: u16,
    pub header_crc32: String,
    pub manifest_len: u32,
}

#[derive(Serialize)]
pub struct ChunkReport {
    pub index: usize,
    pub offset: u64,
    pub length: u32,
    pub sha256: String,
}

#[derive(Serialize)]
pub struct TlvReport {
    pub tag: u16,
    pub len: usize,
}

#[derive(Serialize)]
pub struct SignatureReport {
    pub alg: u8,
    pub pubkey_id: String,
    pub sig_len: usize,
}

#[derive(Serialize)]
pub struct InspectReport {
    pub header: HeaderReport,
    pub manifest: ota_package::Manifest,
    pub chunk_index: Vec<ChunkReport>,
    pub tlv_sections: Vec<TlvReport>,
    pub signature: SignatureReport,
}

pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl From<&ota_package::ParsedPackage> for InspectReport {
    fn from(parsed: &ota_package::ParsedPackage) -> Self {
        InspectReport {
            header: HeaderReport {
                version_major: parsed.header.version_major,
                version_minor: parsed.header.version_minor,
                flags: parsed.header.flags,
                header_crc32: format!("{:08x}", parsed.header.header_crc32),
                manifest_len: parsed.header.manifest_len,
            },
            manifest: parsed.manifest.clone(),
            chunk_index: parsed
                .chunk_index
                .0
                .iter()
                .enumerate()
                .map(|(index, entry)| ChunkReport {
                    index,
                    offset: entry.offset,
                    length: entry.length,
                    sha256: hex(&entry.sha256),
                })
                .collect(),
            tlv_sections: parsed
                .tlv_sections
                .iter()
                .map(|section| TlvReport {
                    tag: section.tag,
                    len: section.value.len(),
                })
                .collect(),
            signature: SignatureReport {
                alg: parsed.signature.alg,
                pubkey_id: hex(&parsed.signature.pubkey_id),
                sig_len: parsed.signature.sig.len(),
            },
        }
    }
}

pub fn print_report(report: &InspectReport, format: Format) -> anyhow::Result<()> {
    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(report)?);
        }
        Format::Text => {
            println!(
                "header: version={}.{} flags={} header_crc32={} manifest_len={}",
                report.header.version_major,
                report.header.version_minor,
                report.header.flags,
                report.header.header_crc32,
                report.header.manifest_len
            );
            println!(
                "manifest: package_id={} target_platform={} chunk_count={} total_payload_size={}",
                report.manifest.package_id,
                report.manifest.target_platform,
                report.manifest.chunk_count,
                report.manifest.total_payload_size
            );
            println!("chunk_index ({} entries):", report.chunk_index.len());
            for chunk in &report.chunk_index {
                println!(
                    "  [{}] offset={} length={} sha256={}",
                    chunk.index, chunk.offset, chunk.length, chunk.sha256
                );
            }
            println!("tlv_sections ({} entries):", report.tlv_sections.len());
            for tlv in &report.tlv_sections {
                println!("  tag={:#06x} len={}", tlv.tag, tlv.len);
            }
            println!(
                "signature: alg={} pubkey_id={} sig_len={}",
                report.signature.alg, report.signature.pubkey_id, report.signature.sig_len
            );
        }
    }
    Ok(())
}
