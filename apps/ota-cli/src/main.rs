mod output;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use ota_package::{Manifest, PackageBuilder};

use output::{print_report, Format, InspectReport};

#[derive(Parser)]
#[command(name = "ota-cli", about = "The ai-ota command-line interface")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build, inspect and verify .otapkg files
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
}

#[derive(Subcommand)]
enum PackageCommand {
    /// Build a signed .otapkg from a manifest JSON file and a payload file
    Build {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        payload: PathBuf,
        /// Path to a raw 32-byte Ed25519 signing-key seed
        #[arg(long)]
        key: PathBuf,
        #[arg(long, default_value_t = 1024)]
        chunk_size: usize,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Dump header, manifest, chunk index, TLV sections and signature
    Inspect {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Verify a .otapkg's signature and every chunk hash
    Verify {
        file: PathBuf,
        /// Path to a raw 32-byte Ed25519 public key
        #[arg(long)]
        pubkey: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Package { command } => match command {
            PackageCommand::Build {
                manifest,
                payload,
                key,
                chunk_size,
                output,
            } => build(&manifest, &payload, &key, chunk_size, &output),
            PackageCommand::Inspect { file, format } => inspect(&file, format),
            PackageCommand::Verify { file, pubkey } => verify_cmd(&file, &pubkey),
        },
    }
}

fn build(
    manifest_path: &Path,
    payload_path: &Path,
    key_path: &Path,
    chunk_size: usize,
    output_path: &Path,
) -> Result<()> {
    let manifest_json = fs::read_to_string(manifest_path)
        .with_context(|| format!("reading manifest {}", manifest_path.display()))?;
    let manifest: Manifest =
        serde_json::from_str(&manifest_json).context("parsing manifest JSON")?;
    let payload = fs::read(payload_path)
        .with_context(|| format!("reading payload {}", payload_path.display()))?;
    let seed = fs::read(key_path)
        .with_context(|| format!("reading signing key {}", key_path.display()))?;
    let seed: [u8; 32] = seed.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "signing key must be exactly 32 raw bytes, got {}",
            seed.len()
        )
    })?;
    let signing_key = SigningKey::from_bytes(&seed);

    let bytes = PackageBuilder::new(manifest)
        .with_payload_chunked(&payload, chunk_size)
        .build_and_sign(&signing_key)?;

    fs::write(output_path, &bytes).with_context(|| format!("writing {}", output_path.display()))?;
    println!("wrote {} ({} bytes)", output_path.display(), bytes.len());
    Ok(())
}

fn inspect(file: &Path, format: Format) -> Result<()> {
    let bytes = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let parsed = ota_package::parse(&bytes)?;
    let report = InspectReport::from(&parsed);
    print_report(&report, format)
}

fn verify_cmd(file: &Path, pubkey_path: &Path) -> Result<()> {
    let bytes = fs::read(file).with_context(|| format!("reading {}", file.display()))?;
    let pubkey_bytes = fs::read(pubkey_path)
        .with_context(|| format!("reading pubkey {}", pubkey_path.display()))?;
    let pubkey_bytes: [u8; 32] = pubkey_bytes.as_slice().try_into().map_err(|_| {
        anyhow::anyhow!(
            "public key must be exactly 32 raw bytes, got {}",
            pubkey_bytes.len()
        )
    })?;
    let pubkey = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| anyhow::anyhow!("invalid public key bytes: {e}"))?;

    match ota_package::verify(&bytes, &pubkey) {
        Ok(parsed) => {
            println!(
                "OK: {} chunks verified, signature valid",
                parsed.chunks.len()
            );
            Ok(())
        }
        Err(e) => bail!("verification failed: {e}"),
    }
}
