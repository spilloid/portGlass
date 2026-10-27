//! Release pipeline tool. Builds and signs the manifest that installed copies of PortGlass trust
//! for updates (see `portglass_core::update`). Run by the release workflow; never shipped.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use portglass_core::update::{self, Manifest, ManifestFile, MANIFEST_NAME, UPDATE_KEYS};

/// Every program a release must carry, per platform. A manifest missing one is refused, so a
/// failed platform job can't produce a release that quietly strands that platform's installs.
const EXPECTED: &[(&str, &str, &str)] = &[
    ("windows-x64", "portglass", ".exe"),
    ("windows-x64", "portglass-probe", ".exe"),
    ("windows-x64", "portglass-relay", ".exe"),
    ("macos-arm64", "portglass", ""),
    ("linux-x64", "portglass-relay", ""),
];

/// The release asset name of one program's raw binary.
fn asset_name(program: &str, version: &str, platform: &str, ext: &str) -> String {
    format!("{program}-v{version}-{platform}{ext}")
}

#[derive(Parser)]
#[command(
    name = "portglass-release",
    about = "PortGlass release signing (CI only)"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an update-signing key. Writes the private key (hex PKCS#8) to --out and prints the
    /// public key for `UPDATE_KEYS`.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Hash the raw binaries in --dir into a manifest.
    Manifest {
        #[arg(long)]
        version: String,
        #[arg(long)]
        dir: PathBuf,
    },
    /// Sign --dir/portglass-manifest.json with the key in the environment variable --key-env.
    Sign {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "UPDATE_SIGNING_KEY")]
        key_env: String,
    },
    /// Check the signed manifest in --dir against the compiled-in keys and the files beside it,
    /// exactly as an installed copy would.
    Verify {
        #[arg(long)]
        dir: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Cmd::Keygen { out } => {
            if out.exists() {
                bail!("{} exists; refusing to overwrite a key", out.display());
            }
            let (private, public) = update::generate_signing_key()?;
            std::fs::write(&out, format!("{private}\n"))?;
            println!("Private key written to {}.", out.display());
            println!("Keep it offline and store it as the release environment's");
            println!("UPDATE_SIGNING_KEY secret. Public key for UPDATE_KEYS:");
            println!("{public}");
            Ok(())
        }
        Cmd::Manifest { version, dir } => {
            let m = build_manifest(&version, &dir)?;
            let path = dir.join(MANIFEST_NAME);
            std::fs::write(&path, serde_json::to_vec_pretty(&m)?)?;
            println!("Wrote {} ({} files).", path.display(), m.files.len());
            Ok(())
        }
        Cmd::Sign { dir, key_env } => {
            let key = std::env::var(&key_env)
                .ok()
                .filter(|k| !k.trim().is_empty())
                .with_context(|| format!("{key_env} is not set; releases are never unsigned"))?;
            let path = dir.join(MANIFEST_NAME);
            let sig = update::sign(&key, &std::fs::read(&path)?)?;
            std::fs::write(dir.join(format!("{MANIFEST_NAME}.sig")), &sig)?;
            println!("Signed {}.", path.display());
            Ok(())
        }
        Cmd::Verify { dir } => verify(&dir),
    }
}

fn build_manifest(version: &str, dir: &Path) -> Result<Manifest> {
    if update::parse_version(version).is_none() || version.starts_with('v') {
        bail!("--version must look like 1.2.3");
    }
    let mut files = Vec::new();
    for (platform, program, ext) in EXPECTED {
        let name = asset_name(program, version, platform, ext);
        let body = std::fs::read(dir.join(&name))
            .with_context(|| format!("{name} is missing from {}", dir.display()))?;
        files.push(ManifestFile {
            platform: platform.to_string(),
            program: program.to_string(),
            sha256: hex::encode(ring::digest::digest(&ring::digest::SHA256, &body)),
            size: body.len() as u64,
            name,
        });
    }
    Ok(Manifest {
        schema: 1,
        product: "portglass".into(),
        version: version.into(),
        files,
    })
}

fn verify(dir: &Path) -> Result<()> {
    let bytes = std::fs::read(dir.join(MANIFEST_NAME))?;
    let sig = std::fs::read_to_string(dir.join(format!("{MANIFEST_NAME}.sig")))?;
    let m = update::verify_manifest(&bytes, &sig, UPDATE_KEYS)
        .context("the manifest does not verify with the keys compiled into this release")?;
    for f in &m.files {
        let body = std::fs::read(dir.join(&f.name))?;
        let digest = hex::encode(ring::digest::digest(&ring::digest::SHA256, &body));
        if digest != f.sha256 || body.len() as u64 != f.size {
            bail!("{} does not match the manifest", f.name);
        }
    }
    println!(
        "OK: v{} manifest verifies; {} files match.",
        m.version,
        m.files.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_manifest_needs_every_platform_and_round_trips_through_signing() {
        let dir = tempfile::tempdir().unwrap();
        for (i, (platform, program, ext)) in EXPECTED.iter().enumerate() {
            if i == EXPECTED.len() - 1 {
                assert!(build_manifest("0.4.0", dir.path()).is_err());
            }
            let name = asset_name(program, "0.4.0", platform, ext);
            std::fs::write(dir.path().join(name), format!("binary {i}")).unwrap();
        }
        assert!(build_manifest("v0.4.0", dir.path()).is_err());
        let m = build_manifest("0.4.0", dir.path()).unwrap();
        assert_eq!(m.files.len(), EXPECTED.len());

        let (sk, pk) = update::generate_signing_key().unwrap();
        let bytes = serde_json::to_vec_pretty(&m).unwrap();
        let sig = update::sign(&sk, &bytes).unwrap();
        assert_eq!(update::verify_manifest(&bytes, &sig, &[&pk]).unwrap(), m);
    }
}
