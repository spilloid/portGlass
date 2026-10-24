//! Device identities: one self-signed ECDSA P-256 certificate per controller or probe.
//!
//! Trust is established by exchanging SHA-256 fingerprints out of band (the probe administrator
//! adds a controller's fingerprint to the probe's allowlist; the technician pins the probe's
//! fingerprint). Certificate chains and expiry are deliberately not part of the trust decision —
//! a fingerprint is either on the list or it is not.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// SHA-256 over the DER encoding of an end-entity certificate.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub [u8; 32]);

impl Fingerprint {
    pub fn of(cert_der: &[u8]) -> Self {
        let digest = ring::digest::digest(&ring::digest::SHA256, cert_der);
        let mut out = [0u8; 32];
        out.copy_from_slice(digest.as_ref());
        Fingerprint(out)
    }

    /// First 8 groups, for compact display. Never use the short form for trust decisions.
    pub fn short(&self) -> String {
        self.to_string()
            .trim_start_matches("sha256:")
            .split(':')
            .take(8)
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex = hex::encode_upper(self.0);
        let grouped: Vec<&str> = (0..hex.len()).step_by(4).map(|i| &hex[i..i + 4]).collect();
        write!(f, "sha256:{}", grouped.join(":"))
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for Fingerprint {
    type Err = anyhow::Error;

    /// Accepts `sha256:` prefixed or bare hex, any case, with `:`, spaces or `-` as separators.
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let s = s
            .strip_prefix("sha256:")
            .or_else(|| s.strip_prefix("SHA256:"))
            .unwrap_or(s);
        let hex: String = s
            .chars()
            .filter(|c| !matches!(c, ':' | ' ' | '-'))
            .collect();
        let bytes = hex::decode(&hex).context("fingerprint is not hexadecimal")?;
        if bytes.len() != 32 {
            bail!(
                "fingerprint must be 32 bytes (64 hex digits), got {}",
                bytes.len()
            );
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Fingerprint(out))
    }
}

impl serde::Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for Fingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A loaded certificate and private key.
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
    pub fingerprint: Fingerprint,
}

impl Clone for Identity {
    fn clone(&self) -> Self {
        Identity {
            cert: self.cert.clone(),
            key: self.key.clone_key(),
            fingerprint: self.fingerprint,
        }
    }
}

impl Identity {
    /// Generate a fresh identity in memory. `role` is `controller` or `probe`; `name` goes into
    /// the certificate's common name for human readers (it carries no authority).
    pub fn generate(role: &str, name: &str) -> Result<(Self, String, String)> {
        let mut params = rcgen::CertificateParams::new(vec![format!("portglass-{role}")])
            .context("building certificate parameters")?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("PortGlass {role}: {name}"),
        );
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "PortGlass");
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(365 * 5);
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .context("generating key pair")?;
        let cert = params
            .self_signed(&key)
            .context("self-signing certificate")?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        let identity = Identity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        Ok((identity, cert_pem, key_pem))
    }

    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let cert = CertificateDer::from_pem_slice(cert_pem).context("reading certificate PEM")?;
        let key = PrivateKeyDer::from_pem_slice(key_pem).context("reading private key PEM")?;
        let fingerprint = Fingerprint::of(&cert);
        Ok(Identity {
            cert,
            key,
            fingerprint,
        })
    }

    pub fn load(dir: &Path, role: &str) -> Result<Self> {
        let (cert_path, key_path) = paths(dir, role);
        let cert = std::fs::read(&cert_path)
            .with_context(|| format!("reading {}", cert_path.display()))?;
        let key =
            std::fs::read(&key_path).with_context(|| format!("reading {}", key_path.display()))?;
        Identity::from_pem(&cert, &key)
    }

    /// Generate and write `<role>.crt` and `<role>.key` into `dir`. Refuses to overwrite an
    /// existing identity: replacing it silently would break every pairing that trusts it.
    pub fn create(dir: &Path, role: &str, name: &str) -> Result<Self> {
        let (cert_path, key_path) = paths(dir, role);
        if cert_path.exists() || key_path.exists() {
            bail!(
                "an identity already exists in {} (delete it deliberately to replace it)",
                dir.display()
            );
        }
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let (identity, cert_pem, key_pem) = Identity::generate(role, name)?;
        write_new(&key_path, key_pem.as_bytes())?;
        restrict_to_owner(&key_path);
        write_new(&cert_path, cert_pem.as_bytes())?;
        Ok(identity)
    }
}

fn paths(dir: &Path, role: &str) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{role}.crt")),
        dir.join(format!("{role}.key")),
    )
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    Ok(())
}

/// Best effort: remove inherited ACEs so only the current user, SYSTEM and Administrators can
/// read the private key. Failure is reported, not fatal — the installer also sets directory ACLs.
fn restrict_to_owner(path: &Path) {
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        if user.is_empty() {
            return;
        }
        let status = std::process::Command::new("icacls")
            .arg(path)
            .args(["/inheritance:r", "/grant:r"])
            .arg(format!("{user}:F"))
            .args(["/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        if !matches!(status, Ok(s) if s.success()) {
            tracing::warn!(
                "could not restrict permissions on {}; restrict them manually",
                path.display()
            );
        }
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_round_trips_through_every_accepted_spelling() {
        let (id, _, _) = Identity::generate("probe", "test").unwrap();
        let canonical = id.fingerprint.to_string();
        assert!(canonical.starts_with("sha256:"));
        let bare = canonical.trim_start_matches("sha256:").replace(':', "");
        for s in [canonical.clone(), bare.to_lowercase(), bare.clone()] {
            assert_eq!(s.parse::<Fingerprint>().unwrap(), id.fingerprint);
        }
        assert!("sha256:abcd".parse::<Fingerprint>().is_err());
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::create(dir.path(), "probe", "p").unwrap();
        assert!(Identity::create(dir.path(), "probe", "p").is_err());
        let b = Identity::load(dir.path(), "probe").unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
    }
}
