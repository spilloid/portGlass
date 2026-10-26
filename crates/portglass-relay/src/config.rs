//! Relay configuration (`relay.toml`): which probes may register here. Controllers are not
//! listed: each probe publishes the controllers its own allowlist accepts, and the relay pairs
//! only those.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use portglass_core::identity::Fingerprint;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfigFile {
    pub relay: RelaySection,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default, rename = "probe")]
    pub probes: Vec<ProbeEntry>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySection {
    pub name: String,
    /// Address probes and controllers connect to, e.g. `0.0.0.0:47200`.
    pub listen: String,
    #[serde(default = "default_identity_dir")]
    pub identity_dir: PathBuf,
    #[serde(default = "default_audit_log")]
    pub audit_log: PathBuf,
}

fn default_identity_dir() -> PathBuf {
    "identity".into()
}
fn default_audit_log() -> PathBuf {
    "audit.jsonl".into()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Spliced connections one probe may have at once (each browser connection is one).
    #[serde(default = "d_pairs")]
    pub max_pairs_per_probe: u32,
    /// Controller requests waiting for one probe to answer.
    #[serde(default = "d_waiting")]
    pub max_waiting_per_probe: u32,
    /// How long a controller waits for the probe to answer before it is told the probe is
    /// unavailable.
    #[serde(default = "d_answer")]
    pub answer_timeout_secs: u32,
    /// A spliced connection with no traffic in either direction for this long is closed.
    #[serde(default = "d_idle")]
    pub idle_timeout_secs: u32,
    /// A registration with no traffic for this long is dropped (probes ping every 15 s).
    #[serde(default = "d_register")]
    pub registration_timeout_secs: u32,
}

fn d_pairs() -> u32 {
    256
}
fn d_waiting() -> u32 {
    32
}
fn d_answer() -> u32 {
    10
}
fn d_idle() -> u32 {
    300
}
fn d_register() -> u32 {
    45
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_pairs_per_probe: d_pairs(),
            max_waiting_per_probe: d_waiting(),
            answer_timeout_secs: d_answer(),
            idle_timeout_secs: d_idle(),
            registration_timeout_secs: d_register(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeEntry {
    /// Recorded in the audit log for this probe's certificate.
    pub name: String,
    pub fingerprint: Fingerprint,
}

/// Validated configuration with paths resolved.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub name: String,
    pub listen: String,
    pub identity_dir: PathBuf,
    pub audit_log: PathBuf,
    pub limits: Limits,
    pub probes: Vec<ProbeEntry>,
}

impl RelayConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: RelayConfigFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        RelayConfig::from_file(file, path.parent().unwrap_or(Path::new(".")))
    }

    pub fn from_file(file: RelayConfigFile, base: &Path) -> Result<Self> {
        let resolve = |p: &Path| {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };
        let mut seen = std::collections::HashSet::new();
        for p in &file.probes {
            if p.name.trim().is_empty() {
                bail!("a [[probe]] entry has an empty name");
            }
            if !seen.insert(p.fingerprint) {
                bail!("probe fingerprint {} is listed twice", p.fingerprint);
            }
        }
        let l = &file.limits;
        if l.max_pairs_per_probe == 0
            || l.max_waiting_per_probe == 0
            || l.answer_timeout_secs == 0
            || l.idle_timeout_secs == 0
            || l.registration_timeout_secs == 0
        {
            bail!("[limits] values must be greater than zero");
        }
        Ok(RelayConfig {
            name: file.relay.name,
            listen: file.relay.listen,
            identity_dir: resolve(&file.relay.identity_dir),
            audit_log: resolve(&file.relay.audit_log),
            limits: file.limits,
            probes: file.probes,
        })
    }

    pub fn probe_name(&self, fp: &Fingerprint) -> Option<&str> {
        self.probes
            .iter()
            .find(|p| &p.fingerprint == fp)
            .map(|p| p.name.as_str())
    }
}

/// The commented template written by `portglass-relay init`.
pub fn template(name: &str) -> String {
    format!(
        r#"# PortGlass Relay configuration.
# The relay lets a probe and a technician's controller meet when neither can reach the other.
# Both dial out to this relay; it copies their end-to-end encrypted connection and cannot read
# or alter it. Only probes listed below may register. Each probe tells the relay which
# technicians it accepts, and the relay pairs only those. Changes apply within a few seconds.

[relay]
name = "{name}"
# Open this TCP port to the internet (or to wherever your probes and technicians are).
listen = "0.0.0.0:{port}"
identity_dir = "identity"
audit_log = "audit.jsonl"

[limits]
max_pairs_per_probe = 256
max_waiting_per_probe = 32
answer_timeout_secs = 10
idle_timeout_secs = 300
registration_timeout_secs = 45

# One block per probe that may register. Get the fingerprint from `portglass-probe fingerprint`.
# [[probe]]
# name = "front-office"
# fingerprint = "sha256:...."
"#,
        port = portglass_proto::DEFAULT_RELAY_PORT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses() {
        let file: RelayConfigFile = toml::from_str(&template("t")).unwrap();
        let cfg = RelayConfig::from_file(file, Path::new(".")).unwrap();
        assert!(cfg.probes.is_empty());
        assert_eq!(cfg.limits.max_pairs_per_probe, 256);
    }

    #[test]
    fn unknown_keys_are_errors() {
        let text = "[relay]\nname='x'\nlisten='127.0.0.1:1'\nopen=true\n";
        assert!(toml::from_str::<RelayConfigFile>(text).is_err());
    }

    #[test]
    fn the_documented_example_parses() {
        let text = include_str!("../../../examples/relay.toml");
        let file: RelayConfigFile = toml::from_str(text).unwrap();
        let cfg = RelayConfig::from_file(file, Path::new(".")).unwrap();
        assert_eq!(cfg.probes.len(), 1);
    }
}
