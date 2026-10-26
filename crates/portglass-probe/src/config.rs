//! Probe configuration (`probe.toml`). Everything the probe may do is written here by an
//! administrator: which controllers may connect, and which destinations they may reach.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use portglass_core::identity::Fingerprint;
use serde::Deserialize;

use crate::policy::{AllowRule, PortSet};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeConfigFile {
    pub probe: ProbeSection,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default, rename = "controller")]
    pub controllers: Vec<ControllerEntry>,
    #[serde(default, rename = "allow")]
    pub allow: Vec<AllowEntry>,
    /// Register with a PortGlass Relay, for technicians who cannot reach `listen` directly.
    #[serde(default)]
    pub relay: Option<RelayEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayEntry {
    /// host:port of the relay, e.g. `relay.example.com:47200`.
    pub address: String,
    /// The relay's fingerprint (`portglass-relay fingerprint`).
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSection {
    pub name: String,
    /// Address the probe accepts controller connections on, e.g. `0.0.0.0:47100`.
    pub listen: String,
    /// Directory holding `probe.crt` and `probe.key`; relative paths are relative to the config.
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
    #[serde(default = "d_max_ttl")]
    pub max_session_ttl_secs: u32,
    #[serde(default = "d_streams")]
    pub max_streams_per_session: u32,
    #[serde(default = "d_sessions")]
    pub max_sessions: u32,
    #[serde(default = "d_idle")]
    pub stream_idle_timeout_secs: u32,
    #[serde(default = "d_connect")]
    pub connect_timeout_secs: u32,
    /// The control connection is dropped (and its sessions revoked) after this much silence.
    #[serde(default = "d_heartbeat")]
    pub control_timeout_secs: u32,
}

fn d_max_ttl() -> u32 {
    4 * 3600
}
fn d_streams() -> u32 {
    32
}
fn d_sessions() -> u32 {
    4
}
fn d_idle() -> u32 {
    300
}
fn d_connect() -> u32 {
    5
}
fn d_heartbeat() -> u32 {
    30
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_session_ttl_secs: d_max_ttl(),
            max_streams_per_session: d_streams(),
            max_sessions: d_sessions(),
            stream_idle_timeout_secs: d_idle(),
            connect_timeout_secs: d_connect(),
            control_timeout_secs: d_heartbeat(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerEntry {
    /// The operator name recorded in the audit log for this certificate.
    pub name: String,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntry {
    /// An address or network, e.g. `192.168.1.50` or `192.168.1.0/24`.
    pub network: String,
    /// Ports, e.g. `[80, 443, "8000-8100"]`.
    pub ports: Vec<PortItem>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PortItem {
    One(u16),
    Text(String),
}

/// Validated configuration with paths resolved.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub name: String,
    pub listen: String,
    pub identity_dir: PathBuf,
    pub audit_log: PathBuf,
    pub limits: Limits,
    pub controllers: Vec<ControllerEntry>,
    pub allow: Vec<AllowRule>,
    pub relay: Option<RelayEntry>,
    pub source: Option<PathBuf>,
}

impl ProbeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let file: ProbeConfigFile =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        let mut cfg = ProbeConfig::from_file(file, base)?;
        cfg.source = Some(path.to_path_buf());
        Ok(cfg)
    }

    pub fn from_file(file: ProbeConfigFile, base: &Path) -> Result<Self> {
        let resolve = |p: &Path| {
            if p.is_absolute() {
                p.to_path_buf()
            } else {
                base.join(p)
            }
        };
        let mut allow = Vec::new();
        for (i, entry) in file.allow.iter().enumerate() {
            allow.push(parse_allow(entry).with_context(|| format!("[[allow]] entry {}", i + 1))?);
        }
        let mut seen = std::collections::HashSet::new();
        for c in &file.controllers {
            if c.name.trim().is_empty() {
                bail!("a [[controller]] entry has an empty name");
            }
            if !seen.insert(c.fingerprint) {
                bail!("controller fingerprint {} is listed twice", c.fingerprint);
            }
        }
        if let Some(r) = &file.relay {
            let valid = r
                .address
                .rsplit_once(':')
                .is_some_and(|(h, p)| !h.is_empty() && p.parse::<u16>().is_ok_and(|p| p != 0));
            if !valid {
                bail!("[relay] address {:?} is not host:port", r.address);
            }
        }
        let l = &file.limits;
        if l.max_session_ttl_secs == 0
            || l.max_streams_per_session == 0
            || l.max_sessions == 0
            || l.connect_timeout_secs == 0
            || l.stream_idle_timeout_secs == 0
            || l.control_timeout_secs == 0
        {
            bail!("[limits] values must be greater than zero");
        }
        Ok(ProbeConfig {
            name: file.probe.name,
            listen: file.probe.listen,
            identity_dir: resolve(&file.probe.identity_dir),
            audit_log: resolve(&file.probe.audit_log),
            limits: file.limits,
            controllers: file.controllers,
            allow,
            relay: file.relay,
            source: None,
        })
    }

    pub fn controller_name(&self, fp: &Fingerprint) -> Option<&str> {
        self.controllers
            .iter()
            .find(|c| &c.fingerprint == fp)
            .map(|c| c.name.as_str())
    }
}

fn parse_allow(entry: &AllowEntry) -> Result<AllowRule> {
    let network: IpNet = match entry.network.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => {
            let ip: std::net::IpAddr = entry.network.parse().with_context(|| {
                format!(
                    "network {:?} is not an IP address or CIDR network (hostnames are resolved \
                     per session and must fall inside an allowed network)",
                    entry.network
                )
            })?;
            IpNet::from(ip)
        }
    };
    let network = network.trunc();
    if entry.ports.is_empty() {
        bail!("ports must list at least one port");
    }
    let mut ports = PortSet::default();
    for p in &entry.ports {
        match p {
            PortItem::One(0) => bail!("port 0 is not a valid destination"),
            PortItem::One(n) => ports.add(*n, *n),
            PortItem::Text(s) => {
                let (a, b) = match s.split_once('-') {
                    Some((a, b)) => (a.trim().parse::<u16>()?, b.trim().parse::<u16>()?),
                    None => {
                        let n = s.trim().parse::<u16>()?;
                        (n, n)
                    }
                };
                if a == 0 || b < a {
                    bail!("invalid port range {s:?}");
                }
                ports.add(a, b);
            }
        }
    }
    Ok(AllowRule {
        network,
        ports,
        label: entry.label.clone(),
    })
}

/// The commented template written by `portglass-probe init`.
pub fn template(name: &str) -> String {
    format!(
        r#"# PortGlass Probe configuration.
# The probe forwards TCP only to destinations listed under [[allow]], only for controllers listed
# under [[controller]]. Changes are picked up within a few seconds; sessions that the new file no
# longer permits are revoked immediately.

[probe]
name = "{name}"
# Accepts controller connections. Allow this port in Windows Firewall only from technician
# addresses (see docs/deployment.md).
listen = "0.0.0.0:{port}"
identity_dir = "identity"
audit_log = "audit.jsonl"

[limits]
max_session_ttl_secs = 14400
max_streams_per_session = 32
max_sessions = 4
stream_idle_timeout_secs = 300
connect_timeout_secs = 5
control_timeout_secs = 30

# One block per authorized technician. Get the fingerprint from `portglass init` on their PC.
# [[controller]]
# name = "alice"
# fingerprint = "sha256:...."

# For technicians on other networks: register with a PortGlass Relay that both sides can reach
# (`portglass-probe use-relay`). The relay carries the same end-to-end encrypted connection.
# [relay]
# address = "relay.example.com:47200"
# fingerprint = "sha256:...."

# One block per destination the probe may reach. Nothing else is reachable.
# [[allow]]
# network = "192.168.1.50"
# ports = [80, 443]
# label = "Front office printer"
#
# [[allow]]
# network = "192.168.1.0/24"
# ports = [80, 443, "8000-8100"]
"#,
        port = portglass_proto::DEFAULT_PROBE_PORT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parses() {
        let file: ProbeConfigFile = toml::from_str(&template("t")).unwrap();
        let cfg = ProbeConfig::from_file(file, Path::new(".")).unwrap();
        assert!(cfg.allow.is_empty() && cfg.controllers.is_empty());
    }

    #[test]
    fn the_documented_example_parses() {
        let text = include_str!("../../../examples/probe.toml");
        let file: ProbeConfigFile = toml::from_str(text).unwrap();
        let cfg = ProbeConfig::from_file(file, Path::new(".")).unwrap();
        assert_eq!(cfg.controllers.len(), 1);
        assert_eq!(cfg.allow.len(), 2);
    }

    #[test]
    fn relay_section_parses_and_is_validated() {
        let fp = "sha256:FFFF:EEEE:DDDD:CCCC:BBBB:AAAA:9999:8888:7777:6666:5555:4444:3333:2222:1111:0000";
        let base = "[probe]\nname='x'\nlisten='127.0.0.1:1'\n";
        let ok = format!("{base}[relay]\naddress='relay.example.com:47200'\nfingerprint='{fp}'\n");
        let cfg = ProbeConfig::from_file(toml::from_str(&ok).unwrap(), Path::new(".")).unwrap();
        assert_eq!(cfg.relay.unwrap().address, "relay.example.com:47200");
        for bad in ["relay.example.com", ":47200", "relay.example.com:0"] {
            let text = format!("{base}[relay]\naddress='{bad}'\nfingerprint='{fp}'\n");
            let file: ProbeConfigFile = toml::from_str(&text).unwrap();
            assert!(
                ProbeConfig::from_file(file, Path::new(".")).is_err(),
                "{bad}"
            );
        }
        let extra = format!("{base}[relay]\naddress='r:1'\nfingerprint='{fp}'\nopen=true\n");
        assert!(toml::from_str::<ProbeConfigFile>(&extra).is_err());
    }

    #[test]
    fn unknown_keys_are_errors_not_silently_ignored() {
        let text = "[probe]\nname='x'\nlisten='127.0.0.1:1'\nallow_everything=true\n";
        assert!(toml::from_str::<ProbeConfigFile>(text).is_err());
    }

    #[test]
    fn rejects_bad_ports_and_networks() {
        for allow in [
            "network='192.168.1.0/24'\nports=[]",
            "network='192.168.1.0/24'\nports=[0]",
            "network='192.168.1.0/24'\nports=['90-80']",
            "network='printer.local'\nports=[80]",
        ] {
            let text = format!("[probe]\nname='x'\nlisten='127.0.0.1:1'\n[[allow]]\n{allow}\n");
            let file: ProbeConfigFile = toml::from_str(&text).unwrap();
            assert!(
                ProbeConfig::from_file(file, Path::new(".")).is_err(),
                "{allow}"
            );
        }
    }
}
