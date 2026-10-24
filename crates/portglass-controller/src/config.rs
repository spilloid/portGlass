//! Controller configuration (`controller.toml`): the technician's identity and the probes they
//! have pinned.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use portglass_core::identity::Fingerprint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerConfig {
    /// Display name sent to probes (probes audit their own name for this certificate).
    #[serde(default = "default_operator")]
    pub operator: String,
    #[serde(default = "default_identity_dir")]
    pub identity_dir: PathBuf,
    #[serde(default = "default_audit_log")]
    pub audit_log: PathBuf,
    #[serde(default = "default_ttl_mins")]
    pub default_ttl_mins: u32,
    /// Forwarded connections with no traffic for this long are closed (the browser reconnects).
    #[serde(default = "default_idle")]
    pub idle_timeout_secs: u32,
    #[serde(default)]
    pub browser: BrowserConfig,
    #[serde(default, rename = "probe")]
    pub probes: Vec<ProbeEntry>,
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserConfig {
    /// Chrome (or Chromium-based) executable. Default: the installed Google Chrome.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// `strict`: the session browser can resolve only the forwarded target, so a page cannot
    /// pull resources from anywhere else. `open`: other host names resolve normally.
    #[serde(default)]
    pub isolation: Isolation,
    /// Navigate to the device's own address (mapped onto the tunnel inside the session browser
    /// only), so Host headers, cookies and same-port redirects behave as on the device's LAN.
    #[serde(default = "yes")]
    pub preserve_address: bool,
    /// Closing the session browser window ends the session.
    #[serde(default = "yes")]
    pub end_session_on_close: bool,
}

impl Default for BrowserConfig {
    fn default() -> Self {
        BrowserConfig {
            path: None,
            isolation: Isolation::Strict,
            preserve_address: true,
            end_session_on_close: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Isolation {
    #[default]
    Strict,
    Open,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeEntry {
    pub name: String,
    /// host:port of the probe, e.g. `10.0.5.20:47100`.
    pub address: String,
    pub fingerprint: Fingerprint,
}

fn default_operator() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "technician".into())
}
fn default_identity_dir() -> PathBuf {
    "identity".into()
}
fn default_audit_log() -> PathBuf {
    "audit.jsonl".into()
}
fn default_ttl_mins() -> u32 {
    60
}
fn default_idle() -> u32 {
    300
}
fn yes() -> bool {
    true
}

pub fn default_dir() -> PathBuf {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("PortGlass")
        .join("controller")
}

pub fn default_path() -> PathBuf {
    default_dir().join("controller.toml")
}

impl ControllerConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: ControllerConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        if cfg.identity_dir.is_relative() {
            cfg.identity_dir = base.join(&cfg.identity_dir);
        }
        if cfg.audit_log.is_relative() {
            cfg.audit_log = base.join(&cfg.audit_log);
        }
        cfg.source = Some(path.to_path_buf());
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        let mut names = std::collections::HashSet::new();
        for p in &self.probes {
            if p.name.trim().is_empty() {
                bail!("a [[probe]] entry has an empty name");
            }
            if !names.insert(p.name.to_lowercase()) {
                bail!("probe name {:?} is listed twice", p.name);
            }
            if p.address
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .is_none()
            {
                bail!(
                    "probe {:?} address {:?} must be host:port",
                    p.name,
                    p.address
                );
            }
        }
        if self.default_ttl_mins == 0 || self.idle_timeout_secs == 0 {
            bail!("default_ttl_mins and idle_timeout_secs must be greater than zero");
        }
        Ok(())
    }

    pub fn probe(&self, name: &str) -> Option<&ProbeEntry> {
        self.probes
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(name))
    }
}

pub fn template(operator: &str) -> String {
    format!(
        r#"# PortGlass Controller configuration.

operator = {operator}
identity_dir = "identity"
audit_log = "audit.jsonl"
default_ttl_mins = 60
idle_timeout_secs = 300

[browser]
# path = 'C:\Program Files\Google\Chrome\Application\chrome.exe'
# strict: the session browser can reach only the forwarded device. open: other names resolve.
isolation = "strict"
# Show the device's own address in the session browser (mapped onto the tunnel).
preserve_address = true
end_session_on_close = true

# Add probes with: portglass probe add --name <name> --address <host:port> --fingerprint <sha256:...>
"#,
        operator = toml::Value::String(operator.to_string())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_documented_example_parses() {
        let cfg: ControllerConfig =
            toml::from_str(include_str!("../../../examples/controller.toml")).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.probes.len(), 1);
    }

    #[test]
    fn template_parses_with_defaults() {
        let cfg: ControllerConfig = toml::from_str(&template("alice")).unwrap();
        assert_eq!(cfg.operator, "alice");
        assert_eq!(cfg.browser.isolation, Isolation::Strict);
        assert!(cfg.browser.preserve_address);
        cfg.validate().unwrap();
    }
}
