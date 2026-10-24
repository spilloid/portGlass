//! Append-only JSON-lines audit log.
//!
//! Records who did what to which destination and how it ended: operator, probe, destination,
//! port, session start/end, connection outcome, byte counts. It has no way to receive payload
//! bytes or credentials — callers pass only the typed fields below.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use serde_json::{Map, Value};

pub struct AuditLog {
    path: Option<PathBuf>,
    file: Option<Mutex<File>>,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening audit log {}", path.display()))?;
        Ok(AuditLog {
            path: Some(path.to_path_buf()),
            file: Some(Mutex::new(file)),
        })
    }

    /// Audit to the diagnostic log only (tests).
    pub fn disabled() -> Self {
        AuditLog {
            path: None,
            file: None,
        }
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Write one event. `fields` must be metadata only.
    pub fn record(&self, event: &str, fields: &[(&str, Value)]) {
        let mut obj = Map::new();
        obj.insert("ts".into(), Value::String(crate::now_rfc3339()));
        obj.insert("event".into(), Value::String(event.into()));
        for (k, v) in fields {
            obj.insert((*k).into(), v.clone());
        }
        let line = Value::Object(obj).to_string();
        tracing::info!(target: "audit", "{line}");
        if let Some(file) = &self.file {
            let mut f = file.lock().unwrap_or_else(|p| p.into_inner());
            if let Err(e) = writeln!(f, "{line}").and_then(|_| f.flush()) {
                tracing::error!("audit log write failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn appends_one_json_object_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        log.record("session_open", &[("target", json!("192.0.2.1:80"))]);
        log.record("session_end", &[("reason", json!("closed_by_controller"))]);
        let text = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<Value> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], "session_open");
        assert!(lines[1]["ts"].is_string());
    }
}
