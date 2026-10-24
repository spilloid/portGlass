//! The dedicated session browser.
//!
//! PortGlass launches the *installed* Google Chrome (no bundled Chromium) with:
//!
//! * a brand-new `--user-data-dir` per session under `%LOCALAPPDATA%\PortGlass\browser-sessions`,
//!   so nothing is shared with the technician's own profile, and everything (cookies, cache,
//!   saved form data) is deleted when the session ends;
//! * `--app=<url>`, a single-purpose window with no tabs or omnibox;
//! * `--host-resolver-rules`, scoped to this one process, mapping the device's own address onto
//!   the local tunnel endpoint (and, in strict isolation, making every other name unresolvable).
//!
//! Nothing global changes: no system proxy, no default-browser change, no certificate or
//! security flags. Chrome's processes are placed in a Job Object so closing the session — or the
//! controller exiting for any reason — ends all of them.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::sync::{oneshot, watch};

use crate::config::{BrowserConfig, Isolation};
use crate::diag::Scheme;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BrowserInfo {
    pub executable: String,
    pub profile_dir: String,
    pub url: String,
    pub resolver_rules: Option<String>,
}

pub fn sessions_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("PortGlass")
        .join("browser-sessions")
}

/// Locate Chrome: configured path, then the App Paths registration, then standard locations.
pub fn find_chrome(cfg: &BrowserConfig) -> Option<PathBuf> {
    if let Some(p) = &cfg.path {
        return p.exists().then(|| p.clone());
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    #[cfg(windows)]
    for hive in ["HKLM", "HKCU"] {
        let key = format!(r"{hive}\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe");
        if let Ok(out) = std::process::Command::new("reg")
            .args(["query", &key, "/ve"])
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            if let Some(line) = text.lines().find(|l| l.contains("REG_SZ")) {
                if let Some(path) = line.split("REG_SZ").nth(1) {
                    candidates.push(PathBuf::from(path.trim().trim_matches('"')));
                }
            }
        }
    }
    for var in ["ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(var) {
            candidates.push(
                PathBuf::from(base)
                    .join("Google")
                    .join("Chrome")
                    .join("Application")
                    .join("chrome.exe"),
            );
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// Where the session browser should go, and how its resolver maps that onto the tunnel.
pub fn plan_navigation(
    cfg: &BrowserConfig,
    scheme: Scheme,
    host: &str,
    port: u16,
    local_port: u16,
) -> (String, Option<String>) {
    let bare = host.trim_matches(['[', ']']);
    let is_v6 = bare.contains(':');
    if cfg.preserve_address && !is_v6 {
        let authority = if port == scheme.default_port() {
            bare.to_string()
        } else {
            format!("{bare}:{port}")
        };
        let mut rules = format!("MAP {bare}:{port} 127.0.0.1:{local_port}");
        if cfg.isolation == Isolation::Strict {
            rules.push_str(", MAP * ~NOTFOUND");
        }
        (format!("{}://{authority}/", scheme.as_str()), Some(rules))
    } else {
        let rules = (cfg.isolation == Isolation::Strict)
            .then(|| "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1".to_string());
        (
            format!("{}://127.0.0.1:{local_port}/", scheme.as_str()),
            rules,
        )
    }
}

/// Remove profile directories left behind by a crash. Called at controller start.
pub fn sweep_stale_profiles() {
    let root = sessions_root();
    let Ok(entries) = std::fs::read_dir(&root) else {
        return;
    };
    for e in entries.flatten() {
        if e.path().is_dir() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
}

fn seed_profile(dir: &Path) -> Result<()> {
    let default = dir.join("Default");
    std::fs::create_dir_all(&default)?;
    // Keep an ephemeral profile quiet and credential-free: no password saving, no autofill,
    // no sign-in or sync prompts, no translation bar over the device's page.
    let prefs = serde_json::json!({
        "credentials_enable_service": false,
        "profile": { "password_manager_enabled": false, "name": "PortGlass session" },
        "autofill": { "profile_enabled": false, "credit_card_enabled": false },
        "signin": { "allowed": false },
        "translate": { "enabled": false },
        "browser": { "has_seen_welcome_page": true, "theme": { "user_color2": -15108398 } }
    });
    std::fs::write(
        default.join("Preferences"),
        serde_json::to_vec_pretty(&prefs)?,
    )?;
    std::fs::write(dir.join("First Run"), b"")?;
    Ok(())
}

pub struct WindowPlacement {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// A running session browser. Dropping it closes the browser and deletes its profile.
pub struct BrowserHandle {
    pub info: BrowserInfo,
    kill: Option<oneshot::Sender<()>>,
    exited: watch::Receiver<bool>,
    finished: Option<tokio::task::JoinHandle<()>>,
}

impl BrowserHandle {
    pub async fn launch(
        exe: &Path,
        session_id: &str,
        url: &str,
        resolver_rules: Option<&str>,
        window: &WindowPlacement,
        extra_args: &[String],
    ) -> Result<BrowserHandle> {
        let profile = sessions_root().join(session_id);
        if profile.exists() {
            std::fs::remove_dir_all(&profile).ok();
        }
        seed_profile(&profile).context("creating the session browser profile")?;

        let mut cmd = tokio::process::Command::new(exe);
        cmd.arg(format!("--user-data-dir={}", profile.display()))
            .arg(format!("--app={url}"))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-sync")
            .arg("--disable-extensions")
            .arg("--disable-background-networking")
            .arg("--disable-component-update")
            .arg("--disable-default-apps")
            .arg(format!("--window-position={},{}", window.x, window.y))
            .arg(format!("--window-size={},{}", window.width, window.height));
        if let Some(rules) = resolver_rules {
            cmd.arg(format!("--host-resolver-rules={rules}"));
        }
        cmd.args(extra_args);
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true);

        let job = job::Job::kill_on_close();
        let mut child = cmd
            .spawn()
            .with_context(|| format!("starting {}", exe.display()))?;
        let pid = child.id();
        let in_job = match (&job, child.raw_handle()) {
            (Some(job), Some(handle)) => job.assign(handle),
            _ => false,
        };
        if !in_job {
            tracing::warn!("could not place the browser (pid {pid:?}) in a job object");
        }
        tracing::debug!("session browser pid {pid:?} started, in job: {in_job}");

        let info = BrowserInfo {
            executable: exe.display().to_string(),
            profile_dir: profile.display().to_string(),
            url: url.to_string(),
            resolver_rules: resolver_rules.map(str::to_owned),
        };
        let (kill_tx, kill_rx) = oneshot::channel::<()>();
        let (exit_tx, exit_rx) = watch::channel(false);
        let finished = tokio::spawn(async move {
            tokio::select! {
                status = child.wait() => {
                    tracing::debug!("session browser pid {pid:?} exited: {status:?}");
                }
                _ = kill_rx => {
                    if let Some(job) = &job { job.terminate(); }
                    let killed = child.kill().await;
                    tracing::debug!("session browser pid {pid:?} terminated: {killed:?}");
                    // Belt and braces: if anything of that process tree is still alive, end it.
                    #[cfg(windows)]
                    if let Some(pid) = pid {
                        if matches!(child.try_wait(), Ok(None)) {
                            tracing::warn!("session browser pid {pid} survived termination; killing its process tree");
                        }
                        let _ = tokio::process::Command::new("taskkill")
                            .args(["/PID", &pid.to_string(), "/T", "/F"])
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status()
                            .await;
                    }
                }
            }
            let _ = exit_tx.send(true);
            drop(job);
            remove_profile(&profile).await;
        });

        // Chrome hands the window to an existing process and exits at once if the profile is
        // already in use. A fresh profile should never be, so an instant exit is a failure.
        let mut probe_exit = exit_rx.clone();
        if tokio::time::timeout(Duration::from_millis(800), probe_exit.wait_for(|e| *e))
            .await
            .is_ok()
        {
            bail!("the browser exited immediately after starting");
        }
        Ok(BrowserHandle {
            info,
            kill: Some(kill_tx),
            exited: exit_rx,
            finished: Some(finished),
        })
    }

    pub fn is_running(&self) -> bool {
        !*self.exited.borrow()
    }

    /// Resolves when the technician closes the browser window.
    pub fn exit_signal(&self) -> watch::Receiver<bool> {
        self.exited.clone()
    }

    /// Close the browser (all of its processes) and delete its profile.
    pub async fn close(mut self) {
        if let Some(k) = self.kill.take() {
            let _ = k.send(());
        }
        if let Some(f) = self.finished.take() {
            let _ = tokio::time::timeout(Duration::from_secs(10), f).await;
        }
    }
}

impl Drop for BrowserHandle {
    fn drop(&mut self) {
        if let Some(k) = self.kill.take() {
            let _ = k.send(());
        }
    }
}

async fn remove_profile(dir: &Path) {
    // Chrome's child processes may hold files for a moment after the browser process exits.
    for attempt in 0..20 {
        match std::fs::remove_dir_all(dir) {
            Ok(()) => return,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) if attempt == 19 => {
                tracing::warn!("could not delete browser profile {}: {e}", dir.display())
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Launch a plain app window (used for the controller's own UI).
pub async fn launch_app_window(
    exe: &Path,
    url: &str,
    window: &WindowPlacement,
) -> Result<BrowserHandle> {
    BrowserHandle::launch(
        exe,
        &format!("ui-{}", std::process::id()),
        url,
        None,
        window,
        &[],
    )
    .await
}

#[cfg(windows)]
mod job {
    use std::os::windows::io::RawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    pub struct Job(HANDLE);
    // The handle is an owned kernel object handle, usable from any thread.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Job {
        pub fn kill_on_close() -> Option<Job> {
            // SAFETY: plain Win32 calls with valid arguments; the handle is owned by `Job`.
            unsafe {
                let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if h.is_null() {
                    return None;
                }
                let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    h,
                    JobObjectExtendedLimitInformation,
                    &info as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                );
                if ok == 0 {
                    CloseHandle(h);
                    return None;
                }
                Some(Job(h))
            }
        }

        pub fn assign(&self, process: RawHandle) -> bool {
            // SAFETY: `process` is a live process handle owned by the tokio Child.
            unsafe { AssignProcessToJobObject(self.0, process as HANDLE) != 0 }
        }

        pub fn terminate(&self) {
            // SAFETY: valid job handle.
            unsafe {
                TerminateJobObject(self.0, 0);
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: closing our own handle; KILL_ON_JOB_CLOSE ends any remaining processes.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(not(windows))]
mod job {
    pub struct Job;
    impl Job {
        pub fn kill_on_close() -> Option<Job> {
            None
        }
        pub fn assign(&self, _: i32) -> bool {
            false
        }
        pub fn terminate(&self) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_preserves_the_device_address_and_isolates() {
        let cfg = BrowserConfig::default();
        let (url, rules) = plan_navigation(&cfg, Scheme::Http, "192.168.1.50", 80, 54321);
        assert_eq!(url, "http://192.168.1.50/");
        assert_eq!(
            rules.as_deref(),
            Some("MAP 192.168.1.50:80 127.0.0.1:54321, MAP * ~NOTFOUND")
        );

        let (url, _) = plan_navigation(&cfg, Scheme::Https, "printer.lan", 8443, 5000);
        assert_eq!(url, "https://printer.lan:8443/");

        let open = BrowserConfig {
            isolation: Isolation::Open,
            preserve_address: false,
            ..BrowserConfig::default()
        };
        let (url, rules) = plan_navigation(&open, Scheme::Http, "192.168.1.50", 80, 5000);
        assert_eq!(url, "http://127.0.0.1:5000/");
        assert!(rules.is_none());
    }
}
