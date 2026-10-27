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
use std::sync::Arc;
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
    crate::config::local_data_dir().join("browser-sessions")
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
    #[cfg(target_os = "macos")]
    {
        candidates.push(PathBuf::from(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ));
        if let Some(home) = std::env::var_os("HOME") {
            candidates.push(
                PathBuf::from(home)
                    .join("Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            );
        }
    }
    candidates.into_iter().find(|p| p.exists())
}

/// Whether the session browser will see the device under its own address (IPv6 literals can't be
/// mapped with `--host-resolver-rules`).
pub fn maps_address(cfg: &BrowserConfig, host: &str) -> bool {
    cfg.preserve_address && !host.trim_matches(['[', ']']).contains(':')
}

/// Where the session browser should go, and how its resolver maps that onto the tunnel.
/// `extra` maps the device's other forwarded ports to their local tunnel ports.
pub fn plan_navigation(
    cfg: &BrowserConfig,
    scheme: Scheme,
    host: &str,
    port: u16,
    local_port: u16,
    extra: &[(u16, u16)],
) -> (String, Option<String>) {
    let bare = host.trim_matches(['[', ']']);
    if maps_address(cfg, host) {
        let authority = if port == scheme.default_port() {
            bare.to_string()
        } else {
            format!("{bare}:{port}")
        };
        let mut rules = format!("MAP {bare}:{port} 127.0.0.1:{local_port}");
        for (device_port, local) in extra {
            rules.push_str(&format!(", MAP {bare}:{device_port} 127.0.0.1:{local}"));
        }
        if cfg.isolation == Isolation::Strict {
            rules.push_str(", MAP * ~NOTFOUND");
        }
        (format!("{}://{authority}/", scheme.as_str()), Some(rules))
    } else {
        // Without address mapping there is no resolver rule at all. (Isolating this mode with
        // "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" would let the device's page reach every loopback
        // service on this PC, so strict isolation requires preserve_address.)
        (
            format!("{}://127.0.0.1:{local_port}/", scheme.as_str()),
            None,
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

/// The set of processes belonging to one session browser (its Job Object). The tunnel admits
/// only connections whose owning process is in this set.
#[derive(Clone)]
pub struct ProcessScope(std::sync::Weak<job::Job>);

impl ProcessScope {
    pub fn contains(&self, pid: u32) -> bool {
        self.0.upgrade().is_some_and(|job| job.contains(pid))
    }
}

/// A running session browser. Dropping it closes the browser and deletes its profile.
pub struct BrowserHandle {
    pub info: BrowserInfo,
    pub scope: ProcessScope,
    kill: Option<oneshot::Sender<()>>,
    exited: watch::Receiver<bool>,
    finished: Option<tokio::task::JoinHandle<()>>,
}

impl BrowserHandle {
    pub async fn launch(
        exe: &Path,
        profile_name: &str,
        url: &str,
        resolver_rules: Option<&str>,
        window: &WindowPlacement,
        extra_args: &[String],
    ) -> Result<BrowserHandle> {
        // The name becomes a directory that is later deleted recursively: never let it be a path.
        if profile_name.is_empty()
            || profile_name.len() > 64
            || !profile_name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            bail!("invalid browser profile name {profile_name:?}");
        }
        let profile = sessions_root().join(profile_name);
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
            // Device traffic must go through the tunnel, never a system proxy or PAC file.
            .arg("--no-proxy-server")
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

        // Start Chrome suspended, put it in the job, then let it run: every process it ever
        // starts is then inside the job, which is both how it is cleaned up and how the tunnel
        // recognizes its connections. Without containment, refuse to launch.
        let job =
            Arc::new(job::Job::kill_on_close().context("creating a job object for the browser")?);
        #[cfg(windows)]
        cmd.creation_flags(job::CREATE_SUSPENDED);
        // On Unix the browser leads its own process group, so it can be ended as a whole, and
        // its processes are recognized by ancestry.
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd
            .spawn()
            .with_context(|| format!("starting {}", exe.display()))?;
        let pid = child.id();
        #[cfg(windows)]
        let contained = match (child.raw_handle(), pid) {
            (Some(handle), Some(pid)) => job.assign(handle) && job::resume(pid),
            _ => false,
        };
        #[cfg(unix)]
        let contained = match pid {
            Some(pid) => job.adopt(pid),
            None => false,
        };
        if !contained {
            let _ = child.kill().await;
            bail!("could not contain the browser process in a job object");
        }
        tracing::debug!("session browser pid {pid:?} started in its job");
        let scope = ProcessScope(Arc::downgrade(&job));

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
                    job.terminate();
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
            scope,
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
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
        JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, PROCESS_QUERY_LIMITED_INFORMATION,
        THREAD_SUSPEND_RESUME,
    };

    pub const CREATE_SUSPENDED: u32 = windows_sys::Win32::System::Threading::CREATE_SUSPENDED;

    /// Resume every thread of a process started with CREATE_SUSPENDED.
    pub fn resume(pid: u32) -> bool {
        // SAFETY: documented Toolhelp/thread APIs; every handle opened here is closed here.
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return false;
            }
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let mut resumed = 0;
            let mut ok = Thread32First(snap, &mut entry) != 0;
            while ok {
                if entry.th32OwnerProcessID == pid {
                    let t = OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID);
                    if !t.is_null() {
                        if ResumeThread(t) != u32::MAX {
                            resumed += 1;
                        }
                        CloseHandle(t);
                    }
                }
                ok = Thread32Next(snap, &mut entry) != 0;
            }
            CloseHandle(snap);
            resumed > 0
        }
    }

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

        /// Is process `pid` in this job (directly or through a nested job Chrome created)?
        pub fn contains(&self, pid: u32) -> bool {
            // SAFETY: the process handle is opened with query rights only and closed here.
            unsafe {
                let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                if h.is_null() {
                    return false;
                }
                let mut result = 0;
                let ok = IsProcessInJob(h, self.0, &mut result);
                CloseHandle(h);
                ok != 0 && result != 0
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

#[cfg(unix)]
mod job {
    use std::sync::atomic::{AtomicU32, Ordering};

    /// The Unix counterpart of the Windows job object: the session browser's root process,
    /// which leads its own process group. Membership is decided by ancestry.
    pub struct Job {
        root: AtomicU32,
    }

    impl Job {
        pub fn kill_on_close() -> Option<Job> {
            Some(Job {
                root: AtomicU32::new(0),
            })
        }

        pub fn adopt(&self, pid: u32) -> bool {
            self.root.store(pid, Ordering::SeqCst);
            pid > 1
        }

        pub fn terminate(&self) {
            let root = self.root.swap(0, Ordering::SeqCst);
            if root > 1 {
                // SAFETY: signals the process group this browser leads (process_group(0)).
                unsafe {
                    libc::killpg(root as libc::pid_t, libc::SIGKILL);
                }
            }
        }

        /// Is `pid` the browser or one of its descendants?
        pub fn contains(&self, pid: u32) -> bool {
            let root = self.root.load(Ordering::SeqCst);
            if root <= 1 {
                return false;
            }
            let mut p = pid;
            for _ in 0..64 {
                if p == root {
                    return true;
                }
                match parent_of(p) {
                    Some(parent) if parent > 1 && parent != p => p = parent,
                    _ => return false,
                }
            }
            false
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            self.terminate();
        }
    }

    #[cfg(target_os = "macos")]
    fn parent_of(pid: u32) -> Option<u32> {
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
        // SAFETY: proc_pidinfo writes at most `size` bytes into `info`.
        let n = unsafe {
            libc::proc_pidinfo(
                pid as libc::c_int,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut _ as *mut libc::c_void,
                size,
            )
        };
        (n == size).then_some(info.pbi_ppid)
    }

    #[cfg(not(target_os = "macos"))]
    fn parent_of(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // The command name is parenthesized and may contain spaces; fields resume after ')'.
        stat.rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigation_preserves_the_device_address_and_isolates() {
        let cfg = BrowserConfig::default();
        let (url, rules) = plan_navigation(&cfg, Scheme::Http, "192.168.1.50", 80, 54321, &[]);
        assert_eq!(url, "http://192.168.1.50/");
        assert_eq!(
            rules.as_deref(),
            Some("MAP 192.168.1.50:80 127.0.0.1:54321, MAP * ~NOTFOUND")
        );

        let (url, _) = plan_navigation(&cfg, Scheme::Https, "printer.lan", 8443, 5000, &[]);
        assert_eq!(url, "https://printer.lan:8443/");

        // A console that moves from http to https to sign in: both ports map, nothing else.
        let (url, rules) =
            plan_navigation(&cfg, Scheme::Http, "192.168.1.50", 80, 5000, &[(443, 5001)]);
        assert_eq!(url, "http://192.168.1.50/");
        assert_eq!(
            rules.as_deref(),
            Some(
                "MAP 192.168.1.50:80 127.0.0.1:5000, MAP 192.168.1.50:443 127.0.0.1:5001, \
                 MAP * ~NOTFOUND"
            )
        );

        // Without address mapping there are no resolver rules, whatever the isolation setting:
        // "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1" would expose every loopback port to the page.
        for isolation in [Isolation::Open, Isolation::Strict] {
            let plain = BrowserConfig {
                isolation,
                preserve_address: false,
                ..BrowserConfig::default()
            };
            let (url, rules) = plan_navigation(
                &plain,
                Scheme::Http,
                "192.168.1.50",
                80,
                5000,
                &[(443, 5001)],
            );
            assert_eq!(url, "http://127.0.0.1:5000/");
            assert!(rules.is_none());
        }
    }

    #[tokio::test]
    async fn profile_names_can_never_be_paths() {
        let window = WindowPlacement {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        };
        for bad in [
            "..\\..\\Documents",
            "C:\\Users\\x",
            "a/b",
            "",
            "UPPER",
            "..",
            "x y",
        ] {
            let r = BrowserHandle::launch(
                Path::new("nonexistent.exe"),
                bad,
                "about:blank",
                None,
                &window,
                &[],
            )
            .await;
            let msg = r.err().expect("must refuse").to_string();
            assert!(msg.contains("invalid browser profile name"), "{bad}: {msg}");
        }
    }
}
