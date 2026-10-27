//! Updates: find out whether a newer PortGlass release exists, and install it when a person asks.
//!
//! Every release carries `portglass-manifest.json`, listing each program's file with its SHA-256,
//! and `portglass-manifest.json.sig`, an Ed25519 signature over the manifest's exact bytes made by
//! the release pipeline. The public half of that key is compiled in ([`UPDATE_KEYS`]). A file is
//! installed only if the manifest verifies against one of those keys, names a newer version, and
//! the downloaded bytes match its hash and size. So someone who can change a GitHub release, or
//! sit between this PC and GitHub, can at most withhold an update, never substitute one.
//!
//! Nothing here runs on its own: programs *check* at startup (one HTTPS request to GitHub, which
//! can be turned off) and say so; installing is always a person's action. The running program is
//! replaced by renaming (`<exe>.old` stays behind until the next start), and takes effect when it
//! next starts.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Where releases live. `PORTGLASS_UPDATE_URL` overrides it (tests, mirrors); a mirror can't do
/// more than GitHub can, because the signature is checked against the compiled-in keys either way.
pub const RELEASES: &str = "https://github.com/spilloid/portGlass/releases";
pub const MANIFEST_NAME: &str = "portglass-manifest.json";
/// Setting this (to anything) turns the startup check off.
pub const NO_CHECK_ENV: &str = "PORTGLASS_NO_UPDATE_CHECK";

/// Ed25519 public keys (hex) trusted to sign release manifests. To rotate, add the new key here,
/// release, and only remove the old key once releases signed with it are no longer supported.
pub const UPDATE_KEYS: &[&str] =
    &["e1c43852ebea008ab0014eea7a16a7fb58041c48d1b2b8082bd344ec7beb5079"];

/// No release asset is anywhere near this; refuse anything bigger before reading it all.
const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_MANIFEST: u64 = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: u32,
    pub product: String,
    pub version: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    /// `windows-x64`, `macos-arm64` or `linux-x64`.
    pub platform: String,
    /// `portglass`, `portglass-probe` or `portglass-relay`.
    pub program: String,
    /// The release asset's file name.
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

/// The platform this build runs on, in manifest terms.
pub fn platform() -> &'static str {
    if cfg!(all(windows, target_arch = "x86_64")) {
        "windows-x64"
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "macos-arm64"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-x64"
    } else {
        "unsupported"
    }
}

/// `1.2.3` as numbers; anything else (pre-release suffixes included) is not a version we offer.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.trim().trim_start_matches('v').split('.');
    let n = |s: Option<&str>| s.and_then(|s| s.parse::<u64>().ok());
    let v = (n(it.next())?, n(it.next())?, n(it.next())?);
    it.next().is_none().then_some(v)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// Check `bytes` against `sig_hex` with any of `keys`, then parse and sanity-check the manifest.
pub fn verify_manifest(bytes: &[u8], sig_hex: &str, keys: &[&str]) -> Result<Manifest> {
    let sig = hex::decode(sig_hex.trim()).context("the signature isn't hex")?;
    let trusted = keys.iter().any(|k| {
        hex::decode(k).is_ok_and(|k| {
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, k)
                .verify(bytes, &sig)
                .is_ok()
        })
    });
    if !trusted {
        bail!("the release manifest isn't signed by a PortGlass release key");
    }
    let m: Manifest = serde_json::from_slice(bytes).context("the release manifest is malformed")?;
    if m.schema != 1 || m.product != "portglass" || parse_version(&m.version).is_none() {
        bail!("the release manifest is not one this version understands");
    }
    for f in &m.files {
        let plain = !f.name.is_empty()
            && f.name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
            && !f.name.starts_with('.');
        if !plain || f.sha256.len() != 64 || hex::decode(&f.sha256).is_err() || f.size > MAX_FILE {
            bail!(
                "the release manifest lists a file it shouldn't ({})",
                f.name
            );
        }
    }
    Ok(m)
}

/// A newer release's file for this program on this platform.
#[derive(Debug, Clone)]
pub struct Available {
    pub version: String,
    pub file: ManifestFile,
    url: String,
}

fn base() -> String {
    std::env::var("PORTGLASS_UPDATE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| RELEASES.to_string())
        .trim_end_matches('/')
        .to_string()
}

fn agent() -> ureq::Agent {
    // The signature is what makes a download trustworthy, but nothing should quietly drop to
    // plain HTTP either: an https base refuses any redirect that leaves https.
    ureq::AgentBuilder::new()
        .https_only(base().starts_with("https://"))
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(300))
        .user_agent(concat!("PortGlass/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn get(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>> {
    let resp = agent
        .get(url)
        .call()
        .with_context(|| format!("downloading {url}"))?;
    let mut body = Vec::new();
    resp.into_reader()
        .take(limit + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("downloading {url}"))?;
    if body.len() as u64 > limit {
        bail!("{url} is larger than expected");
    }
    Ok(body)
}

/// Whether the startup check is turned off for this process.
pub fn check_disabled() -> bool {
    std::env::var_os(NO_CHECK_ENV).is_some()
}

/// Ask the latest release whether there's something newer for `program`. Blocking; call it off
/// the async runtime. `Ok(None)` means up to date.
pub fn check(program: &str, current: &str) -> Result<Option<Available>> {
    check_with_keys(program, current, UPDATE_KEYS)
}

pub fn check_with_keys(program: &str, current: &str, keys: &[&str]) -> Result<Option<Available>> {
    let agent = agent();
    let base = base();
    let latest = format!("{base}/latest/download/{MANIFEST_NAME}");
    let bytes = get(&agent, &latest, MAX_MANIFEST)?;
    let sig = get(&agent, &format!("{latest}.sig"), 1024)?;
    let m = verify_manifest(&bytes, &String::from_utf8_lossy(&sig), keys)?;
    if !is_newer(&m.version, current) {
        return Ok(None);
    }
    let Some(file) = m
        .files
        .iter()
        .find(|f| f.program == program && f.platform == platform())
        .cloned()
    else {
        return Ok(None);
    };
    let url = format!("{base}/download/v{}/{}", m.version, file.name);
    Ok(Some(Available {
        version: m.version,
        file,
        url,
    }))
}

/// Download, verify and install `available` over the running program. Takes effect at the next
/// start. Returns the installed path.
pub fn apply(available: &Available) -> Result<PathBuf> {
    let exe = std::env::current_exe().context("finding this program's file")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    apply_to(available, &exe)?;
    Ok(exe)
}

pub fn apply_to(available: &Available, target: &Path) -> Result<()> {
    // The version installed last, written beside the program. A copy of PortGlass that started
    // before that install (or a replayed older manifest) can't step it backwards. Checked again
    // after the download, the moment before the swap. A missing or unreadable file means no
    // floor beyond the running version, which check() already enforced.
    let floor_path = {
        let mut p = target.as_os_str().to_owned();
        p.push(".version");
        PathBuf::from(p)
    };
    let below_floor = || {
        std::fs::read_to_string(&floor_path)
            .ok()
            .is_some_and(|floor| !is_newer(&available.version, floor.trim()))
    };
    if below_floor() {
        bail!(
            "version {} or newer is already installed here; nothing was changed",
            available.version
        );
    }
    let body = get(&agent(), &available.url, available.file.size)?;
    if below_floor() {
        bail!("a newer version was installed while this one downloaded; nothing was changed");
    }
    install(&body, &available.file, target)?;
    let _ = std::fs::write(&floor_path, &available.version);
    Ok(())
}

/// Check `body` against the manifest entry, then swap it in for `target`, keeping the previous
/// file as `<target>.old` so a failed swap can be undone (and a person can roll back by hand).
pub fn install(body: &[u8], file: &ManifestFile, target: &Path) -> Result<()> {
    let digest = hex::encode(ring::digest::digest(&ring::digest::SHA256, body));
    if body.len() as u64 != file.size || !digest.eq_ignore_ascii_case(&file.sha256) {
        bail!(
            "the download of {} doesn't match the signed manifest; nothing was changed",
            file.name
        );
    }
    let sibling = |ext: &str| {
        let mut p = target.as_os_str().to_owned();
        p.push(ext);
        PathBuf::from(p)
    };
    // A name of its own, so two copies updating at once never write the same staging file.
    let new = sibling(&format!(".new-{}", hex::encode(crate::random_bytes::<6>())));
    let old = sibling(".old");
    let staged = (|| -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(&new)?;
        f.write_all(body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
        }
        // On disk before it is put in place, so a power cut can't leave a half-written program.
        f.sync_all()?;
        Ok(())
    })();
    if let Err(e) = staged {
        let _ = std::fs::remove_file(&new);
        return Err(e).with_context(|| {
            format!(
                "writing next to {} (an administrator install needs an administrator to update \
                 it); nothing was changed",
                target.display()
            )
        });
    }
    swap(&new, &old, target)
}

/// Unix: keep a copy as `.old`, then one atomic rename over the program. There is no moment
/// without a program at `target`.
#[cfg(unix)]
fn swap(new: &Path, old: &Path, target: &Path) -> Result<()> {
    let _ = std::fs::remove_file(old);
    if let Err(e) = std::fs::copy(target, old) {
        let _ = std::fs::remove_file(new);
        return Err(e).with_context(|| format!("keeping a copy of {}", target.display()));
    }
    let _ = std::fs::File::open(old).and_then(|f| f.sync_all());
    if let Err(e) = std::fs::rename(new, target) {
        let _ = std::fs::remove_file(new);
        return Err(e).with_context(|| {
            format!(
                "putting the new {} in place; nothing was changed",
                target.display()
            )
        });
    }
    // The rename itself lives in the directory entry; persist that too.
    if let Some(dir) = target.parent() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    Ok(())
}

/// Windows can't replace a running .exe, but it can rename it: move it aside, then move the new
/// one in. If the second step fails the first is undone, and if *that* fails the error says where
/// the program now is rather than claiming nothing changed.
#[cfg(not(unix))]
fn swap(new: &Path, old: &Path, target: &Path) -> Result<()> {
    let _ = std::fs::remove_file(old);
    if let Err(e) = std::fs::rename(target, old) {
        let _ = std::fs::remove_file(new);
        return Err(e)
            .with_context(|| format!("moving {} aside; nothing was changed", target.display()));
    }
    if let Err(e) = std::fs::rename(new, target) {
        let _ = std::fs::remove_file(new);
        return match std::fs::rename(old, target) {
            Ok(()) => Err(e).with_context(|| {
                format!(
                    "putting the new {} in place; the previous version was restored",
                    target.display()
                )
            }),
            Err(restore) => Err(e).with_context(|| {
                format!(
                    "putting the new {} in place, and restoring the previous version failed \
                     ({restore}). Rename {} back to {} to repair it",
                    target.display(),
                    old.display(),
                    target.display()
                )
            }),
        };
    }
    Ok(())
}

/// Delete the `.old` file a previous update left behind. Called at startup; harmless otherwise.
pub fn remove_previous() {
    if let Ok(exe) = std::env::current_exe() {
        let mut p = exe.into_os_string();
        p.push(".old");
        let _ = std::fs::remove_file(PathBuf::from(p));
    }
}

/// The `update` command of each program: report, and unless `check_only`, install. ASCII output.
pub fn run_cli(program: &str, current: &str, check_only: bool) -> Result<()> {
    println!("{program} {current}: checking {} ...", base());
    let Some(available) = check(program, current)? else {
        println!("Up to date (the latest signed release is not newer).");
        return Ok(());
    };
    println!(
        "Version {} is available ({}, signature verified).",
        available.version, available.file.name
    );
    if check_only {
        println!("Run `{program} update` to install it.");
        return Ok(());
    }
    let path = apply(&available)?;
    println!(
        "Installed {} at {}. It takes effect the next time {program} starts;",
        available.version,
        path.display()
    );
    println!("the previous version is kept beside it as {program}.old until then.");
    Ok(())
}

/// The one line a program prints or logs at startup when a newer signed release exists. Never
/// fails loudly: no network, or checks turned off, just means no notice.
pub fn startup_notice(program: &str, current: &str) -> Option<String> {
    remove_previous();
    if check_disabled() {
        return None;
    }
    match check(program, current) {
        Ok(Some(a)) => Some(format!(
            "PortGlass {} is available (you have {current}). To install it, run: {program} update",
            a.version
        )),
        Ok(None) => None,
        Err(e) => {
            tracing::debug!("update check failed: {e:#}");
            None
        }
    }
}

/// For the release pipeline: a fresh signing key, as (PKCS#8 private key hex, public key hex).
pub fn generate_signing_key() -> Result<(String, String)> {
    use ring::signature::KeyPair;
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| anyhow::anyhow!("generating a key failed"))?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| anyhow::anyhow!("generating a key failed"))?;
    Ok((
        hex::encode(pkcs8.as_ref()),
        hex::encode(pair.public_key().as_ref()),
    ))
}

/// For the release pipeline: sign manifest bytes. Returns the signature as hex.
pub fn sign(pkcs8_hex: &str, bytes: &[u8]) -> Result<String> {
    let der = hex::decode(pkcs8_hex.trim()).context("the signing key isn't hex")?;
    let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&der)
        .map_err(|_| anyhow::anyhow!("the signing key isn't an Ed25519 PKCS#8 key"))?;
    Ok(hex::encode(pair.sign(bytes).as_ref()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(version: &str, body: &[u8]) -> Manifest {
        Manifest {
            schema: 1,
            product: "portglass".into(),
            version: version.into(),
            files: vec![ManifestFile {
                platform: platform().into(),
                program: "portglass-relay".into(),
                name: format!("portglass-relay-v{version}-{}", platform()),
                sha256: hex::encode(ring::digest::digest(&ring::digest::SHA256, body)),
                size: body.len() as u64,
            }],
        }
    }

    #[test]
    fn versions_compare_numerically_and_refuse_odd_ones() {
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("v1.0.0", "0.3.0"));
        assert!(!is_newer("0.3.0", "0.3.0"));
        assert!(!is_newer("0.2.9", "0.3.0"));
        assert!(!is_newer("0.4.0-rc1", "0.3.0"));
        assert!(!is_newer("0.4", "0.3.0"));
        assert!(!is_newer("0.4.0.1", "0.3.0"));
    }

    #[test]
    fn only_a_trusted_signature_over_the_exact_bytes_verifies() {
        let (sk, pk) = generate_signing_key().unwrap();
        let (other_sk, _) = generate_signing_key().unwrap();
        let bytes = serde_json::to_vec(&manifest("0.4.0", b"x")).unwrap();
        let sig = sign(&sk, &bytes).unwrap();
        assert_eq!(
            verify_manifest(&bytes, &sig, &[&pk]).unwrap().version,
            "0.4.0"
        );

        let mut tampered = bytes.clone();
        let at = tampered.iter().position(|&b| b == b'4').unwrap();
        tampered[at] = b'9';
        assert!(verify_manifest(&tampered, &sig, &[&pk]).is_err());
        let forged = sign(&other_sk, &bytes).unwrap();
        assert!(verify_manifest(&bytes, &forged, &[&pk]).is_err());
        assert!(verify_manifest(&bytes, "zz", &[&pk]).is_err());
        assert!(verify_manifest(&bytes, &sig, &[]).is_err());
    }

    #[test]
    fn a_signed_manifest_still_cannot_name_a_path() {
        let (sk, pk) = generate_signing_key().unwrap();
        for name in ["../portglass.exe", "a/b", "a\\b", ".hidden", ""] {
            let mut m = manifest("0.4.0", b"x");
            m.files[0].name = name.into();
            let bytes = serde_json::to_vec(&m).unwrap();
            let sig = sign(&sk, &bytes).unwrap();
            assert!(verify_manifest(&bytes, &sig, &[&pk]).is_err(), "{name:?}");
        }
    }

    #[test]
    fn install_swaps_only_matching_bytes_and_keeps_the_old_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("portglass-relay");
        std::fs::write(&target, b"old build").unwrap();
        let good = b"new build".to_vec();
        let m = manifest("0.4.0", &good);

        assert!(install(b"evil build", &m.files[0], &target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old build");
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no staging file left"
        );

        install(&good, &m.files[0], &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), good);
        assert_eq!(
            std::fs::read(dir.path().join("portglass-relay.old")).unwrap(),
            b"old build"
        );
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "only the program and .old"
        );
    }

    /// Serves `files` over plain HTTP like GitHub's release download URLs, for one test.
    fn serve(files: Vec<(String, Vec<u8>)>) -> String {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                let _ = reader.read_line(&mut line);
                let path = line.split(' ').nth(1).unwrap_or("").to_string();
                loop {
                    let mut h = String::new();
                    if reader.read_line(&mut h).unwrap_or(0) <= 2 {
                        break;
                    }
                }
                let mut s = &stream;
                match files.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) => {
                        let _ = write!(
                            s,
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = s.write_all(body);
                    }
                    None => {
                        let _ = write!(
                            s,
                            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                    }
                }
            }
        });
        format!("http://{addr}")
    }

    #[test]
    fn check_then_install_from_a_release_server() {
        let (sk, pk) = generate_signing_key().unwrap();
        let good = b"the new relay".to_vec();
        let m = manifest("9.0.0", &good);
        let bytes = serde_json::to_vec(&m).unwrap();
        let sig = sign(&sk, &bytes).unwrap();
        let name = m.files[0].name.clone();
        let base = serve(vec![
            (format!("/latest/download/{MANIFEST_NAME}"), bytes),
            (
                format!("/latest/download/{MANIFEST_NAME}.sig"),
                sig.into_bytes(),
            ),
            (format!("/download/v9.0.0/{name}"), good.clone()),
            (format!("/download/v9.0.1/{name}"), b"tampered".to_vec()),
        ]);
        std::env::set_var("PORTGLASS_UPDATE_URL", &base);

        assert!(check_with_keys("portglass-relay", "9.0.0", &[&pk])
            .unwrap()
            .is_none());
        assert!(check_with_keys("portglass-probe", "0.1.0", &[&pk])
            .unwrap()
            .is_none());
        let (other, _) = generate_signing_key().unwrap();
        let other_pk = {
            use ring::signature::KeyPair;
            let der = hex::decode(other).unwrap();
            let pair = ring::signature::Ed25519KeyPair::from_pkcs8(&der).unwrap();
            hex::encode(pair.public_key().as_ref())
        };
        assert!(check_with_keys("portglass-relay", "0.1.0", &[&other_pk]).is_err());

        let available = check_with_keys("portglass-relay", "0.1.0", &[&pk])
            .unwrap()
            .expect("a newer release");
        assert_eq!(available.version, "9.0.0");
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("portglass-relay");
        std::fs::write(&target, b"old").unwrap();

        let tampered = Available {
            url: format!("{base}/download/v9.0.1/{name}"),
            ..available.clone()
        };
        assert!(apply_to(&tampered, &target).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old");

        apply_to(&available, &target).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), good);

        // Once 9.0.0 is installed, a copy still running an older version can't install 9.0.0
        // (or anything older) over it again.
        std::fs::write(&target, b"pretend 9.0.0 is running").unwrap();
        let err = apply_to(&available, &target).unwrap_err();
        assert!(format!("{err:#}").contains("already installed"), "{err:#}");
        assert_eq!(std::fs::read(&target).unwrap(), b"pretend 9.0.0 is running");
        std::env::remove_var("PORTGLASS_UPDATE_URL");
    }

    #[test]
    fn the_compiled_in_keys_are_well_formed() {
        assert!(!UPDATE_KEYS.is_empty());
        for k in UPDATE_KEYS {
            assert_eq!(hex::decode(k).unwrap().len(), 32, "{k}");
        }
    }
}
