//! In-app updates from GitHub Releases: ask for the latest tag, download the
//! platform archive, check it against `SHA256SUMS.txt`, and swap the running
//! executable for the new one before restarting.

use crate::app_dirs;
use crate::archive;
use ghostchat_nostr::{https_get, Transport};
use semver::Version;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const API_HOST: &str = "api.github.com";
const API_PATH: &str = "/repos/aymenmerabta5/ghostchat/releases/latest";
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_JSON: usize = 1 << 20;
const MAX_SUMS: usize = 1 << 20;
const MAX_ARCHIVE: usize = 96 << 20;
const SUMS: &str = "SHA256SUMS.txt";

#[cfg(windows)]
const ARCHIVE_SUFFIX: &str = "-windows-x86_64.zip";
#[cfg(target_os = "linux")]
const ARCHIVE_SUFFIX: &str = "-linux-x86_64.tar.gz";
#[cfg(not(any(windows, target_os = "linux")))]
const ARCHIVE_SUFFIX: &str = "-no-build-for-this-platform";

/// Where the update is in its life; the settings sheet renders each one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    Checking,
    Available,
    Downloading,
    Ready,
    UpToDate,
    Failed,
    /// The executable is replaced; only a restart is left.
    Restart,
}

#[derive(Debug, Clone, Default)]
pub struct State {
    pub phase: Phase,
    pub latest: Option<Release>,
    pub error: Option<String>,
    /// A downloaded, verified executable waiting to replace this one.
    pub staged: Option<PathBuf>,
}

impl State {
    /// The newer release, while it is being offered or applied.
    pub fn pending(&self) -> Option<&Release> {
        match self.phase {
            Phase::Available | Phase::Downloading | Phase::Ready => self.latest.as_ref(),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Release {
    pub version: String,
    pub tag: String,
    pub page: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Clone, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

impl Release {
    fn asset(&self, suffix: &str) -> Option<&Asset> {
        self.assets.iter().find(|asset| asset.name.ends_with(suffix))
    }
}

/// The latest release if it is newer than this build, `None` when this build
/// is current. GitHub omits drafts and prereleases from `latest`; they are
/// refused again here in case the answer ever comes from somewhere else.
pub async fn check(transport: Transport) -> Result<Option<Release>, String> {
    let body = https_get::get_following(API_HOST, API_PATH, transport, MAX_JSON, CHECK_TIMEOUT).await?;
    let api: ApiRelease =
        serde_json::from_slice(&body).map_err(|err| format!("GitHub sent an unreadable release: {err}"))?;
    if api.draft || api.prerelease {
        return Ok(None);
    }
    let latest = version_of(&api.tag_name).ok_or_else(|| format!("release {} is not a version", api.tag_name))?;
    let current = version_of(CURRENT).ok_or_else(|| format!("this build's version ({CURRENT}) is not a version"))?;
    if latest <= current {
        return Ok(None);
    }
    Ok(Some(Release { version: latest.to_string(), tag: api.tag_name, page: api.html_url, assets: api.assets }))
}

/// Download the release's archive, verify its published SHA-256, and extract
/// the executable to the per-user update folder.
pub async fn stage(release: &Release, transport: Transport) -> Result<PathBuf, String> {
    let archive =
        release.asset(ARCHIVE_SUFFIX).ok_or_else(|| format!("{} has no build for this platform", release.tag))?;
    let sums = release.asset(SUMS).ok_or_else(|| format!("{} has no {SUMS}", release.tag))?;
    let (archive_host, archive_path) = split_url(&archive.browser_download_url)?;
    let (sums_host, sums_path) = split_url(&sums.browser_download_url)?;
    let (archive_bytes, sums_bytes) = tokio::try_join!(
        https_get::get_following(&archive_host, &archive_path, transport, MAX_ARCHIVE, DOWNLOAD_TIMEOUT),
        https_get::get_following(&sums_host, &sums_path, transport, MAX_SUMS, CHECK_TIMEOUT),
    )?;
    let expected = expected_sum(&sums_bytes, &archive.name)?;
    let actual = hex_sha256(&archive_bytes);
    if !actual.eq_ignore_ascii_case(&expected) {
        return Err(format!("{} does not match its published SHA-256", archive.name));
    }
    let binary =
        archive::binary(&archive_bytes).map_err(|err| format!("the release archive is unreadable: {err:#}"))?;
    let dir = updates_dir().ok_or("there is no per-user folder for the download")?;
    fs::create_dir_all(&dir).map_err(|err| format!("could not create {}: {err}", dir.display()))?;
    let staged = dir.join(format!("ghostchat-{}{}", release.version, std::env::consts::EXE_SUFFIX));
    fs::write(&staged, &binary).map_err(|err| format!("could not save the update: {err}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("could not make the update executable: {err}"))?;
    }
    Ok(staged)
}

/// Replace the running executable with the staged one; the caller restarts
/// with the returned path. On Windows the running image is renamed aside
/// first (a running exe can be renamed but not overwritten); the next start
/// deletes it.
pub fn install(staged: &Path) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|err| format!("could not find the running ghostchat: {err}"))?;
    replace(&exe, staged)?;
    Ok(exe)
}

#[cfg(windows)]
fn replace(exe: &Path, staged: &Path) -> Result<(), String> {
    // Prepare the new image next to the old one first, so a failed copy
    // leaves the running install untouched. The two renames then happen
    // back to back.
    let next = exe.with_file_name(format!("ghostchat-{CURRENT}-new.exe"));
    if let Err(err) = fs::copy(staged, &next) {
        let _ = fs::remove_file(&next);
        return Err(format!("could not write the new ghostchat: {err}"));
    }
    let old = exe.with_file_name(format!("ghostchat-{CURRENT}-old.exe"));
    let _ = fs::remove_file(&old);
    if let Err(err) = fs::rename(exe, &old) {
        let _ = fs::remove_file(&next);
        return Err(format!("could not move the running ghostchat aside: {err}"));
    }
    if let Err(err) = fs::rename(&next, exe) {
        let _ = fs::rename(&old, exe);
        let _ = fs::remove_file(&next);
        return Err(format!("could not put the new ghostchat in place: {err}"));
    }
    Ok(())
}

#[cfg(unix)]
fn replace(exe: &Path, staged: &Path) -> Result<(), String> {
    const HINT: &str = "If ghostchat came from a .deb, install the new package from the release page instead.";
    let dir = exe.parent().ok_or("ghostchat has no folder")?;
    let next = dir.join(format!(".ghostchat-{}.new", std::process::id()));
    fs::copy(staged, &next).map_err(|err| format!("could not write next to {}: {err}. {HINT}", exe.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(&next, fs::Permissions::from_mode(0o755));
    fs::rename(&next, exe).map_err(|err| {
        let _ = fs::remove_file(&next);
        format!("could not replace {}: {err}. {HINT}", exe.display())
    })
}

/// Remove what an earlier update left behind: the renamed old executable and
/// any prepared-but-unused new one (both unlocked now), plus archives staged
/// for a version this process no longer needs.
pub fn cleanup() {
    let Ok(exe) = std::env::current_exe() else { return };
    if let Some(dir) = exe.parent() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("ghostchat-") && (name.ends_with("-old.exe") || name.ends_with("-new.exe")) {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
    if let Some(dir) = updates_dir() {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

fn updates_dir() -> Option<PathBuf> {
    app_dirs::data_local_dir().map(|dir| dir.join("updates"))
}

fn version_of(tag: &str) -> Option<Version> {
    Version::parse(tag.trim().trim_start_matches('v')).ok()
}

fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| format!("{url} is not https"))?;
    match rest.find('/') {
        Some(at) => Ok((rest[..at].to_string(), rest[at..].to_string())),
        None => Ok((rest.to_string(), "/".to_string())),
    }
}

fn expected_sum(sums: &[u8], name: &str) -> Result<String, String> {
    let text = std::str::from_utf8(sums).map_err(|_| format!("{SUMS} is not text"))?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(file)) = (parts.next(), parts.next()) else { continue };
        if file.trim_start_matches('*') == name {
            return Ok(hash.to_string());
        }
    }
    Err(format!("{SUMS} does not list {name}"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_tags_compare_as_versions() {
        assert!(version_of("v0.3.0") > version_of("0.2.0"));
        assert_eq!(version_of("v0.2.0"), version_of("0.2.0"));
        assert!(version_of("nightly").is_none());
    }

    #[test]
    fn sums_name_the_right_file() {
        let sums = b"aa11  ghostchat-v0.3.0-windows-x86_64.zip\nbb22 *ghostchat-v0.3.0-linux-x86_64.tar.gz\n";
        assert_eq!(expected_sum(sums, "ghostchat-v0.3.0-windows-x86_64.zip").unwrap(), "aa11");
        assert_eq!(expected_sum(sums, "ghostchat-v0.3.0-linux-x86_64.tar.gz").unwrap(), "bb22");
        assert!(expected_sum(sums, "missing.zip").is_err());
    }

    #[test]
    fn release_urls_split_into_host_and_path() {
        assert_eq!(
            split_url("https://github.com/a/b/releases/download/v1/x.zip").unwrap(),
            ("github.com".into(), "/a/b/releases/download/v1/x.zip".into())
        );
        assert!(split_url("http://github.com/x").is_err());
    }

    #[test]
    fn sha256_hex_matches_the_empty_input() {
        assert_eq!(hex_sha256(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn the_staged_binary_replaces_the_executable() {
        let dir = std::env::temp_dir().join(format!("ghostchat-update-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join(format!("ghostchat{}", std::env::consts::EXE_SUFFIX));
        let staged = dir.join(format!("staged{}", std::env::consts::EXE_SUFFIX));
        fs::write(&exe, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        replace(&exe, &staged).unwrap();
        assert_eq!(fs::read(&exe).unwrap(), b"new");
        #[cfg(windows)]
        assert_eq!(fs::read(dir.join(format!("ghostchat-{CURRENT}-old.exe"))).unwrap(), b"old");
        let _ = fs::remove_dir_all(&dir);
    }

    /// `cargo test -p ghostchat-app live_ -- --ignored` (internet).
    #[tokio::test]
    #[ignore = "internet"]
    async fn live_check_reads_the_latest_release() {
        let latest = check(Transport::Direct).await.unwrap();
        assert!(
            latest.as_ref().is_none_or(|release| version_of(&release.version) > version_of(CURRENT)),
            "check offered an older release"
        );
    }

    /// Downloads the published asset, checks its SHA-256 and extracts it.
    #[tokio::test]
    #[ignore = "internet"]
    async fn live_release_downloads_and_verifies() {
        let body =
            https_get::get_following(API_HOST, API_PATH, Transport::Direct, MAX_JSON, CHECK_TIMEOUT).await.unwrap();
        let api: ApiRelease = serde_json::from_slice(&body).unwrap();
        let release = Release {
            version: version_of(&api.tag_name).unwrap().to_string(),
            tag: api.tag_name,
            page: api.html_url,
            assets: api.assets,
        };
        let staged = stage(&release, Transport::Direct).await.unwrap();
        let size = fs::metadata(&staged).unwrap().len();
        assert!(size > 1_000_000, "the extracted binary is suspiciously small: {size}");
        let _ = fs::remove_file(&staged);
    }
}
