//! Filter lists: the IPSet mode, the game filter, the per-user lists, and refreshing the
//! upstream IPSet / hosts data.

use std::io;
use std::path::{Path, PathBuf};

use heli_core::http;
use heli_core::paths::Paths;
use serde::{Deserialize, Serialize};

use crate::bundle::{IPSET_NONE_MARKER, sha256_hex};

pub const IPSET_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/ipset-service.txt";
pub const HOSTS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/refs/heads/main/.service/hosts";
pub const VERSION_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/.service/version.txt";
pub const RELEASES_URL: &str = "https://github.com/Flowseal/zapret-discord-youtube/releases/latest";

const HOSTS_BEGIN: &str = "# >>> HeliBypass hosts >>>";
const HOSTS_END: &str = "# <<< HeliBypass hosts <<<";

#[derive(Debug, thiserror::Error)]
pub enum ListError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("network error: {0}")]
    Http(#[from] http::HttpError),
    #[error("there is no saved IPSet list to restore; update the list first")]
    NoBackup,
    #[error("downloaded data does not look like {0}; keeping the current file")]
    BadPayload(&'static str),
    #[error("invalid port list; use ports or ranges like 1024-1934,1936-65535")]
    BadPorts,
}

// ───────────────────────────── IPSet ─────────────────────────────

/// How the (huge) IP-based filter is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpsetMode {
    /// A dummy address only: IP-based rules match nothing (domain lists still apply).
    None,
    /// The full address list: IP-based rules cover all listed services.
    Loaded,
    /// An empty list: IP-based rules match *every* address.
    Any,
}

impl IpsetMode {
    pub fn label(self) -> &'static str {
        match self {
            IpsetMode::None => "none",
            IpsetMode::Loaded => "loaded",
            IpsetMode::Any => "any",
        }
    }
}

fn ipset_file(paths: &Paths) -> PathBuf {
    paths.lists_dir().join("ipset-all.txt")
}
fn ipset_backup(paths: &Paths) -> PathBuf {
    paths.lists_dir().join("ipset-all.txt.backup")
}

pub fn ipset_mode(paths: &Paths) -> IpsetMode {
    let Ok(text) = std::fs::read_to_string(ipset_file(paths)) else { return IpsetMode::None };
    if text.trim().is_empty() {
        IpsetMode::Any
    } else if text.contains(IPSET_NONE_MARKER) {
        IpsetMode::None
    } else {
        IpsetMode::Loaded
    }
}

/// Switch to `target`, preserving the full list in `ipset-all.txt.backup` so that switching
/// back to [`IpsetMode::Loaded`] restores it.
pub fn set_ipset_mode(paths: &Paths, target: IpsetMode) -> Result<(), ListError> {
    let current = ipset_mode(paths);
    if current == target {
        return Ok(());
    }
    let live = ipset_file(paths);
    let backup = ipset_backup(paths);
    if current == IpsetMode::Loaded {
        std::fs::copy(&live, &backup)?;
    }
    match target {
        IpsetMode::None => std::fs::write(&live, format!("{IPSET_NONE_MARKER}\n"))?,
        IpsetMode::Any => std::fs::write(&live, b"")?,
        IpsetMode::Loaded => {
            if !backup.exists() {
                return Err(ListError::NoBackup);
            }
            std::fs::copy(&backup, &live)?;
        }
    }
    Ok(())
}

/// Plausibility check so that an HTML error page never replaces the real list.
pub fn looks_like_ipset(text: &str) -> bool {
    let mut total = 0usize;
    let mut valid = 0usize;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        total += 1;
        let ip = line.split('/').next().unwrap_or("");
        if ip.parse::<std::net::IpAddr>().is_ok() {
            valid += 1;
        }
    }
    total >= 100 && valid * 100 >= total * 95
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpsetUpdate {
    pub entries: usize,
    pub changed: bool,
}

/// Download the upstream IPSet. If the filter is currently `Loaded` the live file is replaced;
/// otherwise the update is stored as the backup so the next switch to `Loaded` uses it.
pub async fn update_ipset(paths: &Paths) -> Result<IpsetUpdate, ListError> {
    let body = http::get(IPSET_URL).await?.ok()?.text();
    if !looks_like_ipset(&body) {
        return Err(ListError::BadPayload("an IP list"));
    }
    let target = if ipset_mode(paths) == IpsetMode::Loaded { ipset_file(paths) } else { ipset_backup(paths) };
    let changed = std::fs::read_to_string(&target).map(|old| old != body).unwrap_or(true);
    if changed {
        heli_core::paths::write_atomic(&target, body.as_bytes())?;
    }
    let entries = body.lines().filter(|l| !l.trim().is_empty()).count();
    record_check(paths, |s| s.ipset_sha256 = Some(sha256_hex(body.as_bytes())));
    Ok(IpsetUpdate { entries, changed })
}

// ───────────────────────────── Game filter ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GameMode {
    Disabled,
    All,
    Tcp,
    Udp,
}

impl GameMode {
    fn as_str(self) -> &'static str {
        match self {
            GameMode::Disabled => "disabled",
            GameMode::All => "all",
            GameMode::Tcp => "tcp",
            GameMode::Udp => "udp",
        }
    }
}

/// Extends the bypass to game traffic on high ports. Persisted in the same
/// `utils/game_filter.enabled` format as the upstream scripts use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GameFilter {
    pub mode: GameMode,
    pub tcp_range: String,
    pub udp_range: String,
}

pub const DEFAULT_GAME_RANGE: &str = "1024-65535";
/// A port nothing listens on; used for the placeholder when a direction is disabled.
pub const DISABLED_PORT: &str = "12";

impl Default for GameFilter {
    fn default() -> Self {
        Self { mode: GameMode::Disabled, tcp_range: DEFAULT_GAME_RANGE.into(), udp_range: DEFAULT_GAME_RANGE.into() }
    }
}

impl GameFilter {
    fn file(paths: &Paths) -> PathBuf {
        paths.utils_dir().join("game_filter.enabled")
    }

    pub fn load(paths: &Paths) -> Self {
        std::fs::read_to_string(Self::file(paths)).map(|t| Self::parse(&t)).unwrap_or_default()
    }

    pub fn parse(text: &str) -> Self {
        let mut gf = Self::default();
        for line in text.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
            match k.as_str() {
                "mode" => {
                    gf.mode = match v.to_ascii_lowercase().as_str() {
                        "all" => GameMode::All,
                        "tcp" => GameMode::Tcp,
                        "udp" => GameMode::Udp,
                        _ => GameMode::Disabled,
                    }
                }
                // legacy flag-style files
                "all" => gf.mode = GameMode::All,
                "tcp" if v.is_empty() => gf.mode = GameMode::Tcp,
                "udp" if v.is_empty() => gf.mode = GameMode::Udp,
                "tcp" => {
                    if let Some(r) = validate_ports(v) {
                        gf.tcp_range = r;
                    }
                }
                "udp" => {
                    if let Some(r) = validate_ports(v) {
                        gf.udp_range = r;
                    }
                }
                _ => {}
            }
        }
        gf
    }

    pub fn save(&self, paths: &Paths) -> io::Result<()> {
        std::fs::create_dir_all(paths.utils_dir())?;
        std::fs::write(
            Self::file(paths),
            format!("mode={}\r\ntcp={}\r\nudp={}\r\n", self.mode.as_str(), self.tcp_range, self.udp_range),
        )
    }

    /// Value for the `%GameFilterTCP%` placeholder.
    pub fn tcp_arg(&self) -> String {
        if matches!(self.mode, GameMode::All | GameMode::Tcp) { self.tcp_range.clone() } else { DISABLED_PORT.into() }
    }

    /// Value for the `%GameFilterUDP%` placeholder.
    pub fn udp_arg(&self) -> String {
        if matches!(self.mode, GameMode::All | GameMode::Udp) { self.udp_range.clone() } else { DISABLED_PORT.into() }
    }

    pub fn is_enabled(&self) -> bool {
        self.mode != GameMode::Disabled
    }
}

/// Validate `1024-1934,1936-65535`; returns the list without spaces.
pub fn validate_ports(input: &str) -> Option<String> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    for item in cleaned.split(',') {
        let (a, b) = match item.split_once('-') {
            Some((a, b)) => (a, b),
            None => (item, item),
        };
        let ok = |s: &str| !s.is_empty() && s.len() <= 5 && s.bytes().all(|c| c.is_ascii_digit()) && !s.starts_with('0');
        if !ok(a) || !ok(b) {
            return None;
        }
        let (a, b): (u32, u32) = (a.parse().ok()?, b.parse().ok()?);
        if a > 65535 || b > 65535 || a > b {
            return None;
        }
    }
    Some(cleaned)
}

// ───────────────────────────── hosts file ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostsStatus {
    UpToDate,
    NeedsUpdate,
    Unreadable,
}

pub fn system_hosts_path() -> PathBuf {
    let root = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    root.join(r"System32\drivers\etc\hosts")
}

fn looks_like_hosts(text: &str) -> bool {
    text.lines().map(str::trim).any(|l| {
        !l.starts_with('#')
            && l.split_whitespace().next().is_some_and(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            && l.split_whitespace().count() >= 2
    })
}

fn first_last(text: &str) -> Option<(&str, &str)> {
    let mut it = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = it.next()?;
    let last = it.last().unwrap_or(first);
    Some((first, last))
}

/// Compare the system hosts file with the upstream snippet (same first/last-line test as
/// the upstream service script).
pub fn hosts_status(hosts_path: &Path, remote: &str) -> HostsStatus {
    let Ok(local) = std::fs::read_to_string(hosts_path) else { return HostsStatus::Unreadable };
    let Some((first, last)) = first_last(remote) else { return HostsStatus::UpToDate };
    if local.lines().any(|l| l.trim() == first) && local.lines().any(|l| l.trim() == last) {
        HostsStatus::UpToDate
    } else {
        HostsStatus::NeedsUpdate
    }
}

pub async fn fetch_hosts() -> Result<String, ListError> {
    let url = format!("{HOSTS_URL}?t={}", rand::random::<u32>());
    let body = http::get(&url).await?.ok()?.text();
    if !looks_like_hosts(&body) {
        return Err(ListError::BadPayload("a hosts file"));
    }
    Ok(body)
}

/// Insert (or replace) the upstream snippet as a clearly marked block. The original file is
/// saved to `backup_dir` first.
pub fn apply_hosts(hosts_path: &Path, remote: &str, backup_dir: &Path) -> Result<(), ListError> {
    let original = std::fs::read_to_string(hosts_path).unwrap_or_default();
    std::fs::create_dir_all(backup_dir)?;
    let backup = backup_dir.join("hosts.original");
    if !backup.exists() {
        std::fs::write(backup, &original)?;
    }
    let mut kept = strip_hosts_block(&original);
    while kept.ends_with("\r\n\r\n") {
        kept.truncate(kept.len() - 2);
    }
    if !kept.is_empty() && !kept.ends_with('\n') {
        kept.push_str("\r\n");
    }
    let body = remote.trim().replace("\r\n", "\n").replace('\n', "\r\n");
    kept.push_str(&format!("\r\n{HOSTS_BEGIN}\r\n{body}\r\n{HOSTS_END}\r\n"));
    std::fs::write(hosts_path, kept)?;
    Ok(())
}

pub fn remove_hosts_block(hosts_path: &Path) -> Result<(), ListError> {
    let original = std::fs::read_to_string(hosts_path)?;
    std::fs::write(hosts_path, strip_hosts_block(&original))?;
    Ok(())
}

fn strip_hosts_block(text: &str) -> String {
    let (Some(b), Some(e)) = (text.find(HOSTS_BEGIN), text.find(HOSTS_END)) else { return text.to_owned() };
    if e < b {
        return text.to_owned();
    }
    let end = e + HOSTS_END.len();
    let end = text[end..].strip_prefix("\r\n").map(|_| end + 2).or_else(|| text[end..].strip_prefix('\n').map(|_| end + 1)).unwrap_or(end);
    let mut out = text[..b].trim_end_matches(['\r', '\n']).to_owned();
    if !out.is_empty() {
        out.push_str("\r\n");
    }
    out.push_str(&text[end..]);
    out
}

// ───────────────────────────── freshness bookkeeping ─────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListsState {
    /// Unix seconds of the last successful check against upstream.
    pub last_checked: Option<u64>,
    /// SHA-256 of the upstream IPSet at the last check/update.
    pub ipset_sha256: Option<String>,
}

fn state_file(paths: &Paths) -> PathBuf {
    paths.utils_dir().join("lists-state.json")
}

impl ListsState {
    pub fn load(paths: &Paths) -> Self {
        std::fs::read_to_string(state_file(paths)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }
}

fn record_check(paths: &Paths, f: impl FnOnce(&mut ListsState)) {
    let mut s = ListsState::load(paths);
    s.last_checked = Some(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0));
    f(&mut s);
    if let Ok(json) = serde_json::to_vec_pretty(&s) {
        let _ = heli_core::paths::write_atomic(&state_file(paths), &json);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListsStatus {
    /// `None` when upstream could not be reached.
    pub ipset_current: Option<bool>,
    pub hosts: HostsStatus,
}

/// Ask upstream whether our lists are current (downloads the IPSet to compare content).
pub async fn check_lists(paths: &Paths) -> ListsStatus {
    let ipset_current = match http::get(IPSET_URL).await.and_then(|r| r.ok()) {
        Ok(resp) if looks_like_ipset(&resp.text()) => {
            let remote = sha256_hex(&resp.body);
            let local_file = if ipset_mode(paths) == IpsetMode::Loaded { ipset_file(paths) } else { ipset_backup(paths) };
            let local = std::fs::read(&local_file).map(|b| sha256_hex(&b)).ok();
            record_check(paths, |s| s.ipset_sha256 = Some(remote.clone()));
            Some(local.as_deref() == Some(remote.as_str()))
        }
        _ => None,
    };
    let hosts = match fetch_hosts().await {
        Ok(remote) => hosts_status(&system_hosts_path(), &remote),
        Err(_) => HostsStatus::Unreadable,
    };
    ListsStatus { ipset_current, hosts }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(tag: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("heli-lists-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = Paths::at(dir);
        p.ensure_dirs().unwrap();
        p
    }

    #[test]
    fn ipset_modes_cycle_and_preserve_the_full_list() {
        let p = temp_paths("ipset");
        let full: String = (0..300).map(|i| format!("10.{}.{}.0/24\n", i / 256, i % 256)).collect();
        std::fs::write(ipset_file(&p), &full).unwrap();
        assert_eq!(ipset_mode(&p), IpsetMode::Loaded);

        set_ipset_mode(&p, IpsetMode::None).unwrap();
        assert_eq!(ipset_mode(&p), IpsetMode::None);
        assert_eq!(std::fs::read_to_string(ipset_backup(&p)).unwrap(), full, "full list saved as backup");

        set_ipset_mode(&p, IpsetMode::Any).unwrap();
        assert_eq!(ipset_mode(&p), IpsetMode::Any);
        assert_eq!(std::fs::read_to_string(ipset_backup(&p)).unwrap(), full, "backup untouched by none->any");

        set_ipset_mode(&p, IpsetMode::Loaded).unwrap();
        assert_eq!(ipset_mode(&p), IpsetMode::Loaded);
        assert_eq!(std::fs::read_to_string(ipset_file(&p)).unwrap(), full);

        std::fs::remove_file(ipset_backup(&p)).unwrap();
        set_ipset_mode(&p, IpsetMode::None).unwrap(); // backs up again
        std::fs::remove_file(ipset_backup(&p)).unwrap();
        assert!(matches!(set_ipset_mode(&p, IpsetMode::Loaded), Err(ListError::NoBackup)));
        std::fs::remove_dir_all(p.root()).unwrap();
    }

    #[test]
    fn ipset_plausibility() {
        let good: String = (0..200).map(|i| format!("1.2.{i}.0/24\n")).collect();
        assert!(looks_like_ipset(&good));
        assert!(!looks_like_ipset("<html><body>404</body></html>"));
        assert!(!looks_like_ipset("1.2.3.0/24\n"), "too short to be the real list");
    }

    #[test]
    fn game_filter_parse_save_args() {
        let gf = GameFilter::parse("mode=all\r\ntcp=1024-1934,1936-65535\r\nudp=27000-27100\r\n");
        assert_eq!(gf.mode, GameMode::All);
        assert_eq!(gf.tcp_arg(), "1024-1934,1936-65535");
        assert_eq!(gf.udp_arg(), "27000-27100");

        let tcp_only = GameFilter { mode: GameMode::Tcp, ..GameFilter::default() };
        assert_eq!(tcp_only.tcp_arg(), "1024-65535");
        assert_eq!(tcp_only.udp_arg(), DISABLED_PORT);
        assert_eq!(GameFilter::default().tcp_arg(), DISABLED_PORT);

        // legacy flag files and invalid ranges
        assert_eq!(GameFilter::parse("udp=\r\n").mode, GameMode::Udp);
        assert_eq!(GameFilter::parse("mode=tcp\r\ntcp=99999\r\n").tcp_range, DEFAULT_GAME_RANGE);

        let p = temp_paths("game");
        let saved = GameFilter { mode: GameMode::Udp, tcp_range: "5000".into(), udp_range: "6000-7000".into() };
        saved.save(&p).unwrap();
        assert_eq!(GameFilter::load(&p), saved);
        std::fs::remove_dir_all(p.root()).unwrap();
    }

    #[test]
    fn port_validation_matches_upstream_rules() {
        assert_eq!(validate_ports(" 1024 - 2000 ").as_deref(), Some("1024-2000"), "spaces are stripped first");
        assert_eq!(validate_ports("1024-2000, 3000").as_deref(), Some("1024-2000,3000"));
        for bad in ["", "0", "65536", "10-5", "a", "1,,2", "1-", "-1", "123456"] {
            assert!(validate_ports(bad).is_none(), "{bad:?} must be rejected");
        }
        assert!(validate_ports("1-65535").is_some());
    }

    #[test]
    fn hosts_block_roundtrip() {
        let dir = std::env::temp_dir().join(format!("heli-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let hosts = dir.join("hosts");
        let original = "# my hosts\r\n127.0.0.1 localhost\r\n";
        std::fs::write(&hosts, original).unwrap();
        let remote = "# first\n1.2.3.4 a.example\n5.6.7.8 b.example\n# last\n";
        assert_eq!(hosts_status(&hosts, remote), HostsStatus::NeedsUpdate);

        apply_hosts(&hosts, remote, &dir.join("bak")).unwrap();
        assert_eq!(hosts_status(&hosts, remote), HostsStatus::UpToDate);
        let after = std::fs::read_to_string(&hosts).unwrap();
        assert!(after.starts_with(original));
        assert_eq!(after.matches(HOSTS_BEGIN).count(), 1);

        // applying again must replace, not duplicate
        apply_hosts(&hosts, "# first\n9.9.9.9 c.example\n# last\n", &dir.join("bak")).unwrap();
        let again = std::fs::read_to_string(&hosts).unwrap();
        assert_eq!(again.matches(HOSTS_BEGIN).count(), 1);
        assert!(again.contains("9.9.9.9") && !again.contains("1.2.3.4"));

        remove_hosts_block(&hosts).unwrap();
        assert_eq!(std::fs::read_to_string(&hosts).unwrap().trim_end(), original.trim_end());
        assert_eq!(std::fs::read_to_string(dir.join("bak/hosts.original")).unwrap(), original);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
