//! Environment checks that predict why a bypass would not work (port of the upstream
//! `service.bat` diagnostics), each with an optional one-click fix.

use std::path::Path;
use std::time::Duration;

use heli_core::paths::Paths;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

use crate::bundle;
use crate::engine::SERVICE_NAME;
use crate::proc;
use crate::scm::{self, ServiceInfo, ServiceState};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// Remove a stale WinDivert driver service (winws is not running but the driver is loaded).
    UnloadWinDivert,
    /// Stop and delete other bypass tools' services (they fight over WinDivert).
    RemoveConflictingServices(Vec<String>),
    /// Re-extract engine files from the bundle.
    RepairEngineFiles,
    /// Close Discord and clear its cache folders.
    ClearDiscordCache,
    /// Turn TCP timestamps on (needed by `fooling=ts` strategies).
    EnableTcpTimestamps,
}

impl Fix {
    pub fn label(&self) -> &'static str {
        match self {
            Fix::UnloadWinDivert => "Unload WinDivert",
            Fix::RemoveConflictingServices(_) => "Remove services",
            Fix::RepairEngineFiles => "Repair files",
            Fix::ClearDiscordCache => "Clear Discord cache",
            Fix::EnableTcpTimestamps => "Enable now",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub id: &'static str,
    pub title: String,
    pub severity: Severity,
    pub detail: String,
    pub fix: Option<Fix>,
}

impl Check {
    fn new(id: &'static str, severity: Severity, title: &str, detail: impl Into<String>) -> Self {
        Self { id, title: title.to_owned(), severity, detail: detail.into(), fix: None }
    }
    fn with_fix(mut self, fix: Fix) -> Self {
        self.fix = Some(fix);
        self
    }
}

/// Run every check (blocking; call from `spawn_blocking`).
pub fn run(paths: &Paths) -> Vec<Check> {
    let mut out = Vec::new();
    let running = scm::running_services().unwrap_or_default();
    let installed = scm::installed_services().unwrap_or_default();

    out.push(if heli_core::elevation::is_elevated() {
        Check::new("admin", Severity::Ok, "Administrator rights", "Running elevated.")
    } else {
        Check::new("admin", Severity::Fail, "Administrator rights", "Not elevated. The bypass engine (WinDivert) cannot start without administrator rights.")
    });

    out.push(match scm::query("BFE") {
        Ok(ServiceState::Running) => Check::new("bfe", Severity::Ok, "Base Filtering Engine", "Running."),
        _ => Check::new("bfe", Severity::Fail, "Base Filtering Engine", "The service is not running. zapret cannot work without it."),
    });

    out.push(system_proxy_check());

    out.push(
        Check::new(
            "tcp-timestamps",
            Severity::Ok,
            "TCP timestamps",
            "Enabled automatically each time the bypass starts (required by several strategies).",
        )
        .with_fix(Fix::EnableTcpTimestamps),
    );

    out.push(if proc::is_running("AdguardSvc.exe") {
        Check::new("adguard", Severity::Fail, "AdGuard", "AdGuard is running and may break Discord. See github.com/Flowseal/zapret-discord-youtube/issues/417")
    } else {
        Check::new("adguard", Severity::Ok, "AdGuard", "Not found.")
    });

    let find = |pred: &dyn Fn(&str) -> bool| -> Vec<&ServiceInfo> {
        running.iter().filter(|s| pred(&s.name.to_lowercase()) || pred(&s.display_name.to_lowercase())).collect()
    };
    for (id, title, hits, advice) in [
        (
            "killer",
            "Killer network services",
            find(&|n| n.contains("killer")),
            "Killer services conflict with zapret. See github.com/Flowseal/zapret-discord-youtube/issues/2512",
        ),
        (
            "intel",
            "Intel Connectivity Network Service",
            find(&|n| n.contains("intel") && n.contains("connectivity") && n.contains("network")),
            "This Intel service conflicts with zapret.",
        ),
        (
            "checkpoint",
            "Check Point",
            find(&|n| n.contains("tracsrvwrapper") || n.contains("epwd")),
            "Check Point conflicts with zapret. Try to uninstall it.",
        ),
        (
            "smartbyte",
            "SmartByte",
            find(&|n| n.contains("smartbyte")),
            "SmartByte conflicts with zapret. Uninstall it or disable it in services.msc.",
        ),
    ] {
        out.push(if hits.is_empty() {
            Check::new(id, Severity::Ok, title, "Not found.")
        } else {
            Check::new(id, Severity::Fail, title, format!("{advice} Found: {}", join_names(&hits)))
        });
    }

    let vpn = find(&|n| n.contains("vpn"));
    out.push(if vpn.is_empty() {
        Check::new("vpn", Severity::Ok, "VPN services", "None running.")
    } else {
        Check::new("vpn", Severity::Warn, "VPN services", format!("Some VPNs conflict with zapret; make sure they are off. Found: {}", join_names(&vpn)))
    });

    out.push(path_check(paths.root()));
    out.push(engine_files_check(paths));
    out.push(doh_check());
    out.push(hosts_check());

    // WinDivert left behind without winws.exe
    let winws_up = proc::is_running("winws.exe");
    let windivert_active = matches!(scm::query("WinDivert"), Ok(ServiceState::Running | ServiceState::StopPending));
    out.push(if !winws_up && windivert_active {
        Check::new("windivert", Severity::Warn, "WinDivert driver", "winws.exe is not running but the WinDivert driver is still loaded.").with_fix(Fix::UnloadWinDivert)
    } else {
        Check::new("windivert", Severity::Ok, "WinDivert driver", "No stale driver.")
    });

    let conflicts: Vec<String> = ["GoodbyeDPI", "discordfix_zapret", "winws1", "winws2"]
        .iter()
        .filter(|c| installed.iter().any(|s| s.name.eq_ignore_ascii_case(c)))
        .map(|c| (*c).to_owned())
        .collect();
    out.push(if conflicts.is_empty() {
        Check::new("conflicts", Severity::Ok, "Other bypass tools", "No conflicting services.")
    } else {
        Check::new("conflicts", Severity::Fail, "Other bypass tools", format!("Conflicting services installed: {}", conflicts.join(", ")))
            .with_fix(Fix::RemoveConflictingServices(conflicts))
    });

    out.push(Check::new(
        "discord-cache",
        Severity::Ok,
        "Discord cache",
        "Clearing the cache helps when Discord stays stuck after changing strategy.",
    )
    .with_fix(Fix::ClearDiscordCache));

    let svc = scm::query(SERVICE_NAME).unwrap_or(ServiceState::NotInstalled);
    out.push(match svc {
        ServiceState::Running => Check::new("service", Severity::Ok, "zapret service", "Installed and running."),
        ServiceState::NotInstalled => Check::new("service", Severity::Ok, "zapret service", "Not installed."),
        other => Check::new("service", Severity::Warn, "zapret service", format!("State: {other:?}")),
    });
    out
}

fn join_names(items: &[&ServiceInfo]) -> String {
    items.iter().map(|s| s.display_name.as_str()).collect::<Vec<_>>().join(", ")
}

fn system_proxy_check() -> Check {
    let key = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", KEY_READ);
    let enabled = key.as_ref().ok().and_then(|k| k.get_value::<u32, _>("ProxyEnable").ok()).unwrap_or(0) == 1;
    if enabled {
        let server = key.ok().and_then(|k| k.get_value::<String, _>("ProxyServer").ok()).unwrap_or_default();
        Check::new("proxy", Severity::Warn, "System proxy", format!("A system proxy is enabled. Make sure it is valid, or turn it off if you do not use one. Server: {server}"))
    } else {
        Check::new("proxy", Severity::Ok, "System proxy", "Not enabled.")
    }
}

fn path_check(root: &Path) -> Check {
    let s = root.to_string_lossy();
    if !s.is_ascii() {
        return Check::new("path", Severity::Warn, "Install path", format!("The data folder path contains non-ASCII characters. If the bypass misbehaves, move HeliBypass data to an ASCII-only folder (set HELIBYPASS_HOME). Path: {s}"));
    }
    if let Some(od) = std::env::var_os("OneDrive") {
        let od = od.to_string_lossy().to_lowercase();
        if !od.is_empty() && s.to_lowercase().starts_with(&od) {
            return Check::new("path", Severity::Fail, "Install path", "The data folder is inside OneDrive. Move it elsewhere (for example C:\\HeliBypass).");
        }
    }
    Check::new("path", Severity::Ok, "Install path", s.into_owned())
}

fn engine_files_check(paths: &Paths) -> Check {
    let bad = bundle::verify_engine(paths);
    if bad.is_empty() {
        Check::new("engine-files", Severity::Ok, "Engine files", "winws.exe and the WinDivert driver match the bundled copies.")
    } else {
        Check::new("engine-files", Severity::Warn, "Engine files", format!("Missing or modified files: {}", bad.len())).with_fix(Fix::RepairEngineFiles)
    }
}

fn doh_check() -> Check {
    fn any_doh(key: &RegKey, depth: u8) -> bool {
        if key.get_value::<u32, _>("DohFlags").is_ok_and(|f| f > 0) {
            return true;
        }
        if depth == 0 {
            return false;
        }
        key.enum_keys().filter_map(Result::ok).any(|name| key.open_subkey_with_flags(&name, KEY_READ).is_ok_and(|k| any_doh(&k, depth - 1)))
    }
    let found = RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(r"SYSTEM\CurrentControlSet\Services\Dnscache\InterfaceSpecificParameters", KEY_READ)
        .map(|k| any_doh(&k, 5))
        .unwrap_or(false);
    if found {
        Check::new("dns", Severity::Ok, "Secure DNS", "Encrypted DNS (DoH) is configured in Windows.")
    } else {
        Check::new("dns", Severity::Warn, "Secure DNS", "Make sure secure DNS is set up in your browser with a non-default provider, or enable encrypted DNS in Windows 11 settings.")
    }
}

fn hosts_check() -> Check {
    let text = std::fs::read_to_string(crate::lists::system_hosts_path()).unwrap_or_default();
    let has_youtube = text.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| l.contains("youtube.com") || l.contains("youtu.be"));
    if has_youtube {
        Check::new("hosts", Severity::Warn, "hosts file", "The hosts file has entries for youtube.com / youtu.be, which may break YouTube access.")
    } else {
        Check::new("hosts", Severity::Ok, "hosts file", "No YouTube overrides.")
    }
}

/// Apply a fix; returns a human-readable summary.
pub fn apply_fix(fix: &Fix, paths: &Paths) -> Result<String, String> {
    match fix {
        Fix::UnloadWinDivert => {
            let _ = scm::stop("WinDivert", Duration::from_secs(3));
            scm::delete("WinDivert").map_err(|e| format!("Could not remove WinDivert: {e}"))?;
            let _ = scm::stop("WinDivert14", Duration::from_secs(2));
            let _ = scm::delete("WinDivert14");
            Ok("WinDivert driver unloaded.".into())
        }
        Fix::RemoveConflictingServices(names) => {
            let mut done = Vec::new();
            for n in names {
                let _ = scm::stop(n, Duration::from_secs(3));
                match scm::delete(n) {
                    Ok(()) => done.push(n.clone()),
                    Err(e) => return Err(format!("Could not remove {n}: {e}")),
                }
            }
            for n in ["WinDivert", "WinDivert14"] {
                let _ = scm::stop(n, Duration::from_secs(2));
                let _ = scm::delete(n);
            }
            Ok(format!("Removed: {}.", done.join(", ")))
        }
        Fix::RepairEngineFiles => {
            let report = bundle::install(paths).map_err(|e| e.to_string())?;
            if report.locked.is_empty() {
                Ok(format!("Restored {} file(s).", report.written.len()))
            } else {
                Err(format!("These files are in use and could not be replaced: {}", report.locked.join(", ")))
            }
        }
        Fix::ClearDiscordCache => Ok(clear_discord_cache()),
        Fix::EnableTcpTimestamps => {
            use std::os::windows::process::CommandExt;
            let status = std::process::Command::new("netsh")
                .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
                .creation_flags(0x0800_0000)
                .status()
                .map_err(|e| e.to_string())?;
            if status.success() { Ok("TCP timestamps enabled.".into()) } else { Err("netsh failed (run as administrator).".into()) }
        }
    }
}

const DISCORD_VARIANTS: &[(&str, &str, &str)] = &[
    ("Discord.exe", "Discord", "discord"),
    ("DiscordPTB.exe", "Discord PTB", "discordptb"),
    ("DiscordCanary.exe", "Discord Canary", "discordcanary"),
    ("DiscordDevelopment.exe", "Discord Development", "discorddevelopment"),
];

/// Close Discord and delete `Cache`, `Code Cache` and `GPUCache` of every installed variant.
pub fn clear_discord_cache() -> String {
    let Some(appdata) = std::env::var_os("APPDATA").map(std::path::PathBuf::from) else {
        return "APPDATA is not set.".into();
    };
    let mut lines = Vec::new();
    for (exe, label, dir) in DISCORD_VARIANTS {
        let base = appdata.join(dir);
        if !base.is_dir() {
            continue;
        }
        if proc::kill_by_name(exe) > 0 {
            lines.push(format!("{label} was closed."));
            std::thread::sleep(Duration::from_millis(500));
        }
        for sub in ["Cache", "Code Cache", "GPUCache"] {
            let p = base.join(sub);
            if p.is_dir() {
                match std::fs::remove_dir_all(&p) {
                    Ok(()) => lines.push(format!("{label}: cleared {sub}.")),
                    Err(e) => lines.push(format!("{label}: could not clear {sub} ({e}).")),
                }
            }
        }
    }
    if lines.is_empty() { "No Discord installation found.".into() } else { lines.join(" ") }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_run_produces_the_expected_checks() {
        let paths = Paths::at(std::env::temp_dir().join(format!("heli-diag-{}", std::process::id())));
        let checks = run(&paths);
        let ids: Vec<&str> = checks.iter().map(|c| c.id).collect();
        for id in ["admin", "bfe", "proxy", "adguard", "killer", "vpn", "path", "engine-files", "dns", "hosts", "windivert", "conflicts"] {
            assert!(ids.contains(&id), "missing check {id}: {ids:?}");
        }
        // engine files were never installed in the temp folder
        let engine = checks.iter().find(|c| c.id == "engine-files").unwrap();
        assert_eq!(engine.severity, Severity::Warn);
        assert_eq!(engine.fix, Some(Fix::RepairEngineFiles));
        // BFE runs on every healthy Windows machine
        assert_eq!(checks.iter().find(|c| c.id == "bfe").unwrap().severity, Severity::Ok);
    }

    #[test]
    fn non_ascii_and_onedrive_paths_are_flagged() {
        assert_eq!(path_check(Path::new(r"C:\Users\Иван\HeliBypass")).severity, Severity::Warn);
        assert_eq!(path_check(Path::new(r"C:\ProgramData\HeliBypass")).severity, Severity::Ok);
    }
}
