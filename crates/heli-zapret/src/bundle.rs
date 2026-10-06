//! The files that ship inside the executable and how they are put on disk.
//!
//! `winws.exe` and the WinDivert driver run with administrator rights, so they are verified
//! against the embedded copies (SHA-256) before every launch instead of being trusted just
//! because they sit in a folder.

use std::io;
use std::path::PathBuf;

use heli_core::paths::Paths;
use sha2::{Digest, Sha256};

use crate::strategy::{Origin, Strategy};

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
}

/// Version of the upstream zapret-discord-youtube release the bundle was taken from.
pub const BUNDLE_VERSION: &str = "1.10.3";

/// Lists that upstream maintains; refreshed when the bundle version changes.
const MANAGED_LISTS: &[&str] =
    &["lists/list-general.txt", "lists/list-google.txt", "lists/list-exclude.txt", "lists/ipset-exclude.txt"];

/// Dummy address meaning "ipset filter disabled" (RFC 5737 documentation range).
pub const IPSET_NONE_MARKER: &str = "203.0.113.113/32";

pub fn embedded_file(rel: &str) -> Option<&'static [u8]> {
    embedded::FILES.iter().find(|(p, _)| *p == rel).map(|(_, b)| *b)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Engine files that must exist and match the embedded copies.
pub fn engine_files() -> impl Iterator<Item = &'static str> {
    embedded::FILES.iter().map(|(p, _)| *p).filter(|p| p.starts_with("bin/"))
}

pub fn builtin_strategies() -> Vec<Strategy> {
    let mut out: Vec<Strategy> = embedded::FILES
        .iter()
        .filter(|(p, _)| p.starts_with("strategies/") && p.ends_with(".bat"))
        .filter_map(|(p, bytes)| {
            let name = p.trim_start_matches("strategies/").trim_end_matches(".bat");
            let text = String::from_utf8_lossy(bytes);
            Strategy::parse(name, &text, Origin::Builtin).ok()
        })
        .collect();
    out.sort_by_key(|s| crate::strategy::natural_key(&s.name));
    out
}

#[derive(Debug, Default)]
pub struct InstallReport {
    pub written: Vec<String>,
    /// Files that could not be replaced because they are in use (e.g. a running driver).
    pub locked: Vec<String>,
}

/// Bring the on-disk engine folder in line with the bundle. Safe to call repeatedly.
pub fn install(paths: &Paths) -> io::Result<InstallReport> {
    paths.ensure_dirs()?;
    let mut report = InstallReport::default();
    let zapret = paths.zapret_dir();

    // 1. engine binaries: always exactly the bundled bytes
    for rel in engine_files() {
        let bytes = embedded_file(rel).expect("listed file exists");
        let dest = zapret.join(rel);
        if std::fs::read(&dest).map(|d| d == bytes).unwrap_or(false) {
            continue;
        }
        match std::fs::write(&dest, bytes) {
            Ok(()) => report.written.push(rel.to_owned()),
            Err(e) if is_locked(&e) => report.locked.push(rel.to_owned()),
            Err(e) => return Err(e),
        }
    }

    // 2. upstream-managed lists: only (re)written when missing or the bundle version changed
    let marker = paths.utils_dir().join("bundle-version.txt");
    let up_to_date = std::fs::read_to_string(&marker).map(|v| v.trim() == BUNDLE_VERSION).unwrap_or(false);
    for rel in MANAGED_LISTS {
        let dest = zapret.join(rel);
        if up_to_date && dest.exists() {
            continue;
        }
        write_embedded(rel, &dest, &mut report)?;
    }
    if !up_to_date {
        std::fs::write(&marker, BUNDLE_VERSION)?;
    }

    // 3. ipset: ship in "none" mode with the full list kept as the backup, like upstream
    let ipset = paths.lists_dir().join("ipset-all.txt");
    let backup = paths.lists_dir().join("ipset-all.txt.backup");
    if !backup.exists() {
        write_embedded("lists/ipset-full.txt", &backup, &mut report)?;
    }
    if !ipset.exists() {
        std::fs::write(&ipset, format!("{IPSET_NONE_MARKER}\n"))?;
        report.written.push("lists/ipset-all.txt".into());
    }

    // 4. user-editable files: created once, never overwritten
    let targets = paths.utils_dir().join("targets.txt");
    if !targets.exists() {
        write_embedded("utils/targets.txt", &targets, &mut report)?;
    }
    ensure_user_lists(paths)?;
    Ok(report)
}

fn write_embedded(rel: &str, dest: &PathBuf, report: &mut InstallReport) -> io::Result<()> {
    let bytes = embedded_file(rel).unwrap_or_else(|| panic!("missing embedded file {rel}"));
    std::fs::write(dest, bytes)?;
    report.written.push(rel.to_owned());
    Ok(())
}

/// The three per-user list files the strategies refer to must exist (winws refuses missing files).
pub fn ensure_user_lists(paths: &Paths) -> io::Result<()> {
    let lists = paths.lists_dir();
    let defaults: [(&str, &str); 3] = [
        ("ipset-exclude-user.txt", "203.0.113.113/32\n"),
        ("list-general-user.txt", "# Never leave this file empty\ndomain.example.abc\n"),
        ("list-exclude-user.txt", "domain.example.abc\n"),
    ];
    for (name, content) in defaults {
        let p = lists.join(name);
        if !p.exists() {
            std::fs::write(p, content)?;
        }
    }
    Ok(())
}

/// Engine files that are missing or differ from the bundle (empty = all good).
pub fn verify_engine(paths: &Paths) -> Vec<String> {
    engine_files()
        .filter(|rel| {
            let bytes = embedded_file(rel).expect("listed file exists");
            std::fs::read(paths.zapret_dir().join(rel)).map(|d| d != bytes).unwrap_or(true)
        })
        .map(str::to_owned)
        .collect()
}

fn is_locked(e: &io::Error) -> bool {
    // ERROR_ACCESS_DENIED / ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
    matches!(e.raw_os_error(), Some(5 | 32 | 33)) || e.kind() == io::ErrorKind::PermissionDenied
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_paths(tag: &str) -> Paths {
        let dir = std::env::temp_dir().join(format!("heli-bundle-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Paths::at(dir)
    }

    #[test]
    fn bundle_contains_engine_and_all_strategies() {
        for f in ["bin/winws.exe", "bin/WinDivert64.sys", "bin/WinDivert.dll", "bin/cygwin1.dll"] {
            assert!(embedded_file(f).is_some_and(|b| !b.is_empty()), "{f}");
        }
        assert_eq!(builtin_strategies().len(), 22);
        assert_eq!(builtin_strategies()[0].name, "general");
    }

    #[test]
    fn install_is_idempotent_and_verifies() {
        let paths = temp_paths("install");
        let first = install(&paths).unwrap();
        assert!(first.written.iter().any(|w| w == "bin/winws.exe"));
        assert!(verify_engine(&paths).is_empty());
        assert_eq!(std::fs::read_to_string(paths.lists_dir().join("ipset-all.txt")).unwrap().trim(), IPSET_NONE_MARKER);
        assert!(paths.lists_dir().join("ipset-all.txt.backup").metadata().unwrap().len() > 100_000);
        assert!(paths.lists_dir().join("list-general-user.txt").exists());

        // user edits survive; a tampered engine file is repaired
        std::fs::write(paths.lists_dir().join("list-general-user.txt"), "mine.example\n").unwrap();
        std::fs::write(paths.bin_dir().join("winws.exe"), b"tampered").unwrap();
        assert_eq!(verify_engine(&paths), vec!["bin/winws.exe".to_owned()]);
        let second = install(&paths).unwrap();
        assert_eq!(second.written, vec!["bin/winws.exe".to_owned()]);
        assert!(verify_engine(&paths).is_empty());
        assert_eq!(std::fs::read_to_string(paths.lists_dir().join("list-general-user.txt")).unwrap(), "mine.example\n");
        std::fs::remove_dir_all(paths.root()).unwrap();
    }
}
