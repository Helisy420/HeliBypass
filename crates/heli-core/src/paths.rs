//! Where HeliBypass keeps its files.
//!
//! The root is chosen once per process:
//! 1. `HELIBYPASS_HOME` if set (development, portable use, tests);
//! 2. `%ProgramData%\HeliBypass` when it can be created and written — an ASCII-only,
//!    admin-protected location, which matters because `winws.exe` is run elevated and
//!    chokes on non-ASCII paths (a Cyrillic user name in `%APPDATA%` is the classic failure);
//! 3. `%LOCALAPPDATA%\HeliBypass` as a last resort for unelevated runs.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}

impl Paths {
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The process-wide default location (see module docs).
    pub fn default_location() -> &'static Paths {
        static P: OnceLock<Paths> = OnceLock::new();
        P.get_or_init(|| Paths { root: resolve_root() })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn config_file(&self) -> PathBuf {
        self.root.join("config.json")
    }
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }
    /// Mirrors the layout of the upstream zapret package: `bin/`, `lists/`, `utils/`.
    pub fn zapret_dir(&self) -> PathBuf {
        self.root.join("zapret")
    }
    pub fn bin_dir(&self) -> PathBuf {
        self.zapret_dir().join("bin")
    }
    pub fn lists_dir(&self) -> PathBuf {
        self.zapret_dir().join("lists")
    }
    pub fn utils_dir(&self) -> PathBuf {
        self.zapret_dir().join("utils")
    }
    /// User-supplied strategy `.bat` files; they extend/override the built-in ones.
    pub fn strategies_dir(&self) -> PathBuf {
        self.zapret_dir().join("strategies")
    }
    pub fn test_results_dir(&self) -> PathBuf {
        self.utils_dir().join("test results")
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        for d in [
            self.root.clone(),
            self.logs_dir(),
            self.bin_dir(),
            self.lists_dir(),
            self.utils_dir(),
            self.strategies_dir(),
        ] {
            std::fs::create_dir_all(d)?;
        }
        hide(&self.zapret_dir());
        Ok(())
    }
}

/// The engine folder is a cache the app owns and rebuilds itself; keep it out of sight in
/// Explorer (it stays reachable with "show hidden items").
#[cfg(windows)]
fn hide(dir: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, GetFileAttributesW, INVALID_FILE_ATTRIBUTES, SetFileAttributesW};
    let wide: Vec<u16> = dir.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: NUL-terminated wide string that outlives both calls.
    unsafe {
        let attrs = GetFileAttributesW(wide.as_ptr());
        if attrs != INVALID_FILE_ATTRIBUTES && attrs & FILE_ATTRIBUTE_HIDDEN == 0 {
            SetFileAttributesW(wide.as_ptr(), attrs | FILE_ATTRIBUTE_HIDDEN);
        }
    }
}

#[cfg(not(windows))]
fn hide(_dir: &Path) {}

fn resolve_root() -> PathBuf {
    if let Some(p) = std::env::var_os("HELIBYPASS_HOME").filter(|p| !p.is_empty()) {
        return PathBuf::from(p);
    }
    for var in ["ProgramData", "LOCALAPPDATA"] {
        if let Some(base) = std::env::var_os(var) {
            let candidate = PathBuf::from(base).join("HeliBypass");
            if writable_dir(&candidate) {
                return candidate;
            }
        }
    }
    std::env::temp_dir().join("HeliBypass")
}

fn writable_dir(dir: &Path) -> bool {
    if std::fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(".write-test");
    let ok = std::fs::write(&probe, b"x").is_ok();
    let _ = std::fs::remove_file(probe);
    ok
}

/// Atomically replace `path` with `contents` (write to a sibling temp file, then rename).
pub fn write_atomic(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("dat")
    ));
    std::fs::write(&tmp, contents)?;
    std::fs::rename(&tmp, path).or_else(|_| {
        // Windows refuses to rename over a file that is open elsewhere; fall back to copy.
        let r = std::fs::copy(&tmp, path).map(|_| ());
        let _ = std::fs::remove_file(&tmp);
        r
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_mirrors_upstream_package() {
        let p = Paths::at("C:/HeliBypass");
        assert!(p.bin_dir().ends_with("zapret/bin") || p.bin_dir().ends_with("zapret\\bin"));
        assert!(p.lists_dir().ends_with("lists"));
        assert!(p.test_results_dir().ends_with("test results"));
    }

    #[test]
    fn atomic_write_replaces_content() {
        let dir = std::env::temp_dir().join(format!("heli-paths-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.json");
        write_atomic(&f, b"one").unwrap();
        write_atomic(&f, b"two").unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"two");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
