//! Generates `embedded.rs`: a table of every file under `assets/zapret/` as `include_bytes!`,
//! so the final executable is self-contained (engine, WinDivert driver, lists, strategies).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn collect(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            collect(&p, base, out);
        } else {
            let rel = p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/");
            out.push((rel, p));
        }
    }
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let assets = manifest.join("../../assets/zapret").canonicalize().expect("assets/zapret must exist");
    println!("cargo:rerun-if-changed={}", assets.display());
    println!("cargo:rerun-if-changed=build.rs");

    let mut files = Vec::new();
    collect(&assets, &assets, &mut files);

    let mut src = String::from("pub static FILES: &[(&str, &[u8])] = &[\n");
    for (rel, abs) in &files {
        let abs = abs.to_string_lossy().replace('\\', "/");
        // strip the verbatim prefix produced by canonicalize on Windows
        let abs = abs.strip_prefix("//?/").unwrap_or(&abs);
        let _ = writeln!(src, "    ({rel:?}, include_bytes!({abs:?})),");
    }
    src.push_str("];\n");
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("embedded.rs");
    std::fs::write(out, src).unwrap();
}
