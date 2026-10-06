//! Parses every upstream strategy file and checks that everything they reference ships with us.

use std::path::{Path, PathBuf};

use heli_zapret::strategy::{ArgContext, Origin, Strategy};

fn assets() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/zapret")
}

/// Files that are created at runtime (per-user lists) and therefore not in the asset folder.
const RUNTIME_LISTS: &[&str] = &["list-general-user.txt", "list-exclude-user.txt", "ipset-exclude-user.txt", "ipset-all.txt"];

#[test]
fn every_upstream_strategy_parses_and_its_files_exist() {
    let dir = assets().join("strategies");
    let ctx = ArgContext {
        bin_dir: PathBuf::from("<BIN>"),
        lists_dir: PathBuf::from("<LISTS>"),
        game_tcp: "1024-65535".into(),
        game_udp: "1024-65535".into(),
    };
    let mut count = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("bat") {
            continue;
        }
        let s = Strategy::load_file(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(matches!(s.origin, Origin::User(_)));
        let args = s.args(&ctx);
        let name = &s.name;

        assert!(args[0].starts_with("--wf-tcp="), "{name}: first arg is {}", args[0]);
        assert!(args[1].starts_with("--wf-udp="), "{name}: second arg is {}", args[1]);
        assert!(args.iter().filter(|a| *a == "--new").count() >= 5, "{name}: too few rule groups");
        for a in &args {
            assert!(!a.contains(['%', '^', '"']), "{name}: leftover syntax in {a:?}");
        }
        assert!(s.uses_game_filter(), "{name}");

        for a in &args {
            let Some((opt, value)) = a.split_once('=') else { continue };
            // option values may be comma separated hex/filenames only for fake payloads; files are single
            if let Some(file) = value.strip_prefix("<LISTS>\\") {
                if matches!(opt, "--hostlist" | "--hostlist-exclude" | "--ipset" | "--ipset-exclude") {
                    assert!(
                        RUNTIME_LISTS.contains(&file) || assets().join("lists").join(file).exists(),
                        "{name}: {opt} references missing list {file}"
                    );
                }
            }
            if let Some(file) = value.strip_prefix("<BIN>\\") {
                assert!(assets().join("bin").join(file).exists(), "{name}: {opt} references missing payload {file}");
            }
        }
        count += 1;
    }
    assert_eq!(count, 22, "expected the 22 strategies of release 1.10.3");
}

#[test]
fn well_known_strategy_has_expected_shape() {
    let s = Strategy::load_file(&assets().join("strategies").join("general (ALT).bat")).unwrap();
    assert_eq!(s.name, "general (ALT)");
    assert!(s.note.is_none());
    assert!(s.technique().contains("fakedsplit"));
    let alt5 = Strategy::load_file(&assets().join("strategies").join("general (ALT5).bat")).unwrap();
    assert_eq!(alt5.note.as_deref(), Some("NOT RECOMMENDED"));
}
