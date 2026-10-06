//! Prints the diagnostics report (read-only): `cargo run -p heli-zapret --example diag`.
use heli_core::paths::Paths;

fn main() {
    let paths = Paths::default_location();
    println!("data root: {}", paths.root().display());
    for c in heli_zapret::diagnostics::run(paths) {
        let mark = match c.severity {
            heli_zapret::diagnostics::Severity::Ok => "OK  ",
            heli_zapret::diagnostics::Severity::Warn => "WARN",
            heli_zapret::diagnostics::Severity::Fail => "FAIL",
        };
        println!("[{mark}] {:<34} {}{}", c.title, c.detail, c.fix.as_ref().map(|f| format!("  <fix: {}>", f.label())).unwrap_or_default());
    }
}
