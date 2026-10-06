#[path = "src/logo.rs"]
#[allow(dead_code)]
mod logo;

fn main() {
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent-dark".into())
        .with_bundled_translations("lang")
        .with_default_translation_context(slint_build::DefaultTranslationContext::None);
    slint_build::compile_with_config("ui/main.slint", config).expect("Slint UI failed to compile");
    println!("cargo:rerun-if-changed=../../assets");
    println!("cargo:rerun-if-changed=lang");

    // executable icon (rendered from the same vector as the tray icon) + version info
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let ico = out.join("heli-bypass.ico");
    std::fs::write(&ico, logo::ico_bytes(&[16, 24, 32, 48, 64, 128, 256])).unwrap();
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon(ico.to_str().unwrap());
        res.set("ProductName", "Heli Bypass");
        res.set("FileDescription", "Heli Bypass: Telegram proxy and DPI bypass");
        res.set("LegalCopyright", "MIT licence; see THIRD_PARTY.md");
        if let Err(e) = res.compile() {
            println!("cargo:warning=could not embed the icon/version resources: {e}");
        }
    }
}
