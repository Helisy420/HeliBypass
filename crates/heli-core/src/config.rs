//! Persisted application settings (`config.json`).
//!
//! Every field has a serde default so older/partial files keep loading after upgrades.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::paths::write_atomic;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppConfig {
    pub telegram: TelegramConfig,
    pub bypass: BypassConfig,
    pub app: AppSettings,
    pub lists: UserLists,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            telegram: TelegramConfig::default(),
            bypass: BypassConfig::default(),
            app: AppSettings::default(),
            lists: UserLists::default(),
        }
    }
}

/// The user's own zapret lists, one entry per line. The app is the source of truth: the files
/// the engine reads are generated from these. `None` means "not taken over yet": on first start
/// the content of an existing list file is imported once.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct UserLists {
    /// Extra domains the bypass should handle (`list-general-user.txt`).
    pub general: Option<String>,
    /// Domains the bypass must leave alone (`list-exclude-user.txt`).
    pub exclude: Option<String>,
    /// Addresses / ranges the bypass must leave alone (`ipset-exclude-user.txt`).
    pub ipset_exclude: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TelegramConfig {
    /// Start the proxy together with the app.
    pub autostart: bool,
    pub host: String,
    pub port: u16,
    /// 32 hex characters (16 bytes).
    pub secret: String,
    /// One `DC:IP` rule per entry, e.g. `2:149.154.167.220`.
    pub dc_ip: Vec<String>,
    pub buf_kb: u32,
    pub pool_size: u32,
    /// Fall back to Cloudflare-proxied WebSockets when direct WS is unavailable.
    pub cfproxy: bool,
    /// Own Cloudflare domain(s), space/comma separated. Empty = built-in pool.
    pub cfproxy_user_domain: String,
    pub cfproxy_worker_domain: String,
    /// Last resort: plain TCP straight to the data center.
    pub tcp_fallback: bool,
    /// BETA: media sessions on the Cloudflare route share HTTP/2 connections.
    pub h2_media: bool,
    /// Speed cap for Telegram in MB/s per direction; 0 = unlimited.
    pub speed_limit_mb: u32,
    /// Fake-TLS ("ee" secret) masking domain; empty disables it.
    pub fake_tls_domain: String,
    pub force_test_dc: bool,
    pub proxy_protocol: bool,
}

impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            autostart: true,
            host: "127.0.0.1".into(),
            port: 1443,
            secret: generate_secret(),
            dc_ip: vec!["2:149.154.167.220".into(), "4:149.154.167.220".into()],
            buf_kb: 256,
            pool_size: 4,
            cfproxy: true,
            cfproxy_user_domain: String::new(),
            cfproxy_worker_domain: String::new(),
            tcp_fallback: true,
            h2_media: false,
            speed_limit_mb: 10,
            fake_tls_domain: String::new(),
            force_test_dc: false,
            proxy_protocol: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct BypassConfig {
    /// Display name of the selected strategy, e.g. `general (ALT)`.
    pub strategy: String,
    /// Start the bypass together with the app.
    pub autostart: bool,
    /// Check upstream for newer ipset/hosts lists.
    pub check_list_updates: bool,
    /// The user's own services, checked by the strategy tests next to the built-in ones.
    pub test_services: Vec<TestService>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TestService {
    pub name: String,
    /// `https://host[:port]/path`
    pub url: String,
}

impl Default for BypassConfig {
    fn default() -> Self {
        Self { strategy: "general".into(), autostart: false, check_list_updates: true, test_services: Vec::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AppSettings {
    pub launch_at_login: bool,
    pub start_minimized: bool,
    /// Closing the window hides it to the tray instead of quitting.
    pub close_to_tray: bool,
    pub check_app_updates: bool,
    pub verbose_logs: bool,
    /// Strategy Studio shows every setting (otherwise only the one-click card).
    pub studio_advanced: bool,
    /// `en` or `ru`.
    pub language: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            launch_at_login: false,
            start_minimized: false,
            close_to_tray: true,
            check_app_updates: true,
            verbose_logs: false,
            studio_advanced: false,
            language: "en".into(),
        }
    }
}

/// Convert the `config.json` of the original Python `tg-ws-proxy` tray app (see its
/// `docs/EN/TrayConfig.md`) so an existing user keeps the same secret, port and DC rules and
/// Telegram does not need to be set up again.
pub fn import_tg_ws_proxy(json: &str) -> Option<TelegramConfig> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut t = TelegramConfig::default();
    if let Some(h) = v.get("host").and_then(|x| x.as_str()) {
        t.host = h.to_owned();
    }
    if let Some(p) = v.get("port").and_then(|x| x.as_u64()).and_then(|p| u16::try_from(p).ok()) {
        t.port = p;
    }
    t.secret = v.get("secret").and_then(|x| x.as_str()).filter(|s| is_valid_secret(s))?.to_ascii_lowercase();
    if let Some(rules) = v.get("dc_ip").and_then(|x| x.as_array()) {
        t.dc_ip = rules.iter().filter_map(|r| r.as_str().map(str::to_owned)).collect();
    }
    if let Some(n) = v.get("buf_kb").and_then(|x| x.as_u64()) {
        t.buf_kb = n as u32;
    }
    if let Some(n) = v.get("pool_size").and_then(|x| x.as_u64()) {
        t.pool_size = n as u32;
    }
    if let Some(b) = v.get("cfproxy").and_then(|x| x.as_bool()) {
        t.cfproxy = b;
    }
    if let Some(b) = v.get("force_test_dc").and_then(|x| x.as_bool()) {
        t.force_test_dc = b;
    }
    // the domain fields are either a string or a list depending on the version
    let words = |key: &str| match v.get(key) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(" "),
        _ => String::new(),
    };
    t.cfproxy_user_domain = words("cfproxy_user_domain");
    t.cfproxy_worker_domain = words("cfproxy_worker_domain");
    t.sanitize_in_place();
    Some(t)
}

impl TelegramConfig {
    fn sanitize_in_place(&mut self) {
        self.buf_kb = self.buf_kb.max(4);
        self.pool_size = self.pool_size.min(64);
        if self.port == 0 {
            self.port = 1443;
        }
    }
}

pub fn generate_secret() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn is_valid_secret(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

impl AppConfig {
    /// Load from `path`; a missing or unreadable file yields defaults (a corrupt file is kept
    /// aside as `*.corrupt` so the user's data is not silently destroyed on the next save).
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else { return Self::default() };
        match serde_json::from_str::<Self>(&text) {
            Ok(mut cfg) => {
                cfg.sanitize();
                cfg
            }
            Err(e) => {
                tracing::warn!("config {} is invalid ({e}); starting from defaults", path.display());
                let _ = std::fs::rename(path, path.with_extension("json.corrupt"));
                Self::default()
            }
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        write_atomic(path, &json)
    }

    /// Repair values that would make the proxy unusable.
    pub fn sanitize(&mut self) {
        if !is_valid_secret(&self.telegram.secret) {
            self.telegram.secret = generate_secret();
        }
        if self.telegram.port == 0 {
            self.telegram.port = 1443;
        }
        self.telegram.buf_kb = self.telegram.buf_kb.max(4);
        self.telegram.pool_size = self.telegram.pool_size.min(64);
        if self.telegram.host.trim().is_empty() {
            self.telegram.host = "127.0.0.1".into();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_valid_secret() {
        let c = AppConfig::default();
        assert!(is_valid_secret(&c.telegram.secret));
        assert_eq!(c.telegram.port, 1443);
    }

    #[test]
    fn partial_json_fills_defaults_and_repairs() {
        let mut c: AppConfig = serde_json::from_str(r#"{"telegram":{"port":2000,"secret":"zz"}}"#).unwrap();
        c.sanitize();
        assert_eq!(c.telegram.port, 2000);
        assert!(is_valid_secret(&c.telegram.secret));
        assert_eq!(c.telegram.dc_ip.len(), 2);
        assert_eq!(c.app.language, "en");
    }

    #[test]
    fn imports_the_original_tray_app_config() {
        let json = r#"{"host":"127.0.0.1","port":2443,"secret":"F9E0B3532A35A749A7B8B71E832385B7",
            "dc_ip":["2:149.154.167.220","4:149.154.167.220"],"buf_kb":512,"pool_size":8,"cfproxy":false,
            "cfproxy_user_domain":["a.example","b.example"],"cfproxy_worker_domain":"w.example.dev"}"#;
        let t = import_tg_ws_proxy(json).unwrap();
        assert_eq!((t.port, t.buf_kb, t.pool_size, t.cfproxy), (2443, 512, 8, false));
        assert_eq!(t.secret, "f9e0b3532a35a749a7b8b71e832385b7");
        assert_eq!(t.cfproxy_user_domain, "a.example b.example");
        assert_eq!(t.cfproxy_worker_domain, "w.example.dev");
        assert!(import_tg_ws_proxy(r#"{"secret":"short"}"#).is_none(), "an unusable secret is not imported");
        assert!(import_tg_ws_proxy("not json").is_none());
    }

    #[test]
    fn roundtrips_on_disk() {
        let dir = std::env::temp_dir().join(format!("heli-cfg-test-{}", std::process::id()));
        let f = dir.join("config.json");
        let mut c = AppConfig::default();
        c.bypass.strategy = "general (ALT)".into();
        c.save(&f).unwrap();
        assert_eq!(AppConfig::load(&f), c);
        std::fs::write(&f, "{not json").unwrap();
        let fresh = AppConfig::load(&f);
        assert_eq!(fresh.bypass.strategy, "general");
        assert!(f.with_extension("json.corrupt").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
