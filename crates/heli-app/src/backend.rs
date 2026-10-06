//! Application state and actions. The UI layer (`bridge.rs`) is a thin shell over this.
//!
//! Every user-visible action is a method here; long-running work is spawned on the tokio
//! runtime and reports back through `changed()`, which asks the UI thread to re-sync.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use heli_core::activity;
use heli_core::config::{AppConfig, is_valid_secret};
use heli_core::paths::Paths;
use heli_tgproxy::ProxyHandle;
use heli_tgproxy::config::{ProxyConfig, coerce_domain_list, default_cf_domains, parse_dc_ip_list};
use heli_tgproxy::ws::{ConnectOpts, WsConn};
use heli_zapret::bundle;
use heli_zapret::diagnostics::{self, Check, Fix};
use heli_zapret::engine::{Engine, EngineState};
use heli_zapret::lists::{self, GameFilter, GameMode, HostsStatus, IpsetMode, ListsState};
use heli_zapret::scm::ServiceState;
use heli_zapret::service::{self, ServiceStatus};
use heli_zapret::strategy::{Origin, Strategy, natural_key};
use heli_zapret::tester::{self, TestKind, TestRunner};
use heli_zapret::builder::WebSpec;
use heli_zapret::userlists::{self, UserList};
use tokio::runtime::Handle;

use crate::i18n::{Language, tr, trf};
use crate::platform;

type Wake = Arc<dyn Fn() + Send + Sync>;

#[derive(Default)]
pub struct TgState {
    pub handle: Option<ProxyHandle>,
    pub busy: bool,
    pub error: String,
    pub latency: Option<Duration>,
    pub cf_testing: bool,
    pub cf_result: String,
    pub speed: crate::speed::Speed,
    /// Bumped on every start so a sampler of an earlier run stops by itself.
    pub generation: u64,
}

#[derive(Default)]
pub struct Misc {
    pub toast: Option<(String, i32)>,
    pub test_tab: i32,
    /// Tab the last test run was started from (its results are only shown on that tab).
    pub test_run_tab: i32,
    /// Auto-builder: the strategy the current/last build started from, and its outcome.
    pub build_base: String,
    pub build_note: String,
    /// The last build saved `general (ALT14)`.
    pub built: bool,
    pub strategy_filter: String,
    pub bp_error: String,
    pub test_error: String,
    pub ipset_busy: bool,
    pub ipset_info: String,
    pub hosts_busy: bool,
    pub hosts: Option<(HostsStatus, String)>,
    pub game_error: String,
    pub svc: Option<ServiceStatus>,
    pub svc_busy: bool,
    pub diag: Vec<Check>,
    pub diag_running: bool,
    pub diag_ran: bool,
    pub health: Vec<(String, Option<Duration>)>,
    pub lists_checked: Option<u64>,
    pub lists_current: Option<bool>,
}

pub struct Backend {
    pub rt: Handle,
    pub paths: Paths,
    pub cfg: Mutex<AppConfig>,
    pub strategies: RwLock<Vec<Strategy>>,
    pub engine: Arc<Engine>,
    pub tests: Arc<TestRunner>,
    pub tg: Mutex<TgState>,
    pub misc: Mutex<Misc>,
    pub page: AtomicI32,
    pub visible: AtomicBool,
    wake: Wake,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl Backend {
    pub fn new(rt: Handle, paths: Paths, wake: Wake) -> Arc<Self> {
        let _ = paths.ensure_dirs();
        let mut cfg = AppConfig::load(&paths.config_file());
        if !paths.config_file().exists() {
            cfg.app.language = Language::system_default().code().to_owned();
            // an existing tg-ws-proxy install: keep its secret/port so Telegram keeps working
            let old = std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("TgWsProxy").join("config.json"));
            if let Some(t) = old.and_then(|f| std::fs::read_to_string(f).ok()).and_then(|j| heli_core::config::import_tg_ws_proxy(&j)) {
                cfg.telegram = t;
                tracing::info!("imported the Telegram proxy settings of an existing tg-ws-proxy installation");
            }
            let _ = cfg.save(&paths.config_file());
        }
        crate::i18n::set_language(Language::from_code(&cfg.app.language));
        let engine = Engine::new(paths.clone());
        let tests = TestRunner::new(Arc::clone(&engine), paths.clone());
        let b = Arc::new(Self {
            rt,
            paths: paths.clone(),
            cfg: Mutex::new(cfg),
            strategies: RwLock::new(Vec::new()),
            engine,
            tests,
            tg: Mutex::new(TgState::default()),
            misc: Mutex::new(Misc::default()),
            page: AtomicI32::new(0),
            visible: AtomicBool::new(true),
            wake,
        });
        b.reload_strategies();
        b
    }

    pub fn changed(&self) {
        (self.wake)();
    }

    // ───────────── startup ─────────────

    /// Background start-up work: install engine files, recover from interrupted tests, autostart.
    pub fn start_background(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let paths = this.paths.clone();
            let _ = tokio::task::spawn_blocking(move || {
                if let Err(e) = bundle::install(&paths) {
                    tracing::warn!("could not install engine files: {e}");
                }
                if let Some(mode) = tester::recover_interrupted(&paths) {
                    tracing::info!("restored the IPSet mode after an interrupted test run: {mode:?}");
                }
            })
            .await;
            let me = Arc::clone(&this);
            let _ = tokio::task::spawn_blocking(move || me.sync_user_lists()).await;
            this.refresh_lists_info();
            this.check_lists();
            this.changed();

            let (tg_auto, bp_auto) = {
                let c = lock(&this.cfg);
                (c.telegram.autostart, c.bypass.autostart)
            };
            if tg_auto {
                this.tg_start().await;
            }
            if bp_auto && heli_core::elevation::is_elevated() {
                this.bp_start().await;
            }
            this.spawn_monitors();
        });
    }

    /// Periodic work: latency, connection health, list freshness.
    fn spawn_monitors(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(10));
            let mut n = 0u64;
            loop {
                tick.tick().await;
                n += 1;
                if !this.visible.load(Ordering::Relaxed) {
                    continue;
                }
                let on_overview = this.page.load(Ordering::Relaxed) == 0;
                if n == 1 || n % 3 == 0 {
                    if on_overview {
                        this.measure_health().await;
                    }
                }
                if lock(&this.tg).handle.is_some() {
                    this.measure_tg_latency().await;
                }
                if n % 2160 == 0 {
                    this.check_lists(); // every 6 hours
                }
            }
        });
    }

    // ───────────── configuration ─────────────

    pub fn save_cfg(&self) {
        let cfg = lock(&self.cfg).clone();
        if let Err(e) = cfg.save(&self.paths.config_file()) {
            tracing::warn!("could not save the configuration: {e}");
        }
    }

    pub fn toast(self: &Arc<Self>, text: impl Into<String>, tone: i32) {
        lock(&self.misc).toast = Some((text.into(), tone));
        self.changed();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(3200)).await;
            lock(&this.misc).toast = None;
            this.changed();
        });
    }

    pub fn set_language(&self, lang: Language) {
        crate::i18n::set_language(lang);
        lock(&self.cfg).app.language = lang.code().to_owned();
        self.save_cfg();
        let _ = slint::select_bundled_translation(if lang == Language::Russian { "ru" } else { "" });
        self.changed();
    }

    // ───────────── strategies ─────────────

    pub fn reload_strategies(&self) {
        let mut list = bundle::builtin_strategies();
        if let Ok(rd) = std::fs::read_dir(self.paths.strategies_dir()) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x.eq_ignore_ascii_case("bat")) {
                    if let Ok(s) = Strategy::load_file(&p) {
                        list.retain(|x| x.name != s.name);
                        list.push(s);
                    }
                }
            }
        }
        list.sort_by_key(|s| natural_key(&s.name));
        *self.strategies.write().unwrap_or_else(|e| e.into_inner()) = list;
    }

    pub fn selected_strategy(&self) -> Option<Strategy> {
        let name = lock(&self.cfg).bypass.strategy.clone();
        let list = self.strategies.read().unwrap_or_else(|e| e.into_inner());
        list.iter().find(|s| s.name == name).or_else(|| list.first()).cloned()
    }

    pub fn selected_name(&self) -> String {
        self.selected_strategy().map(|s| s.name).unwrap_or_default()
    }

    pub fn game_filter(&self) -> GameFilter {
        GameFilter::load(&self.paths)
    }

    pub fn is_user_strategy(s: &Strategy) -> bool {
        matches!(s.origin, Origin::User(_))
    }

    // ───────────── Telegram proxy ─────────────

    /// Translate the persisted settings into a runtime proxy configuration.
    pub fn build_proxy_config(t: &heli_core::config::TelegramConfig) -> Result<ProxyConfig, String> {
        if !is_valid_secret(&t.secret) {
            return Err("The secret must be exactly 32 hexadecimal characters.".into());
        }
        let mut secret = [0u8; 16];
        secret.copy_from_slice(&hex::decode(&t.secret).map_err(|e| e.to_string())?);
        let dc_redirects = parse_dc_ip_list(&t.dc_ip).map_err(|e| e.to_string())?;
        Ok(ProxyConfig {
            host: t.host.trim().to_owned(),
            port: t.port,
            secret,
            dc_redirects,
            buffer_size: t.buf_kb.max(4) as usize * 1024,
            pool_size: t.pool_size as usize,
            fallback_cfproxy: t.cfproxy,
            h2_media: t.h2_media,
            speed_limit: u64::from(t.speed_limit_mb) * 1024 * 1024,
            cfproxy_user_domains: coerce_domain_list(&t.cfproxy_user_domain),
            cfproxy_worker_domains: coerce_domain_list(&t.cfproxy_worker_domain),
            tcp_fallback: t.tcp_fallback,
            disable_secure: false,
            fake_tls_domain: t.fake_tls_domain.trim().to_owned(),
            proxy_protocol: t.proxy_protocol,
            force_test_dc: t.force_test_dc,
            cf_domains_url: Some(heli_tgproxy::config::CFPROXY_DOMAINS_URL.to_owned()),
        })
    }

    pub async fn tg_start(self: &Arc<Self>) {
        {
            let mut tg = lock(&self.tg);
            if tg.handle.is_some() || tg.busy {
                return;
            }
            tg.busy = true;
            tg.error.clear();
        }
        self.changed();
        let tcfg = lock(&self.cfg).telegram.clone();
        let result = match Self::build_proxy_config(&tcfg) {
            Ok(pc) => heli_tgproxy::start(pc).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::AddrInUse {
                    format!("Port {} is already in use. Pick another port or close the program that uses it.", tcfg.port)
                } else {
                    e.to_string()
                }
            }),
            Err(e) => Err(e),
        };
        {
            let mut tg = lock(&self.tg);
            tg.busy = false;
            match result {
                Ok(h) => {
                    activity::push("proxy", format!("listening {}:{}", tcfg.host, tcfg.port));
                    tg.handle = Some(h);
                    tg.generation += 1;
                    tg.speed = crate::speed::Speed::default();
                    self.spawn_speed_sampler(tg.generation);
                }
                Err(e) => {
                    activity::error("proxy", format!("start failed: {e}"));
                    tg.error = e;
                }
            }
        }
        self.changed();
    }

    /// One sample per second while this run of the proxy is up (feeds the live dashboard).
    fn spawn_speed_sampler(self: &Arc<Self>, generation: u64) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                {
                    let mut tg = lock(&this.tg);
                    if tg.generation != generation {
                        break;
                    }
                    let Some(h) = tg.handle.as_ref() else { break };
                    let (stats, sessions) = (h.stats(), h.sessions());
                    tg.speed.sample(Instant::now(), stats.bytes_up, stats.bytes_down, &sessions);
                }
                if this.visible.load(Ordering::Relaxed) && matches!(this.page.load(Ordering::Relaxed), 0 | 1) {
                    this.changed();
                }
            }
        });
    }

    pub async fn tg_stop(self: &Arc<Self>) {
        let handle = lock(&self.tg).handle.take();
        if let Some(h) = handle {
            h.stop().await;
            activity::push("proxy", "stopped");
        }
        {
            let mut tg = lock(&self.tg);
            tg.latency = None;
        }
        self.changed();
    }

    pub fn tg_toggle(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            if lock(&this.tg).handle.is_some() {
                this.tg_stop().await;
            } else {
                this.tg_start().await;
            }
        });
    }

    pub fn tg_link(&self) -> Option<String> {
        lock(&self.tg).handle.as_ref().map(|h| h.tg_link())
    }

    pub fn tg_open(self: &Arc<Self>) {
        if let Some(link) = self.tg_link() {
            if !platform::open(&link) {
                self.toast("Could not open Telegram. Use “Copy tg:// link” instead.", 3);
            }
        }
    }

    pub fn tg_copy_link(self: &Arc<Self>) {
        if let Some(link) = self.tg_link() {
            if platform::copy_to_clipboard(&link) {
                self.toast(tr("Copied the Telegram proxy link"), 1);
            }
        }
    }

    /// Validate and store the Telegram settings; restarts the proxy if it is running.
    #[allow(clippy::too_many_arguments)]
    pub fn tg_save(self: &Arc<Self>, host: &str, port: &str, secret: &str, dc_rules: &str, cf: bool, tcp: bool, h2: bool) {
        let port: u16 = match port.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => return self.toast("The port must be a number from 1 to 65535.", 3),
        };
        let rules: Vec<String> = dc_rules.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect();
        if let Err(e) = parse_dc_ip_list(&rules) {
            return self.toast(e.to_string(), 3);
        }
        if !is_valid_secret(secret.trim()) {
            return self.toast("The secret must be exactly 32 hexadecimal characters.", 3);
        }
        if host.trim().is_empty() {
            return self.toast("Enter an IP address to listen on (for example 127.0.0.1).", 3);
        }
        {
            let mut c = lock(&self.cfg);
            let t = &mut c.telegram;
            t.host = host.trim().to_owned();
            t.port = port;
            t.secret = secret.trim().to_ascii_lowercase();
            t.dc_ip = rules;
            t.cfproxy = cf;
            t.tcp_fallback = tcp;
            t.h2_media = h2;
        }
        self.save_cfg();
        self.toast(tr("Saved"), 1);
        if lock(&self.tg).handle.is_some() {
            let this = Arc::clone(self);
            self.rt.spawn(async move {
                this.tg_stop().await;
                this.tg_start().await;
            });
        }
    }

    /// Change the Telegram speed cap (MB/s, 0 = unlimited); applies at once, no restart.
    pub fn tg_set_limit(&self, mb: u32) {
        lock(&self.cfg).telegram.speed_limit_mb = mb;
        self.save_cfg();
        if let Some(h) = lock(&self.tg).handle.as_ref() {
            h.set_speed_limit(u64::from(mb) * 1024 * 1024);
        }
        self.changed();
    }

    async fn measure_tg_latency(self: &Arc<Self>) {
        let ip = {
            let c = lock(&self.cfg);
            c.telegram
                .dc_ip
                .iter()
                .find_map(|r| parse_dc_ip_list(&[r.as_str()]).ok().and_then(|m| m.get(&2).copied()))
                .unwrap_or(std::net::Ipv4Addr::new(149, 154, 167, 51))
        };
        let lat = heli_tgproxy::measure_dc_latency(ip).await;
        lock(&self.tg).latency = lat;
        self.changed();
    }

    /// Opens a WebSocket through a Cloudflare domain and reports how long that took.
    pub fn tg_test_cf(self: &Arc<Self>) {
        {
            let mut tg = lock(&self.tg);
            if tg.cf_testing {
                return;
            }
            tg.cf_testing = true;
            tg.cf_result.clear();
        }
        self.changed();
        let this = Arc::clone(self);
        let (user, enabled) = {
            let c = lock(&self.cfg);
            (coerce_domain_list(&c.telegram.cfproxy_user_domain), c.telegram.cfproxy)
        };
        self.rt.spawn(async move {
            let msg = if !enabled {
                tr("Not tested")
            } else {
                let mut domains = if user.is_empty() { default_cf_domains() } else { user };
                rand::seq::SliceRandom::shuffle(&mut domains[..], &mut rand::rng());
                let mut ok = None;
                for d in domains.iter().take(4) {
                    let host = format!("kws2.{d}");
                    let started = Instant::now();
                    let opts = ConnectOpts {
                        host: &host,
                        domain: &host,
                        path: "/apiws",
                        timeout: Duration::from_secs(8),
                        sni: None,
                        secure: true,
                        buffer_size: 64 * 1024,
                    };
                    if WsConn::connect(&opts).await.is_ok() {
                        ok = Some(started.elapsed());
                        break;
                    }
                }
                match ok {
                    Some(d) => trf("Cloudflare is reachable ({} ms)", &[&d.as_millis().to_string()]),
                    None => tr("Cloudflare is not reachable"),
                }
            };
            activity::push("proxy", msg.clone());
            {
                let mut tg = lock(&this.tg);
                tg.cf_testing = false;
                tg.cf_result = msg;
            }
            this.changed();
        });
    }

    // ───────────── bypass engine ─────────────

    pub async fn bp_start(self: &Arc<Self>) {
        let Some(strategy) = self.selected_strategy() else { return };
        lock(&self.misc).bp_error.clear();
        self.changed();
        let game = self.game_filter();
        if let Err(e) = self.engine.start(&strategy, &game).await {
            lock(&self.misc).bp_error = e.to_string();
        }
        self.changed();
    }

    pub async fn bp_stop(self: &Arc<Self>) {
        self.engine.stop().await;
        lock(&self.misc).bp_error.clear();
        self.changed();
    }

    pub fn bp_toggle(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            match this.engine.state() {
                EngineState::Running { .. } | EngineState::Starting(_) => this.bp_stop().await,
                _ => this.bp_start().await,
            }
        });
    }

    pub fn bp_select(self: &Arc<Self>, name: &str) {
        if lock(&self.cfg).bypass.strategy == name {
            return;
        }
        lock(&self.cfg).bypass.strategy = name.to_owned();
        self.save_cfg();
        self.changed();
        if self.engine.state().is_running() {
            let this = Arc::clone(self);
            self.rt.spawn(async move { this.bp_start().await });
        }
    }

    pub fn toggle_all(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let protected = lock(&this.tg).handle.is_some() || this.engine.state().is_running();
            if protected {
                this.tg_stop().await;
                this.bp_stop().await;
            } else {
                this.tg_start().await;
                this.bp_start().await;
            }
        });
    }

    // ───────────── tests ─────────────

    pub fn tests_run(self: &Arc<Self>) {
        let tab = lock(&self.misc).test_tab;
        let kind = if tab == 1 { TestKind::Dpi } else { TestKind::Standard };
        let strategies = self.strategies.read().unwrap_or_else(|e| e.into_inner()).clone();
        self.run_tests(kind, strategies, tab);
    }

    fn run_tests(self: &Arc<Self>, kind: TestKind, strategies: Vec<Strategy>, tab: i32) {
        let game = self.game_filter();
        let services = self.test_services();
        {
            let mut m = lock(&self.misc);
            m.test_error.clear();
            m.test_run_tab = tab;
        }
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            if let Err(e) = this.tests.start(kind, strategies, game, services).await {
                lock(&this.misc).test_error = e.to_string();
            }
            this.changed();
        });
    }

    /// The user's own services for the tests.
    pub fn test_services(&self) -> Vec<tester::Service> {
        lock(&self.cfg).bypass.test_services.iter().map(|s| tester::Service { name: s.name.clone(), url: s.url.clone() }).collect()
    }

    /// Add a service to the tests; returns an error message for the form.
    pub fn service_add(&self, name: &str, url: &str) -> Result<(), String> {
        let (name, url) = (name.trim(), url.trim());
        let url = if url.contains("://") { url.to_owned() } else { format!("https://{url}") };
        let svc = tester::Service { name: if name.is_empty() { url.trim_start_matches("https://").split('/').next().unwrap_or("").to_owned() } else { name.to_owned() }, url };
        if tester::service_target(&svc).is_none() {
            return Err(tr("Enter an https:// address, for example https://example.com"));
        }
        {
            let mut c = lock(&self.cfg);
            if c.bypass.test_services.iter().any(|s| s.url == svc.url) {
                return Err(tr("This address is already in the list."));
            }
            c.bypass.test_services.push(heli_core::config::TestService { name: svc.name, url: svc.url });
        }
        self.save_cfg();
        self.changed();
        Ok(())
    }

    pub fn service_remove(&self, idx: usize) {
        {
            let mut c = lock(&self.cfg);
            if idx < c.bypass.test_services.len() {
                c.bypass.test_services.remove(idx);
            }
        }
        self.save_cfg();
        self.changed();
    }

    /// The strategy the Studio starts from: the winner of the last standard test run if there
    /// is one, otherwise the selected strategy.
    pub fn build_base(&self) -> Option<Strategy> {
        let list = self.strategies.read().unwrap_or_else(|e| e.into_inner()).clone();
        let p = self.tests.progress();
        let tested_best = (p.kind == TestKind::Standard).then_some(p.best).flatten().and_then(|b| list.iter().find(|s| s.name == b).cloned());
        tested_best.or_else(|| self.selected_strategy()).filter(|s| heli_zapret::builder::web_recipe(s).is_some())
    }

    /// Save a strategy as `customhelibypass` and make it selectable.
    fn save_custom(&self, s: &Strategy, note: &str) -> Result<(), String> {
        let path = self.paths.strategies_dir().join(format!("{}.bat", heli_zapret::builder::BUILT_NAME));
        heli_core::paths::write_atomic(&path, s.to_bat(note).as_bytes()).map_err(|e| e.to_string())?;
        self.reload_strategies();
        activity::push("studio", format!("saved {}", heli_zapret::builder::BUILT_NAME));
        Ok(())
    }

    /// Strategy Studio: smart selection (three-stage search, see `TestRunner::start_smart`).
    /// With `apply`, the result is selected and the bypass turned on (the one-click mode).
    pub fn studio_smart(self: &Arc<Self>, apply: bool) {
        let Some(base) = self.build_base() else {
            lock(&self.misc).test_error = "Pick a strategy other than general (ALT5) to build from.".into();
            return self.changed();
        };
        let pool = bundle::builtin_strategies();
        let game = self.game_filter();
        let services = self.test_services();
        let was_running = self.engine.state().is_running();
        {
            let mut m = lock(&self.misc);
            m.test_error.clear();
            m.test_run_tab = 0;
            m.build_base = base.name.clone();
            m.build_note.clear();
            m.built = false;
        }
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let mut rx = this.tests.subscribe();
            if let Err(e) = this.tests.start_smart(base.clone(), pool, game, services).await {
                lock(&this.misc).test_error = e.to_string();
                return this.changed();
            }
            activity::push("studio", format!("smart selection from {}", base.name));
            this.changed();
            let progress = loop {
                if rx.changed().await.is_err() {
                    return;
                }
                let p = rx.borrow().clone();
                if matches!(p.phase, tester::Phase::Finished | tester::Phase::Cancelled) {
                    break p;
                }
            };
            let note = match (progress.phase, &progress.winner) {
                (tester::Phase::Finished, Some(w)) => {
                    let label = w.name.split_once(" · ").map_or(w.name.as_str(), |(_, l)| l).to_owned();
                    match this.save_custom(w, "Auto-built") {
                        Ok(()) => {
                            lock(&this.misc).built = true;
                            trf("Saved as {} · {}", &[heli_zapret::builder::BUILT_NAME, &label])
                        }
                        Err(e) => e,
                    }
                }
                (tester::Phase::Finished, None) => tr("No variation worked on this connection."),
                _ => tr("Cancelled"),
            };
            let built = lock(&this.misc).built;
            let note = if apply && built {
                this.bp_select(heli_zapret::builder::BUILT_NAME);
                this.bp_start().await;
                tr("Done! The bypass is on with your own strategy, customhelibypass.")
            } else {
                note
            };
            lock(&this.misc).build_note = note;
            if was_running && !this.engine.state().is_running() {
                this.bp_start().await;
            }
            this.changed();
        });
    }

    /// The strategy the hand-made settings apply to.
    pub fn studio_base(&self) -> Option<Strategy> {
        self.selected_strategy()
            .filter(|s| heli_zapret::builder::web_recipe(s).is_some())
            .or_else(|| bundle::builtin_strategies().into_iter().next())
    }

    /// Run the standard tests on the hand-made strategy.
    pub fn studio_test(self: &Arc<Self>, spec: &WebSpec) -> Result<(), String> {
        if let Some(p) = spec.problems().first() {
            return Err(tr(p));
        }
        let base = self.studio_base().ok_or_else(|| tr("No strategy to start from."))?;
        let s = spec.compose(&base, heli_zapret::builder::BUILT_NAME);
        self.run_tests(TestKind::Standard, vec![s], 0);
        Ok(())
    }

    pub fn studio_save(self: &Arc<Self>, spec: &WebSpec) -> Result<(), String> {
        if let Some(p) = spec.problems().first() {
            return Err(tr(p));
        }
        let base = self.studio_base().ok_or_else(|| tr("No strategy to start from."))?;
        self.save_custom(&spec.compose(&base, heli_zapret::builder::BUILT_NAME), "Studio")?;
        self.toast(trf("Saved as {}", &[heli_zapret::builder::BUILT_NAME]), 1);
        if self.selected_name() == heli_zapret::builder::BUILT_NAME && self.engine.state().is_running() {
            let this = Arc::clone(self);
            self.rt.spawn(async move { this.bp_start().await });
        }
        self.changed();
        Ok(())
    }

    pub fn tests_stop(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move { this.tests.cancel().await });
    }

    pub fn tests_switch_tab(&self, tab: i32) {
        lock(&self.misc).test_tab = tab;
        self.changed();
    }

    pub fn export_results(self: &Arc<Self>) {
        let file: Option<PathBuf> = self.tests.progress().results_file;
        match file {
            Some(f) if f.exists() => platform::reveal_in_explorer(&f),
            _ => {
                let dir = self.paths.test_results_dir();
                let _ = std::fs::create_dir_all(&dir);
                platform::open(&dir.to_string_lossy());
            }
        }
    }

    // ───────────── lists, game filter, hosts ─────────────

    pub fn refresh_lists_info(&self) {
        let mode = lists::ipset_mode(&self.paths);
        let st = ListsState::load(&self.paths);
        let mut m = lock(&self.misc);
        m.lists_checked = st.last_checked;
        let entries = std::fs::read_to_string(self.paths.lists_dir().join("ipset-all.txt"))
            .map(|t| t.lines().filter(|l| !l.trim().is_empty()).count())
            .unwrap_or(0);
        m.ipset_info = match (mode, st.last_checked) {
            (IpsetMode::Loaded, Some(t)) => format!("{entries} · {}", crate::i18n::ago(now_secs().saturating_sub(t))),
            (IpsetMode::Loaded, None) => entries.to_string(),
            _ => String::new(),
        };
    }

    pub fn check_lists(self: &Arc<Self>) {
        if !lock(&self.cfg).bypass.check_list_updates {
            return;
        }
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let status = lists::check_lists(&this.paths).await;
            {
                let mut m = lock(&this.misc);
                m.lists_current = status.ipset_current;
                m.lists_checked = Some(now_secs());
                let info = match status.hosts {
                    HostsStatus::UpToDate => (status.hosts, String::new()),
                    other => (other, String::new()),
                };
                m.hosts = Some(info);
            }
            this.refresh_lists_info();
            this.changed();
        });
    }

    pub fn ipset_set(self: &Arc<Self>, idx: i32) {
        let mode = match idx {
            1 => IpsetMode::Loaded,
            2 => IpsetMode::Any,
            _ => IpsetMode::None,
        };
        if let Err(e) = lists::set_ipset_mode(&self.paths, mode) {
            self.toast(e.to_string(), 3);
        }
        self.refresh_lists_info();
        self.changed();
        if self.engine.state().is_running() {
            let this = Arc::clone(self);
            self.rt.spawn(async move { this.bp_start().await });
        }
    }

    pub fn ipset_update(self: &Arc<Self>) {
        lock(&self.misc).ipset_busy = true;
        self.changed();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res = lists::update_ipset(&this.paths).await;
            lock(&this.misc).ipset_busy = false;
            match res {
                Ok(u) => {
                    activity::push("lists", "ipset-all.txt updated");
                    this.toast(format!("{} · {}", u.entries, if u.changed { "OK" } else { "=" }), 1);
                    lock(&this.misc).lists_current = Some(true);
                }
                Err(e) => this.toast(e.to_string(), 3),
            }
            this.refresh_lists_info();
            this.changed();
        });
    }

    pub fn game_apply(self: &Arc<Self>, mode: i32, tcp: &str, udp: &str) {
        let mode = match mode {
            1 => GameMode::All,
            2 => GameMode::Tcp,
            3 => GameMode::Udp,
            _ => GameMode::Disabled,
        };
        let (Some(tcp), Some(udp)) = (lists::validate_ports(tcp), lists::validate_ports(udp)) else {
            lock(&self.misc).game_error = tr("Invalid port list; use ports or ranges like 1024-1934,1936-65535");
            self.changed();
            return;
        };
        lock(&self.misc).game_error.clear();
        let gf = GameFilter { mode, tcp_range: tcp, udp_range: udp };
        match gf.save(&self.paths) {
            Ok(()) => {
                self.toast(tr("Saved"), 1);
                if self.engine.state().is_running() {
                    let this = Arc::clone(self);
                    self.rt.spawn(async move { this.bp_start().await });
                }
            }
            Err(e) => self.toast(e.to_string(), 3),
        }
        self.changed();
    }

    pub fn hosts_update(self: &Arc<Self>) {
        lock(&self.misc).hosts_busy = true;
        self.changed();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res: Result<(), String> = async {
                let remote = lists::fetch_hosts().await.map_err(|e| e.to_string())?;
                let hosts_path = lists::system_hosts_path();
                let backup = this.paths.root().join("backups");
                tokio::task::spawn_blocking(move || lists::apply_hosts(&hosts_path, &remote, &backup))
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| e.to_string())
            }
            .await;
            lock(&this.misc).hosts_busy = false;
            match res {
                Ok(()) => {
                    activity::push("lists", "hosts file updated");
                    lock(&this.misc).hosts = Some((HostsStatus::UpToDate, String::new()));
                    this.toast(tr("Up to date"), 1);
                }
                Err(e) => this.toast(e, 3),
            }
            this.changed();
        });
    }

    pub fn hosts_remove(self: &Arc<Self>) {
        match lists::remove_hosts_block(&lists::system_hosts_path()) {
            Ok(()) => {
                lock(&self.misc).hosts = Some((HostsStatus::NeedsUpdate, String::new()));
                self.toast(tr("Saved"), 1);
            }
            Err(e) => self.toast(e.to_string(), 3),
        }
        self.changed();
    }

    // ───────────── user lists (edited in the app, stored in the settings) ─────────────

    /// Take existing list files over once, then (re)write the engine's copies from the settings.
    pub fn sync_user_lists(&self) {
        let (lists, imported) = {
            let mut c = lock(&self.cfg);
            let mut imported = false;
            for l in UserList::ALL {
                let slot = list_slot(&mut c.lists, l);
                if slot.is_none() {
                    *slot = Some(userlists::import_file(&self.paths, l));
                    imported = true;
                }
            }
            (c.lists.clone(), imported)
        };
        if imported {
            self.save_cfg();
            tracing::info!("user lists are now stored in the settings");
        }
        for l in UserList::ALL {
            if let Err(e) = userlists::write_file(&self.paths, l, list_ref(&lists, l)) {
                tracing::warn!("could not write {}: {e}", l.file_name());
            }
        }
    }

    pub fn list_text(&self, l: UserList) -> String {
        list_ref(&lock(&self.cfg).lists, l).to_owned()
    }

    /// Entry count and the first problem, for the editor's status line.
    pub fn list_check(&self, l: UserList, text: &str) -> (String, String) {
        match userlists::validate(l, text) {
            Ok(n) => (trf("Entries: {}", &[&n.to_string()]), String::new()),
            Err(bad) => {
                let (line, entry) = &bad[0];
                let what = if l.holds_addresses() {
                    trf("Line {}: “{}” is not an address, network or range.", &[&line.to_string(), entry])
                } else {
                    trf("Line {}: “{}” is not a domain name.", &[&line.to_string(), entry])
                };
                let more = if bad.len() > 1 { format!(" {}", trf("({} more)", &[&(bad.len() - 1).to_string()])) } else { String::new() };
                (String::new(), what + &more)
            }
        }
    }

    /// Validate and store a list; the engine is restarted so it picks the change up.
    pub fn list_save(self: &Arc<Self>, l: UserList, text: &str) -> Result<(), String> {
        let text = userlists::normalize(l, text);
        let (_, err) = self.list_check(l, &text);
        if !err.is_empty() {
            return Err(err);
        }
        {
            let mut c = lock(&self.cfg);
            *list_slot(&mut c.lists, l) = Some(text.clone());
        }
        self.save_cfg();
        userlists::write_file(&self.paths, l, &text).map_err(|e| e.to_string())?;
        activity::push("lists", format!("{} saved", l.file_name()));
        self.toast(tr("Saved"), 1);
        if self.engine.state().is_running() {
            let this = Arc::clone(self);
            self.rt.spawn(async move { this.bp_start().await });
        }
        self.changed();
        Ok(())
    }

    // ───────────── service ─────────────

    pub fn refresh_service(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let st = tokio::task::spawn_blocking(service::status).await.ok();
            lock(&this.misc).svc = st;
            this.changed();
        });
    }

    pub fn svc_install(self: &Arc<Self>) {
        let Some(strategy) = self.selected_strategy() else { return };
        let game = self.game_filter();
        lock(&self.misc).svc_busy = true;
        self.changed();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            this.engine.stop().await;
            let paths = this.paths.clone();
            let res = tokio::task::spawn_blocking(move || service::install(&paths, &strategy, &game)).await;
            lock(&this.misc).svc_busy = false;
            match res {
                Ok(Ok(())) => this.toast(tr("Installed"), 1),
                Ok(Err(e)) => this.toast(e.to_string(), 3),
                Err(e) => this.toast(e.to_string(), 3),
            }
            this.refresh_service();
        });
    }

    pub fn svc_remove(self: &Arc<Self>) {
        lock(&self.misc).svc_busy = true;
        self.changed();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let res = tokio::task::spawn_blocking(service::remove).await;
            lock(&this.misc).svc_busy = false;
            match res {
                Ok(Ok(())) => this.toast(tr("Saved"), 1),
                Ok(Err(e)) => this.toast(e.to_string(), 3),
                Err(e) => this.toast(e.to_string(), 3),
            }
            this.refresh_service();
        });
    }

    // ───────────── diagnostics ─────────────

    pub fn diag_run(self: &Arc<Self>) {
        lock(&self.misc).diag_running = true;
        self.changed();
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let paths = this.paths.clone();
            let checks = tokio::task::spawn_blocking(move || diagnostics::run(&paths)).await.unwrap_or_default();
            {
                let mut m = lock(&this.misc);
                m.diag = checks;
                m.diag_running = false;
                m.diag_ran = true;
            }
            this.changed();
        });
    }

    pub fn diag_fix(self: &Arc<Self>, id: &str) {
        let fix: Option<Fix> = lock(&self.misc).diag.iter().find(|c| c.id == id).and_then(|c| c.fix.clone());
        let Some(fix) = fix else { return };
        let this = Arc::clone(self);
        self.rt.spawn(async move {
            let paths = this.paths.clone();
            let res = tokio::task::spawn_blocking(move || diagnostics::apply_fix(&fix, &paths)).await;
            match res {
                Ok(Ok(msg)) => this.toast(msg, 1),
                Ok(Err(msg)) => this.toast(msg, 3),
                Err(e) => this.toast(e.to_string(), 3),
            }
            this.diag_run();
        });
    }

    // ───────────── connection health ─────────────

    async fn measure_health(self: &Arc<Self>) {
        const HOSTS: [(&str, &str); 4] =
            [("Discord", "discord.com"), ("YouTube", "www.youtube.com"), ("Telegram", "web.telegram.org"), ("Cloudflare", "www.cloudflare.com")];
        let mut set = tokio::task::JoinSet::new();
        for (i, (name, host)) in HOSTS.iter().enumerate() {
            let (name, host) = ((*name).to_owned(), (*host).to_owned());
            set.spawn(async move { (i, name, heli_zapret::probe::tls_latency(&host, Duration::from_secs(4)).await) });
        }
        let mut out = Vec::new();
        while let Some(Ok(r)) = set.join_next().await {
            out.push(r);
        }
        out.sort_by_key(|(i, _, _)| *i);
        lock(&self.misc).health = out.into_iter().map(|(_, n, l)| (n, l)).collect();
        self.changed();
    }

    pub fn start_health(self: &Arc<Self>) {
        let this = Arc::clone(self);
        self.rt.spawn(async move { this.measure_health().await });
    }

    // ───────────── settings ─────────────

    pub fn apply_settings(self: &Arc<Self>, s: SettingsValues) {
        let launch_changed;
        {
            let mut c = lock(&self.cfg);
            launch_changed = c.app.launch_at_login != s.launch_login || (s.launch_login && c.app.start_minimized != s.start_min);
            c.app.launch_at_login = s.launch_login;
            c.app.start_minimized = s.start_min;
            c.app.close_to_tray = s.close_tray;
            c.app.check_app_updates = s.check_updates;
            c.app.verbose_logs = s.verbose;
            c.telegram.autostart = s.tg_auto;
            c.bypass.autostart = s.bp_auto;
            c.bypass.check_list_updates = s.check_updates;
        }
        self.save_cfg();
        if launch_changed {
            if let Err(e) = platform::set_autostart(s.launch_login, s.start_min) {
                self.toast(e, 3);
            }
        }
    }

    // ───────────── shutdown ─────────────

    pub async fn shutdown(self: &Arc<Self>) {
        self.tests.cancel().await;
        self.tg_stop().await;
        self.engine.stop().await;
    }
}

fn list_slot(lists: &mut heli_core::config::UserLists, l: UserList) -> &mut Option<String> {
    match l {
        UserList::General => &mut lists.general,
        UserList::Exclude => &mut lists.exclude,
        UserList::IpsetExclude => &mut lists.ipset_exclude,
    }
}

fn list_ref(lists: &heli_core::config::UserLists, l: UserList) -> &str {
    match l {
        UserList::General => lists.general.as_deref(),
        UserList::Exclude => lists.exclude.as_deref(),
        UserList::IpsetExclude => lists.ipset_exclude.as_deref(),
    }
    .unwrap_or("")
}

#[derive(Clone, Copy)]
pub struct SettingsValues {
    pub launch_login: bool,
    pub start_min: bool,
    pub close_tray: bool,
    pub check_updates: bool,
    pub tg_auto: bool,
    pub bp_auto: bool,
    pub verbose: bool,
}

pub fn service_state_label(state: ServiceState) -> (String, i32) {
    match state {
        ServiceState::Running => (tr("Running"), 1),
        ServiceState::NotInstalled => (tr("Not installed"), 0),
        ServiceState::Stopped => (tr("Stopped"), 2),
        ServiceState::StartPending | ServiceState::StopPending => (tr("Starting…"), 2),
        ServiceState::Other(_) => (tr("Unknown"), 2),
    }
}
