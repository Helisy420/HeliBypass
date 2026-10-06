//! Connects the Slint UI to the backend: builds a plain-Rust `View` from backend state,
//! applies it to the `AppState` global(s), and wires the UI callbacks.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use heli_core::activity;
use heli_core::config::generate_secret;
use heli_tgproxy::config::parse_dc_ip_list;
use heli_zapret::engine::EngineState;
use heli_zapret::lists::{self, GameMode, HostsStatus, IpsetMode};
use heli_zapret::tester::{GroupStatus, Phase, ResultState, TestKind};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::backend::{Backend, SettingsValues, now_secs, service_state_label};
use heli_zapret::builder::WebSpec;
use crate::i18n::{Language, ago, tr, tr_dyn, trf};
use crate::{AppState, CheckRow, HealthRow, LogRow, MainWindow, RouteRow, StrategyRow, TestRow};

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{n} B") } else { format!("{v:.1} {}", UNITS[u]) }
}

fn ms(d: std::time::Duration) -> String {
    trf("{} ms", &[&d.as_millis().to_string()])
}

/// Everything the UI displays that comes from the backend, as plain values.
#[derive(Default, Clone, PartialEq)]
pub struct View {
    pub admin: bool,
    pub protected: bool,
    pub lists_text: String,
    pub lists_sub: String,
    pub lists_tone: i32,
    pub toast: String,
    pub toast_tone: i32,

    pub tg_running: bool,
    pub tg_busy: bool,
    pub tg_addr: String,
    pub tg_route: String,
    pub tg_dcs: String,
    pub tg_latency: String,
    pub tg_sessions: String,
    pub tg_traffic: String,
    pub tg_traffic_sub: String,
    pub tg_error: String,
    pub tg_route_note: String,
    pub tg_cf_testing: bool,
    pub tg_cf_result: String,
    pub tg_down: String,
    pub tg_up: String,
    pub tg_peak: String,
    pub tg_graph_down: Vec<f32>,
    pub tg_graph_up: Vec<f32>,
    pub tg_routes: Vec<RouteRowV>,

    pub bp_state: i32,
    pub bp_strategy: String,
    pub bp_error: String,
    pub bp_chips: Vec<String>,
    pub strategies: Vec<(String, String, String, bool)>,

    pub health: Vec<(String, String, bool)>,
    pub activity: Vec<(String, String, String, i32)>,

    pub test_tab: i32,
    pub build_base: String,
    pub build_note: String,
    pub smart_running: bool,
    pub studio_base: String,
    pub services: Vec<(String, String)>,
    pub test_running: bool,
    pub test_progress: f32,
    pub test_label: String,
    pub test_count: String,
    pub test_rows: Vec<TestRowV>,
    pub test_best: String,
    pub test_footer: String,
    pub test_error: String,

    pub svc_state: String,
    pub svc_tone: i32,
    pub svc_strategy: String,
    pub svc_driver: String,
    pub svc_installed: bool,
    pub svc_busy: bool,

    pub ipset_mode: i32,
    pub ipset_info: String,
    pub ipset_busy: bool,
    pub game_error: String,
    pub hosts_state: String,
    pub hosts_tone: i32,
    pub hosts_busy: bool,

    pub list_counts: Vec<String>,
    pub checks: Vec<(String, String, String, i32, String)>,
    pub diag_running: bool,
    pub diag_summary: String,
    pub data_dir: String,
}

#[derive(Clone, PartialEq, Default)]
pub struct RouteRowV {
    pub dc: String,
    pub route: String,
    pub kind: i32,
    pub sessions: String,
    pub down: String,
    pub up: String,
    pub share: f32,
}

#[derive(Clone, PartialEq, Default)]
pub struct TestRowV {
    pub name: String,
    pub g: [i32; 4],
    pub score: String,
    pub best: bool,
    pub running: bool,
    pub error: String,
    pub d: [String; 3],
}

fn group_int(g: GroupStatus) -> i32 {
    match g {
        GroupStatus::Pending => 0,
        GroupStatus::Ok => 1,
        GroupStatus::Partial => 2,
        GroupStatus::Fail => 3,
        GroupStatus::NotTested => 4,
    }
}

fn translate_error(msg: &str) -> String {
    tr_dyn(msg)
}

pub fn build_view(b: &Arc<Backend>) -> View {
    let cfg = b.cfg.lock().unwrap_or_else(|e| e.into_inner()).clone();
    let misc = b.misc.lock().unwrap_or_else(|e| e.into_inner());
    let tg = b.tg.lock().unwrap_or_else(|e| e.into_inner());
    let engine_state = b.engine.state();
    let progress = b.tests.progress();
    let mut v = View { admin: heli_core::elevation::is_elevated(), data_dir: b.paths.root().display().to_string(), ..View::default() };

    // ── Telegram ──
    v.tg_running = tg.handle.is_some();
    v.tg_busy = tg.busy;
    v.tg_addr = format!("{}:{}", cfg.telegram.host, cfg.telegram.port);
    v.tg_route = if cfg.telegram.cfproxy { tr("via Cloudflare") } else { tr("WebSocket") };
    let mut dcs: Vec<String> = parse_dc_ip_list(&cfg.telegram.dc_ip).map(|m| m.keys().map(|d| format!("DC{d}")).collect()).unwrap_or_default();
    if dcs.is_empty() {
        dcs.push("DC".into());
    }
    v.tg_dcs = dcs.join(" / ");
    v.tg_latency = tg.latency.filter(|_| v.tg_running).map_or("—".into(), ms);
    if let Some(h) = &tg.handle {
        let s = h.stats();
        v.tg_sessions = s.connections_active.to_string();
        v.tg_traffic = human_bytes(s.bytes_up + s.bytes_down);
        v.tg_traffic_sub = trf("{} in · {} out", &[&human_bytes(s.bytes_down), &human_bytes(s.bytes_up)]);
    } else {
        v.tg_sessions = "0".into();
        v.tg_traffic = "0 B".into();
        v.tg_traffic_sub = String::new();
    }
    v.tg_error = translate_error(&tg.error);
    // data centers with a configured address use a direct WebSocket; the rest (and any session
    // whose direct connection fails) take the Cloudflare route when it is enabled
    let direct = if v.tg_dcs == "DC" { tr("None") } else { v.tg_dcs.clone() };
    v.tg_route_note = if cfg.telegram.cfproxy {
        trf("Direct WebSocket: {}. Other data centers and fallbacks go through Cloudflare.", &[&direct])
    } else {
        trf("Direct WebSocket: {}. Other data centers use the plain TCP fallback.", &[&direct])
    };
    v.tg_cf_testing = tg.cf_testing;
    v.tg_cf_result = tg.cf_result.clone();
    // ── live speed ──
    let sp = &tg.speed;
    v.tg_down = crate::speed::human_rate(if v.tg_running { sp.current_down() } else { 0.0 });
    v.tg_up = crate::speed::human_rate(if v.tg_running { sp.current_up() } else { 0.0 });
    v.tg_peak = trf("Peak {}", &[&crate::speed::human_rate(sp.peak_down)]);
    (v.tg_graph_down, v.tg_graph_up) = sp.graph();
    let total_down: f64 = sp.routes.iter().map(|r| r.down).sum();
    v.tg_routes = sp
        .routes
        .iter()
        .filter(|_| v.tg_running)
        .map(|r| RouteRowV {
            dc: if r.media { trf("DC{} media", &[&r.dc.to_string()]) } else { format!("DC{}", r.dc) } + &format!(" · {}", r.sessions),
            route: tr(r.route.label()),
            kind: r.route as i32,
            sessions: r.sessions.to_string(),
            down: crate::speed::human_rate(r.down),
            up: crate::speed::human_rate(r.up),
            share: if total_down > 0.0 { (r.down / total_down) as f32 } else { 0.0 },
        })
        .collect();
    drop(tg);

    // ── bypass ──
    let (state, running_name, failed) = match &engine_state {
        EngineState::Stopped => (0, None, None),
        EngineState::Starting(n) => (1, Some(n.clone()), None),
        EngineState::Running { strategy, .. } => (2, Some(strategy.clone()), None),
        EngineState::Failed(m) => (3, None, Some(m.clone())),
    };
    v.bp_state = state;
    v.bp_strategy = running_name.unwrap_or_else(|| b.selected_name());
    v.bp_error = translate_error(&if !misc.bp_error.is_empty() { misc.bp_error.clone() } else { failed.unwrap_or_default() });
    // the filter settings apply to the next start too, so show them while stopped as well
    if b.game_filter().is_enabled() {
        v.bp_chips.push(tr("Game filter"));
    }
    v.bp_chips.push(trf("IPSet: {}", &[&tr(lists::ipset_mode(&b.paths).label())]));
    if state == 2 {
        v.bp_chips.push("winws.exe".into());
    }
    let selected = b.selected_name();
    let filter = misc.strategy_filter.to_lowercase();
    v.strategies = b
        .strategies
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .iter()
        .filter(|s| filter.is_empty() || s.name.to_lowercase().contains(&filter))
        .map(|s| {
            let note = match &s.note {
                Some(n) if n.eq_ignore_ascii_case("not recommended") => tr("Not recommended"),
                Some(n) if n == "Auto-built" => tr("Auto-built"),
                Some(n) => n.clone(),
                None if Backend::is_user_strategy(s) => tr("Custom"),
                None => String::new(),
            };
            (s.name.clone(), s.technique(), note, s.name == selected)
        })
        .collect();
    v.protected = v.tg_running || state == 2;

    // ── footer, toast ──
    let (text, tone) = match misc.lists_current {
        Some(true) => (tr("Lists up to date"), 1),
        Some(false) => (tr("Lists outdated"), 2),
        None => (tr("Not checked yet"), 0),
    };
    v.lists_text = text;
    v.lists_tone = tone;
    v.lists_sub = misc.lists_checked.map(|t| trf("Checked {}", &[&ago(now_secs().saturating_sub(t))])).unwrap_or_default();
    if let Some((t, tone)) = &misc.toast {
        v.toast = tr_dyn(t);
        v.toast_tone = *tone;
    }

    // ── overview ──
    v.health = if misc.health.is_empty() {
        ["Discord", "YouTube", "Telegram", "Cloudflare"].iter().map(|n| (n.to_string(), "—".to_string(), true)).collect()
    } else {
        misc.health.iter().map(|(n, l)| (n.clone(), l.map_or("—".into(), ms), l.is_some())).collect()
    };
    // newest first: the panel clips at the bottom, so the latest entries must come first
    v.activity = activity::tail(14)
        .into_iter()
        .rev()
        .map(|e| (e.time, e.source, e.message, match e.level { activity::Level::Info => 0, activity::Level::Warn => 1, activity::Level::Error => 2 }))
        .collect();

    // ── tests ──
    v.test_tab = misc.test_tab;
    v.test_error = translate_error(&misc.test_error);
    v.test_running = progress.phase == Phase::Running;
    let total = progress.total.max(1);
    v.test_progress = match progress.phase {
        Phase::Idle => 0.0,
        Phase::Running => ((progress.done as f32 + 0.45) / total as f32).min(0.99),
        _ => 1.0,
    };
    let secs = progress.elapsed().as_secs();
    let clock = format!("{:02}:{:02}", secs / 60, secs % 60);
    v.test_label = match progress.phase {
        Phase::Idle => tr("Ready"),
        Phase::Running => match progress.stage {
            Some((n, of)) => {
                let what = match n {
                    1 => tr("screening"),
                    2 => tr("refining"),
                    _ => tr("confirming"),
                };
                format!("{} · {}", trf("Stage {} of {}: {}", &[&n.to_string(), &of.to_string(), &what]), progress.current.as_deref().unwrap_or("…"))
            }
            None => trf("Testing {}", &[progress.current.as_deref().unwrap_or("…")]),
        },
        Phase::Finished => match &progress.best {
            Some(b) => trf("Best strategy: {}", &[b]),
            None => tr("No strategy worked"),
        },
        Phase::Cancelled => tr("Cancelled"),
    };
    v.test_count = if progress.phase == Phase::Idle { String::new() } else { format!("{} · {clock}", trf("{} of {}", &[&progress.done.to_string(), &progress.total.to_string()])) };
    v.test_best = if progress.phase == Phase::Finished { progress.best.clone().unwrap_or_default() } else { String::new() };
    v.test_footer = trf("Results are stored locally in {}", &[&b.paths.test_results_dir().display().to_string()]);
    let dpi = progress.kind == TestKind::Dpi;
    v.test_rows = progress
        .results
        .iter()
        .map(|r| {
            let mut row = TestRowV { name: r.name.clone(), best: v.test_best == r.name, running: r.state == ResultState::Running, score: "–".into(), ..Default::default() };
            match &r.state {
                ResultState::Failed(m) => row.error = m.lines().next().unwrap_or("").to_owned(),
                ResultState::Done if dpi => {
                    let lines: usize = r.dpi.iter().map(|t| t.lines.len()).sum();
                    row.d = [r.dpi_ok.to_string(), r.dpi_blocked.to_string(), (lines as u32).saturating_sub(r.dpi_ok + r.dpi_blocked).to_string()];
                    row.score = format!("{}/{}", r.dpi_ok, lines);
                }
                ResultState::Done => {
                    row.g = [group_int(r.groups[0]), group_int(r.groups[1]), group_int(r.groups[2]), group_int(r.groups[3])];
                    row.score = format!("{}/{}", r.score, r.groups_tested.max(1));
                }
                _ => {}
            }
            row
        })
        .collect();
    // the tabs share one results table: show it only on the tab the run was started from
    if misc.test_run_tab != misc.test_tab {
        v.test_rows.clear();
    }
    let smart = progress.kind == TestKind::Smart;
    v.build_base = if smart && progress.phase == Phase::Running && !misc.build_base.is_empty() {
        misc.build_base.clone()
    } else {
        b.build_base().map(|s| s.name).unwrap_or_default()
    };
    v.build_note = misc.build_note.clone();
    v.smart_running = smart && progress.phase == Phase::Running;
    v.studio_base = b.studio_base().map(|s| s.name).unwrap_or_default();
    v.services = b.test_services().into_iter().map(|s| (s.name, s.url)).collect();
    // after a smart selection the useful choice is the saved strategy, not a candidate's working name
    if smart && misc.built {
        v.test_best = heli_zapret::builder::BUILT_NAME.to_owned();
    }

    // ── service ──
    if let Some(st) = &misc.svc {
        let (label, tone) = service_state_label(st.service);
        v.svc_state = label;
        v.svc_tone = tone;
        v.svc_installed = st.service != heli_zapret::scm::ServiceState::NotInstalled;
        v.svc_strategy = st.strategy.clone().unwrap_or_default();
        v.svc_driver = if matches!(st.windivert, heli_zapret::scm::ServiceState::Running) { tr("Loaded") } else { tr("Not loaded") };
    } else {
        v.svc_state = tr("Unknown");
    }
    v.svc_busy = misc.svc_busy;

    // ── ipset / hosts ──
    v.ipset_mode = match lists::ipset_mode(&b.paths) {
        IpsetMode::None => 0,
        IpsetMode::Loaded => 1,
        IpsetMode::Any => 2,
    };
    v.ipset_info = misc.ipset_info.clone();
    v.ipset_busy = misc.ipset_busy;
    v.game_error = misc.game_error.clone();
    let (hs, ht) = match &misc.hosts {
        Some((HostsStatus::UpToDate, _)) => (tr("Up to date"), 1),
        Some((HostsStatus::NeedsUpdate, _)) => (tr("Needs update"), 2),
        Some((HostsStatus::Unreadable, _)) => (tr("Cannot read hosts file"), 0),
        None => (tr("Unknown"), 0),
    };
    v.hosts_state = hs;
    v.hosts_tone = ht;
    v.hosts_busy = misc.hosts_busy;

    v.list_counts = heli_zapret::userlists::UserList::ALL
        .iter()
        .map(|l| match heli_zapret::userlists::validate(*l, b.list_text(*l).as_str()) {
            Ok(0) => tr("Empty"),
            Ok(n) => trf("Entries: {}", &[&n.to_string()]),
            Err(_) => tr("Has invalid lines"),
        })
        .collect();

    // ── diagnostics ──
    v.diag_running = misc.diag_running;
    v.checks = misc
        .diag
        .iter()
        .map(|c| {
            let sev = match c.severity {
                heli_zapret::diagnostics::Severity::Ok => 0,
                heli_zapret::diagnostics::Severity::Warn => 1,
                heli_zapret::diagnostics::Severity::Fail => 2,
            };
            (c.id.to_owned(), tr_dyn(&c.title), tr_dyn(&c.detail), sev, c.fix.as_ref().map(|f| tr(f.label())).unwrap_or_default())
        })
        .collect();
    let (fails, warns) = (
        misc.diag.iter().filter(|c| c.severity == heli_zapret::diagnostics::Severity::Fail).count(),
        misc.diag.iter().filter(|c| c.severity == heli_zapret::diagnostics::Severity::Warn).count(),
    );
    v.diag_summary = if !misc.diag_ran {
        tr("Run diagnostics to check your system.")
    } else if fails + warns == 0 {
        tr("No problems found")
    } else {
        trf("{} problem(s), {} warning(s)", &[&fails.to_string(), &warns.to_string()])
    };
    v
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

fn ss(s: &str) -> SharedString {
    SharedString::from(s)
}

/// Push a view into an `AppState` global. Scalar setters ignore unchanged values; models are
/// only replaced when `prev` shows that they changed, so scroll positions and hover states survive.
pub fn apply(s: &AppState, v: &View, prev: Option<&View>) {
    let changed = |f: &dyn Fn(&View) -> bool| prev.is_none_or(|p| !f(p));
    s.set_admin(v.admin);
    s.set_protected(v.protected);
    s.set_lists_text(ss(&v.lists_text));
    s.set_lists_sub(ss(&v.lists_sub));
    s.set_lists_tone(v.lists_tone);
    s.set_toast(ss(&v.toast));
    s.set_toast_tone(v.toast_tone);

    s.set_tg_running(v.tg_running);
    s.set_tg_busy(v.tg_busy);
    s.set_tg_addr(ss(&v.tg_addr));
    s.set_tg_route(ss(&v.tg_route));
    s.set_tg_dcs(ss(&v.tg_dcs));
    s.set_tg_latency(ss(&v.tg_latency));
    s.set_tg_sessions(ss(&v.tg_sessions));
    s.set_tg_traffic(ss(&v.tg_traffic));
    s.set_tg_traffic_sub(ss(&v.tg_traffic_sub));
    s.set_tg_error(ss(&v.tg_error));
    s.set_tg_route_note(ss(&v.tg_route_note));
    s.set_tg_cf_testing(v.tg_cf_testing);
    s.set_tg_cf_result(ss(&v.tg_cf_result));
    s.set_tg_down(ss(&v.tg_down));
    s.set_tg_up(ss(&v.tg_up));
    s.set_tg_peak(ss(&v.tg_peak));
    if changed(&|p| p.tg_graph_down == v.tg_graph_down && p.tg_graph_up == v.tg_graph_up) {
        s.set_tg_graph(model(v.tg_graph_down.iter().zip(&v.tg_graph_up).map(|(d, u)| crate::GraphPoint { down: *d, up: *u }).collect()));
    }
    if changed(&|p| p.tg_routes == v.tg_routes) {
        s.set_tg_routes(model(
            v.tg_routes
                .iter()
                .map(|r| RouteRow {
                    dc: ss(&r.dc),
                    route: ss(&r.route),
                    kind: r.kind,
                    sessions: ss(&r.sessions),
                    down: ss(&r.down),
                    up: ss(&r.up),
                    share: r.share,
                })
                .collect(),
        ));
    }

    s.set_bp_state(v.bp_state);
    s.set_bp_strategy(ss(&v.bp_strategy));
    s.set_bp_error(ss(&v.bp_error));
    if changed(&|p| p.bp_chips == v.bp_chips) {
        s.set_bp_chips(model(v.bp_chips.iter().map(|c| ss(c)).collect()));
    }
    if changed(&|p| p.strategies == v.strategies) {
        s.set_strategies(model(v.strategies.iter().map(|(n, t, no, sel)| StrategyRow { name: ss(n), technique: ss(t), note: ss(no), selected: *sel }).collect()));
    }
    if changed(&|p| p.health == v.health) {
        s.set_health(model(v.health.iter().map(|(n, m, ok)| HealthRow { name: ss(n), ms: ss(m), ok: *ok }).collect()));
    }
    if changed(&|p| p.activity == v.activity) {
        s.set_activity(model(v.activity.iter().map(|(t, src, m, l)| LogRow { time: ss(t), source: ss(src), message: ss(m), level: *l }).collect()));
    }

    s.set_test_tab(v.test_tab);
    s.set_build_base(ss(&v.build_base));
    s.set_build_note(ss(&v.build_note));
    s.set_smart_running(v.smart_running);
    s.set_studio_base(ss(&v.studio_base));
    if changed(&|p| p.services == v.services) {
        s.set_services(model(v.services.iter().map(|(n, u)| crate::ServiceRow { name: ss(n), url: ss(u) }).collect()));
    }
    s.set_test_running(v.test_running);
    s.set_test_progress(v.test_progress);
    s.set_test_label(ss(&v.test_label));
    s.set_test_count(ss(&v.test_count));
    s.set_test_best(ss(&v.test_best));
    s.set_test_footer(ss(&v.test_footer));
    s.set_test_error(ss(&v.test_error));
    if changed(&|p| p.test_rows == v.test_rows) {
        s.set_test_rows(model(
            v.test_rows
                .iter()
                .map(|r| TestRow {
                    name: ss(&r.name),
                    g0: r.g[0],
                    g1: r.g[1],
                    g2: r.g[2],
                    g3: r.g[3],
                    score: ss(&r.score),
                    best: r.best,
                    running: r.running,
                    error: ss(&r.error),
                    d0: ss(&r.d[0]),
                    d1: ss(&r.d[1]),
                    d2: ss(&r.d[2]),
                })
                .collect(),
        ));
    }

    s.set_svc_state(ss(&v.svc_state));
    s.set_svc_tone(v.svc_tone);
    s.set_svc_strategy(ss(&v.svc_strategy));
    s.set_svc_driver(ss(&v.svc_driver));
    s.set_svc_installed(v.svc_installed);
    s.set_svc_busy(v.svc_busy);

    s.set_ipset_mode(v.ipset_mode);
    s.set_ipset_info(ss(&v.ipset_info));
    s.set_ipset_busy(v.ipset_busy);
    s.set_game_error(ss(&v.game_error));
    s.set_hosts_state(ss(&v.hosts_state));
    s.set_hosts_tone(v.hosts_tone);
    s.set_hosts_busy(v.hosts_busy);

    if changed(&|p| p.list_counts == v.list_counts) {
        s.set_list_counts(model(v.list_counts.iter().map(|c| ss(c)).collect()));
    }
    if changed(&|p| p.checks == v.checks) {
        s.set_checks(model(v.checks.iter().map(|(id, t, d, sev, fix)| CheckRow { id: ss(id), title: ss(t), detail: ss(d), severity: *sev, fix: ss(fix) }).collect()));
    }
    s.set_diag_running(v.diag_running);
    s.set_diag_summary(ss(&v.diag_summary));
    s.set_data_dir(ss(&v.data_dir));
}

/// Load the editable form fields from the saved configuration.
pub fn load_forms(s: &AppState, b: &Backend) {
    let c = b.cfg.lock().unwrap_or_else(|e| e.into_inner()).clone();
    s.set_tg_host(ss(&c.telegram.host));
    s.set_tg_port(ss(&c.telegram.port.to_string()));
    s.set_tg_secret(ss(&c.telegram.secret));
    s.set_tg_dc_rules(ss(&c.telegram.dc_ip.join("\n")));
    s.set_tg_cf(c.telegram.cfproxy);
    s.set_tg_tcp_fallback(c.telegram.tcp_fallback);
    s.set_tg_h2(c.telegram.h2_media);
    s.set_tg_unlimited(c.telegram.speed_limit_mb == 0);
    s.set_tg_limit_text(ss(&if c.telegram.speed_limit_mb == 0 { "10".to_owned() } else { c.telegram.speed_limit_mb.to_string() }));
    let gf = b.game_filter();
    s.set_game_mode(match gf.mode {
        GameMode::Disabled => 0,
        GameMode::All => 1,
        GameMode::Tcp => 2,
        GameMode::Udp => 3,
    });
    s.set_game_tcp(ss(&gf.tcp_range));
    s.set_game_udp(ss(&gf.udp_range));
}

pub fn load_settings(s: &AppState, b: &Backend) {
    let c = b.cfg.lock().unwrap_or_else(|e| e.into_inner()).clone();
    s.set_set_launch_login(c.app.launch_at_login);
    s.set_set_start_min(c.app.start_minimized);
    s.set_set_close_tray(c.app.close_to_tray);
    s.set_set_check_updates(c.app.check_app_updates);
    s.set_set_tg_autostart(c.telegram.autostart);
    s.set_set_bp_autostart(c.bypass.autostart);
    s.set_set_verbose(c.app.verbose_logs);
    s.set_language(Language::from_code(&c.app.language).index());
    s.set_studio_advanced(c.app.studio_advanced);
}

/// Callbacks that both the main window and the tray popup use.
pub fn wire_common(s: &AppState, b: &Arc<Backend>) {
    let bb = Arc::clone(b);
    s.on_tg_toggle(move || bb.tg_toggle());
    let bb = Arc::clone(b);
    s.on_bp_toggle(move || bb.bp_toggle());
    let bb = Arc::clone(b);
    s.on_bp_select(move |n| bb.bp_select(n.as_str()));
    let bb = Arc::clone(b);
    s.on_toggle_all(move || bb.toggle_all());
    let bb = Arc::clone(b);
    s.on_tg_open(move || bb.tg_open());
    let bb = Arc::clone(b);
    s.on_tg_copy_link(move || bb.tg_copy_link());
}

/// Callbacks that only exist on the main window.
pub fn wire_main(ui: &MainWindow, b: &Arc<Backend>) {
    let s = ui.global::<AppState>();
    wire_common(&s, b);

    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_tg_save(move || {
        if let Some(ui) = w.upgrade() {
            let s = ui.global::<AppState>();
            bb.tg_save(s.get_tg_host().as_str(), s.get_tg_port().as_str(), s.get_tg_secret().as_str(), s.get_tg_dc_rules().as_str(), s.get_tg_cf(), s.get_tg_tcp_fallback(), s.get_tg_h2());
            load_forms(&s, &bb);
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_tg_cancel(move || {
        if let Some(ui) = w.upgrade() {
            load_forms(&ui.global::<AppState>(), &bb);
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_tg_regen_secret(move || {
        let _ = &bb;
        if let Some(ui) = w.upgrade() {
            ui.global::<AppState>().set_tg_secret(ss(&generate_secret()));
        }
    });
    let bb = Arc::clone(b);
    s.on_tg_test_cf(move || bb.tg_test_cf());
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_tg_limit_changed(move || {
        let Some(ui) = w.upgrade() else { return };
        let s = ui.global::<AppState>();
        if s.get_tg_unlimited() {
            bb.tg_set_limit(0);
        } else if let Ok(mb) = s.get_tg_limit_text().trim().parse::<u32>() {
            if (1..=100_000).contains(&mb) {
                bb.tg_set_limit(mb);
            }
        }
    });

    let bb = Arc::clone(b);
    s.on_set_strategy_filter(move |t| {
        bb.misc.lock().unwrap_or_else(|e| e.into_inner()).strategy_filter = t.to_string();
        bb.changed();
    });
    let bb = Arc::clone(b);
    s.on_tests_run_all(move || bb.tests_run());
    let bb = Arc::clone(b);
    s.on_tests_stop(move || bb.tests_stop());
    let bb = Arc::clone(b);
    s.on_tests_switch_tab(move |t| bb.tests_switch_tab(t));
    let bb = Arc::clone(b);
    s.on_tests_use_best(move || {
        let built = {
            let m = bb.misc.lock().unwrap_or_else(|e| e.into_inner());
            m.built && bb.tests.progress().kind == TestKind::Smart
        };
        if built {
            bb.bp_select(heli_zapret::builder::BUILT_NAME);
        } else if let Some(name) = bb.tests.progress().best {
            bb.bp_select(&name);
        }
    });
    let bb = Arc::clone(b);
    s.on_tests_export(move || bb.export_results());

    let bb = Arc::clone(b);
    s.on_svc_install(move || bb.svc_install());
    let bb = Arc::clone(b);
    s.on_svc_remove(move || bb.svc_remove());
    let bb = Arc::clone(b);
    s.on_ipset_set(move |i| bb.ipset_set(i));
    let bb = Arc::clone(b);
    s.on_ipset_update(move || bb.ipset_update());
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_game_apply(move || {
        if let Some(ui) = w.upgrade() {
            let s = ui.global::<AppState>();
            bb.game_apply(s.get_game_mode(), s.get_game_tcp().as_str(), s.get_game_udp().as_str());
        }
    });
    let bb = Arc::clone(b);
    s.on_hosts_update(move || bb.hosts_update());
    let bb = Arc::clone(b);
    s.on_hosts_restore(move || bb.hosts_remove());
    // ── Strategy Studio ──
    let bb = Arc::clone(b);
    s.on_studio_smart(move || bb.studio_smart(false));
    let bb = Arc::clone(b);
    s.on_studio_auto(move || bb.studio_smart(true));
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_studio_mode_changed(move || {
        if let Some(ui) = w.upgrade() {
            bb.cfg.lock().unwrap_or_else(|e| e.into_inner()).app.studio_advanced = ui.global::<AppState>().get_studio_advanced();
            bb.save_cfg();
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_studio_load(move || {
        if let Some(ui) = w.upgrade() {
            let spec = bb.studio_base().map(|s| WebSpec::from_strategy(&s)).unwrap_or_default();
            set_spec(&ui.global::<AppState>(), &spec);
        }
    });
    let w = ui.as_weak();
    s.on_studio_changed(move || {
        if let Some(ui) = w.upgrade() {
            refresh_preview(&ui.global::<AppState>());
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_studio_test(move || {
        let Some(ui) = w.upgrade() else { return };
        let s = ui.global::<AppState>();
        match bb.studio_test(&read_spec(&s)) {
            Ok(()) => s.set_page(3),
            Err(e) => s.set_studio_problems(ss(&e)),
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_studio_save(move || {
        let Some(ui) = w.upgrade() else { return };
        let s = ui.global::<AppState>();
        if let Err(e) = bb.studio_save(&read_spec(&s)) {
            s.set_studio_problems(ss(&e));
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_service_add(move || {
        let Some(ui) = w.upgrade() else { return };
        let s = ui.global::<AppState>();
        match bb.service_add(s.get_tsvc_name().as_str(), s.get_tsvc_url().as_str()) {
            Ok(()) => {
                s.set_tsvc_name(SharedString::new());
                s.set_tsvc_url(SharedString::new());
                s.set_tsvc_error(SharedString::new());
            }
            Err(e) => s.set_tsvc_error(ss(&e)),
        }
    });
    let bb = Arc::clone(b);
    s.on_service_remove(move |i| bb.service_remove(usize::try_from(i).unwrap_or(usize::MAX)));

    // in-app list editor
    use heli_zapret::userlists::UserList;
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_list_open(move |i| {
        let (Some(ui), Some(l)) = (w.upgrade(), UserList::from_index(i)) else { return };
        let s = ui.global::<AppState>();
        let text = bb.list_text(l);
        let (status, error) = bb.list_check(l, &text);
        let (title, hint) = match l {
            UserList::General => (tr("Extra domains to bypass"), tr("One domain per line, for example example.com. Subdomains are included automatically.")),
            UserList::Exclude => (tr("Domains to leave alone"), tr("One domain per line, for example example.com. Subdomains are included automatically.")),
            UserList::IpsetExclude => (
                tr("Addresses to leave alone"),
                tr("One entry per line: an address (1.2.3.4), a network (10.0.0.0/8) or a range (1.2.3.4-1.2.3.9)."),
            ),
        };
        s.set_list_editor_id(i);
        s.set_list_editor_title(ss(&title));
        s.set_list_editor_hint(ss(&hint));
        s.set_list_editor_text(ss(&text));
        s.set_list_editor_status(ss(&status));
        s.set_list_editor_error(ss(&error));
        s.set_list_editor_open(true);
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_list_edited(move |text| {
        let Some(ui) = w.upgrade() else { return };
        let s = ui.global::<AppState>();
        let Some(l) = UserList::from_index(s.get_list_editor_id()) else { return };
        let (status, error) = bb.list_check(l, text.as_str());
        s.set_list_editor_status(ss(&status));
        s.set_list_editor_error(ss(&error));
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_list_save(move || {
        let Some(ui) = w.upgrade() else { return };
        let s = ui.global::<AppState>();
        let Some(l) = UserList::from_index(s.get_list_editor_id()) else { return };
        match bb.list_save(l, s.get_list_editor_text().as_str()) {
            Ok(()) => s.set_list_editor_open(false),
            Err(e) => s.set_list_editor_error(ss(&e)),
        }
    });
    let bb = Arc::clone(b);
    s.on_diag_run(move || bb.diag_run());
    let bb = Arc::clone(b);
    s.on_diag_fix(move |id| bb.diag_fix(id.as_str()));

    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_settings_changed(move || {
        if let Some(ui) = w.upgrade() {
            let s = ui.global::<AppState>();
            bb.apply_settings(SettingsValues {
                launch_login: s.get_set_launch_login(),
                start_min: s.get_set_start_min(),
                close_tray: s.get_set_close_tray(),
                check_updates: s.get_set_check_updates(),
                tg_auto: s.get_set_tg_autostart(),
                bp_auto: s.get_set_bp_autostart(),
                verbose: s.get_set_verbose(),
            });
        }
    });
    let (bb, w) = (Arc::clone(b), ui.as_weak());
    s.on_language_changed(move |i| {
        bb.set_language(Language::from_index(i));
        if let Some(ui) = w.upgrade() {
            ui.global::<AppState>().set_language(i);
        }
    });
    let bb = Arc::clone(b);
    s.on_open_data_dir(move || {
        crate::platform::open(&bb.paths.root().to_string_lossy());
    });
    s.on_open_url(move |u| {
        if u.starts_with("https://") {
            crate::platform::open(u.as_str());
        }
    });
    s.on_restart_admin(move || {
        if heli_core::elevation::relaunch_elevated(&[]) {
            let _ = slint::quit_event_loop();
        }
    });
}

// ── Strategy Studio form <-> WebSpec ──

const TECHNIQUES: [&str; 4] = ["multisplit", "fakedsplit", "multidisorder", "hostfakesplit"];

fn read_spec(s: &AppState) -> WebSpec {
    let tech = TECHNIQUES.get(usize::try_from(s.get_studio_tech()).unwrap_or(0)).copied().unwrap_or("multisplit");
    let num = |t: SharedString| t.trim().parse::<u32>().unwrap_or(0);
    WebSpec {
        method: if s.get_studio_fake() { format!("fake,{tech}") } else { tech.to_owned() },
        split_pos: s.get_studio_pos().to_string(),
        seqovl: num(s.get_studio_seqovl()),
        fooling: heli_zapret::builder::FOOLINGS.get(usize::try_from(s.get_studio_fooling()).unwrap_or(0)).copied().unwrap_or("none").to_owned(),
        repeats: num(s.get_studio_repeats()).max(1),
        fake_file: heli_zapret::builder::TLS_FAKES.get(usize::try_from(s.get_studio_file()).unwrap_or(0)).copied().unwrap_or(heli_zapret::builder::TLS_FAKES[0]).to_owned(),
        fake_host: s.get_studio_host().to_string(),
        quic_repeats: num(s.get_studio_quic()),
        voice_repeats: num(s.get_studio_voice()),
    }
}

fn set_spec(s: &AppState, spec: &WebSpec) {
    let tech = spec.method.trim_start_matches("fake,");
    s.set_studio_tech(TECHNIQUES.iter().position(|t| *t == tech).unwrap_or(0) as i32);
    s.set_studio_fake(spec.method.starts_with("fake,"));
    s.set_studio_pos(ss(&spec.split_pos));
    s.set_studio_seqovl(ss(&spec.seqovl.to_string()));
    s.set_studio_fooling(heli_zapret::builder::FOOLINGS.iter().position(|f| *f == spec.fooling).unwrap_or(0) as i32);
    s.set_studio_repeats(ss(&spec.repeats.to_string()));
    s.set_studio_file(heli_zapret::builder::TLS_FAKES.iter().position(|f| *f == spec.fake_file).unwrap_or(0) as i32);
    s.set_studio_host(ss(&spec.fake_host));
    s.set_studio_quic(ss(&if spec.quic_repeats == 0 { String::new() } else { spec.quic_repeats.to_string() }));
    s.set_studio_voice(ss(&if spec.voice_repeats == 0 { String::new() } else { spec.voice_repeats.to_string() }));
    refresh_preview(s);
}

fn refresh_preview(s: &AppState) {
    let spec = read_spec(s);
    s.set_studio_preview(ss(&spec.recipe().join(" ")));
    s.set_studio_problems(ss(&spec.problems().iter().map(|p| tr(p)).collect::<Vec<_>>().join(" ")));
}

/// Page-entry side effects (refresh data that is expensive to poll).
pub fn on_page_changed(b: &Arc<Backend>, ui: &MainWindow, page: i32) {
    b.page.store(page, Ordering::Relaxed);
    let s = ui.global::<AppState>();
    match page {
        0 => b.start_health(),
        1 => load_forms(&s, b),
        4 => b.refresh_service(),
        8 => {
            if s.get_studio_pos().is_empty() {
                s.invoke_studio_load();
            }
        }
        5 => {
            load_forms(&s, b);
            b.refresh_lists_info();
            b.check_lists();
        }
        6 => {
            let ran = b.misc.lock().unwrap_or_else(|e| e.into_inner()).diag_ran;
            if !ran {
                b.diag_run();
            }
        }
        _ => {}
    }
}
