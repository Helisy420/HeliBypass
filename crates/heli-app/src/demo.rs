//! Development-only sample data (`heli-bypass --demo`), used to screenshot every page without
//! needing live services. Not compiled into release builds.

use slint::{ModelRc, SharedString, VecModel};

use crate::{AppState, CheckRow, GraphPoint, HealthRow, LogRow, RouteRow, StrategyRow, TestRow};

fn row(name: &str, g: [i32; 4], score: &str, best: bool, running: bool) -> TestRow {
    TestRow {
        name: name.into(),
        g0: g[0],
        g1: g[1],
        g2: g[2],
        g3: g[3],
        score: score.into(),
        best,
        running,
        error: SharedString::new(),
        d0: SharedString::new(),
        d1: SharedString::new(),
        d2: SharedString::new(),
    }
}

pub fn apply(s: &AppState) {
    s.set_tg_running(true);
    s.set_protected(true);
    s.set_bp_state(2);
    s.set_bp_strategy("general (ALT)".into());
    s.set_tg_latency("42 ms".into());
    s.set_tg_sessions("6".into());
    s.set_tg_traffic("128 MB".into());
    s.set_tg_traffic_sub("116 MB in · 12 MB out".into());
    s.set_tg_secret("f9e0b3532a35a749a7b8b71e832385b7".into());
    s.set_tg_dc_rules("2:149.154.167.220\n4:149.154.167.220".into());
    s.set_tg_down("6.8 MB/s".into());
    s.set_tg_up("212 KB/s".into());
    s.set_tg_peak("Peak 9.1 MB/s".into());
    let graph: Vec<GraphPoint> = (0..60)
        .map(|i| {
            let t = i as f32;
            let down = if i < 14 { 0.03 } else { (0.45 + 0.35 * (t / 5.0).sin() + 0.15 * (t / 1.7).cos()).clamp(0.05, 1.0) };
            GraphPoint { down, up: if i % 7 == 0 { 0.12 } else { 0.03 } }
        })
        .collect();
    s.set_tg_graph(ModelRc::new(VecModel::from(graph)));
    let r = |dc: &str, route: &str, kind, n: &str, d: &str, u: &str, share| RouteRow { dc: dc.into(), route: route.into(), kind, sessions: n.into(), down: d.into(), up: u.into(), share };
    s.set_tg_routes(ModelRc::new(VecModel::from(vec![
        r("DC5 media · 4", "HTTP/2", 5, "4", "4.1 MB/s", "18 KB/s", 0.6),
        r("DC203 media · 3", "Direct", 1, "3", "2.2 MB/s", "9 KB/s", 0.32),
        r("DC2 · 12", "Direct", 1, "2", "410 KB/s", "180 KB/s", 0.06),
        r("DC4 · 1", "Cloudflare", 2, "1", "96 KB/s", "5 KB/s", 0.02),
    ])));
    s.set_tg_h2(true);
    s.set_bp_chips(ModelRc::new(VecModel::from(vec!["Game filter".into(), "IPSet: loaded".into(), "winws.exe".into()])));
    let h = |n: &str, ms: &str, ok| HealthRow { name: n.into(), ms: ms.into(), ok };
    s.set_health(ModelRc::new(VecModel::from(vec![h("Discord", "38 ms", true), h("YouTube", "51 ms", true), h("Telegram", "42 ms", true), h("Cloudflare", "29 ms", true)])));
    let l = |t: &str, src: &str, m: &str| LogRow { time: t.into(), source: src.into(), message: m.into(), level: 0 };
    s.set_activity(ModelRc::new(VecModel::from(vec![
        l("12:04:11", "bypass", "started · general (ALT)"),
        l("12:04:12", "proxy", "listening 127.0.0.1:1443"),
        l("12:09:40", "proxy", "Cloudflare test ok · 42 ms"),
        l("12:31:02", "lists", "ipset-all.txt updated"),
        l("12:48:19", "tests", "5 of 6 strategies checked"),
    ])));
    s.set_test_running(true);
    s.set_test_progress(0.62);
    s.set_test_label("Testing general (SIMPLE FAKE)".into());
    s.set_test_count("5 of 8 · 00:42".into());
    s.set_test_best("general (FAKE TLS AUTO)".into());
    s.set_test_footer("Results are stored locally in test results".into());
    s.set_test_rows(ModelRc::new(VecModel::from(vec![
        row("general", [1, 3, 1, 1], "3/4", false, false),
        row("general (ALT)", [1, 1, 2, 1], "3/4", false, false),
        row("general (ALT2)", [3, 3, 1, 1], "2/4", false, false),
        row("general (FAKE TLS)", [1, 2, 1, 1], "3/4", false, false),
        row("general (FAKE TLS AUTO)", [1, 1, 1, 1], "4/4", true, false),
        row("general (SIMPLE FAKE)", [0, 0, 0, 0], "–", false, true),
    ])));
    let st = |n: &str, t: &str, note: &str, sel| StrategyRow { name: n.into(), technique: t.into(), note: note.into(), selected: sel };
    s.set_strategies(ModelRc::new(VecModel::from(vec![
        st("general", "multisplit · fake", "", false),
        st("general (ALT)", "fakedsplit · fake", "", true),
        st("general (ALT2)", "multisplit · fake", "", false),
        st("general (ALT5)", "hostfakesplit · fake", "Not recommended", false),
        st("general (FAKE TLS AUTO)", "multidisorder · fake", "", false),
    ])));
    s.set_svc_state("Running".into());
    s.set_svc_tone(1);
    s.set_svc_installed(true);
    s.set_svc_strategy("general (ALT)".into());
    s.set_svc_driver("Loaded".into());
    s.set_ipset_mode(1);
    s.set_ipset_info("612 340 addresses · updated 2 hours ago".into());
    s.set_hosts_state("Up to date".into());
    s.set_hosts_tone(1);
    s.set_hosts_info("12 entries in the HeliBypass block.".into());
    s.set_data_dir("C:\\ProgramData\\HeliBypass".into());
    let c = |id: &str, t: &str, d: &str, sev, fix: &str| CheckRow { id: id.into(), title: t.into(), detail: d.into(), severity: sev, fix: fix.into() };
    s.set_checks(ModelRc::new(VecModel::from(vec![
        c("admin", "Administrator rights", "Running elevated.", 0, ""),
        c("bfe", "Base Filtering Engine", "Running.", 0, ""),
        c("vpn", "VPN services", "Some VPNs conflict with zapret; make sure they are off. Found: Radmin VPN Control Service", 1, ""),
        c("windivert", "WinDivert driver", "winws.exe is not running but the WinDivert driver is still loaded.", 1, "Unload WinDivert"),
        c("conflicts", "Other bypass tools", "Conflicting services installed: GoodbyeDPI", 2, "Remove services"),
    ])));
    s.set_diag_summary("1 problem, 2 warnings".into());
}
