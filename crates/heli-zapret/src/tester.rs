//! Strategy tests: start each strategy in turn, probe real services through it, rank them.
//!
//! Started from upstream `utils/test zapret.ps1` (standard HTTP / TLS1.2 / TLS1.3 checks + ping,
//! and the "TCP 16-20 KB freeze" DPI suite), extended with long transfers, Discord's gateway and
//! media ports, the user's own services, and a smart search that builds a strategy for this
//! connection. Everything runs in-process, in parallel, and reports progress to the UI.

use std::sync::Arc;
use std::time::{Duration, Instant};

use heli_core::activity;
use heli_core::paths::Paths;
use heli_core::tls::TlsVersions;
use tokio::sync::{Mutex, Semaphore, watch};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::engine::{Engine, EngineState, SERVICE_NAME};
use crate::lists::{GameFilter, IpsetMode, ipset_mode, set_ipset_mode};
use crate::probe::{
    DpiLine, DpiStatus, ProbeStatus, any_tcp_reachable, discord_gateway_probe, discord_rtc_probe, dpi_probe, http_probe, ping, transfer_probe,
};
use crate::scm::{self, ServiceState};
use crate::strategy::Strategy;

pub const DPI_SUITE_URL: &str = "https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json";

// ───────────────────────────── targets ─────────────────────────────

/// The service groups shown as columns in the results table. Telegram is not tested here: the
/// built-in proxy carries it, independently of the bypass strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Group {
    Discord = 0,
    YouTube = 1,
    Cloudflare = 2,
    /// The user's own services (see [`Service`]).
    Custom = 3,
}

pub const GROUPS: [Group; 4] = [Group::Discord, Group::YouTube, Group::Cloudflare, Group::Custom];

impl Group {
    pub fn label(self) -> &'static str {
        match self {
            Group::Discord => "Discord",
            Group::YouTube => "YouTube",
            Group::Cloudflare => "Cloudflare",
            Group::Custom => "Custom",
        }
    }
}

/// One measurement made against a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// `HEAD /` with automatic, TLS 1.2-only and TLS 1.3-only negotiation.
    Head,
    /// Download at least `min_bytes` of `path` over one connection: catches the "freezes after
    /// 16-20 KB" blocking and desync that breaks longer transfers, and measures the speed.
    Transfer { path: String, min_bytes: usize },
    /// Discord's gateway WebSocket held open with heartbeats (a long-lived connection).
    DiscordGateway,
    /// Discord's voice region lookup on this port (the media ports 2053/8443 are filtered by a
    /// separate profile). On 443 the voice servers' own addresses are checked as well.
    DiscordRtc { port: u16 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub key: String,
    /// `None` for ping-only targets (public DNS servers), which are informational.
    pub group: Option<Group>,
    pub host: Option<String>,
    pub port: u16,
    pub ping_host: String,
    pub checks: Vec<Check>,
}

/// A service the user added to the tests: a name and an `https://` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub url: String,
}

fn site(key: &str, group: Group, host: &str, checks: Vec<Check>) -> Target {
    Target { key: key.into(), group: Some(group), host: Some(host.into()), port: 443, ping_host: host.into(), checks }
}

fn transfer(path: &str, kb: usize) -> Check {
    Check::Transfer { path: path.into(), min_bytes: kb * 1024 }
}

/// The built-in test set.
pub fn builtin_targets() -> Vec<Target> {
    use Check::*;
    use Group::*;
    vec![
        site("DiscordMain", Discord, "discord.com", vec![Head, transfer("/", 160)]),
        site("DiscordGateway", Discord, "gateway.discord.gg", vec![DiscordGateway]),
        site("DiscordCDN", Discord, "cdn.discordapp.com", vec![Head]),
        site("DiscordMedia", Discord, "latency.discord.media", vec![DiscordRtc { port: 443 }, DiscordRtc { port: 8443 }, DiscordRtc { port: 2053 }]),
        site("YouTubeWeb", YouTube, "www.youtube.com", vec![Head, transfer("/", 256)]),
        site("YouTubeImage", YouTube, "i.ytimg.com", vec![Head]),
        site("YouTubeVideo", YouTube, "redirector.googlevideo.com", vec![Head]),
        site("GoogleMain", YouTube, "www.google.com", vec![Head]),
        site("GoogleStatic", YouTube, "www.gstatic.com", vec![Head]),
        site("CloudflareWeb", Cloudflare, "www.cloudflare.com", vec![Head]),
        site("CloudflareCDN", Cloudflare, "cdnjs.cloudflare.com", vec![Head, transfer("/ajax/libs/jquery/3.7.1/jquery.min.js", 80)]),
        Target { key: "CloudflareDNS1111".into(), group: None, host: None, port: 0, ping_host: "1.1.1.1".into(), checks: vec![] },
        Target { key: "GoogleDNS8888".into(), group: None, host: None, port: 0, ping_host: "8.8.8.8".into(), checks: vec![] },
    ]
}

/// A user service as a target: `HEAD` plus a download of the given address.
pub fn service_target(s: &Service) -> Option<Target> {
    let rest = s.url.trim().strip_prefix("https://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_owned()),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, 443),
    };
    if host.is_empty() || !host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        return None;
    }
    let key: String = s.name.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
    Some(Target {
        key: if key.is_empty() { host.to_owned() } else { key },
        group: Some(Group::Custom),
        host: Some(host.to_owned()),
        port,
        ping_host: host.to_owned(),
        checks: vec![Check::Head, Check::Transfer { path, min_bytes: 64 * 1024 }],
    })
}

/// Built-in targets plus the user's services.
pub fn targets_for(services: &[Service]) -> Vec<Target> {
    let mut t = builtin_targets();
    t.extend(services.iter().filter_map(service_target));
    t
}

/// The quicker subset used to screen many candidates: one negotiation per site, the main
/// downloads, the media port, no pings and no gateway session.
fn quick(targets: &[Target]) -> Vec<Target> {
    targets
        .iter()
        .filter(|t| t.host.is_some())
        .map(|t| Target {
            checks: t
                .checks
                .iter()
                .filter(|c| !matches!(c, Check::DiscordGateway | Check::DiscordRtc { port: 443 | 2053 }))
                .cloned()
                .collect(),
            ..t.clone()
        })
        .filter(|t| !t.checks.is_empty())
        .collect()
}

// ───────────────────────────── results ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupStatus {
    Pending,
    Ok,
    /// Some probes passed, some failed (shown as an amber "minus").
    Partial,
    Fail,
    /// No targets in this group (e.g. no services of your own added).
    NotTested,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TargetResult {
    pub key: String,
    pub group: Option<Group>,
    /// `HTTP`, `TLS1.2`, `TLS1.3` outcomes (empty for ping-only targets).
    pub probes: Vec<(&'static str, ProbeStatus)>,
    pub ping: Option<Duration>,
    /// Download speed of the long transfer, bytes per second.
    pub rate: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ResultState {
    Pending,
    Running,
    Done,
    /// The strategy could not even be started (message).
    Failed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct DpiTargetResult {
    pub id: String,
    pub provider: String,
    pub country: String,
    pub lines: Vec<DpiLine>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StrategyResult {
    pub name: String,
    pub state: ResultState,
    pub targets: Vec<TargetResult>,
    pub dpi: Vec<DpiTargetResult>,
    pub groups: [GroupStatus; 4],
    /// Number of service groups that fully work.
    pub score: u8,
    /// Number of groups that had something to test.
    pub groups_tested: u8,
    /// Sum of the long-transfer speeds, bytes per second (tie-breaker).
    pub throughput: f64,
    pub ok_probes: u32,
    pub ping_ok: u32,
    pub dpi_ok: u32,
    pub dpi_blocked: u32,
}

impl StrategyResult {
    pub fn pending(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            state: ResultState::Pending,
            targets: Vec::new(),
            dpi: Vec::new(),
            groups: [GroupStatus::Pending; 4],
            score: 0,
            groups_tested: 0,
            throughput: 0.0,
            ok_probes: 0,
            ping_ok: 0,
            dpi_ok: 0,
            dpi_blocked: 0,
        }
    }

    fn apply_standard(&mut self, targets: Vec<TargetResult>) {
        let (groups, score, ok, ping_ok) = summarize_standard(&targets);
        self.groups_tested = groups.iter().filter(|g| **g != GroupStatus::NotTested).count() as u8;
        self.throughput = targets.iter().filter_map(|t| t.rate).sum();
        self.targets = targets;
        self.groups = groups;
        self.score = score;
        self.ok_probes = ok;
        self.ping_ok = ping_ok;
        self.state = ResultState::Done;
    }

    fn apply_dpi(&mut self, dpi: Vec<DpiTargetResult>) {
        let lines = dpi.iter().flat_map(|t| &t.lines);
        self.dpi_ok = lines.clone().filter(|l| l.status == DpiStatus::Ok).count() as u32;
        self.dpi_blocked = lines.filter(|l| l.status == DpiStatus::LikelyBlocked).count() as u32;
        self.dpi = dpi;
        self.state = ResultState::Done;
    }
}

/// Reduce raw probe outcomes to the table's four columns, the score and the tie-break counters.
pub fn summarize_standard(targets: &[TargetResult]) -> ([GroupStatus; 4], u8, u32, u32) {
    let mut groups = [GroupStatus::Fail; 4];
    for g in GROUPS {
        let statuses: Vec<ProbeStatus> = targets
            .iter()
            .filter(|t| t.group == Some(g))
            .flat_map(|t| t.probes.iter().map(|(_, s)| *s))
            .filter(|s| *s != ProbeStatus::Unsupported)
            .collect();
        let ok = statuses.iter().filter(|s| **s == ProbeStatus::Ok).count();
        groups[g as usize] = if statuses.is_empty() {
            GroupStatus::NotTested
        } else if ok == statuses.len() {
            GroupStatus::Ok
        } else if ok == 0 {
            GroupStatus::Fail
        } else {
            GroupStatus::Partial
        };
    }
    let score = groups.iter().filter(|g| **g == GroupStatus::Ok).count() as u8;
    let ok_probes = targets.iter().flat_map(|t| &t.probes).filter(|(_, s)| *s == ProbeStatus::Ok).count() as u32;
    let ping_ok = targets.iter().filter(|t| t.ping.is_some()).count() as u32;
    (groups, score, ok_probes, ping_ok)
}

/// Best strategy: most fully-working groups, then most passing probes, then most pings.
pub fn best_standard(results: &[StrategyResult]) -> Option<&StrategyResult> {
    results
        .iter()
        .filter(|r| r.state == ResultState::Done)
        .max_by_key(|r| (r.score, r.ok_probes, r.ping_ok, std::cmp::Reverse(r.name.len())))
        .filter(|r| r.ok_probes > 0)
}

/// Best strategy for DPI runs: most OK lines, fewest "likely blocked".
pub fn best_dpi(results: &[StrategyResult]) -> Option<&StrategyResult> {
    results
        .iter()
        .filter(|r| r.state == ResultState::Done)
        .max_by_key(|r| (r.dpi_ok, std::cmp::Reverse(r.dpi_blocked)))
        .filter(|r| r.dpi_ok > 0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestKind {
    Standard,
    Dpi,
    /// Smart search: builds a strategy for this connection (see [`TestRunner::start_smart`]).
    Smart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Running,
    Finished,
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct Progress {
    pub phase: Phase,
    pub kind: TestKind,
    pub total: usize,
    pub done: usize,
    pub current: Option<String>,
    pub started: Option<Instant>,
    pub finished_after: Option<Duration>,
    pub results: Vec<StrategyResult>,
    pub best: Option<String>,
    pub error: Option<String>,
    pub results_file: Option<std::path::PathBuf>,
    /// Smart search: current stage, e.g. `(2, 3)`.
    pub stage: Option<(u8, u8)>,
    /// Smart search: the strategy it settled on.
    pub winner: Option<Strategy>,
}

impl Progress {
    fn idle() -> Self {
        Self {
            phase: Phase::Idle,
            kind: TestKind::Standard,
            total: 0,
            done: 0,
            current: None,
            started: None,
            finished_after: None,
            results: Vec::new(),
            best: None,
            error: None,
            results_file: None,
            stage: None,
            winner: None,
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.finished_after.or_else(|| self.started.map(|s| s.elapsed())).unwrap_or_default()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TestError {
    #[error("A test run is already in progress.")]
    Busy,
    #[error("Administrator rights are required to run strategy tests.")]
    NotElevated,
    #[error("The Windows service \"zapret\" is installed. Remove it before running tests.")]
    ServiceInstalled,
    #[error("No strategies selected.")]
    NothingSelected,
}

// ───────────────────────────── runner ─────────────────────────────

pub struct TestRunner {
    engine: Arc<Engine>,
    paths: Paths,
    tx: watch::Sender<Progress>,
    cancel: Mutex<Option<CancellationToken>>,
}

impl TestRunner {
    pub fn new(engine: Arc<Engine>, paths: Paths) -> Arc<Self> {
        let (tx, _) = watch::channel(Progress::idle());
        Arc::new(Self { engine, paths, tx, cancel: Mutex::new(None) })
    }

    pub fn subscribe(&self) -> watch::Receiver<Progress> {
        self.tx.subscribe()
    }

    pub fn progress(&self) -> Progress {
        self.tx.borrow().clone()
    }

    pub async fn cancel(&self) {
        if let Some(t) = self.cancel.lock().await.as_ref() {
            t.cancel();
        }
    }

    /// Checks that a run may start and claims the runner.
    async fn begin(&self, kind: TestKind, names: &[String]) -> Result<CancellationToken, TestError> {
        let mut slot = self.cancel.lock().await;
        if self.tx.borrow().phase == Phase::Running {
            return Err(TestError::Busy);
        }
        if !heli_core::elevation::is_elevated() {
            return Err(TestError::NotElevated);
        }
        if !matches!(scm::query(SERVICE_NAME), Ok(ServiceState::NotInstalled)) {
            return Err(TestError::ServiceInstalled);
        }
        let token = CancellationToken::new();
        *slot = Some(token.clone());
        drop(slot);
        self.tx.send_replace(Progress {
            phase: Phase::Running,
            kind,
            total: names.len(),
            started: Some(Instant::now()),
            results: names.iter().map(|n| StrategyResult::pending(n)).collect(),
            ..Progress::idle()
        });
        Ok(token)
    }

    pub async fn start(self: &Arc<Self>, kind: TestKind, strategies: Vec<Strategy>, game: GameFilter, services: Vec<Service>) -> Result<(), TestError> {
        if strategies.is_empty() {
            return Err(TestError::NothingSelected);
        }
        let names: Vec<String> = strategies.iter().map(|s| s.name.clone()).collect();
        let token = self.begin(kind, &names).await?;
        let this = Arc::clone(self);
        tokio::spawn(async move { this.run(kind, strategies, game, services, token).await });
        Ok(())
    }

    /// Smart search (BETA). Builds a strategy for this connection in three stages:
    /// 1. screening: the base strategy with the web settings of every upstream strategy, quick checks;
    /// 2. refining: the three best, plus variations of them, with every check (long transfers,
    ///    Discord's gateway and media ports, the user's services);
    /// 3. confirming: the two best are tested once more, so a lucky single run does not win.
    ///
    /// Ties go to the gentler strategy (fewer fake packets, less fragmentation), which is both
    /// kinder to long connections and less conspicuous to the censor. The result is in
    /// `Progress::winner`.
    pub async fn start_smart(self: &Arc<Self>, base: Strategy, pool: Vec<Strategy>, game: GameFilter, services: Vec<Service>) -> Result<(), TestError> {
        if crate::builder::web_recipe(&base).is_none() {
            return Err(TestError::NothingSelected);
        }
        let token = self.begin(TestKind::Smart, &[]).await?;
        let this = Arc::clone(self);
        tokio::spawn(async move { this.run_smart(base, pool, game, services, token).await });
        Ok(())
    }

    /// Start `strategy`, run the checks, stop it. Returns `None` when cancelled.
    async fn test_one(&self, idx: usize, strategy: &Strategy, game: &GameFilter, targets: &[Target], quick: bool, cancel: &CancellationToken) -> Option<StrategyResult> {
        self.tx.send_modify(|p| {
            p.current = Some(strategy.name.clone());
            p.results[idx].state = ResultState::Running;
        });
        match self.engine.start(strategy, game).await {
            Err(e) => {
                let msg = e.to_string();
                self.tx.send_modify(|p| p.results[idx].state = ResultState::Failed(msg));
            }
            Ok(()) => {
                tokio::time::sleep(Duration::from_millis(400)).await;
                let res = tokio::select! {
                    _ = cancel.cancelled() => None,
                    r = run_targets(targets, quick) => Some(r),
                };
                self.engine.stop().await;
                let r = res?;
                self.tx.send_modify(|p| p.results[idx].apply_standard(r));
            }
        }
        let out = self.tx.borrow().results[idx].clone();
        Some(out)
    }

    fn add_rows(&self, names: &[String], expected_total: usize) -> usize {
        let mut first = 0;
        self.tx.send_modify(|p| {
            first = p.results.len();
            p.results.extend(names.iter().map(|n| StrategyResult::pending(n)));
            p.total = expected_total.max(p.results.len());
        });
        first
    }

    async fn run_smart(self: Arc<Self>, base: Strategy, pool: Vec<Strategy>, game: GameFilter, services: Vec<Service>, cancel: CancellationToken) {
        use crate::builder;
        self.engine.stop().await;
        let full = targets_for(&services);
        let quick_targets = quick(&full);
        let rank = |s: &Strategy, r: &StrategyResult| (r.score, r.ok_probes, std::cmp::Reverse(builder::footprint(s)), r.throughput as u64);
        let usable = |r: &StrategyResult| r.state == ResultState::Done && r.ok_probes > 0;
        let mut cancelled = false;
        let mut done = 0usize;

        // ── stage 1: screening ──
        let stage1 = builder::candidates(&base, &pool);
        let est_total = stage1.len() + 3 + builder::REFINE_LIMIT + 2;
        let names: Vec<String> = stage1.iter().map(|c| format!("1 · {}", c.name)).collect();
        let first = self.add_rows(&names, est_total);
        self.tx.send_modify(|p| p.stage = Some((1, 3)));
        let mut screened: Vec<(Strategy, StrategyResult)> = Vec::new();
        for (i, c) in stage1.iter().enumerate() {
            if cancel.is_cancelled() {
                cancelled = true;
                break;
            }
            match self.test_one(first + i, c, &game, &quick_targets, true, &cancel).await {
                Some(r) => screened.push((c.clone(), r)),
                None => {
                    cancelled = true;
                    break;
                }
            }
            done += 1;
            self.tx.send_modify(|p| p.done = done);
        }

        // ── stage 2: refining ──
        let mut refined: Vec<(Strategy, StrategyResult)> = Vec::new();
        if !cancelled {
            screened.sort_by(|a, b| rank(&b.0, &b.1).cmp(&rank(&a.0, &a.1)));
            let top: Vec<Strategy> = screened.iter().filter(|(_, r)| usable(r)).take(3).map(|(s, _)| s.clone()).collect();
            let tested: Vec<Vec<String>> = stage1.iter().map(|s| s.template().to_vec()).collect();
            let mut stage2 = top.clone();
            stage2.extend(builder::refine(&top, &tested, stage1.len()));
            let names: Vec<String> = stage2.iter().map(|c| format!("2 · {}", c.name)).collect();
            let first = self.add_rows(&names, done + stage2.len() + 2);
            self.tx.send_modify(|p| p.stage = Some((2, 3)));
            for (i, c) in stage2.iter().enumerate() {
                if cancel.is_cancelled() {
                    cancelled = true;
                    break;
                }
                match self.test_one(first + i, c, &game, &full, false, &cancel).await {
                    Some(r) => refined.push((c.clone(), r)),
                    None => {
                        cancelled = true;
                        break;
                    }
                }
                done += 1;
                self.tx.send_modify(|p| p.done = done);
            }
        }

        // ── stage 3: confirming ──
        let mut winner: Option<(Strategy, String)> = None;
        if !cancelled {
            refined.sort_by(|a, b| rank(&b.0, &b.1).cmp(&rank(&a.0, &a.1)));
            let finalists: Vec<(Strategy, StrategyResult)> = refined.iter().filter(|(_, r)| usable(r)).take(2).cloned().collect();
            let names: Vec<String> = finalists.iter().map(|(c, _)| format!("3 · {}", c.name)).collect();
            let first = self.add_rows(&names, done + finalists.len());
            self.tx.send_modify(|p| p.stage = Some((3, 3)));
            let mut best: Option<((u16, u32, std::cmp::Reverse<u32>, u64), Strategy, String)> = None;
            for (i, (c, earlier)) in finalists.iter().enumerate() {
                let Some(again) = self.test_one(first + i, c, &game, &full, false, &cancel).await else {
                    cancelled = true;
                    break;
                };
                done += 1;
                self.tx.send_modify(|p| p.done = done);
                // both runs count: a strategy that works only some of the time loses
                let key = (
                    u16::from(earlier.score) + u16::from(again.score),
                    earlier.ok_probes + again.ok_probes,
                    std::cmp::Reverse(builder::footprint(c)),
                    (earlier.throughput + again.throughput) as u64,
                );
                if best.as_ref().is_none_or(|(k, ..)| key > *k) {
                    best = Some((key, c.clone(), names[i].clone()));
                }
            }
            winner = best.map(|(_, s, row)| (s, row));
        }

        let file = if cancelled { None } else { write_results_file(&self.paths, TestKind::Standard, &self.tx.borrow().results) };
        self.tx.send_modify(|p| {
            p.phase = if cancelled { Phase::Cancelled } else { Phase::Finished };
            p.current = None;
            p.total = p.results.len();
            p.done = done;
            p.finished_after = p.started.map(|s| s.elapsed());
            p.best = winner.as_ref().map(|(_, row)| row.clone());
            p.winner = winner.as_ref().map(|(s, _)| s.clone());
            p.results_file = file;
        });
        activity::push(
            "tests",
            match (&winner, cancelled) {
                (_, true) => "smart build cancelled".to_owned(),
                (Some((s, _)), _) => format!("smart build: {done} runs · winner {}", s.name),
                (None, _) => format!("smart build: {done} runs · nothing worked"),
            },
        );
    }

    async fn run(self: Arc<Self>, kind: TestKind, strategies: Vec<Strategy>, game: GameFilter, services: Vec<Service>, cancel: CancellationToken) {
        let previous = self.engine.state();
        let previous_strategy = match &previous {
            EngineState::Running { strategy, .. } => Some(strategy.clone()),
            _ => None,
        };
        self.engine.stop().await;

        // DPI checks need every destination covered, so run with the IP filter set to "any".
        let guard = (kind == TestKind::Dpi).then(|| IpsetGuard::engage(&self.paths));

        let targets = targets_for(&services);
        let dpi_targets = if kind == TestKind::Dpi { fetch_dpi_targets().await } else { Vec::new() };
        let payload: Arc<Vec<u8>> = Arc::new({
            let mut p = vec![0u8; 64 * 1024];
            rand::fill(&mut p[..]);
            p
        });

        let total = strategies.len();
        let mut cancelled = false;
        for (idx, strategy) in strategies.iter().enumerate() {
            if cancel.is_cancelled() {
                cancelled = true;
                break;
            }
            self.tx.send_modify(|p| {
                p.current = Some(strategy.name.clone());
                p.results[idx].state = ResultState::Running;
            });

            match self.engine.start(strategy, &game).await {
                Err(e) => {
                    let msg = e.to_string();
                    self.tx.send_modify(|p| p.results[idx].state = ResultState::Failed(msg));
                }
                Ok(()) => {
                    tokio::time::sleep(Duration::from_millis(400)).await;
                    match kind {
                        TestKind::Standard | TestKind::Smart => {
                            let res = tokio::select! {
                                _ = cancel.cancelled() => None,
                                r = run_targets(&targets, false) => Some(r),
                            };
                            if let Some(r) = res {
                                self.tx.send_modify(|p| p.results[idx].apply_standard(r));
                            }
                        }
                        TestKind::Dpi => {
                            let res = tokio::select! {
                                _ = cancel.cancelled() => None,
                                r = run_dpi(&dpi_targets, &payload) => Some(r),
                            };
                            if let Some(r) = res {
                                self.tx.send_modify(|p| p.results[idx].apply_dpi(r));
                            }
                        }
                    }
                    self.engine.stop().await;
                }
            }
            self.tx.send_modify(|p| p.done = idx + 1);
        }

        drop(guard); // restore the IP filter mode
        if let Some(name) = previous_strategy {
            // put the bypass back the way the user had it
            if let Some(s) = strategies.iter().find(|s| s.name == name) {
                let _ = self.engine.start(s, &game).await;
            }
        }

        let file = if cancelled { None } else { write_results_file(&self.paths, kind, &self.tx.borrow().results) };
        self.tx.send_modify(|p| {
            p.phase = if cancelled { Phase::Cancelled } else { Phase::Finished };
            p.current = None;
            p.finished_after = p.started.map(|s| s.elapsed());
            p.best = match kind {
                TestKind::Standard | TestKind::Smart => best_standard(&p.results).map(|r| r.name.clone()),
                TestKind::Dpi => best_dpi(&p.results).map(|r| r.name.clone()),
            };
            p.results_file = file;
        });
        let best = self.tx.borrow().best.clone();
        activity::push(
            "tests",
            match (&best, cancelled) {
                (_, true) => "test run cancelled".to_owned(),
                (Some(b), _) => format!("{total} strategies checked · best: {b}"),
                (None, _) => format!("{total} strategies checked · none worked"),
            },
        );
    }
}

async fn run_targets(targets: &[Target], quick: bool) -> Vec<TargetResult> {
    let limit = Arc::new(Semaphore::new(std::thread::available_parallelism().map_or(8, |n| (n.get() * 2).clamp(8, 16))));
    let mut set = JoinSet::new();
    for (i, t) in targets.iter().cloned().enumerate() {
        let limit = Arc::clone(&limit);
        set.spawn(async move {
            let _permit = limit.acquire_owned().await.ok();
            let mut probes: Vec<(&'static str, ProbeStatus)> = Vec::new();
            let mut rate = None;
            if let Some(host) = &t.host {
                for check in &t.checks {
                    match check {
                        Check::Head => {
                            let all = [("HTTP", TlsVersions::Any), ("TLS1.2", TlsVersions::Tls12), ("TLS1.3", TlsVersions::Tls13)];
                            for (label, v) in if quick { &all[..1] } else { &all[..] } {
                                probes.push((label, http_probe(host, t.port, *v, Duration::from_secs(4)).await));
                            }
                        }
                        Check::Transfer { path, min_bytes } => {
                            let (st, r) = transfer_probe(host, t.port, path, *min_bytes, Duration::from_secs(if quick { 7 } else { 10 })).await;
                            probes.push(("BIG", st));
                            rate = r.or(rate);
                        }
                        Check::DiscordGateway => probes.push(("WS", discord_gateway_probe(3, Duration::from_secs(14)).await)),
                        Check::DiscordRtc { port } => {
                            let (st, ips) = discord_rtc_probe(*port, Duration::from_secs(6)).await;
                            let label = match port {
                                443 => "RTC",
                                8443 => "RTC:8443",
                                2053 => "RTC:2053",
                                _ => "RTC:other",
                            };
                            probes.push((label, st));
                            if *port == 443 && st == ProbeStatus::Ok && !ips.is_empty() {
                                // the voice servers themselves are reached by address
                                let mut voice = any_tcp_reachable(&ips, 443, Duration::from_secs(2)).await;
                                if voice != ProbeStatus::Ok && ping(&ips[0], Duration::from_secs(1)).await.is_some() {
                                    voice = ProbeStatus::Ok;
                                }
                                probes.push(("VOICE-IP", voice));
                            }
                        }
                    }
                }
            }
            let ping = if quick { None } else { ping(&t.ping_host, Duration::from_secs(1)).await };
            (i, TargetResult { key: t.key, group: t.group, probes, ping, rate })
        });
    }
    let mut out: Vec<(usize, TargetResult)> = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            out.push(r);
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

#[derive(Debug, Clone)]
pub struct DpiTarget {
    pub id: String,
    pub provider: String,
    pub country: String,
    pub host: String,
}

/// The community "DPI checkers" suite (https://github.com/hyperion-cs/dpi-checkers, Apache-2.0).
pub async fn fetch_dpi_targets() -> Vec<DpiTarget> {
    let Ok(resp) = heli_core::http::get(DPI_SUITE_URL).await.and_then(|r| r.ok()) else { return Vec::new() };
    parse_dpi_suite(&resp.text())
}

pub fn parse_dpi_suite(json: &str) -> Vec<DpiTarget> {
    let Ok(serde_json::Value::Array(items)) = serde_json::from_str::<serde_json::Value>(json) else { return Vec::new() };
    items
        .iter()
        .filter_map(|v| {
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(str::to_owned);
            Some(DpiTarget { id: s("id")?, provider: s("provider").unwrap_or_default(), country: s("country").unwrap_or_default(), host: s("host")? })
        })
        .collect()
}

async fn run_dpi(targets: &[DpiTarget], payload: &Arc<Vec<u8>>) -> Vec<DpiTargetResult> {
    let limit = Arc::new(Semaphore::new(std::thread::available_parallelism().map_or(8, |n| (n.get() * 2).clamp(8, 16))));
    let mut set = JoinSet::new();
    for (i, t) in targets.iter().cloned().enumerate() {
        let limit = Arc::clone(&limit);
        let payload = Arc::clone(payload);
        set.spawn(async move {
            let _permit = limit.acquire_owned().await.ok();
            let mut lines = Vec::new();
            for (label, v) in [("HTTP", TlsVersions::Any), ("TLS1.2", TlsVersions::Tls12), ("TLS1.3", TlsVersions::Tls13)] {
                lines.push(dpi_probe(&t.host, label, v, &payload, Duration::from_secs(5)).await);
            }
            (i, DpiTargetResult { id: t.id, provider: t.provider, country: t.country, lines })
        });
    }
    let mut out = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(r) = r {
            out.push(r);
        }
    }
    out.sort_by_key(|(i, _)| *i);
    out.into_iter().map(|(_, r)| r).collect()
}

// ───────────────────────────── ipset guard ─────────────────────────────

/// Switches the IPSet filter to `any` for the duration of a DPI run and restores it afterwards.
/// A flag file survives a crash so [`recover_interrupted`] can restore it on the next start.
struct IpsetGuard {
    paths: Paths,
    original: IpsetMode,
}

fn flag_file(paths: &Paths) -> std::path::PathBuf {
    paths.zapret_dir().join("ipset_switched.flag")
}

impl IpsetGuard {
    fn engage(paths: &Paths) -> Self {
        let original = ipset_mode(paths);
        if original != IpsetMode::Any {
            let _ = std::fs::write(flag_file(paths), original.label());
            let _ = set_ipset_mode(paths, IpsetMode::Any);
        }
        Self { paths: paths.clone(), original }
    }
}

impl Drop for IpsetGuard {
    fn drop(&mut self) {
        if self.original != IpsetMode::Any {
            let _ = set_ipset_mode(&self.paths, self.original);
            let _ = std::fs::remove_file(flag_file(&self.paths));
        }
    }
}

/// Restore the IPSet mode if a previous DPI run was interrupted (call at startup).
pub fn recover_interrupted(paths: &Paths) -> Option<IpsetMode> {
    let text = std::fs::read_to_string(flag_file(paths)).ok()?;
    let mode = match text.trim() {
        "loaded" => IpsetMode::Loaded,
        "none" => IpsetMode::None,
        _ => return None,
    };
    let _ = set_ipset_mode(paths, mode);
    let _ = std::fs::remove_file(flag_file(paths));
    Some(mode)
}

// ───────────────────────────── result files ─────────────────────────────

fn write_results_file(paths: &Paths, kind: TestKind, results: &[StrategyResult]) -> Option<std::path::PathBuf> {
    let dir = paths.test_results_dir();
    std::fs::create_dir_all(&dir).ok()?;
    let stamp = {
        // seconds since epoch keeps the file name unique and sortable without a date library
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    };
    let path = dir.join(format!("test_results_{stamp}.txt"));
    std::fs::write(&path, render_results(kind, results)).ok()?;
    Some(path)
}

pub fn render_results(kind: TestKind, results: &[StrategyResult]) -> String {
    let mut out = String::new();
    for r in results {
        out.push_str(&format!("Config: {}.bat (Type: {})\n", r.name, if kind == TestKind::Dpi { "dpi" } else { "standard" }));
        match &r.state {
            ResultState::Failed(msg) => out.push_str(&format!("  failed to start: {}\n", msg.lines().next().unwrap_or(""))),
            ResultState::Done if kind == TestKind::Standard => {
                for t in &r.targets {
                    let probes: Vec<String> = t.probes.iter().map(|(l, s)| format!("{l}:{}", s.label())).collect();
                    let ping = t.ping.map_or("Timeout".to_owned(), |d| format!("{} ms", d.as_millis()));
                    out.push_str(&format!("  {} : {} | Ping: {ping}\n", t.key, probes.join(" ")));
                }
            }
            ResultState::Done => {
                for t in &r.dpi {
                    out.push_str(&format!("  Target: [{}] {} ({})\n", t.country, t.id, t.provider));
                    for l in &t.lines {
                        out.push_str(&format!(
                            "    {}: up={:.1} KB  down={:.1} KB  time={:.2}s  status={:?}\n",
                            l.label,
                            l.up_bytes as f64 / 1024.0,
                            l.down_bytes as f64 / 1024.0,
                            l.seconds,
                            l.status
                        ));
                    }
                }
            }
            _ => out.push_str("  not run\n"),
        }
        out.push('\n');
    }
    out.push_str("=== ANALYTICS ===\n");
    for r in results.iter().filter(|r| r.state == ResultState::Done) {
        if kind == TestKind::Standard {
            out.push_str(&format!(
                "{} : groups OK: {}/{}, checks OK: {}, Ping OK: {}, speed: {:.0} KB/s\n",
                r.name,
                r.score,
                r.groups_tested,
                r.ok_probes,
                r.ping_ok,
                r.throughput / 1024.0
            ));
        } else {
            out.push_str(&format!("{} : OK: {}, BLOCKED: {}\n", r.name, r.dpi_ok, r.dpi_blocked));
        }
    }
    let best = if kind == TestKind::Standard { best_standard(results) } else { best_dpi(results) };
    out.push_str(&format!("Best strategy: {}\n", best.map_or("none", |b| b.name.as_str())));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr(key: &str, group: Option<Group>, st: [ProbeStatus; 3], ping: bool) -> TargetResult {
        TargetResult {
            key: key.into(),
            group,
            probes: vec![("HTTP", st[0]), ("TLS1.2", st[1]), ("TLS1.3", st[2])],
            ping: ping.then(|| Duration::from_millis(30)),
            rate: None,
        }
    }

    #[test]
    fn builtin_targets_skip_telegram_and_cover_long_connections() {
        let t = builtin_targets();
        assert!(t.iter().all(|x| !x.key.to_ascii_lowercase().contains("telegram")));
        assert!(t.iter().any(|x| x.checks.contains(&Check::DiscordGateway)));
        assert!(t.iter().any(|x| x.checks.contains(&Check::DiscordRtc { port: 8443 })));
        assert!(t.iter().filter(|x| x.checks.iter().any(|c| matches!(c, Check::Transfer { .. }))).count() >= 3);
        // quick mode keeps one negotiation per site and drops the slow gateway session
        let q = quick(&t);
        assert!(q.iter().all(|x| !x.checks.contains(&Check::DiscordGateway) && x.host.is_some()));
    }

    #[test]
    fn user_services_become_custom_targets() {
        let s = |n: &str, u: &str| Service { name: n.into(), url: u.into() };
        let t = service_target(&s("My site", "https://example.org:8443/big/file.bin")).unwrap();
        assert_eq!((t.key.as_str(), t.host.as_deref(), t.port, t.group), ("Mysite", Some("example.org"), 8443, Some(Group::Custom)));
        assert!(t.checks.contains(&Check::Transfer { path: "/big/file.bin".into(), min_bytes: 64 * 1024 }));
        assert_eq!(service_target(&s("x", "https://example.org")).unwrap().checks[1], Check::Transfer { path: "/".into(), min_bytes: 64 * 1024 });
        assert!(service_target(&s("x", "http://example.org")).is_none(), "only https");
        assert!(service_target(&s("x", "https://bad host/")).is_none());
        assert_eq!(targets_for(&[s("a", "https://a.example")]).len(), builtin_targets().len() + 1);
    }

    #[test]
    fn scoring_matches_the_design_table() {
        use ProbeStatus::*;
        let all_ok = [Ok, Ok, Ok];
        // Discord ok, YouTube ok, Cloudflare partial (one probe fails), own service ok -> 3/4
        let results = vec![
            tr("D1", Some(Group::Discord), all_ok, true),
            tr("Y1", Some(Group::YouTube), all_ok, true),
            tr("C1", Some(Group::Cloudflare), [Ok, Error, Ok], true),
            tr("U1", Some(Group::Custom), all_ok, true),
            tr("DNS", None, [Ok, Ok, Ok], false),
        ];
        let (groups, score, ok, ping) = summarize_standard(&results);
        assert_eq!(groups, [GroupStatus::Ok, GroupStatus::Ok, GroupStatus::Partial, GroupStatus::Ok]);
        assert_eq!(score, 3);
        assert_eq!(ok, 14);
        assert_eq!(ping, 4);

        // a fully failing group and "unsupported" probes being neutral
        let results = vec![
            tr("D1", Some(Group::Discord), [Error, Error, Error], false),
            tr("Y1", Some(Group::YouTube), [Ok, Ok, Unsupported], true),
        ];
        let (groups, score, _, _) = summarize_standard(&results);
        assert_eq!(groups[0], GroupStatus::Fail);
        assert_eq!(groups[1], GroupStatus::Ok);
        assert_eq!(groups[2], GroupStatus::NotTested, "no Cloudflare targets");
        assert_eq!(groups[3], GroupStatus::NotTested, "no services of your own");
        assert_eq!(score, 1);
    }

    #[test]
    fn best_strategy_prefers_score_then_probes_then_pings() {
        use ProbeStatus::*;
        let make = |name: &str, results: Vec<TargetResult>| {
            let mut r = StrategyResult::pending(name);
            r.apply_standard(results);
            r
        };
        let a = make("a", vec![tr("D", Some(Group::Discord), [Ok, Ok, Ok], true), tr("Y", Some(Group::YouTube), [Error; 3], true)]);
        let b = make("b", vec![tr("D", Some(Group::Discord), [Ok, Ok, Ok], true), tr("Y", Some(Group::YouTube), [Ok, Ok, Ok], false)]);
        let failed = StrategyResult { state: ResultState::Failed("x".into()), ..StrategyResult::pending("c") };
        assert_eq!(best_standard(&[a.clone(), b.clone(), failed]).unwrap().name, "b");
        let none_working = make("n", vec![tr("D", Some(Group::Discord), [Error; 3], false)]);
        assert!(best_standard(&[none_working]).is_none());
    }

    #[test]
    fn dpi_suite_json_is_parsed() {
        let json = r#"[{"id":"US.CF-01","provider":"Cloudflare","country":"US","host":"cdn.example.com","extra":1},{"id":"bad"}]"#;
        let t = parse_dpi_suite(json);
        assert_eq!(t.len(), 1);
        assert_eq!((t[0].host.as_str(), t[0].provider.as_str()), ("cdn.example.com", "Cloudflare"));
        assert!(parse_dpi_suite("not json").is_empty());
    }

    #[test]
    fn ipset_guard_restores_and_recovers_after_crash() {
        let paths = Paths::at(std::env::temp_dir().join(format!("heli-tester-{}", std::process::id())));
        crate::bundle::install(&paths).unwrap();
        let full = paths.lists_dir().join("ipset-all.txt.backup");
        std::fs::copy(&full, paths.lists_dir().join("ipset-all.txt")).unwrap();
        assert_eq!(ipset_mode(&paths), IpsetMode::Loaded);
        {
            let _g = IpsetGuard::engage(&paths);
            assert_eq!(ipset_mode(&paths), IpsetMode::Any);
            assert!(flag_file(&paths).exists());
        }
        assert_eq!(ipset_mode(&paths), IpsetMode::Loaded);
        assert!(!flag_file(&paths).exists());

        // simulate a crash: guard leaked, flag file left behind
        std::mem::forget(IpsetGuard::engage(&paths));
        assert_eq!(ipset_mode(&paths), IpsetMode::Any);
        assert_eq!(recover_interrupted(&paths), Some(IpsetMode::Loaded));
        assert_eq!(ipset_mode(&paths), IpsetMode::Loaded);
        std::fs::remove_dir_all(paths.root()).unwrap();
    }

    #[test]
    fn results_file_has_upstream_shape() {
        use ProbeStatus::*;
        let mut r = StrategyResult::pending("general (ALT)");
        r.apply_standard(vec![tr("DiscordMain", Some(Group::Discord), [Ok, Ok, Unsupported], true)]);
        let text = render_results(TestKind::Standard, &[r]);
        assert!(text.contains("Config: general (ALT).bat (Type: standard)"));
        assert!(text.contains("DiscordMain : HTTP:OK TLS1.2:OK TLS1.3:UNSUP | Ping: 30 ms"));
        assert!(text.contains("Best strategy: general (ALT)"));
    }
}
