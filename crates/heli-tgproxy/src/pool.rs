//! Warm WebSocket connections to Telegram's gateways.
//!
//! Opening a TLS+WebSocket connection costs several round trips; Telegram clients open a lot
//! of short sessions. The pool keeps a few ready connections per (DC, media, test) so a new
//! client session starts instantly, and refills in the background with exponential back-off.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::ProxyConfig;
use crate::consts::{FRONTING_SNI, WS_PATH, WS_PATH_TEST, ws_domains};
use crate::stats::Stats;
use crate::ws::{ConnectOpts, WsConn};

const MAX_AGE: Duration = Duration::from_secs(120);
const CHECK_INTERVAL: Duration = Duration::from_secs(5);
const BACKOFF_INITIAL: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// (dc, is_media, is_test)
type Key = (u32, bool, bool);

#[derive(Default)]
struct Bucket {
    idle: VecDeque<(WsConn, Instant)>,
    refilling: bool,
    rotating: bool,
    failures: u32,
    refill_after: Option<Instant>,
}

#[derive(Default)]
struct State {
    buckets: HashMap<Key, Bucket>,
    try_fronting_first: bool,
}

struct Inner {
    cfg: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    cancel: CancellationToken,
    state: Mutex<State>,
}

#[derive(Clone)]
pub struct WsPool(Arc<Inner>);

impl WsPool {
    pub fn new(cfg: Arc<ProxyConfig>, stats: Arc<Stats>, cancel: CancellationToken) -> Self {
        Self(Arc::new(Inner { cfg, stats, cancel, state: Mutex::new(State::default()) }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Take a ready connection for `(dc, is_media)` if one is available.
    pub fn get(&self, dc: u32, is_media: bool, is_test: bool) -> Option<WsConn> {
        let cfg = &self.0.cfg;
        let ip = cfg.dc_redirects.get(&dc)?;
        if cfg.pool_size == 0 {
            return None;
        }
        let key = (dc, is_media, is_test);
        let ip = ip.to_string();
        let now = Instant::now();

        let mut taken = None;
        {
            let mut st = self.lock();
            let bucket = st.buckets.entry(key).or_default();
            while let Some((mut ws, created)) = bucket.idle.pop_front() {
                if now.duration_since(created) >= MAX_AGE || !ws.is_alive() {
                    continue; // dropping closes the socket
                }
                taken = Some(ws);
                break;
            }
        }
        match &taken {
            Some(_) => self.0.stats.pool_hits.fetch_add(1, Relaxed),
            None => self.0.stats.pool_misses.fetch_add(1, Relaxed),
        };
        self.schedule_refill(key, ip);
        taken
    }

    /// A new direct connection for a session that found the pool empty. Telegram opens many
    /// connections at once (several downloads, media, the main session); without this, every
    /// session beyond the pool size would take the slower Cloudflare route although the direct
    /// gateway works. Skipped while the gateway is failing (the refill is backing off), so a
    /// blocked gateway does not delay the fallback.
    pub async fn connect_fresh(&self, dc: u32, is_media: bool, is_test: bool) -> Option<WsConn> {
        if self.0.cfg.pool_size == 0 {
            return None; // 0 disables the direct route altogether
        }
        let ip = self.0.cfg.dc_redirects.get(&dc)?.to_string();
        let backing_off = {
            let st = self.lock();
            st.buckets.get(&(dc, is_media, is_test)).is_some_and(|b| b.refill_after.is_some_and(|t| Instant::now() < t))
        };
        if backing_off || self.0.cancel.is_cancelled() {
            return None;
        }
        let ws = tokio::time::timeout(Duration::from_secs(6), self.connect_one(&ip, dc, is_media, is_test)).await.ok().flatten();
        if ws.is_some() {
            self.0.stats.pool_fresh.fetch_add(1, Relaxed);
        }
        ws
    }

    /// Start filling the pool for every configured DC (called once after startup).
    pub fn warmup(&self) {
        let cfg = &self.0.cfg;
        for (dc, ip) in &cfg.dc_redirects {
            for is_media in [false, true] {
                self.schedule_refill((*dc, is_media, cfg.force_test_dc), ip.to_string());
            }
        }
        tracing::info!("WS pool warmup started for {} DC(s)", cfg.dc_redirects.len());
    }

    fn schedule_refill(&self, key: Key, ip: String) {
        if self.0.cfg.pool_size == 0 || self.0.cancel.is_cancelled() {
            return;
        }
        let (start_rotation, start_refill) = {
            let mut st = self.lock();
            let b = st.buckets.entry(key).or_default();
            let rotation = !b.rotating;
            b.rotating = true;
            let backing_off = b.refill_after.is_some_and(|t| Instant::now() < t);
            let refill = !b.refilling && !backing_off;
            if refill {
                b.refilling = true;
            }
            (rotation, refill)
        };
        if start_rotation {
            tokio::spawn(self.clone().rotate(key, ip.clone()));
        }
        if start_refill {
            tokio::spawn(self.clone().refill(key, ip));
        }
    }

    async fn refill(self, key: Key, ip: String) {
        let (dc, is_media, is_test) = key;
        let needed = {
            let st = self.lock();
            let have = st.buckets.get(&key).map_or(0, |b| b.idle.len());
            self.0.cfg.pool_size.saturating_sub(have)
        };
        let mut connected = 0usize;
        if needed > 0 {
            let mut set = JoinSet::new();
            for _ in 0..needed {
                let pool = self.clone();
                let ip = ip.clone();
                set.spawn(async move { pool.connect_one(&ip, dc, is_media, is_test).await });
            }
            loop {
                let next = tokio::select! {
                    _ = self.0.cancel.cancelled() => return,
                    n = set.join_next() => n,
                };
                match next {
                    None => break,
                    Some(Ok(Some(ws))) => {
                        let mut st = self.lock();
                        st.buckets.entry(key).or_default().idle.push_back((ws, Instant::now()));
                        connected += 1;
                    }
                    Some(_) => {}
                }
            }
        }

        let mut st = self.lock();
        let b = st.buckets.entry(key).or_default();
        b.refilling = false;
        if needed == 0 {
            return;
        }
        if connected > 0 {
            b.failures = 0;
            b.refill_after = None;
        } else {
            b.failures += 1;
            let delay = (BACKOFF_INITIAL * 2u32.pow((b.failures - 1).min(12))).min(BACKOFF_MAX);
            b.refill_after = Some(Instant::now() + delay);
            tracing::info!(
                "WS pool refill failed for DC{dc}{}{}, retry in {}s",
                if is_test { "t" } else { "" },
                if is_media { "m" } else { "" },
                delay.as_secs()
            );
        }
    }

    async fn connect_one(&self, ip: &str, dc: u32, is_media: bool, is_test: bool) -> Option<WsConn> {
        let path = if is_test { WS_PATH_TEST } else { WS_PATH };
        for domain in ws_domains(dc, is_media) {
            let fronting_first = self.lock().try_fronting_first;
            let modes = if fronting_first { [true, false] } else { [false, true] };
            for fronted in modes {
                let opts = ConnectOpts {
                    host: ip,
                    domain: &domain,
                    path,
                    timeout: Duration::from_secs(if fronted { 7 } else { 8 }),
                    sni: fronted.then_some(FRONTING_SNI),
                    secure: true,
                    buffer_size: self.0.cfg.buffer_size,
                };
                match WsConn::connect(&opts).await {
                    Ok(ws) => {
                        self.lock().try_fronting_first = fronted;
                        if fronted {
                            self.0.stats.connections_fronting.fetch_add(1, Relaxed);
                        }
                        tracing::debug!("WS pool connected {domain}{path} via {ip} (fronting={fronted})");
                        return Some(ws);
                    }
                    Err(e) => {
                        self.0.stats.ws_errors.fetch_add(1, Relaxed);
                        tracing::debug!("WS pool connect {domain}{path} via {ip} (fronting={fronted}): {e}");
                    }
                }
            }
        }
        None
    }

    /// Per-key housekeeping: drop expired/dead connections and trigger refills.
    async fn rotate(self, key: Key, ip: String) {
        loop {
            if self.0.cancel.is_cancelled() || self.0.cfg.pool_size == 0 {
                break;
            }
            let now = Instant::now();
            let (below_target, wake_at) = {
                let mut st = self.lock();
                let b = st.buckets.entry(key).or_default();
                let before = b.idle.len();
                b.idle.retain_mut(|(ws, created)| now.duration_since(*created) < MAX_AGE && ws.is_alive());
                if b.idle.len() != before {
                    tracing::debug!("WS pool rotated {key:?}: {} stale, {} ready", before - b.idle.len(), b.idle.len());
                }
                let mut wake = now + CHECK_INTERVAL;
                if let Some(oldest) = b.idle.iter().map(|(_, c)| *c + MAX_AGE).min() {
                    wake = wake.min(oldest);
                }
                if let Some(t) = b.refill_after.filter(|t| *t > now && !b.refilling) {
                    wake = wake.min(t);
                }
                (b.idle.len() < self.0.cfg.pool_size, wake)
            };
            if below_target {
                // `schedule_refill` re-checks the rotating flag, which is already set for us
                self.schedule_refill_only(key, ip.clone());
            }
            tokio::select! {
                _ = self.0.cancel.cancelled() => break,
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at.max(Instant::now()))) => {}
            }
        }
        self.lock().buckets.entry(key).or_default().rotating = false;
    }

    fn schedule_refill_only(&self, key: Key, ip: String) {
        let start = {
            let mut st = self.lock();
            let b = st.buckets.entry(key).or_default();
            let backing_off = b.refill_after.is_some_and(|t| Instant::now() < t);
            let start = !b.refilling && !backing_off;
            if start {
                b.refilling = true;
            }
            start
        };
        if start {
            tokio::spawn(self.clone().refill(key, ip));
        }
    }

    /// Close everything and stop background work.
    pub fn shutdown(&self) {
        self.0.cancel.cancel();
        self.lock().buckets.clear();
    }

    #[cfg(test)]
    pub fn idle_count(&self, key: Key) -> usize {
        self.lock().buckets.get(&key).map_or(0, |b| b.idle.len())
    }
}

/// Ready connections for the Cloudflare-proxied route (`kws{dc}.<domain>`), used for DCs that
/// have no direct gateway configured. A DC is only kept warm after a session has actually needed
/// it, so idle installs do not hold connections they never use. Telegram opens a fresh connection
/// for most file downloads; without a spare one each of them first pays TCP + TLS + WebSocket
/// round trips through Cloudflare.
#[derive(Default)]
pub struct CfRoutePool {
    idle: Mutex<HashMap<u32, VecDeque<(WsConn, Instant)>>>,
    refilling: Mutex<std::collections::HashSet<u32>>,
}

/// Cloudflare closes idle WebSockets after 100 s.
const CF_ROUTE_MAX_AGE: Duration = Duration::from_secs(80);
/// Spare connections kept per DC.
pub const CF_ROUTE_SPARES: usize = 2;

impl CfRoutePool {
    pub fn take(&self, dc: u32) -> Option<WsConn> {
        let now = Instant::now();
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = idle.get_mut(&dc)?;
        while let Some((mut ws, created)) = bucket.pop_front() {
            if now.duration_since(created) < CF_ROUTE_MAX_AGE && ws.is_alive() {
                return Some(ws);
            }
        }
        None
    }

    /// Spare connections still needed for `dc`, or `None` if a refill is already running.
    pub fn begin_refill(&self, dc: u32, target: usize) -> Option<usize> {
        if !self.refilling.lock().unwrap_or_else(|e| e.into_inner()).insert(dc) {
            return None;
        }
        let now = Instant::now();
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = idle.entry(dc).or_default();
        bucket.retain_mut(|(ws, created)| now.duration_since(*created) < CF_ROUTE_MAX_AGE && ws.is_alive());
        Some(target.saturating_sub(bucket.len()))
    }

    pub fn put(&self, dc: u32, ws: WsConn) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).entry(dc).or_default().push_back((ws, Instant::now()));
    }

    pub fn end_refill(&self, dc: u32) {
        self.refilling.lock().unwrap_or_else(|e| e.into_inner()).remove(&dc);
    }

    pub fn clear(&self) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// Connections to user-deployed Cloudflare Workers that relay to a data center.
pub struct CfWorkerPool {
    cfg: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    idle: Mutex<HashMap<u32, VecDeque<(WsConn, Instant, String)>>>,
    refilling: Mutex<std::collections::HashSet<u32>>,
}

const WORKER_MAX_AGE: Duration = Duration::from_secs(100);

impl CfWorkerPool {
    pub fn new(cfg: Arc<ProxyConfig>, stats: Arc<Stats>) -> Arc<Self> {
        Arc::new(Self { cfg, stats, idle: Mutex::new(HashMap::new()), refilling: Mutex::new(Default::default()) })
    }

    pub fn get(self: &Arc<Self>, dc: u32, fallback_dst: &str) -> Option<(WsConn, String)> {
        let now = Instant::now();
        let mut found = None;
        {
            let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
            let bucket = idle.entry(dc).or_default();
            while let Some((mut ws, created, domain)) = bucket.pop_front() {
                if now.duration_since(created) > WORKER_MAX_AGE || !ws.is_alive() {
                    continue;
                }
                found = Some((ws, domain));
                break;
            }
        }
        if found.is_some() {
            self.stats.cf_pool_hits.fetch_add(1, Relaxed);
            self.schedule_refill(dc, fallback_dst.to_owned());
        } else {
            self.stats.cf_pool_misses.fetch_add(1, Relaxed);
        }
        found
    }

    pub fn schedule_refill(self: &Arc<Self>, dc: u32, fallback_dst: String) {
        if !self.refilling.lock().unwrap_or_else(|e| e.into_inner()).insert(dc) {
            return;
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let have = this.idle.lock().unwrap_or_else(|e| e.into_inner()).get(&dc).map_or(0, |b| b.len());
            let target = this.cfg.pool_size.min(1);
            for _ in have..target {
                match this.connect_one(&fallback_dst, dc).await {
                    Some((ws, domain)) => this
                        .idle
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .entry(dc)
                        .or_default()
                        .push_back((ws, Instant::now(), domain)),
                    None => break,
                }
            }
            this.refilling.lock().unwrap_or_else(|e| e.into_inner()).remove(&dc);
        });
    }

    pub async fn connect_one(&self, fallback_dst: &str, dc: u32) -> Option<(WsConn, String)> {
        let path = format!("/apiws?dst={fallback_dst}&dc={dc}");
        let mut domains = self.cfg.cfproxy_worker_domains.clone();
        rand::seq::SliceRandom::shuffle(&mut domains[..], &mut rand::rng());
        for domain in domains {
            let opts = ConnectOpts {
                host: &domain,
                domain: &domain,
                path: &path,
                timeout: Duration::from_secs(8),
                sni: None,
                secure: !self.cfg.disable_secure,
                buffer_size: self.cfg.buffer_size,
            };
            match WsConn::connect(&opts).await {
                Ok(ws) => return Some((ws, domain)),
                Err(e) => tracing::debug!("CF worker {domain} failed: {e}"),
            }
        }
        None
    }

    pub fn warmup(self: &Arc<Self>) {
        if self.cfg.cfproxy_worker_domains.is_empty() {
            return;
        }
        let dcs: Vec<(u32, &str)> = crate::consts::DC_DEFAULT_IPS
            .iter()
            .copied()
            .filter(|(dc, _)| !self.cfg.dc_redirects.contains_key(dc))
            .collect();
        for (dc, ip) in &dcs {
            self.schedule_refill(*dc, (*ip).to_owned());
        }
        tracing::info!("CF worker pool warmup started for {} DC(s)", dcs.len());
    }

    pub fn clear(&self) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}
