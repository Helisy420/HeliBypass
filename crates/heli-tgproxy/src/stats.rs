//! Lock-free counters, readable from the UI while the proxy is running.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use crate::consts::human_bytes;

#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicU64,
    pub connections_active: AtomicU64,
    pub connections_ws: AtomicU64,
    pub connections_tcp_fallback: AtomicU64,
    pub connections_cfproxy: AtomicU64,
    pub connections_fronting: AtomicU64,
    pub connections_bad: AtomicU64,
    pub connections_masked: AtomicU64,
    pub ws_errors: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub pool_hits: AtomicU64,
    pub pool_misses: AtomicU64,
    pub cf_pool_hits: AtomicU64,
    pub cf_pool_misses: AtomicU64,
    pub connections_h2: AtomicU64,
    /// Sessions that found the pool empty and got a new direct connection.
    pub pool_fresh: AtomicU64,
    pub h2_requests: AtomicU64,
    pub h2_errors: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub connections_total: u64,
    pub connections_active: u64,
    pub connections_ws: u64,
    pub connections_tcp_fallback: u64,
    pub connections_cfproxy: u64,
    pub connections_fronting: u64,
    pub connections_bad: u64,
    pub connections_masked: u64,
    pub ws_errors: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub pool_hits: u64,
    pub pool_misses: u64,
    pub cf_pool_hits: u64,
    pub cf_pool_misses: u64,
    pub connections_h2: u64,
    pub pool_fresh: u64,
    pub h2_requests: u64,
    pub h2_errors: u64,
}

impl Stats {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            connections_total: self.connections_total.load(Relaxed),
            connections_active: self.connections_active.load(Relaxed),
            connections_ws: self.connections_ws.load(Relaxed),
            connections_tcp_fallback: self.connections_tcp_fallback.load(Relaxed),
            connections_cfproxy: self.connections_cfproxy.load(Relaxed),
            connections_fronting: self.connections_fronting.load(Relaxed),
            connections_bad: self.connections_bad.load(Relaxed),
            connections_masked: self.connections_masked.load(Relaxed),
            ws_errors: self.ws_errors.load(Relaxed),
            bytes_up: self.bytes_up.load(Relaxed),
            bytes_down: self.bytes_down.load(Relaxed),
            pool_hits: self.pool_hits.load(Relaxed),
            pool_misses: self.pool_misses.load(Relaxed),
            cf_pool_hits: self.cf_pool_hits.load(Relaxed),
            cf_pool_misses: self.cf_pool_misses.load(Relaxed),
            connections_h2: self.connections_h2.load(Relaxed),
            pool_fresh: self.pool_fresh.load(Relaxed),
            h2_requests: self.h2_requests.load(Relaxed),
            h2_errors: self.h2_errors.load(Relaxed),
        }
    }

    pub fn add(counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Relaxed);
    }

    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Relaxed);
    }

    pub fn dec(counter: &AtomicU64) {
        counter.fetch_sub(1, Relaxed);
    }
}

impl Snapshot {
    /// Same layout as the Python `stats.summary()` line.
    pub fn summary(&self) -> String {
        let ratio = |h: u64, m: u64| if h + m == 0 { "n/a".to_owned() } else { format!("{h}/{}", h + m) };
        format!(
            "total={} active={} ws={} fresh={} tcp_fb={} cf={} h2={} h2_req={} h2_err={} front={} bad={} masked={} err={} pool={} cf_pool={} up={} down={}",
            self.connections_total,
            self.connections_active,
            self.connections_ws,
            self.pool_fresh,
            self.connections_tcp_fallback,
            self.connections_cfproxy,
            self.connections_h2,
            self.h2_requests,
            self.h2_errors,
            self.connections_fronting,
            self.connections_bad,
            self.connections_masked,
            self.ws_errors,
            ratio(self.pool_hits, self.pool_misses),
            ratio(self.cf_pool_hits, self.cf_pool_misses),
            human_bytes(self.bytes_up),
            human_bytes(self.bytes_down),
        )
    }
}
