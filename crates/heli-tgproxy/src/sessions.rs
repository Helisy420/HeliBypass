//! Live registry of the client sessions a running proxy carries, for the UI's speed dashboard.
//!
//! Each session gets a [`Meter`]: the bridge loops add the bytes they move to it (one relaxed
//! atomic add per chunk, the same cost as the global counters), and the session removes itself
//! from the registry when its guard is dropped.

use std::collections::HashMap;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicU8, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// How a session reaches Telegram.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Route {
    /// Still choosing a route.
    Connecting = 0,
    /// Pooled WebSocket straight to Telegram's gateway.
    Direct = 1,
    /// WebSocket through a Cloudflare-proxied domain.
    Cloudflare = 2,
    /// WebSocket through a user's Cloudflare Worker.
    Worker = 3,
    /// Plain TCP to the data center (last resort).
    Tcp = 4,
    /// HTTP/2 media multiplexing through Cloudflare (BETA).
    H2 = 5,
}

impl Route {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Route::Direct,
            2 => Route::Cloudflare,
            3 => Route::Worker,
            4 => Route::Tcp,
            5 => Route::H2,
            _ => Route::Connecting,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Route::Connecting => "Connecting",
            Route::Direct => "Direct",
            Route::Cloudflare => "Cloudflare",
            Route::Worker => "CF Worker",
            Route::Tcp => "TCP",
            Route::H2 => "HTTP/2",
        }
    }
}

/// Byte counters of one session.
pub struct Meter {
    pub dc: u32,
    pub media: bool,
    pub started: Instant,
    route: AtomicU8,
    up: AtomicU64,
    down: AtomicU64,
}

impl Meter {
    pub fn set_route(&self, route: Route) {
        self.route.store(route as u8, Relaxed);
    }
    pub fn route(&self) -> Route {
        Route::from_u8(self.route.load(Relaxed))
    }
    #[inline]
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Relaxed);
    }
    #[inline]
    pub fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Relaxed);
    }
}

/// A point-in-time copy of one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: u64,
    pub dc: u32,
    pub media: bool,
    pub route: Route,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub started: Instant,
}

#[derive(Default)]
pub struct Sessions {
    next_id: AtomicU64,
    live: Mutex<HashMap<u64, Arc<Meter>>>,
}

impl Sessions {
    /// Register a session; it stays listed until the returned guard is dropped.
    pub fn open(self: &Arc<Self>, dc: u32, media: bool) -> SessionGuard {
        let id = self.next_id.fetch_add(1, Relaxed) + 1;
        let meter = Arc::new(Meter {
            dc,
            media,
            started: Instant::now(),
            route: AtomicU8::new(Route::Connecting as u8),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
        });
        self.live.lock().unwrap_or_else(|e| e.into_inner()).insert(id, Arc::clone(&meter));
        SessionGuard { id, sessions: Arc::clone(self), meter }
    }

    pub fn snapshot(&self) -> Vec<SessionInfo> {
        let live = self.live.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<SessionInfo> = live
            .iter()
            .map(|(id, m)| SessionInfo {
                id: *id,
                dc: m.dc,
                media: m.media,
                route: m.route(),
                bytes_up: m.up.load(Relaxed),
                bytes_down: m.down.load(Relaxed),
                started: m.started,
            })
            .collect();
        out.sort_by_key(|s| s.id);
        out
    }
}

pub struct SessionGuard {
    id: u64,
    sessions: Arc<Sessions>,
    meter: Arc<Meter>,
}

impl SessionGuard {
    pub fn meter(&self) -> &Meter {
        &self.meter
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.sessions.live.lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_are_listed_until_dropped() {
        let s = Arc::new(Sessions::default());
        let a = s.open(2, false);
        let b = s.open(5, true);
        a.meter().set_route(Route::Direct);
        a.meter().add_down(1000);
        b.meter().add_up(7);
        let snap = s.snapshot();
        assert_eq!(snap.len(), 2);
        assert_eq!((snap[0].dc, snap[0].route, snap[0].bytes_down), (2, Route::Direct, 1000));
        assert_eq!((snap[1].media, snap[1].route, snap[1].bytes_up), (true, Route::Connecting, 7));
        drop(a);
        assert_eq!(s.snapshot().len(), 1);
    }
}
