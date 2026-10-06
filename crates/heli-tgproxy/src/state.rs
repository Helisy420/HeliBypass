//! State shared by all client sessions of one running proxy instance.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::balancer::Balancer;
use crate::config::ProxyConfig;
use crate::pool::{CfRoutePool, CfWorkerPool, WsPool};
use crate::h2media::H2Pool;
use crate::ratelimit::RateLimit;
use crate::sessions::Sessions;
use crate::stats::Stats;

pub struct Shared {
    pub cfg: Arc<ProxyConfig>,
    pub stats: Arc<Stats>,
    pub pool: WsPool,
    pub cf_pool: Arc<CfWorkerPool>,
    pub cf_route: CfRoutePool,
    pub sessions: Arc<Sessions>,
    pub h2: H2Pool,
    pub down_limit: RateLimit,
    pub up_limit: RateLimit,
    pub balancer: Balancer,
    pub tcp_backoff: TcpBackoff,
    pub cancel: CancellationToken,
}

const TCP_BACKOFF_INITIAL: Duration = Duration::from_secs(30);
const TCP_BACKOFF_MAX: Duration = Duration::from_secs(3600);

/// Exponential back-off for the plain-TCP fallback so that a blocked DC address is not
/// hammered by every new session.
#[derive(Default)]
pub struct TcpBackoff {
    inner: Mutex<BackoffState>,
}

#[derive(Default)]
struct BackoffState {
    failures: HashMap<(String, u16), u32>,
    retry_after: HashMap<(String, u16), Instant>,
    connecting: HashSet<(String, u16)>,
}

impl TcpBackoff {
    /// `true` if the caller may attempt a connection now (and must call `done` afterwards).
    pub fn begin(&self, key: &(String, u16)) -> bool {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if s.connecting.contains(key) || s.retry_after.get(key).is_some_and(|t| Instant::now() < *t) {
            return false;
        }
        s.connecting.insert(key.clone());
        true
    }

    /// Record the outcome; returns the back-off delay when the attempt failed.
    pub fn done(&self, key: &(String, u16), ok: bool) -> Option<Duration> {
        let mut s = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        s.connecting.remove(key);
        if ok {
            s.failures.remove(key);
            s.retry_after.remove(key);
            return None;
        }
        let failures = s.failures.entry(key.clone()).or_insert(0);
        *failures += 1;
        let delay = (TCP_BACKOFF_INITIAL * 2u32.pow((*failures - 1).min(7))).min(TCP_BACKOFF_MAX);
        s.retry_after.insert(key.clone(), Instant::now() + delay);
        Some(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_resets() {
        let b = TcpBackoff::default();
        let k = ("149.154.167.51".to_owned(), 443);
        assert!(b.begin(&k));
        assert!(!b.begin(&k), "already connecting");
        assert_eq!(b.done(&k, false), Some(Duration::from_secs(30)));
        assert!(!b.begin(&k), "backing off");
        // pretend the delay elapsed
        b.inner.lock().unwrap().retry_after.clear();
        assert!(b.begin(&k));
        assert_eq!(b.done(&k, false), Some(Duration::from_secs(60)));
        b.inner.lock().unwrap().retry_after.clear();
        assert!(b.begin(&k));
        assert_eq!(b.done(&k, true), None);
        assert!(b.begin(&k));
    }
}
