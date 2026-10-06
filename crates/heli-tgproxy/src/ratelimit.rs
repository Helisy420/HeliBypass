//! A shared speed cap for all sessions of the proxy (token bucket). The rate can be changed
//! while the proxy runs; 0 means unlimited and costs one atomic load per chunk.

use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{Duration, Instant};

pub struct RateLimit {
    bytes_per_sec: AtomicU64,
    bucket: Mutex<(f64, Instant)>,
}

impl RateLimit {
    pub fn new(bytes_per_sec: u64) -> Self {
        Self { bytes_per_sec: AtomicU64::new(bytes_per_sec), bucket: Mutex::new((0.0, Instant::now())) }
    }

    pub fn set(&self, bytes_per_sec: u64) {
        self.bytes_per_sec.store(bytes_per_sec, Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.bytes_per_sec.load(Relaxed)
    }

    /// How long the caller must wait after moving `n` bytes. The bucket may go into debt, so a
    /// large chunk is let through at once and paid for by waiting afterwards.
    fn charge(&self, n: usize, now: Instant) -> Duration {
        let rate = self.bytes_per_sec.load(Relaxed);
        if rate == 0 {
            return Duration::ZERO;
        }
        let rate = rate as f64;
        // a fifth of a second of burst keeps short replies instant without exceeding the cap
        let burst = (rate * 0.2).max(64.0 * 1024.0);
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.saturating_duration_since(b.1).as_secs_f64();
        b.0 = (b.0 + elapsed * rate).min(burst) - n as f64;
        b.1 = now;
        if b.0 >= 0.0 { Duration::ZERO } else { Duration::from_secs_f64(-b.0 / rate) }
    }

    pub async fn consume(&self, n: usize) {
        let wait = self.charge(n, Instant::now());
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unlimited_never_waits() {
        let l = RateLimit::new(0);
        assert_eq!(l.charge(100 << 20, Instant::now()), Duration::ZERO);
    }

    #[test]
    fn sustained_rate_matches_the_cap() {
        let l = RateLimit::new(1 << 20); // 1 MB/s
        let start = Instant::now();
        // 10 MB in 64 KB chunks: the waits must add up to about ten seconds
        let mut now = start;
        for _ in 0..160 {
            now += l.charge(64 * 1024, now);
        }
        let secs = now.duration_since(start).as_secs_f64();
        assert!((9.5..10.1).contains(&secs), "{secs}");
        l.set(0);
        assert_eq!(l.charge(1 << 30, now), Duration::ZERO, "the cap can be lifted at any time");
    }
}
