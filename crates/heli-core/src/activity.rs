//! A small in-memory feed of user-facing events ("bypass started", "lists updated", ...).
//!
//! The UI shows the tail of this feed in the Activity panel. Verbose diagnostics go through
//! `tracing` instead; only state changes and results that a person cares about belong here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const CAPACITY: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Local time, `HH:MM:SS`.
    pub time: String,
    /// Short lowercase subsystem name: `bypass`, `proxy`, `lists`, `tests`, `app`.
    pub source: String,
    pub message: String,
    pub level: Level,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
    Error,
}

struct Feed {
    entries: Mutex<VecDeque<Entry>>,
    version: AtomicU64,
}

fn feed() -> &'static Feed {
    static FEED: OnceLock<Feed> = OnceLock::new();
    FEED.get_or_init(|| Feed { entries: Mutex::new(VecDeque::with_capacity(CAPACITY)), version: AtomicU64::new(0) })
}

pub fn push(source: &str, message: impl Into<String>) {
    push_level(Level::Info, source, message);
}

pub fn warn(source: &str, message: impl Into<String>) {
    push_level(Level::Warn, source, message);
}

pub fn error(source: &str, message: impl Into<String>) {
    push_level(Level::Error, source, message);
}

pub fn push_level(level: Level, source: &str, message: impl Into<String>) {
    let message = message.into();
    tracing::info!(target: "activity", source, "{message}");
    let f = feed();
    let mut q = f.entries.lock().unwrap_or_else(|e| e.into_inner());
    if q.len() == CAPACITY {
        q.pop_front();
    }
    q.push_back(Entry { time: local_time_hms(), source: source.to_owned(), message, level });
    drop(q);
    f.version.fetch_add(1, Ordering::Release);
}

/// Monotonic counter, bumped on every push. Lets the UI skip redraws when nothing changed.
pub fn version() -> u64 {
    feed().version.load(Ordering::Acquire)
}

/// The most recent `n` entries, oldest first.
pub fn tail(n: usize) -> Vec<Entry> {
    let q = feed().entries.lock().unwrap_or_else(|e| e.into_inner());
    q.iter().skip(q.len().saturating_sub(n)).cloned().collect()
}

#[cfg(windows)]
fn local_time_hms() -> String {
    use windows_sys::Win32::System::SystemInformation::GetLocalTime;
    // SAFETY: GetLocalTime fills the provided struct and has no failure mode.
    let t = unsafe {
        let mut t = std::mem::zeroed();
        GetLocalTime(&mut t);
        t
    };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

#[cfg(not(windows))]
fn local_time_hms() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_and_bumps_version() {
        let v0 = version();
        push("bypass", "started · general (ALT)");
        push("proxy", "listening 127.0.0.1:1443");
        assert!(version() >= v0 + 2);
        let t = tail(2);
        assert_eq!(t[0].source, "bypass");
        assert_eq!(t[1].message, "listening 127.0.0.1:1443");
        assert_eq!(t[0].time.len(), 8);
    }
}
