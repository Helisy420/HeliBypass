//! Turns the proxy's byte counters into the live-speed dashboard: a one-minute history of
//! download/upload rates and the current rate per data center and route.

use std::collections::{HashMap, VecDeque};
use std::time::Instant;

use heli_tgproxy::{Route, SessionInfo};

/// Seconds of history shown in the graph (one sample per second).
pub const POINTS: usize = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct RouteStat {
    pub dc: u32,
    pub media: bool,
    pub route: Route,
    pub sessions: usize,
    /// bytes per second
    pub down: f64,
    pub up: f64,
}

#[derive(Default)]
pub struct Speed {
    last: Option<(Instant, u64, u64)>,
    last_sessions: HashMap<u64, (u64, u64)>,
    /// Oldest first, bytes per second.
    pub down: VecDeque<f64>,
    pub up: VecDeque<f64>,
    pub routes: Vec<RouteStat>,
    pub peak_down: f64,
}

impl Speed {
    /// Record one sample: total bytes moved so far and the sessions that are open now.
    pub fn sample(&mut self, now: Instant, total_up: u64, total_down: u64, sessions: &[SessionInfo]) {
        let secs = self.last.map(|(t, ..)| now.duration_since(t).as_secs_f64()).filter(|s| *s > 0.05);
        if let (Some((_, up0, down0)), Some(secs)) = (self.last, secs) {
            let down = total_down.saturating_sub(down0) as f64 / secs;
            let up = total_up.saturating_sub(up0) as f64 / secs;
            push(&mut self.down, down);
            push(&mut self.up, up);
            self.peak_down = self.peak_down.max(down);
        }
        let mut groups: HashMap<(u32, bool, Route), RouteStat> = HashMap::new();
        let mut seen = HashMap::with_capacity(sessions.len());
        for s in sessions {
            let (up0, down0) = self.last_sessions.get(&s.id).copied().unwrap_or((0, 0));
            let (du, dd) = match secs {
                Some(secs) => (s.bytes_up.saturating_sub(up0) as f64 / secs, s.bytes_down.saturating_sub(down0) as f64 / secs),
                None => (0.0, 0.0),
            };
            let g = groups.entry((s.dc, s.media, s.route)).or_insert(RouteStat {
                dc: s.dc,
                media: s.media,
                route: s.route,
                sessions: 0,
                down: 0.0,
                up: 0.0,
            });
            g.sessions += 1;
            g.down += dd;
            g.up += du;
            seen.insert(s.id, (s.bytes_up, s.bytes_down));
        }
        self.last_sessions = seen;
        let mut routes: Vec<RouteStat> = groups.into_values().collect();
        routes.sort_by(|a, b| b.down.total_cmp(&a.down).then(a.dc.cmp(&b.dc)).then(a.media.cmp(&b.media)).then(a.route.cmp(&b.route)));
        self.routes = routes;
        self.last = Some((now, total_up, total_down));
    }

    pub fn current_down(&self) -> f64 {
        self.down.back().copied().unwrap_or(0.0)
    }

    pub fn current_up(&self) -> f64 {
        self.up.back().copied().unwrap_or(0.0)
    }

    /// Both series scaled to 0..1 against a common maximum, padded to [`POINTS`] on the left.
    pub fn graph(&self) -> (Vec<f32>, Vec<f32>) {
        let max = self.down.iter().chain(self.up.iter()).copied().fold(64.0 * 1024.0, f64::max);
        let scale = |q: &VecDeque<f64>| {
            let mut v = vec![0.0f32; POINTS - q.len().min(POINTS)];
            v.extend(q.iter().map(|x| (x / max) as f32));
            v
        };
        (scale(&self.down), scale(&self.up))
    }
}

fn push(q: &mut VecDeque<f64>, v: f64) {
    if q.len() == POINTS {
        q.pop_front();
    }
    q.push_back(v);
}

/// `1.4 MB/s`, `512 KB/s`, `0 B/s`
pub fn human_rate(bytes_per_sec: f64) -> String {
    let v = bytes_per_sec.max(0.0);
    if v >= 1024.0 * 1024.0 {
        format!("{:.1} MB/s", v / (1024.0 * 1024.0))
    } else if v >= 1024.0 {
        format!("{:.0} KB/s", v / 1024.0)
    } else {
        format!("{:.0} B/s", v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sess(id: u64, dc: u32, media: bool, route: Route, up: u64, down: u64, t: Instant) -> SessionInfo {
        SessionInfo { id, dc, media, route, bytes_up: up, bytes_down: down, started: t }
    }

    #[test]
    fn rates_per_second_and_per_route() {
        let t0 = Instant::now();
        let mut s = Speed::default();
        s.sample(t0, 0, 0, &[sess(1, 2, false, Route::Direct, 0, 0, t0)]);
        assert!(s.down.is_empty(), "the first sample only sets the baseline");
        let t1 = t0 + Duration::from_secs(2);
        let sessions = [
            sess(1, 2, false, Route::Direct, 100, 2_000_000, t0),
            sess(2, 5, true, Route::H2, 0, 1_000_000, t1),
            sess(3, 5, true, Route::H2, 0, 1_000_000, t1),
        ];
        s.sample(t1, 100, 4_000_000, &sessions);
        assert_eq!(s.current_down(), 2_000_000.0);
        assert_eq!(s.current_up(), 50.0);
        assert_eq!(s.routes.len(), 2);
        assert_eq!((s.routes[0].dc, s.routes[0].sessions, s.routes[0].down), (2, 1, 1_000_000.0));
        assert_eq!((s.routes[1].route, s.routes[1].sessions, s.routes[1].down), (Route::H2, 2, 1_000_000.0));
        let (down, up) = s.graph();
        assert_eq!((down.len(), up.len()), (POINTS, POINTS));
        assert_eq!(down[POINTS - 1], 1.0);
    }

    #[test]
    fn history_is_capped() {
        let t0 = Instant::now();
        let mut s = Speed::default();
        for i in 0..(POINTS as u64 + 10) {
            s.sample(t0 + Duration::from_secs(i), 0, i * 1000, &[]);
        }
        assert_eq!(s.down.len(), POINTS);
    }

    #[test]
    fn formats_rates() {
        assert_eq!(human_rate(0.0), "0 B/s");
        assert_eq!(human_rate(2048.0), "2 KB/s");
        assert_eq!(human_rate(3.5 * 1024.0 * 1024.0), "3.5 MB/s");
    }
}
