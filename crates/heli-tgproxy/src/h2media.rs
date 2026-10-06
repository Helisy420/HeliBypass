//! HTTP/2 media multiplexing through Cloudflare (BETA). Port of upstream `cf_h2.py` and
//! `h2_transport.py`.
//!
//! Instead of one WebSocket per media connection, every MTProto packet of a media session is
//! sent as its own `POST https://kws{dc}.<cf-domain>/api` request (Telegram's HTTP transport),
//! and all media sessions of a DC share **one** TLS + HTTP/2 connection. Requests of one session
//! run in parallel (up to [`MAX_CHANNEL_REQUESTS`]), so large files arrive over several streams
//! at once and no session pays its own TCP + TLS + WebSocket setup.
//!
//! The HTTP transport only lets the server answer requests. Telegram clients speak the TCP
//! transport and never send `http_wait`, so when a session goes quiet the most recent packet is
//! re-sent ("replayed") as a poll: the server ignores the duplicate message but uses the request
//! to deliver anything it has queued. A request whose answer is overdue is replayed the same way.
//! The rules below follow upstream exactly (see `_replay_blocker` there).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use cipher::StreamCipher;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;

use crate::balancer::Balancer;
use crate::client_io::{ClientReader, ClientWriter};
use crate::consts::{PROTO_TAG_ABRIDGED, PROTO_TAG_SECURE, default_dc_ip};
use crate::crypto::Aes256Ctr;
use crate::sessions::Meter;
use crate::stats::Stats;

pub const MAX_PACKET: usize = 4 * 1024 * 1024;
pub const MAX_CHANNEL_REQUESTS: usize = 8;
const MAX_CHANNEL_BYTES: usize = 8 * 1024 * 1024;
const MAX_LANE_REQUESTS: usize = 64;
const MAX_LANE_BYTES: usize = 32 * 1024 * 1024;
const MAX_LANE_REPLY_BYTES: usize = 32 * 1024 * 1024;
const DOMAIN_COOLDOWN: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(65);
const SETUP_TIMEOUT: Duration = Duration::from_secs(8);
const REPLAY_IDLE: Duration = Duration::from_secs(1);
const REPLAY_REQUEST: Duration = Duration::from_secs(3);
const REPLAY_CHECK: Duration = Duration::from_millis(250);
const REPLAY_MAX_AGE: Duration = Duration::from_secs(30);
const REPLAY_HISTORY_BYTES: usize = 64 * 1024;
const REPLAY_HISTORY_PACKETS: usize = 16;
const MAX_CHANNEL_REPLAYS: usize = 2;
const REPLAY_SLOT: Duration = Duration::from_secs(30);
const REPLAY_RETRY: Duration = Duration::from_secs(2);
const REPLAY_MAX_ATTEMPTS: u32 = 3;
const STREAM_RECEIVE_WINDOW: u32 = 256 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

#[derive(Debug, Clone, thiserror::Error)]
pub enum H2Error {
    /// Network or protocol failure; the Cloudflare host is put on cooldown.
    #[error("{0}")]
    Http(String),
    #[error("timed out")]
    Timeout,
    /// An MTProto transport error (e.g. -404) that must be reported to the client.
    #[error("MTProto transport error {0}")]
    Transport(i32),
    /// A local memory bound was hit.
    #[error("{0}")]
    Bound(&'static str),
    #[error("H2 channel closed")]
    Closed,
}

fn http_err(e: impl std::fmt::Display) -> H2Error {
    H2Error::Http(e.to_string())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ───────────── client transport framing ─────────────

/// Read one packet in the client's MTProto transport framing. Returns the payload and the
/// "quick ack" flag.
pub async fn read_packet(r: &mut ClientReader, dec: &mut Aes256Ctr, tag: [u8; 4]) -> std::io::Result<(Bytes, bool)> {
    let bad = |m: String| std::io::Error::new(std::io::ErrorKind::InvalidData, m);
    let (quick, length) = if tag == PROTO_TAG_ABRIDGED {
        let mut first = [0u8; 1];
        r.read_exact(&mut first).await?;
        dec.apply_keystream(&mut first);
        let mut words = usize::from(first[0] & 0x7F);
        if words == 0x7F {
            let mut ext = [0u8; 3];
            r.read_exact(&mut ext).await?;
            dec.apply_keystream(&mut ext);
            words = usize::from(ext[0]) | usize::from(ext[1]) << 8 | usize::from(ext[2]) << 16;
        }
        (first[0] & 0x80 != 0, words * 4)
    } else {
        let mut hdr = [0u8; 4];
        r.read_exact(&mut hdr).await?;
        dec.apply_keystream(&mut hdr);
        let v = u32::from_le_bytes(hdr);
        (v & 0x8000_0000 != 0, (v & 0x7FFF_FFFF) as usize)
    };
    let slack = if tag == PROTO_TAG_SECURE { 15 } else { 0 };
    if !(24..=MAX_PACKET + slack).contains(&length) {
        return Err(bad(format!("native packet length outside supported range: {length}")));
    }
    let mut body = vec![0u8; length];
    r.read_exact(&mut body).await?;
    dec.apply_keystream(&mut body);
    if tag == PROTO_TAG_SECURE {
        let packet_len = if body[..8] == [0u8; 8] {
            20 + u32::from_le_bytes(body[16..20].try_into().expect("4 bytes")) as usize
        } else {
            24 + ((length - 24) / 16) * 16
        };
        if !(24..=length).contains(&packet_len) || length - packet_len > 15 {
            return Err(bad("invalid padded native packet".into()));
        }
        body.truncate(packet_len);
    }
    if body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(bad("invalid native packet alignment or size".into()));
    }
    Ok((Bytes::from(body), quick))
}

/// Frame a reply in the client's transport framing (not yet encrypted).
pub fn encode_reply(body: &[u8], tag: [u8; 4]) -> Result<Vec<u8>, H2Error> {
    if body.is_empty() || body.len() % 4 != 0 || body.len() > MAX_PACKET {
        return Err(H2Error::Http(format!("invalid HTTP MTProto response length: {}", body.len())));
    }
    let mut out = Vec::with_capacity(body.len() + 8);
    if tag == PROTO_TAG_ABRIDGED {
        let words = body.len() / 4;
        if words < 0x7F {
            out.push(words as u8);
        } else {
            out.push(0x7F);
            out.extend_from_slice(&(words as u32).to_le_bytes()[..3]);
        }
        out.extend_from_slice(body);
    } else {
        let pad = if tag == PROTO_TAG_SECURE { usize::from(rand::random::<u8>() % 4) } else { 0 };
        out.extend_from_slice(&((body.len() + pad) as u32).to_le_bytes());
        out.extend_from_slice(body);
        out.extend((0..pad).map(|_| rand::random::<u8>()));
    }
    Ok(out)
}

// ───────────── lane: one HTTP/2 connection to one Cloudflare host ─────────────

struct Conn {
    send: h2::client::SendRequest<Bytes>,
    dead: Arc<AtomicBool>,
    driver: JoinHandle<()>,
}

#[derive(Default)]
struct LaneCap {
    inflight: usize,
    bytes: usize,
    closed: bool,
}

struct Lane {
    id: u64,
    host: String,
    conn: AsyncMutex<Option<Conn>>,
    failed_until: Mutex<Option<Instant>>,
    cap: Mutex<LaneCap>,
    cap_changed: Notify,
    reply_buffer: AtomicUsize,
    channels: Mutex<Vec<Weak<Channel>>>,
}

impl Lane {
    fn new(id: u64, host: String) -> Arc<Self> {
        Arc::new(Self {
            id,
            host,
            conn: AsyncMutex::new(None),
            failed_until: Mutex::new(None),
            cap: Mutex::new(LaneCap::default()),
            cap_changed: Notify::new(),
            reply_buffer: AtomicUsize::new(0),
            channels: Mutex::new(Vec::new()),
        })
    }

    fn cooling_down(&self, now: Instant) -> bool {
        lock(&self.failed_until).is_some_and(|t| now < t)
    }

    async fn sender(&self) -> Result<h2::client::SendRequest<Bytes>, H2Error> {
        let mut g = self.conn.lock().await;
        if let Some(c) = g.as_ref() {
            if !c.dead.load(Relaxed) {
                return Ok(c.send.clone());
            }
        }
        if let Some(old) = g.take() {
            old.driver.abort();
        }
        let c = tokio::time::timeout(SETUP_TIMEOUT, connect_h2(&self.host)).await.map_err(|_| H2Error::Timeout)??;
        tracing::debug!("H2 lane={} TCP_OPEN host={}", self.id, self.host);
        let send = c.send.clone();
        *g = Some(c);
        Ok(send)
    }

    fn has_capacity(c: &LaneCap, len: usize) -> bool {
        c.inflight < MAX_LANE_REQUESTS && c.bytes + len <= MAX_LANE_BYTES
    }

    async fn reserve(&self, len: usize, wait: bool) -> Result<bool, H2Error> {
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let notified = self.cap_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut c = lock(&self.cap);
                if c.closed {
                    return Err(H2Error::Closed);
                }
                if Self::has_capacity(&c, len) {
                    c.inflight += 1;
                    c.bytes += len;
                    return Ok(true);
                }
                if !wait {
                    return Ok(false);
                }
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(H2Error::Timeout);
            }
        }
    }

    fn release(&self, len: usize) {
        {
            let mut c = lock(&self.cap);
            c.inflight = c.inflight.saturating_sub(1);
            c.bytes = c.bytes.saturating_sub(len);
        }
        self.cap_changed.notify_waiters();
    }

    fn live_channels(&self) -> Vec<Arc<Channel>> {
        let mut list = lock(&self.channels);
        list.retain(|w| w.strong_count() > 0);
        list.iter().filter_map(Weak::upgrade).collect()
    }

    fn api_uri(&self) -> String {
        format!("https://{}/api", self.host)
    }

    /// `HEAD /api` must answer over HTTP/2 before the lane is used.
    async fn preflight(&self) -> Result<(), H2Error> {
        let mut send = self.sender().await?.ready().await.map_err(http_err)?;
        let req = http::Request::head(self.api_uri()).body(()).map_err(http_err)?;
        let (resp, _) = send.send_request(req, true).map_err(http_err)?;
        let resp = tokio::time::timeout(SETUP_TIMEOUT, resp).await.map_err(|_| H2Error::Timeout)?.map_err(http_err)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) || status == 405 || status == 501 {
            Ok(())
        } else {
            Err(H2Error::Http(format!("CF /api preflight HTTP {status}")))
        }
    }

    async fn post(&self, body: Bytes, chan: &Channel, task: u64) -> Result<Bytes, H2Error> {
        let r = self.post_inner(body, chan, task).await;
        if matches!(r, Err(H2Error::Http(_) | H2Error::Timeout)) {
            *lock(&self.failed_until) = Some(Instant::now() + DOMAIN_COOLDOWN);
        }
        r
    }

    async fn post_inner(&self, body: Bytes, chan: &Channel, task: u64) -> Result<Bytes, H2Error> {
        // `ready` waits for a free stream slot (the server's max concurrent streams)
        let mut send = tokio::time::timeout(REQUEST_TIMEOUT, self.sender().await?.ready())
            .await
            .map_err(|_| H2Error::Timeout)?
            .map_err(http_err)?;
        let req = http::Request::post(self.api_uri())
            .header("content-type", "application/octet-stream")
            .header("accept-encoding", "identity")
            .body(())
            .map_err(http_err)?;
        let (resp, mut stream) = send.send_request(req, false).map_err(http_err)?;
        tokio::time::timeout(REQUEST_TIMEOUT, send_body(&mut stream, body)).await.map_err(|_| H2Error::Timeout)??;
        chan.mark_sent(task);

        let resp = tokio::time::timeout(REQUEST_TIMEOUT, resp).await.map_err(|_| H2Error::Timeout)?.map_err(http_err)?;
        let status = resp.status().as_u16();
        let header = |n: &str| resp.headers().get(n).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let ray = header("cf-ray").unwrap_or_else(|| "-".into());
        if matches!(status, 403 | 404 | 429 | 444) {
            return Err(H2Error::Transport(-i32::from(status)));
        }
        if status != 200 {
            return Err(H2Error::Http(format!("CF /api HTTP {status} cf_ray={ray}")));
        }
        if header("content-type").is_some_and(|c| c.to_ascii_lowercase().contains("text/html")) {
            return Err(H2Error::Http("CF /api returned HTML instead of MTProto".into()));
        }
        let declared: Option<usize> = header("content-length").and_then(|v| v.parse().ok());
        if declared.is_some_and(|d| d > MAX_PACKET) {
            return Err(H2Error::Http("H2 response Content-Length exceeds native packet bound".into()));
        }
        let identity = header("content-encoding").is_none_or(|e| e == "identity");
        chan.mark_receiving(task);

        let mut recv = resp.into_body();
        let mut content = BytesMut::new();
        let mut buffered = ReplyBufferGuard { lane: self, bytes: 0 };
        while let Some(chunk) = tokio::time::timeout(REQUEST_TIMEOUT, recv.data()).await.map_err(|_| H2Error::Timeout)? {
            let chunk = chunk.map_err(http_err)?;
            let _ = recv.flow_control().release_capacity(chunk.len());
            if content.len() + chunk.len() > MAX_PACKET {
                return Err(H2Error::Http("H2 response exceeds native packet bound".into()));
            }
            if self.reply_buffer.load(Relaxed) + chunk.len() > MAX_LANE_REPLY_BYTES {
                return Err(H2Error::Bound("H2 lane response buffers exceeded bound"));
            }
            self.reply_buffer.fetch_add(chunk.len(), Relaxed);
            buffered.bytes += chunk.len();
            content.extend_from_slice(&chunk);
            chan.progress();
        }
        if identity && declared.is_some_and(|d| d != content.len()) {
            return Err(H2Error::Http("incomplete H2 response body".into()));
        }
        if content.len() % 4 != 0 {
            return Err(H2Error::Http("CF /api response is not an aligned MTProto packet".into()));
        }
        if content.len() == 4 {
            let code = i32::from_le_bytes(content[..4].try_into().expect("4 bytes"));
            if code < 0 {
                return Err(H2Error::Transport(code));
            }
        }
        Ok(content.freeze())
    }

    fn close(&self) {
        lock(&self.cap).closed = true;
        self.cap_changed.notify_waiters();
        if let Ok(mut g) = self.conn.try_lock() {
            if let Some(c) = g.take() {
                c.driver.abort();
            }
        }
    }
}

struct ReplyBufferGuard<'a> {
    lane: &'a Lane,
    bytes: usize,
}

impl Drop for ReplyBufferGuard<'_> {
    fn drop(&mut self) {
        self.lane.reply_buffer.fetch_sub(self.bytes, Relaxed);
    }
}

async fn connect_h2(host: &str) -> Result<Conn, H2Error> {
    let tcp = TcpStream::connect((host, 443)).await.map_err(http_err)?;
    crate::net::tune_socket(&tcp);
    let name = ServerName::try_from(host.to_owned()).map_err(http_err)?;
    let tls = TlsConnector::from(heli_core::tls::client_config_h2()).connect(name, tcp).await.map_err(http_err)?;
    if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
        return Err(H2Error::Http("CF origin did not negotiate h2".into()));
    }
    let (send, connection) = h2::client::Builder::new()
        .initial_window_size(STREAM_RECEIVE_WINDOW)
        .initial_connection_window_size(CONNECTION_RECEIVE_WINDOW)
        .enable_push(false)
        .handshake::<_, Bytes>(tls)
        .await
        .map_err(http_err)?;
    let dead = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&dead);
    let driver = tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("H2 connection ended: {e}");
        }
        flag.store(true, Relaxed);
    });
    Ok(Conn { send, dead, driver })
}

async fn send_body(stream: &mut h2::SendStream<Bytes>, mut data: Bytes) -> Result<(), H2Error> {
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let cap = match std::future::poll_fn(|cx| stream.poll_capacity(cx)).await {
            Some(Ok(n)) => n,
            Some(Err(e)) => return Err(http_err(e)),
            None => return Err(H2Error::Http("H2 stream closed while uploading".into())),
        };
        if cap == 0 {
            continue;
        }
        let chunk = data.split_to(cap.min(data.len()));
        stream.send_data(chunk, data.is_empty()).map_err(http_err)?;
    }
    Ok(())
}

// ───────────── channel: one client media session ─────────────

struct TaskInfo {
    len: usize,
    /// When the request body was handed to HTTP/2 (cleared when its slot is reclaimed).
    sent_at: Option<Instant>,
    /// Response headers arrived and the body is streaming in.
    receiving: bool,
    replay: bool,
}

struct ReplayPacket {
    sent_at: Instant,
    body: Bytes,
    seq: u64,
    attempts: u32,
    last_attempt_at: Option<Instant>,
    /// The replay request currently in flight for this packet.
    pending: Option<u64>,
    /// Original (non-replay) requests of this packet still in flight.
    originals: HashSet<u64>,
    retired: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UploadWait {
    SendLock,
    ChannelCapacity,
    LaneCapacity,
}

#[derive(Default)]
struct ChanState {
    closed: bool,
    transport_error: Option<i32>,
    pending: HashMap<u64, TaskInfo>,
    pending_bytes: usize,
    /// Replies queued for the client but not written yet.
    reply_bytes: usize,
    delivering: bool,
    history: Vec<ReplayPacket>,
    replay_key: Option<[u8; 8]>,
    last_progress: Option<Instant>,
    requests: u64,
    replays: u64,
    next_task: u64,
    upload_wait: Option<(UploadWait, usize)>,
}

impl ChanState {
    fn has_capacity(&self, len: usize) -> bool {
        self.pending.len() < MAX_CHANNEL_REQUESTS && self.pending_bytes + len <= MAX_CHANNEL_BYTES
    }

    fn backpressure(&self) -> bool {
        self.reply_bytes > 0 || self.delivering
    }

    fn replay_slots_used(&self) -> usize {
        self.pending.values().filter(|t| t.replay).count()
    }

    fn receiving(&self, task: u64) -> bool {
        self.pending.get(&task).is_some_and(|t| t.receiving)
    }

    fn replay_limit(&self, idx: usize) -> u32 {
        let e = &self.history[idx];
        if !e.originals.is_empty() || e.retired || idx + 1 == self.history.len() { REPLAY_MAX_ATTEMPTS } else { 0 }
    }

    /// An original request of this packet has waited too long for its response headers.
    fn overdue_original(&self, idx: usize, now: Instant) -> bool {
        let e = &self.history[idx];
        e.retired
            || e.originals.iter().any(|t| {
                self.pending.get(t).is_some_and(|i| !i.receiving && i.sent_at.is_some_and(|s| now - s >= REPLAY_REQUEST))
            })
    }

    /// `None` when the packet may be replayed now, otherwise the reason it may not.
    fn replay_blocker(&self, idx: usize, now: Instant) -> Option<&'static str> {
        let e = &self.history[idx];
        if now.checked_duration_since(e.sent_at).is_none_or(|age| age > REPLAY_MAX_AGE) {
            return Some("expired");
        }
        if e.attempts >= self.replay_limit(idx) {
            return Some("budget-used");
        }
        if self.backpressure() {
            return Some("native-backpressure");
        }
        if e.originals.iter().any(|t| self.receiving(*t)) {
            return Some("original-body");
        }
        if e.pending.is_some_and(|t| self.receiving(t)) {
            return Some("replay-body");
        }
        let replayed = e.attempts > 0;
        if replayed && e.last_attempt_at.is_some_and(|t| now - t < REPLAY_RETRY) {
            return Some("backoff-or-progress");
        }
        if self.overdue_original(idx, now) {
            return None;
        }
        if idx + 1 != self.history.len() || self.pending.keys().any(|t| Some(*t) != e.pending) {
            return Some("receiver-active");
        }
        if replayed && self.last_progress.is_some_and(|t| now - t < REPLAY_IDLE) {
            return Some("backoff-or-progress");
        }
        None
    }

    /// Remember a native packet for replays; returns its index in the history.
    fn remember_packet(&mut self, body: &Bytes, now: Instant) -> Option<usize> {
        let key: [u8; 8] = body[..8].try_into().ok()?;
        if key == [0u8; 8] {
            return None; // unencrypted handshake messages are never replayed
        }
        if self.replay_key != Some(key) {
            self.history.clear();
            self.replay_key = Some(key);
        }
        if body.len() > REPLAY_HISTORY_BYTES {
            return None;
        }
        if let Some(i) = self.history.iter().position(|e| e.body == *body) {
            return Some(i);
        }
        self.history.push(ReplayPacket {
            sent_at: now,
            body: body.clone(),
            seq: self.requests,
            attempts: 0,
            last_attempt_at: None,
            pending: None,
            originals: HashSet::new(),
            retired: false,
        });
        Some(self.history.len() - 1)
    }

    fn trim_history(&mut self, now: Instant) {
        loop {
            let total: usize = self.history.iter().map(|e| e.body.len()).sum();
            if self.history.len() <= REPLAY_HISTORY_PACKETS && total <= REPLAY_HISTORY_BYTES {
                return;
            }
            let victim = self
                .history
                .iter()
                .position(|e| {
                    e.originals.is_empty()
                        && !(e.retired && e.attempts < REPLAY_MAX_ATTEMPTS && now.saturating_duration_since(e.sent_at) <= REPLAY_MAX_AGE)
                })
                .unwrap_or(0);
            self.history.remove(victim);
        }
    }

    /// A stuck request whose slot can be reclaimed so a waiting upload can go out.
    fn capacity_candidate(&mut self, now: Instant) -> Option<u64> {
        let mut tasks: Vec<(bool, Instant, u64)> = self
            .pending
            .iter()
            .filter(|(_, i)| !i.receiving)
            .filter_map(|(t, i)| i.sent_at.map(|s| (!i.replay, s, *t)))
            .filter(|(_, s, _)| now - *s >= REPLAY_REQUEST)
            .collect();
        tasks.sort();
        for (original, _, t) in tasks {
            if !original {
                return Some(t);
            }
            if let Some(e) = self.history.iter_mut().find(|e| e.originals.contains(&t)) {
                if now.saturating_duration_since(e.sent_at) <= REPLAY_MAX_AGE {
                    e.retired = true;
                    if let Some(i) = self.pending.get_mut(&t) {
                        i.sent_at = None;
                    }
                    return Some(t);
                }
            }
        }
        None
    }
}

pub struct Channel {
    id: u64,
    label: String,
    lane: Arc<Lane>,
    stats: Arc<Stats>,
    st: Mutex<ChanState>,
    capacity_changed: Notify,
    wakeup: Notify,
    closing: CancellationToken,
    replies: mpsc::UnboundedSender<Bytes>,
    send_lock: AsyncMutex<()>,
    tasks: Mutex<HashMap<u64, JoinHandle<()>>>,
}

struct FinishGuard {
    chan: Arc<Channel>,
    task: u64,
}

impl Drop for FinishGuard {
    fn drop(&mut self) {
        self.chan.finish_request(self.task);
    }
}

impl Channel {
    fn state(&self) -> MutexGuard<'_, ChanState> {
        lock(&self.st)
    }

    fn mark_sent(&self, task: u64) {
        if let Some(t) = self.state().pending.get_mut(&task) {
            t.sent_at = Some(Instant::now());
        }
    }

    fn mark_receiving(&self, task: u64) {
        let mut st = self.state();
        st.last_progress = Some(Instant::now());
        if let Some(t) = st.pending.get_mut(&task) {
            t.receiving = true;
        }
    }

    fn progress(&self) {
        self.state().last_progress = Some(Instant::now());
    }

    fn wake_receiver(&self) {
        let st = self.state();
        if !st.closed && st.pending.is_empty() && !st.backpressure() {
            self.wakeup.notify_one();
        }
    }

    fn fail(&self, err: &H2Error) {
        {
            let mut st = self.state();
            if st.closed {
                return;
            }
            if let H2Error::Transport(code) = err {
                st.transport_error = Some(*code);
            }
            st.closed = true;
            st.reply_bytes = 0;
        }
        self.closing.cancel();
        self.wakeup.notify_one();
        self.capacity_changed.notify_waiters();
    }

    fn finish_request(&self, task: u64) {
        let len = {
            let mut st = self.state();
            let Some(info) = st.pending.remove(&task) else { return };
            st.pending_bytes = st.pending_bytes.saturating_sub(info.len);
            for e in st.history.iter_mut() {
                e.originals.remove(&task);
                if e.pending == Some(task) {
                    e.pending = None;
                }
            }
            info.len
        };
        lock(&self.tasks).remove(&task);
        self.lane.release(len);
        self.capacity_changed.notify_waiters();
        self.wake_receiver();
    }

    async fn abort_and_wait(&self, task: u64) {
        let handle = lock(&self.tasks).remove(&task);
        if let Some(h) = handle {
            h.abort();
            let _ = h.await;
        }
    }

    fn set_upload_wait(&self, w: Option<(UploadWait, usize)>) {
        self.state().upload_wait = w;
    }

    /// Send one packet as a request. Native packets wait for capacity; replays never wait and
    /// return `Ok(false)` when they cannot go out now.
    pub async fn send(self: &Arc<Self>, body: Bytes, replay: bool) -> Result<bool, H2Error> {
        let _guard = if replay {
            match self.send_lock.try_lock() {
                Ok(g) => g,
                Err(_) => return Ok(false),
            }
        } else {
            self.set_upload_wait(Some((UploadWait::SendLock, body.len())));
            self.send_lock.lock().await
        };
        let r = self.send_locked(body, replay).await;
        if !replay {
            self.set_upload_wait(None);
        }
        r
    }

    async fn send_locked(self: &Arc<Self>, body: Bytes, replay: bool) -> Result<bool, H2Error> {
        let len = body.len();
        let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
        loop {
            let notified = self.capacity_changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut st = self.state();
                if st.closed {
                    return Err(H2Error::Closed);
                }
                if st.has_capacity(len) {
                    break;
                }
                if replay {
                    return Ok(false);
                }
                st.upload_wait = Some((UploadWait::ChannelCapacity, len));
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return Err(H2Error::Timeout);
            }
        }
        if !replay {
            self.set_upload_wait(Some((UploadWait::LaneCapacity, len)));
        }
        if !self.lane.reserve(len, !replay).await? {
            return Ok(false);
        }
        let now = Instant::now();
        let task = {
            let mut st = self.state();
            let replay_idx = if replay { st.history.iter().position(|e| e.body == body) } else { None };
            let refuse = st.closed
                || (replay
                    && match replay_idx {
                        None => true,
                        Some(i) => st.history[i].pending.is_some() || st.replay_blocker(i, now).is_some(),
                    });
            if refuse {
                let closed = st.closed;
                drop(st);
                self.lane.release(len);
                return if closed { Err(H2Error::Closed) } else { Ok(false) };
            }
            st.next_task += 1;
            let task = st.next_task;
            st.pending_bytes += len;
            st.requests += 1;
            st.pending.insert(task, TaskInfo { len, sent_at: None, receiving: false, replay });
            if replay {
                st.replays += 1;
                let e = &mut st.history[replay_idx.expect("checked above")];
                e.attempts += 1;
                e.last_attempt_at = Some(now);
                e.pending = Some(task);
            } else if let Some(i) = st.remember_packet(&body, now) {
                st.history[i].originals.insert(task);
                st.trim_history(now);
            }
            task
        };
        self.stats.h2_requests.fetch_add(1, Relaxed);
        self.spawn_request(task, body);
        Ok(true)
    }

    fn spawn_request(self: &Arc<Self>, task: u64, body: Bytes) {
        let me = Arc::clone(self);
        let handle = tokio::spawn(async move {
            let guard = FinishGuard { chan: Arc::clone(&me), task };
            let res = me.lane.post(body, &me, task).await;
            match res {
                Ok(reply) => {
                    let mut st = me.state();
                    st.last_progress = Some(Instant::now());
                    if !reply.is_empty() && !st.closed {
                        if st.reply_bytes + reply.len() > MAX_CHANNEL_BYTES {
                            drop(st);
                            me.fail(&H2Error::Bound("H2 client response queue exceeded bound"));
                        } else {
                            st.reply_bytes += reply.len();
                            drop(st);
                            let _ = me.replies.send(reply);
                        }
                    }
                }
                Err(e) => {
                    me.stats.h2_errors.fetch_add(1, Relaxed);
                    if !me.state().closed {
                        match &e {
                            H2Error::Transport(code) => tracing::warn!(
                                "[{}] H2 lane={} channel={} host={} MTProto transport error {code}; reporting to client",
                                me.label,
                                me.lane.id,
                                me.id,
                                me.lane.host
                            ),
                            other => tracing::warn!(
                                "[{}] H2 lane={} channel={} request failed: {other}; closing the session, the client reconnects",
                                me.label,
                                me.lane.id,
                                me.id
                            ),
                        }
                    }
                    me.fail(&e);
                }
            }
            drop(guard);
        });
        let finished = !self.state().pending.contains_key(&task);
        if !finished {
            lock(&self.tasks).insert(task, handle);
        }
    }

    /// Free a slot for a waiting upload by cancelling the oldest stuck request.
    async fn make_upload_room(self: &Arc<Self>, now: Instant) {
        let Some((phase, bytes)) = self.state().upload_wait else { return };
        let channels: Vec<Arc<Channel>> = match phase {
            UploadWait::ChannelCapacity => {
                if self.state().has_capacity(bytes) {
                    return;
                }
                vec![Arc::clone(self)]
            }
            UploadWait::LaneCapacity => {
                if Lane::has_capacity(&lock(&self.lane.cap), bytes) {
                    return;
                }
                let mut all = self.lane.live_channels();
                all.sort_by_key(|c| c.state().pending.values().filter_map(|t| t.sent_at).min().unwrap_or(now));
                all
            }
            UploadWait::SendLock => return,
        };
        for ch in channels {
            let candidate = ch.state().capacity_candidate(now);
            if let Some(task) = candidate {
                tracing::debug!("H2 CAPACITY lane={} channel={} releases a stuck request", self.lane.id, ch.id);
                ch.abort_and_wait(task).await;
                return;
            }
        }
    }

    /// Polls with replays while the session is quiet, and retries overdue requests.
    async fn recover(self: &Arc<Self>) {
        loop {
            let _ = tokio::time::timeout(REPLAY_CHECK, self.wakeup.notified()).await;
            if self.state().closed {
                return;
            }
            let now = Instant::now();
            self.make_upload_room(now).await;
            let action = {
                let st = self.state();
                if st.closed {
                    return;
                }
                if st.backpressure() {
                    continue;
                }
                let mut order: Vec<usize> = (0..st.history.len()).collect();
                order.sort_by_key(|&i| {
                    let overdue = st.overdue_original(i, now);
                    let seq = st.history[i].seq as i64;
                    (!overdue, if overdue { seq } else { -seq })
                });
                let mut chosen = None;
                for i in order {
                    if st.replay_blocker(i, now).is_some() {
                        continue;
                    }
                    let mut replace = st.history[i].pending;
                    if replace.is_none() && st.replay_slots_used() >= MAX_CHANNEL_REPLAYS {
                        replace = st.pending.iter().find(|(_, t)| t.replay && !t.receiving).map(|(id, _)| *id);
                        if replace.is_none() {
                            continue;
                        }
                    }
                    if let Some(r) = replace {
                        let Some(t) = st.pending.get(&r) else { continue };
                        if t.receiving || t.sent_at.is_none_or(|s| now - s < REPLAY_SLOT) {
                            continue;
                        }
                    }
                    chosen = Some((st.history[i].body.clone(), replace));
                    break;
                }
                chosen
            };
            if let Some((body, replace)) = action {
                if let Some(r) = replace {
                    self.abort_and_wait(r).await;
                }
                if let Err(e) = self.send(body, true).await {
                    tracing::debug!("[{}] H2 channel={} replay not sent: {e}", self.label, self.id);
                }
            }
        }
    }

    async fn close(&self) {
        self.fail(&H2Error::Closed);
        let handles: Vec<JoinHandle<()>> = lock(&self.tasks).drain().map(|(_, h)| h).collect();
        for h in &handles {
            h.abort();
        }
        for h in handles {
            let _ = h.await;
        }
        let st = self.state();
        tracing::debug!(
            "[{}] H2 channel={} closed lane={} requests={} replays={}",
            self.label,
            self.id,
            self.lane.id,
            st.requests,
            st.replays
        );
    }
}

// ───────────── pool ─────────────

/// All HTTP/2 lanes of a running proxy, keyed by Cloudflare host.
#[derive(Default)]
pub struct H2Pool {
    lanes: Mutex<HashMap<String, Arc<Lane>>>,
    host_locks: Mutex<HashMap<String, Arc<AsyncMutex<()>>>>,
    failed_until: Mutex<HashMap<String, Instant>>,
    setup_retry_after: Mutex<HashMap<u32, Instant>>,
    next_lane: AtomicU64,
    next_channel: AtomicU64,
    closed: AtomicBool,
}

pub struct OpenChannel {
    channel: Arc<Channel>,
    replies: mpsc::UnboundedReceiver<Bytes>,
}

impl H2Pool {
    /// A channel for a media session to `dc`, or `None` to use the WebSocket route instead.
    pub async fn open(&self, dc: u32, label: &str, balancer: &Balancer, stats: &Arc<Stats>) -> Option<OpenChannel> {
        if self.closed.load(Relaxed) || lock(&self.setup_retry_after).get(&dc).is_some_and(|t| Instant::now() < *t) {
            return None;
        }
        match tokio::time::timeout(SETUP_TIMEOUT, self.open_inner(dc, label, balancer, stats)).await {
            Ok(r) => r,
            Err(_) => {
                lock(&self.setup_retry_after).insert(dc, Instant::now() + DOMAIN_COOLDOWN);
                stats.h2_errors.fetch_add(1, Relaxed);
                tracing::warn!("[{label}] H2 DC{dc} setup timed out; using WebSocket for {}s", DOMAIN_COOLDOWN.as_secs());
                None
            }
        }
    }

    async fn open_inner(&self, dc: u32, label: &str, balancer: &Balancer, stats: &Arc<Stats>) -> Option<OpenChannel> {
        default_dc_ip(dc, false)?;
        for base in balancer.domains_for_dc(dc) {
            let host = format!("kws{dc}.{base}");
            let host_lock = Arc::clone(lock(&self.host_locks).entry(host.clone()).or_default());
            let _held = host_lock.lock().await;
            if self.closed.load(Relaxed) {
                return None;
            }
            let now = Instant::now();
            let existing = lock(&self.lanes).get(&host).cloned();
            let host_failed = lock(&self.failed_until).get(&host).is_some_and(|t| now < *t);
            if host_failed || existing.as_ref().is_some_and(|l| l.cooling_down(now)) {
                continue;
            }
            let lane = match existing {
                Some(l) => l,
                None => {
                    let lane = Lane::new(self.next_lane.fetch_add(1, Relaxed) + 1, host.clone());
                    if let Err(e) = lane.preflight().await {
                        stats.h2_errors.fetch_add(1, Relaxed);
                        lock(&self.failed_until).insert(host.clone(), Instant::now() + DOMAIN_COOLDOWN);
                        tracing::warn!("[{label}] H2 lane={} preflight failed host={host}: {e}", lane.id);
                        lane.close();
                        continue;
                    }
                    if self.closed.load(Relaxed) {
                        lane.close();
                        return None;
                    }
                    lock(&self.lanes).insert(host.clone(), Arc::clone(&lane));
                    lane
                }
            };
            let (tx, rx) = mpsc::unbounded_channel();
            let channel = Arc::new(Channel {
                id: self.next_channel.fetch_add(1, Relaxed) + 1,
                label: label.to_owned(),
                lane: Arc::clone(&lane),
                stats: Arc::clone(stats),
                st: Mutex::new(ChanState::default()),
                capacity_changed: Notify::new(),
                wakeup: Notify::new(),
                closing: CancellationToken::new(),
                replies: tx,
                send_lock: AsyncMutex::new(()),
                tasks: Mutex::new(HashMap::new()),
            });
            lock(&lane.channels).push(Arc::downgrade(&channel));
            balancer.update_domain_for_dc(dc, &base);
            tracing::info!("[{label}] ROUTE DC{dc} media -> H2 lane={} channel={} host={host}", lane.id, channel.id);
            return Some(OpenChannel { channel, replies: rx });
        }
        tracing::debug!("[{label}] H2 DC{dc} unavailable; using WebSocket");
        None
    }

    pub fn close(&self) {
        self.closed.store(true, Relaxed);
        for (_, lane) in lock(&self.lanes).drain() {
            lane.close();
        }
    }
}

/// Carry one client media session over an HTTP/2 channel until either side ends it.
#[allow(clippy::too_many_arguments)]
pub async fn bridge(
    open: OpenChannel,
    mut client_r: ClientReader,
    mut client_w: ClientWriter,
    mut clt_dec: Aes256Ctr,
    mut clt_enc: Aes256Ctr,
    tag: [u8; 4],
    stats: &Stats,
    meter: &Meter,
    (up_limit, down_limit): (&crate::ratelimit::RateLimit, &crate::ratelimit::RateLimit),
    cancel: &CancellationToken,
) {
    let OpenChannel { channel: chan, mut replies } = open;
    let started = Instant::now();
    let mut reason = String::from("normal");
    {
        let up = async {
            loop {
                let (body, _quick) = match read_packet(&mut client_r, &mut clt_dec, tag).await {
                    Ok(p) => p,
                    Err(e) => return Err::<(), String>(e.to_string()),
                };
                stats.bytes_up.fetch_add(body.len() as u64, Relaxed);
                meter.add_up(body.len());
                up_limit.consume(body.len()).await;
                if let Err(e) = chan.send(body, false).await {
                    return Err(e.to_string());
                }
            }
        };
        let down = async {
            loop {
                let body = tokio::select! {
                    biased;
                    _ = chan.closing.cancelled() => return Ok::<(), String>(()),
                    r = replies.recv() => match r { Some(b) => b, None => return Ok(()) },
                };
                {
                    let mut st = chan.state();
                    st.reply_bytes = st.reply_bytes.saturating_sub(body.len());
                    st.delivering = true;
                }
                let framed = encode_reply(&body, tag).map(|mut f| {
                    clt_enc.apply_keystream(&mut f);
                    f
                });
                let res = match framed {
                    Ok(f) => client_w.write_all(&f).await.map_err(|e| e.to_string()),
                    Err(e) => Err(e.to_string()),
                };
                {
                    let mut st = chan.state();
                    st.delivering = false;
                    st.last_progress = Some(Instant::now());
                }
                chan.wake_receiver();
                res?;
                stats.bytes_down.fetch_add(body.len() as u64, Relaxed);
                meter.add_down(body.len());
                down_limit.consume(body.len()).await;
            }
        };
        let recover = chan.recover();
        tokio::pin!(up, down, recover);
        tokio::select! {
            r = &mut up => if let Err(e) = r { reason = format!("client: {e}"); },
            r = &mut down => if let Err(e) = r { reason = format!("client write: {e}"); },
            _ = &mut recover => reason = "channel closed".into(),
            _ = cancel.cancelled() => reason = "proxy stopped".into(),
        }
    }
    let transport_error = chan.state().transport_error;
    if let Some(code) = transport_error {
        if let Ok(mut f) = encode_reply(&code.to_le_bytes(), tag) {
            clt_enc.apply_keystream(&mut f);
            let _ = client_w.write_all(&f).await;
        }
        reason = format!("MTProto transport error {code}");
    }
    chan.close().await;
    client_w.shutdown().await;
    tracing::info!(
        "[{}] DC media H2 channel={} closed ({reason}) after {:.1}s",
        chan.label,
        chan.id,
        started.elapsed().as_secs_f64()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::PROTO_TAG_INTERMEDIATE;

    fn state_with(history: &[(&[u8], u32)], now: Instant) -> ChanState {
        let mut st = ChanState::default();
        for (i, (body, attempts)) in history.iter().enumerate() {
            let mut b = vec![1u8; 8];
            b.extend_from_slice(body);
            let idx = st.remember_packet(&Bytes::from(b), now).unwrap();
            st.history[idx].attempts = *attempts;
            st.history[idx].seq = i as u64;
        }
        st
    }

    #[test]
    fn reply_framing_matches_transports() {
        let body = vec![7u8; 24];
        let a = encode_reply(&body, PROTO_TAG_ABRIDGED).unwrap();
        assert_eq!(a[0], 6);
        assert_eq!(&a[1..], &body[..]);
        let big = vec![1u8; 0x7F * 4];
        let a = encode_reply(&big, PROTO_TAG_ABRIDGED).unwrap();
        assert_eq!(&a[..4], &[0x7F, 0x7F, 0, 0]);
        let i = encode_reply(&body, PROTO_TAG_INTERMEDIATE).unwrap();
        assert_eq!(u32::from_le_bytes(i[..4].try_into().unwrap()), 24);
        let p = encode_reply(&body, PROTO_TAG_SECURE).unwrap();
        let declared = u32::from_le_bytes(p[..4].try_into().unwrap()) as usize;
        assert!((24..=27).contains(&declared) && p.len() == 4 + declared);
        assert!(encode_reply(&[1, 2, 3], PROTO_TAG_ABRIDGED).is_err());
    }

    #[test]
    fn idle_session_polls_with_its_latest_packet_once_per_backoff() {
        let now = Instant::now();
        let mut st = state_with(&[(b"aaaaaaaa", 0), (b"bbbbbbbb", 0)], now);
        // nothing in flight, nothing waiting for the client: the latest packet is due
        assert_eq!(st.replay_blocker(1, now), None);
        // older packets without in-flight originals have no replay budget
        assert_eq!(st.replay_blocker(0, now), Some("budget-used"));
        // replies waiting for the client block polling
        st.reply_bytes = 10;
        assert_eq!(st.replay_blocker(1, now), Some("native-backpressure"));
        st.reply_bytes = 0;
        // a fresh attempt backs off for REPLAY_RETRY
        st.history[1].attempts = 1;
        st.history[1].last_attempt_at = Some(now);
        assert_eq!(st.replay_blocker(1, now + Duration::from_millis(500)), Some("backoff-or-progress"));
        assert_eq!(st.replay_blocker(1, now + REPLAY_RETRY), None);
        // the budget is three attempts, and only within REPLAY_MAX_AGE
        st.history[1].attempts = REPLAY_MAX_ATTEMPTS;
        assert_eq!(st.replay_blocker(1, now + REPLAY_RETRY), Some("budget-used"));
        st.history[1].attempts = 0;
        assert_eq!(st.replay_blocker(1, now + REPLAY_MAX_AGE + Duration::from_secs(1)), Some("expired"));
    }

    #[test]
    fn overdue_original_is_replayed_even_while_others_are_in_flight() {
        let now = Instant::now();
        let mut st = state_with(&[(b"aaaaaaaa", 0), (b"bbbbbbbb", 0)], now);
        st.pending.insert(1, TaskInfo { len: 16, sent_at: Some(now), receiving: false, replay: false });
        st.pending.insert(2, TaskInfo { len: 16, sent_at: Some(now), receiving: false, replay: false });
        st.history[0].originals.insert(1);
        st.history[1].originals.insert(2);
        // both requests are fresh: the session is active, nobody polls
        assert_eq!(st.replay_blocker(0, now), Some("receiver-active"));
        assert_eq!(st.replay_blocker(1, now), Some("receiver-active"));
        // packet 0 got no headers for REPLAY_REQUEST: it is retried
        let later = now + REPLAY_REQUEST;
        assert_eq!(st.replay_blocker(0, later), None);
        // but not while its response body is streaming in
        st.pending.get_mut(&1).unwrap().receiving = true;
        assert_eq!(st.replay_blocker(0, later), Some("original-body"));
    }

    #[test]
    fn history_resets_on_new_key_and_skips_handshakes_and_big_packets() {
        let now = Instant::now();
        let mut st = ChanState::default();
        let mut plain = vec![0u8; 8];
        plain.extend_from_slice(&[5u8; 16]);
        assert_eq!(st.remember_packet(&Bytes::from(plain), now), None);
        let mut a = vec![1u8; 8];
        a.extend_from_slice(&[5u8; 16]);
        assert_eq!(st.remember_packet(&Bytes::from(a.clone()), now), Some(0));
        assert_eq!(st.remember_packet(&Bytes::from(a), now), Some(0), "same packet is not stored twice");
        let mut big = vec![1u8; 8];
        big.extend_from_slice(&vec![0u8; REPLAY_HISTORY_BYTES]);
        assert_eq!(st.remember_packet(&Bytes::from(big), now), None);
        let mut other_key = vec![2u8; 8];
        other_key.extend_from_slice(&[5u8; 16]);
        assert_eq!(st.remember_packet(&Bytes::from(other_key), now), Some(0));
        assert_eq!(st.history.len(), 1);
        for i in 0..40u8 {
            let mut p = vec![2u8; 8];
            p.extend_from_slice(&[i; 16]);
            st.remember_packet(&Bytes::from(p), now);
            st.trim_history(now);
        }
        assert!(st.history.len() <= REPLAY_HISTORY_PACKETS);
    }

    #[test]
    fn stuck_replays_are_reclaimed_before_originals() {
        let now = Instant::now();
        let mut st = state_with(&[(b"aaaaaaaa", 0)], now);
        st.pending.insert(1, TaskInfo { len: 16, sent_at: Some(now), receiving: false, replay: false });
        st.pending.insert(2, TaskInfo { len: 16, sent_at: Some(now), receiving: false, replay: true });
        st.history[0].originals.insert(1);
        assert_eq!(st.capacity_candidate(now), None, "nothing is stuck yet");
        let later = now + REPLAY_REQUEST;
        assert_eq!(st.capacity_candidate(later), Some(2));
        st.pending.remove(&2);
        assert_eq!(st.capacity_candidate(later), Some(1));
        assert!(st.history[0].retired, "a reclaimed original is retired so its packet gets replayed");
    }
}
