//! Listener, client handshake and session setup.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::balancer::Balancer;
use crate::bridge::{FallbackParams, bridge_ws, do_fallback};
use crate::client_io::{ClientReader, ClientWriter};
use crate::config::{ProxyConfig, decode_cf_domain, default_cf_domains, is_valid_domain};
use crate::consts::HANDSHAKE_LEN;
use crate::crypto::{MsgSplitter, build_crypto_ctx, generate_relay_init, try_handshake};
use crate::fake_tls::{
    FakeTlsReader, FakeTlsWriter, TLS_RECORD_HANDSHAKE, build_server_hello, proxy_to_masking_domain, verify_client_hello,
};
use crate::pool::{CfRoutePool, CfWorkerPool, WsPool};
use crate::state::{Shared, TcpBackoff};
use crate::stats::{Snapshot, Stats};

const INIT_TIMEOUT: Duration = Duration::from_secs(10);
const CF_REFRESH_INTERVAL: Duration = Duration::from_secs(3600);
const MIN_VALID_CF_DOMAINS: usize = 3;

/// A running proxy. Dropping the handle does **not** stop it; call [`ProxyHandle::stop`].
pub struct ProxyHandle {
    shared: Arc<Shared>,
    local_addr: SocketAddr,
    accept_task: JoinHandle<()>,
}

/// Bind the listener and start serving. Bind errors (port already in use, ...) are returned
/// here so the caller can show them immediately.
pub async fn start(cfg: ProxyConfig) -> io::Result<ProxyHandle> {
    let cfg = Arc::new(cfg);
    let listener = TcpListener::bind((cfg.host.as_str(), cfg.port)).await?;
    let local_addr = listener.local_addr()?;

    let cancel = CancellationToken::new();
    let stats = Arc::new(Stats::default());
    let shared = Arc::new(Shared {
        cfg: Arc::clone(&cfg),
        stats: Arc::clone(&stats),
        pool: WsPool::new(Arc::clone(&cfg), Arc::clone(&stats), cancel.child_token()),
        cf_pool: CfWorkerPool::new(Arc::clone(&cfg), Arc::clone(&stats)),
        cf_route: CfRoutePool::default(),
        sessions: Arc::default(),
        h2: Default::default(),
        down_limit: crate::ratelimit::RateLimit::new(cfg.speed_limit),
        up_limit: crate::ratelimit::RateLimit::new(cfg.speed_limit),
        balancer: Balancer::default(),
        tcp_backoff: TcpBackoff::default(),
        cancel: cancel.clone(),
    });

    if cfg.cfproxy_user_domains.is_empty() {
        shared.balancer.update_domains_list(&default_cf_domains());
        if cfg.fallback_cfproxy {
            if let Some(url) = cfg.cf_domains_url.clone() {
                tokio::spawn(refresh_cf_domains_loop(Arc::clone(&shared), url));
            }
        }
    } else {
        shared.balancer.update_domains_list(&cfg.cfproxy_user_domains);
    }

    tracing::info!("Telegram MTProto WS proxy listening on {local_addr}");
    if !cfg.fake_tls_domain.is_empty() {
        tracing::info!("Fake TLS masking domain: {}", cfg.fake_tls_domain);
    }
    for (dc, ip) in &cfg.dc_redirects {
        tracing::info!("  DC{dc} -> {ip}");
    }

    shared.pool.warmup();
    shared.cf_pool.warmup();
    tokio::spawn(stats_logger(Arc::clone(&shared)));

    let accept_task = tokio::spawn(accept_loop(listener, Arc::clone(&shared)));
    Ok(ProxyHandle { shared, local_addr, accept_task })
}

impl ProxyHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn config(&self) -> &ProxyConfig {
        &self.shared.cfg
    }
    pub fn stats(&self) -> Snapshot {
        self.shared.stats.snapshot()
    }
    /// Change the speed cap while running (bytes per second per direction, 0 = unlimited).
    pub fn set_speed_limit(&self, bytes_per_sec: u64) {
        self.shared.down_limit.set(bytes_per_sec);
        self.shared.up_limit.set(bytes_per_sec);
    }

    /// The sessions that are open right now, with their routes and byte counts.
    pub fn sessions(&self) -> Vec<crate::sessions::SessionInfo> {
        self.shared.sessions.snapshot()
    }
    pub fn tg_link(&self) -> String {
        self.shared.cfg.tg_link()
    }
    pub fn is_running(&self) -> bool {
        !self.accept_task.is_finished()
    }

    /// Stop accepting, close all sessions and background tasks.
    pub async fn stop(self) {
        self.shared.cancel.cancel();
        self.shared.pool.shutdown();
        self.shared.cf_pool.clear();
        self.shared.cf_route.clear();
        self.shared.h2.close();
        let _ = tokio::time::timeout(Duration::from_secs(3), self.accept_task).await;
        tracing::info!("Proxy stopped. Final stats: {}", self.shared.stats.snapshot().summary());
    }
}

async fn accept_loop(listener: TcpListener, shared: Arc<Shared>) {
    let mut consecutive_errors = 0u32;
    loop {
        let accepted = tokio::select! {
            _ = shared.cancel.cancelled() => break,
            r = listener.accept() => r,
        };
        match accepted {
            Ok((stream, peer)) => {
                consecutive_errors = 0;
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let cancel = shared.cancel.clone();
                    tokio::select! {
                        _ = cancel.cancelled() => {}
                        _ = handle_client(shared, stream, peer) => {}
                    }
                });
            }
            Err(e) => {
                consecutive_errors += 1;
                tracing::warn!("accept failed: {e}");
                // e.g. EMFILE: back off instead of spinning
                tokio::time::sleep(Duration::from_millis(50 * u64::from(consecutive_errors.min(40)))).await;
            }
        }
    }
}

struct ActiveGuard(Arc<Stats>);
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        Stats::dec(&self.0.connections_active);
    }
}

async fn handle_client(shared: Arc<Shared>, stream: TcpStream, peer: SocketAddr) {
    Stats::inc(&shared.stats.connections_total);
    Stats::inc(&shared.stats.connections_active);
    let _guard = ActiveGuard(Arc::clone(&shared.stats));
    let label = peer.to_string();
    crate::net::tune_socket(&stream);

    if let Err(e) = serve_client(&shared, stream, label.clone()).await {
        match e.kind() {
            io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe => tracing::debug!("[{label}] client disconnected: {e}"),
            io::ErrorKind::TimedOut => tracing::warn!("[{label}] timeout during handshake"),
            _ => tracing::error!("[{label}] unexpected: {e}"),
        }
    }
}

enum Init {
    Ready { handshake: [u8; HANDSHAKE_LEN], reader: ClientReader, writer: ClientWriter, label: String },
    Handled,
}

async fn serve_client(shared: &Arc<Shared>, stream: TcpStream, label: String) -> io::Result<()> {
    let cfg = &shared.cfg;
    let (rd, wr) = stream.into_split();
    let Init::Ready { handshake, reader: client_r, writer: client_w, label } =
        read_client_init(shared, rd, wr, label).await?
    else {
        return Ok(());
    };
    let mut client_r = client_r;
    let client_w = client_w;

    let Some(hs) = try_handshake(&handshake, &shared.cfg.secret) else {
        Stats::inc(&shared.stats.connections_bad);
        tracing::warn!("[{label}] bad handshake (wrong secret or proto)");
        // Keep the connection open and silent, like a server that just ignores garbage.
        let mut sink = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(30), async {
            while client_r.read(&mut sink).await.is_ok_and(|n| n > 0) {}
        })
        .await;
        return Ok(());
    };

    let mut dc = hs.dc;
    let is_media = hs.is_media;
    let is_test = cfg.force_test_dc || dc >= 10000;
    if dc >= 10000 {
        tracing::info!("[{label}] test DC{dc} -> DC{}", dc - 10000);
        dc -= 10000;
    }
    let dc_idx = if is_media { -(dc as i32) } else { dc as i32 };
    tracing::debug!(
        "[{label}] handshake ok: DC{dc}{} proto=0x{:08X}",
        if is_media { " media" } else { "" },
        hs.proto_int()
    );

    let session = shared.sessions.open(dc, is_media);
    let meter = session.meter();
    let relay_init = generate_relay_init(hs.proto_tag, dc_idx as i16);
    let ctx = build_crypto_ctx(&hs.prekey_iv, &cfg.secret, &relay_init);
    let media_tag = if is_media { " media" } else { "" };

    let mut direct = shared.pool.get(dc, is_media, is_test);
    if let Some(ws) = direct.as_mut() {
        // A pooled socket can die between the liveness check and now; fall back if so.
        if ws.send(&relay_init).await.is_err() {
            direct = None;
        }
    }
    let mut fresh = false;
    if direct.is_none() {
        // pool empty: a new direct connection beats the Cloudflare route
        if let Some(mut ws) = shared.pool.connect_fresh(dc, is_media, is_test).await {
            if ws.send(&relay_init).await.is_ok() {
                direct = Some(ws);
                fresh = true;
            }
        }
    }

    match direct {
        Some(ws) => {
            tracing::info!("[{label}] DC{dc}{media_tag} -> {}", if fresh { "new direct WS (pool empty)" } else { "WS pool hit" });
            Stats::inc(&shared.stats.connections_ws);
            let splitter = Some(MsgSplitter::new(&relay_init, hs.proto_int()));
            meter.set_route(crate::sessions::Route::Direct);
            bridge_ws(shared, client_r, client_w, ws, &label, ctx, dc, is_media, splitter, meter).await;
        }
        None => {
            tracing::info!("[{label}] DC{dc}{media_tag} WS pool unavailable -> fallback");
            let params = FallbackParams { label: label.clone(), dc, is_test, is_media, relay_init, proto_tag: hs.proto_tag };
            let splitter = Some(MsgSplitter::new(&relay_init, hs.proto_int()));
            if do_fallback(shared, client_r, client_w, &params, ctx, splitter, meter).await {
                tracing::info!("[{label}] DC{dc}{media_tag} fallback closed");
            } else {
                tracing::warn!("[{label}] DC{dc}{media_tag} no fallback available");
            }
        }
    }
    Ok(())
}

async fn with_timeout<T>(fut: impl std::future::Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(INIT_TIMEOUT, fut)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "handshake timed out"))?
}

/// Read the client's first bytes and work out which transport it speaks.
async fn read_client_init(
    shared: &Arc<Shared>,
    mut rd: OwnedReadHalf,
    mut wr: OwnedWriteHalf,
    mut label: String,
) -> io::Result<Init> {
    let cfg = &shared.cfg;
    let masking = cfg.fake_tls_domain.as_str();

    if cfg.proxy_protocol {
        // PROXY protocol v1: a single text line like "PROXY TCP4 1.2.3.4 5.6.7.8 1111 2222"
        let line = with_timeout(async {
            let mut line = Vec::with_capacity(108);
            loop {
                let b = rd.read_u8().await?;
                if b == b'\n' {
                    break;
                }
                line.push(b);
                if line.len() > 256 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "PROXY header too long"));
                }
            }
            Ok(String::from_utf8_lossy(&line).trim().to_owned())
        })
        .await?;
        if line.starts_with("PROXY ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                label = format!("{}:{}", parts[2], parts[4]);
            }
            tracing::debug!("[{label}] PROXY protocol: {line}");
        } else {
            tracing::debug!("[{label}] expected PROXY header, got: {:?}", &line[..line.len().min(60)]);
        }
    }

    let first = with_timeout(async { rd.read_u8().await }).await?;

    if first == TLS_RECORD_HANDSHAKE && !masking.is_empty() {
        let mut hdr_rest = [0u8; 4];
        with_timeout(async { rd.read_exact(&mut hdr_rest).await.map(|_| ()) }).await?;
        let record_len = usize::from(u16::from_be_bytes([hdr_rest[2], hdr_rest[3]]));
        let mut hello = vec![0u8; 5 + record_len];
        hello[0] = first;
        hello[1..5].copy_from_slice(&hdr_rest);
        with_timeout(async { rd.read_exact(&mut hello[5..]).await.map(|_| ()) }).await?;

        let Some(ch) = verify_client_hello(&hello, &cfg.secret) else {
            tracing::debug!("[{label}] Fake TLS verify failed (size={} rec={record_len}) -> masking", hello.len());
            Stats::inc(&shared.stats.connections_masked);
            if let Err(e) = proxy_to_masking_domain(rd, wr, &hello, masking).await {
                tracing::warn!("[{label}] masking: cannot reach {masking}:443: {e}");
            }
            return Ok(Init::Handled);
        };
        tracing::debug!("[{label}] Fake TLS handshake ok (ts={})", ch.timestamp);
        let server_hello = build_server_hello(&cfg.secret, &ch.client_random, &ch.session_id);
        wr.write_all(&server_hello).await?;

        let mut reader = ClientReader::FakeTls(FakeTlsReader::new(rd));
        let writer = ClientWriter::FakeTls(FakeTlsWriter::new(wr));
        let mut handshake = [0u8; HANDSHAKE_LEN];
        with_timeout(reader.read_exact(&mut handshake)).await?;
        return Ok(Init::Ready { handshake, reader, writer, label });
    }

    if !masking.is_empty() {
        tracing::debug!("[{label}] non-TLS byte 0x{first:02X} -> HTTP redirect");
        let redirect = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{masking}/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        wr.write_all(redirect.as_bytes()).await?;
        let _ = wr.shutdown().await;
        return Ok(Init::Handled);
    }

    let mut handshake = [0u8; HANDSHAKE_LEN];
    handshake[0] = first;
    with_timeout(async { rd.read_exact(&mut handshake[1..]).await.map(|_| ()) }).await?;
    Ok(Init::Ready { handshake, reader: ClientReader::Plain(rd), writer: ClientWriter::Plain(wr), label })
}

async fn stats_logger(shared: Arc<Shared>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.tick().await;
    loop {
        tokio::select! {
            _ = shared.cancel.cancelled() => return,
            _ = tick.tick() => tracing::info!("stats: {}", shared.stats.snapshot().summary()),
        }
    }
}

/// Pull the community-maintained Cloudflare domain list now and then; the built-in pool is
/// used until (and unless) a good list arrives.
async fn refresh_cf_domains_loop(shared: Arc<Shared>, url: String) {
    loop {
        refresh_cf_domains(&shared, &url).await;
        tokio::select! {
            _ = shared.cancel.cancelled() => return,
            _ = tokio::time::sleep(CF_REFRESH_INTERVAL) => {}
        }
    }
}

async fn refresh_cf_domains(shared: &Shared, url: &str) {
    let cache_buster: String = (0..7).map(|_| char::from(b'a' + rand::random_range(0..26u8))).collect();
    let fetched = match heli_core::http::get(&format!("{url}?{cache_buster}")).await.and_then(|r| r.ok()) {
        Ok(r) => r.text(),
        Err(e) => {
            tracing::warn!("Failed to fetch CF proxy domain list: {e}");
            return;
        }
    };
    let pool = parse_cf_domain_list(&fetched);
    if pool.len() >= MIN_VALID_CF_DOMAINS {
        shared.balancer.update_domains_list(&pool);
        tracing::info!("CF proxy domain pool updated from GitHub ({} domains)", pool.len());
    } else {
        tracing::warn!("Ignoring fetched CF proxy domains (valid={}, required>={MIN_VALID_CF_DOMAINS})", pool.len());
    }
}

/// Decode, validate and de-duplicate an upstream list payload.
pub fn parse_cf_domain_list(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| decode_cf_domain(l).to_ascii_lowercase())
        .filter(|d| is_valid_domain(d))
        .filter(|d| seen.insert(d.clone()))
        .collect()
}

/// Time for a TCP + TLS handshake with a data center's WebSocket gateway.
///
/// A bare TCP connect is not a trustworthy figure: transparent proxies and TUN-mode VPNs
/// accept the connection locally in under a millisecond. The TLS handshake needs an answer
/// from the real server, so it measures the actual path.
pub async fn measure_dc_latency(ip: Ipv4Addr) -> Option<Duration> {
    use rustls::pki_types::ServerName;
    let started = std::time::Instant::now();
    let work = async {
        let tcp = TcpStream::connect((ip, 443)).await.ok()?;
        let name = ServerName::try_from("kws2.web.telegram.org").ok()?;
        tokio_rustls::TlsConnector::from(heli_core::tls::client_config()).connect(name, tcp).await.ok()?;
        Some(())
    };
    tokio::time::timeout(Duration::from_secs(4), work).await.ok().flatten()?;
    Some(started.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cf_list_is_decoded_validated_and_deduped() {
        let raw = "# comment\nvirkgj.com\nvirkgj.com\n\nnot a domain\nvmmzovy.com\n";
        let d = parse_cf_domain_list(raw);
        assert_eq!(d.len(), 2);
        assert!(d.iter().all(|x| x.ends_with(".co.uk")));
    }
}
