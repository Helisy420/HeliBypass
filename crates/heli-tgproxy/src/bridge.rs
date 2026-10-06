//! Moves bytes between a client and Telegram, re-encrypting on the way, and implements the
//! fallback chain used when no pooled direct WebSocket is available.
//!
//! client ciphertext -> decrypt(client key) -> encrypt(relay key) -> Telegram
//! Telegram ciphertext -> decrypt(relay key) -> encrypt(client key) -> client

use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use cipher::StreamCipher;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

use crate::client_io::{ClientReader, ClientWriter};
use crate::consts::{HANDSHAKE_LEN, default_dc_ip, human_bytes};
use crate::crypto::{Aes256Ctr, CryptoCtx, MsgSplitter};
use crate::sessions::{Meter, Route};
use crate::state::Shared;
use crate::ws::{ConnectOpts, Incoming, WsConn, WsWriter};

const CHUNK: usize = 64 * 1024;

pub struct FallbackParams {
    pub label: String,
    pub dc: u32,
    pub is_test: bool,
    pub is_media: bool,
    pub relay_init: [u8; HANDSHAKE_LEN],
    /// The client's transport (abridged / intermediate / padded intermediate).
    pub proto_tag: [u8; 4],
}

/// Try, in order: Cloudflare worker, Cloudflare-proxied domains, plain TCP.
/// Returns `true` if one of them carried the session (to its end).
pub async fn do_fallback(
    shared: &Arc<Shared>,
    mut client_r: ClientReader,
    mut client_w: ClientWriter,
    p: &FallbackParams,
    mut ctx: CryptoCtx,
    mut splitter: Option<MsgSplitter>,
    meter: &Meter,
) -> bool {
    let cfg = &shared.cfg;
    let fallback_dst = default_dc_ip(p.dc, p.is_test);
    let media_tag = if p.is_media { " media" } else { "" };

    enum Method {
        CfWorker,
        Cf,
        Tcp,
    }
    let mut methods = Vec::new();
    if !cfg.cfproxy_worker_domains.is_empty() && fallback_dst.is_some() {
        methods.push(Method::CfWorker);
    }
    if cfg.fallback_cfproxy && !p.is_test {
        methods.push(Method::Cf);
    }
    if cfg.tcp_fallback && fallback_dst.is_some() {
        methods.push(Method::Tcp);
    }

    for method in methods {
        match method {
            Method::CfWorker => {
                let dst = fallback_dst.expect("checked above");
                let pooled = if p.is_test { None } else { shared.cf_pool.get(p.dc, dst) };
                let found = match pooled {
                    Some(hit) => {
                        tracing::info!("[{}] DC{}{media_tag} -> CF worker pool hit via {} for {dst}", p.label, p.dc, hit.1);
                        Some(hit)
                    }
                    None => {
                        tracing::info!("[{}] DC{}{media_tag} -> trying CF worker for {dst}", p.label, p.dc);
                        shared.cf_pool.connect_one(dst, p.dc).await
                    }
                };
                if let Some((mut ws, _domain)) = found {
                    shared.stats.connections_cfproxy.fetch_add(1, Relaxed);
                    if ws.send(&p.relay_init).await.is_err() {
                        continue;
                    }
                    meter.set_route(Route::Worker);
                    bridge_ws(shared, client_r, client_w, ws, &p.label, ctx, p.dc, p.is_media, None, meter).await;
                    return true;
                }
            }
            Method::Cf => {
                // BETA: media sessions share one HTTP/2 connection per Cloudflare host
                let h2_ok = cfg.h2_media && p.is_media && !p.is_test && !cfg.disable_secure;
                if h2_ok {
                    if let Some(open) = shared.h2.open(p.dc, &p.label, &shared.balancer, &shared.stats).await {
                        shared.stats.connections_h2.fetch_add(1, Relaxed);
                        shared.stats.connections_cfproxy.fetch_add(1, Relaxed);
                        meter.set_route(Route::H2);
                        let CryptoCtx { clt_dec, clt_enc, .. } = ctx;
                        crate::h2media::bridge(
                            open,
                            client_r,
                            client_w,
                            clt_dec,
                            clt_enc,
                            p.proto_tag,
                            &shared.stats,
                            meter,
                            (&shared.up_limit, &shared.down_limit),
                            &shared.cancel,
                        )
                        .await;
                        return true;
                    }
                }
                // a warm spare first (it can have died since the liveness check), then a new one
                let mut ws = None;
                if let Some(mut spare) = shared.cf_route.take(p.dc) {
                    if spare.send(&p.relay_init).await.is_ok() {
                        tracing::info!("[{}] DC{}{media_tag} -> CF proxy pool hit", p.label, p.dc);
                        ws = Some(spare);
                    }
                }
                if ws.is_none() {
                    if let Some(mut fresh) = connect_cf(shared, p.dc, &p.label, media_tag).await {
                        if fresh.send(&p.relay_init).await.is_ok() {
                            ws = Some(fresh);
                        }
                    }
                }
                if let Some(ws) = ws {
                    refill_cf_route(shared, p.dc);
                    shared.stats.connections_cfproxy.fetch_add(1, Relaxed);
                    meter.set_route(Route::Cloudflare);
                    bridge_ws(shared, client_r, client_w, ws, &p.label, ctx, p.dc, p.is_media, splitter.take(), meter).await;
                    return true;
                }
            }
            Method::Tcp => {
                let dst = fallback_dst.expect("checked above");
                if let Some(remote) = connect_tcp(shared, dst, &p.label, &p.relay_init).await {
                    shared.stats.connections_tcp_fallback.fetch_add(1, Relaxed);
                    meter.set_route(Route::Tcp);
                    bridge_tcp(shared, &mut client_r, &mut client_w, remote, &mut ctx, meter).await;
                    client_w.shutdown().await;
                    return true;
                }
            }
        }
    }
    false
}

/// Keep a few connections for `dc`'s Cloudflare route ready in the background.
fn refill_cf_route(shared: &Arc<Shared>, dc: u32) {
    let target = shared.cfg.pool_size.min(crate::pool::CF_ROUTE_SPARES);
    if target == 0 || shared.cancel.is_cancelled() {
        return;
    }
    let Some(needed) = shared.cf_route.begin_refill(dc, target) else { return };
    let shared = Arc::clone(shared);
    tokio::spawn(async move {
        for _ in 0..needed {
            let ws = tokio::select! {
                _ = shared.cancel.cancelled() => break,
                ws = connect_cf(&shared, dc, "pool", "") => ws,
            };
            match ws {
                Some(ws) => shared.cf_route.put(dc, ws),
                None => break,
            }
        }
        shared.cf_route.end_refill(dc);
    });
}

async fn connect_cf(shared: &Arc<Shared>, dc: u32, label: &str, media_tag: &str) -> Option<WsConn> {
    tracing::info!("[{label}] DC{dc}{media_tag} -> trying CF proxy");
    let started = Instant::now();
    for base in shared.balancer.domains_for_dc(dc) {
        let domain = format!("kws{dc}.{base}");
        let opts = ConnectOpts {
            host: &domain,
            domain: &domain,
            path: crate::consts::WS_PATH,
            timeout: Duration::from_secs(10),
            sni: None,
            secure: !shared.cfg.disable_secure,
            buffer_size: shared.cfg.buffer_size,
        };
        match WsConn::connect(&opts).await {
            Ok(ws) => {
                tracing::debug!("[{label}] WS CONNECT DC{dc}{media_tag} route=cf setup_ms={:.0}", started.elapsed().as_secs_f64() * 1000.0);
                if shared.balancer.update_domain_for_dc(dc, &base) {
                    tracing::info!("[{label}] Switched active CF domain");
                }
                return Some(ws);
            }
            Err(e) => tracing::warn!("[{label}] DC{dc}{media_tag} CF proxy failed: {e}"),
        }
    }
    None
}

async fn connect_tcp(shared: &Arc<Shared>, dst: &str, label: &str, relay_init: &[u8]) -> Option<TcpStream> {
    let key = (dst.to_owned(), 443u16);
    if !shared.tcp_backoff.begin(&key) {
        tracing::debug!("[{label}] TCP fallback to {dst}:443 skipped (backoff or connecting)");
        return None;
    }
    tracing::info!("[{label}] TCP fallback to {dst}:443");
    let attempt = async {
        let mut s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect((dst, 443)))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "connect timed out"))??;
        crate::net::tune_socket(&s);
        s.write_all(relay_init).await?;
        Ok::<_, io::Error>(s)
    }
    .await;
    match attempt {
        Ok(s) => {
            shared.tcp_backoff.done(&key, true);
            Some(s)
        }
        Err(e) => {
            let delay = shared.tcp_backoff.done(&key, false).unwrap_or_default();
            tracing::warn!("[{label}] TCP fallback to {dst}:443 failed: {e}; retry in {}s", delay.as_secs());
            None
        }
    }
}

/// Run a client session over an established WebSocket (the relay init must already be sent).
#[allow(clippy::too_many_arguments)]
pub async fn bridge_ws(
    shared: &Arc<Shared>,
    mut client_r: ClientReader,
    mut client_w: ClientWriter,
    ws: WsConn,
    label: &str,
    ctx: CryptoCtx,
    dc: u32,
    is_media: bool,
    splitter: Option<MsgSplitter>,
    meter: &Meter,
) {
    let dc_tag = format!("DC{dc}{}", if is_media { "m" } else { "" });
    let started = Instant::now();
    let CryptoCtx { clt_dec, clt_enc, tg_enc, tg_dec } = ctx;
    let (mut ws_r, ws_w) = ws.split();
    let ws_w = Mutex::new(ws_w);

    let stats = &shared.stats;
    let (mut up_bytes, mut down_bytes, mut up_pkts, mut down_pkts) = (0u64, 0u64, 0u64, 0u64);
    let mut close_reason = String::from("normal");

    {
        let up = upstream_loop(&mut client_r, &ws_w, clt_dec, tg_enc, splitter, stats, meter, &shared.up_limit, &mut up_bytes, &mut up_pkts);
        let down =
            downstream_loop(&mut ws_r, &ws_w, &mut client_w, tg_dec, clt_enc, stats, meter, &shared.down_limit, &mut down_bytes, &mut down_pkts);
        tokio::pin!(up, down);
        tokio::select! {
            r = &mut up => if let Err(e) = r { close_reason = format!("client: {e}"); },
            r = &mut down => match r {
                Ok(()) => close_reason = "upstream: ws_close".into(),
                Err(e) => close_reason = format!("upstream: {e}"),
            },
            _ = shared.cancel.cancelled() => close_reason = "proxy stopped".into(),
        }
    }

    tracing::info!(
        "[{label}] {dc_tag} WS session closed ({close_reason}): ^{} ({up_pkts} pkts) v{} ({down_pkts} pkts) in {:.1}s",
        human_bytes(up_bytes),
        human_bytes(down_bytes),
        started.elapsed().as_secs_f64()
    );
    let mut w = ws_w.lock().await;
    let _ = w.send_close(&[]).await;
    w.shutdown().await;
    drop(w);
    client_w.shutdown().await;
}

#[allow(clippy::too_many_arguments)]
async fn upstream_loop(
    client_r: &mut ClientReader,
    ws_w: &Mutex<WsWriter>,
    mut clt_dec: Aes256Ctr,
    mut tg_enc: Aes256Ctr,
    mut splitter: Option<MsgSplitter>,
    stats: &crate::stats::Stats,
    meter: &Meter,
    limit: &crate::ratelimit::RateLimit,
    up_bytes: &mut u64,
    up_pkts: &mut u64,
) -> io::Result<()> {
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = client_r.read(&mut buf).await?;
        if n == 0 {
            if let Some(tail) = splitter.as_mut().and_then(|s| s.flush()) {
                ws_w.lock().await.send(&tail).await?;
            }
            return Ok(());
        }
        stats.bytes_up.fetch_add(n as u64, Relaxed);
        meter.add_up(n);
        *up_bytes += n as u64;
        limit.consume(n).await;
        *up_pkts += 1;
        let chunk = &mut buf[..n];
        clt_dec.apply_keystream(chunk);
        tg_enc.apply_keystream(chunk);
        match splitter.as_mut() {
            Some(sp) => {
                let parts = sp.split(chunk);
                match parts.len() {
                    0 => {}
                    1 => ws_w.lock().await.send(&parts[0]).await?,
                    _ => ws_w.lock().await.send_batch(&parts).await?,
                }
            }
            None => ws_w.lock().await.send(chunk).await?,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn downstream_loop(
    ws_r: &mut crate::ws::WsReader,
    ws_w: &Mutex<WsWriter>,
    client_w: &mut ClientWriter,
    mut tg_dec: Aes256Ctr,
    mut clt_enc: Aes256Ctr,
    stats: &crate::stats::Stats,
    meter: &Meter,
    limit: &crate::ratelimit::RateLimit,
    down_bytes: &mut u64,
    down_pkts: &mut u64,
) -> Result<(), crate::ws::WsError> {
    loop {
        // cut-through: forward each part of a (possibly huge) frame as soon as it arrives
        match ws_r.recv_stream().await? {
            Incoming::Data(mut data) => {
                let n = data.len() as u64;
                stats.bytes_down.fetch_add(n, Relaxed);
                meter.add_down(n as usize);
                *down_bytes += n;
                limit.consume(n as usize).await;
                *down_pkts += 1;
                tg_dec.apply_keystream(&mut data);
                clt_enc.apply_keystream(&mut data);
                client_w.write_all(&data).await?;
            }
            Incoming::Ping(payload) => ws_w.lock().await.send_pong(&payload).await?,
            Incoming::Close(payload) => {
                let _ = ws_w.lock().await.send_close(&payload).await;
                tracing::debug!("WS OP_CLOSE from upstream: {}", describe_close(&payload));
                return Ok(());
            }
        }
    }
}

fn describe_close(payload: &[u8]) -> String {
    if payload.len() < 2 {
        return "no status".into();
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let name = match code {
        1000 => "normal",
        1001 => "going_away",
        1002 => "protocol_error",
        1003 => "unsupported_data",
        1006 => "abnormal",
        1007 => "bad_data",
        1008 => "policy_violation",
        1009 => "too_big",
        1010 => "missing_extension",
        1011 => "internal_error",
        _ => "?",
    };
    format!("code={code} ({name}) {}", String::from_utf8_lossy(&payload[2..]))
}

/// Client <-> Telegram over plain TCP with re-encryption (the last-resort fallback).
async fn bridge_tcp(
    shared: &Arc<Shared>,
    client_r: &mut ClientReader,
    client_w: &mut ClientWriter,
    remote: TcpStream,
    ctx: &mut CryptoCtx,
    meter: &Meter,
) {
    let (mut remote_r, mut remote_w): (OwnedReadHalf, OwnedWriteHalf) = remote.into_split();
    let stats = &shared.stats;
    let CryptoCtx { clt_dec, clt_enc, tg_enc, tg_dec } = ctx;

    {
        let up = async {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = client_r.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<(), io::Error>(());
                }
                stats.bytes_up.fetch_add(n as u64, Relaxed);
                meter.add_up(n);
                shared.up_limit.consume(n).await;
                clt_dec.apply_keystream(&mut buf[..n]);
                tg_enc.apply_keystream(&mut buf[..n]);
                remote_w.write_all(&buf[..n]).await?;
            }
        };
        let down = async {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = remote_r.read(&mut buf).await?;
                if n == 0 {
                    return Ok::<(), io::Error>(());
                }
                stats.bytes_down.fetch_add(n as u64, Relaxed);
                meter.add_down(n);
                shared.down_limit.consume(n).await;
                tg_dec.apply_keystream(&mut buf[..n]);
                clt_enc.apply_keystream(&mut buf[..n]);
                client_w.write_all(&buf[..n]).await?;
            }
        };
        tokio::pin!(up, down);
        tokio::select! {
            r = &mut up => { if let Err(e) = r { tracing::debug!("forward ended: {e}"); } }
            r = &mut down => { if let Err(e) = r { tracing::debug!("forward ended: {e}"); } }
            _ = shared.cancel.cancelled() => {}
        }
    }
    let _ = remote_w.shutdown().await;
}
