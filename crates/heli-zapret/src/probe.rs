//! Network probes used by the strategy tests. They replace the `curl.exe`/PowerShell
//! calls of the upstream test script with in-process TLS connections (rustls), which makes
//! them faster, parallel without subprocesses, and independent of the installed curl build.

use std::io;
use std::time::{Duration, Instant};

use heli_core::tls::{self, TlsVersions};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProbeStatus {
    Ok,
    /// Connection reset/timeout/handshake failure: what DPI blocking typically looks like.
    Error,
    /// The server (or our TLS stack) does not support this protocol version.
    Unsupported,
    /// Certificate problem: usually a hijacked or intercepted connection.
    Cert,
    /// Name resolution failed.
    Dns,
}

impl ProbeStatus {
    pub fn label(self) -> &'static str {
        match self {
            ProbeStatus::Ok => "OK",
            ProbeStatus::Error => "ERROR",
            ProbeStatus::Unsupported => "UNSUP",
            ProbeStatus::Cert => "SSL",
            ProbeStatus::Dns => "DNS",
        }
    }
}

fn classify(e: &io::Error) -> ProbeStatus {
    if let Some(re) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        use rustls::AlertDescription::{HandshakeFailure, ProtocolVersion};
        return match re {
            rustls::Error::InvalidCertificate(_) => ProbeStatus::Cert,
            rustls::Error::PeerIncompatible(_) => ProbeStatus::Unsupported,
            rustls::Error::AlertReceived(ProtocolVersion) => ProbeStatus::Unsupported,
            rustls::Error::AlertReceived(HandshakeFailure) => ProbeStatus::Error,
            _ => ProbeStatus::Error,
        };
    }
    ProbeStatus::Error
}

async fn resolve_connect(host: &str, port: u16, connect_timeout: Duration) -> Result<TcpStream, ProbeStatus> {
    let addrs: Vec<_> = match tokio::net::lookup_host((host, port)).await {
        Ok(a) => a.collect(),
        Err(_) => return Err(ProbeStatus::Dns),
    };
    if addrs.is_empty() {
        return Err(ProbeStatus::Dns);
    }
    for addr in addrs {
        if let Ok(Ok(s)) = tokio::time::timeout(connect_timeout, TcpStream::connect(addr)).await {
            s.set_nodelay(true).ok();
            return Ok(s);
        }
    }
    Err(ProbeStatus::Error)
}

/// `HEAD /` over TLS (forcing the given protocol version) or plain HTTP when `port == 80`.
/// Any HTTP status line counts as success - the question is only whether the path works.
pub async fn http_probe(host: &str, port: u16, versions: TlsVersions, total: Duration) -> ProbeStatus {
    let work = async {
        let tcp = match resolve_connect(host, port, Duration::from_secs(2).min(total)).await {
            Ok(s) => s,
            Err(st) => return st,
        };
        let request = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: HeliBypass\r\nAccept: */*\r\nConnection: close\r\n\r\n");
        if port == 80 {
            return read_status_line(tcp, &request).await;
        }
        let Ok(name) = ServerName::try_from(host.to_owned()) else { return ProbeStatus::Error };
        match TlsConnector::from(tls::client_config_versioned(versions)).connect(name, tcp).await {
            Ok(stream) => read_status_line(stream, &request).await,
            Err(e) => classify(&e),
        }
    };
    tokio::time::timeout(total, work).await.unwrap_or(ProbeStatus::Error)
}

async fn read_status_line<S: AsyncReadExt + AsyncWriteExt + Unpin>(mut s: S, request: &str) -> ProbeStatus {
    if s.write_all(request.as_bytes()).await.is_err() {
        return ProbeStatus::Error;
    }
    let mut buf = [0u8; 16];
    let mut got = 0;
    while got < 5 {
        match s.read(&mut buf[got..]).await {
            Ok(0) => return ProbeStatus::Error,
            Ok(n) => got += n,
            // a missing close_notify after the data is still "we got an answer"
            Err(_) if got >= 5 => break,
            Err(_) => return ProbeStatus::Error,
        }
    }
    if &buf[..5] == b"HTTP/" { ProbeStatus::Ok } else { ProbeStatus::Error }
}

/// Time to establish TCP + TLS to `host:443`; a cheap "is it reachable and how fast" figure.
pub async fn tls_latency(host: &str, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    let work = async {
        let tcp = resolve_connect(host, 443, timeout).await.ok()?;
        let name = ServerName::try_from(host.to_owned()).ok()?;
        TlsConnector::from(tls::client_config()).connect(name, tcp).await.ok()?;
        Some(())
    };
    tokio::time::timeout(timeout, work).await.ok().flatten()?;
    Some(start.elapsed())
}

/// ICMP echo round-trip time via the Windows IP helper API (IPv4 only).
pub async fn ping(host: &str, timeout: Duration) -> Option<Duration> {
    let host = host.to_owned();
    let ip = tokio::net::lookup_host((host.as_str(), 0)).await.ok()?.find_map(|a| match a.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    })?;
    tokio::task::spawn_blocking(move || icmp_echo(ip, timeout)).await.ok().flatten()
}

fn icmp_echo(ip: std::net::Ipv4Addr, timeout: Duration) -> Option<Duration> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{ICMP_ECHO_REPLY, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho};
    // The reply buffer must hold one ICMP_ECHO_REPLY plus the echoed payload plus 8 bytes of
    // error data; use u64 storage so the struct is suitably aligned.
    let payload = b"HeliBypass-ping!";
    let mut reply = vec![0u64; (std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 64).div_ceil(8)];
    // SAFETY: the handle is closed on every path; buffers outlive the synchronous call.
    unsafe {
        let h = IcmpCreateFile();
        if h.is_null() || h as isize == -1 {
            return None;
        }
        let dest = u32::from_le_bytes(ip.octets());
        let n = IcmpSendEcho(
            h,
            dest,
            payload.as_ptr().cast(),
            payload.len() as u16,
            std::ptr::null(),
            reply.as_mut_ptr().cast(),
            (reply.len() * 8) as u32,
            timeout.as_millis().min(u128::from(u32::MAX)) as u32,
        );
        let result = if n > 0 {
            let r = &*(reply.as_ptr().cast::<ICMP_ECHO_REPLY>());
            (r.Status == 0).then(|| Duration::from_millis(u64::from(r.RoundTripTime)))
        } else {
            None
        };
        IcmpCloseHandle(h);
        result
    }
}

// ───────────────────────────── long transfers ─────────────────────────────

/// `GET https://host:port/path` and keep reading until `min_bytes` of body arrived (or the whole
/// body, if it is smaller). A connection that stalls part-way through is what the Russian
/// "16-20 KB" blocking and over-fragmented desync both look like, so it counts as an error.
/// Returns the body throughput in bytes per second on success.
pub async fn transfer_probe(host: &str, port: u16, path: &str, min_bytes: usize, total: Duration) -> (ProbeStatus, Option<f64>) {
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    let body_bytes = AtomicUsize::new(0);
    let work = async {
        let tcp = resolve_connect(host, port, Duration::from_secs(3).min(total)).await?;
        let name = ServerName::try_from(host.to_owned()).map_err(|_| ProbeStatus::Error)?;
        let mut s = TlsConnector::from(tls::client_config()).connect(name, tcp).await.map_err(|e| classify(&e))?;
        let started = Instant::now();
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) HeliBypass\r\n\
             Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.map_err(|_| ProbeStatus::Error)?;
        let mut head = Vec::new();
        let mut buf = vec![0u8; 32 * 1024];
        let mut content_length: Option<usize> = None;
        let mut in_body = false;
        loop {
            let n = match s.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => n,
                // a missing close_notify after a complete body is fine; judged below
                Err(_) => break,
            };
            if in_body {
                body_bytes.fetch_add(n, Relaxed);
            } else {
                head.extend_from_slice(&buf[..n]);
                if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    let text = String::from_utf8_lossy(&head[..end]).to_ascii_lowercase();
                    if !text.starts_with("http/") {
                        return Err(ProbeStatus::Error);
                    }
                    content_length = text.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse().ok());
                    body_bytes.fetch_add(head.len() - end - 4, Relaxed);
                    in_body = true;
                }
            }
            if body_bytes.load(Relaxed) >= min_bytes {
                break;
            }
        }
        let got = body_bytes.load(Relaxed);
        let wanted = content_length.map_or(min_bytes, |c| c.min(min_bytes));
        if in_body && got >= wanted && got > 0 {
            Ok(got as f64 / started.elapsed().as_secs_f64().max(0.001))
        } else {
            Err(ProbeStatus::Error)
        }
    };
    match tokio::time::timeout(total, work).await {
        Ok(Ok(rate)) => (ProbeStatus::Ok, Some(rate)),
        Ok(Err(st)) => (st, None),
        Err(_) => (ProbeStatus::Error, None),
    }
}

// ───────────────────────────── Discord ─────────────────────────────

/// Discord's real-time gateway is one long-lived WebSocket. Open it, wait for HELLO and send a
/// few heartbeats, each of which must be acknowledged: a strategy that breaks long connections
/// (or gets them noticed and cut) fails here even when single requests work.
pub async fn discord_gateway_probe(heartbeats: u32, total: Duration) -> ProbeStatus {
    let work = async {
        let host = "gateway.discord.gg";
        let tcp = resolve_connect(host, 443, Duration::from_secs(3)).await?;
        let name = ServerName::try_from(host).map_err(|_| ProbeStatus::Error)?;
        let mut s = TlsConnector::from(tls::client_config()).connect(name, tcp).await.map_err(|e| classify(&e))?;
        let req = "GET /?v=10&encoding=json HTTP/1.1\r\nHost: gateway.discord.gg\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nUser-Agent: HeliBypass\r\n\r\n";
        s.write_all(req.as_bytes()).await.map_err(|_| ProbeStatus::Error)?;
        let mut rbuf: Vec<u8> = Vec::new();
        let mut tmp = [0u8; 8192];
        // upgrade response
        let end = loop {
            if let Some(p) = rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p;
            }
            let n = s.read(&mut tmp).await.map_err(|_| ProbeStatus::Error)?;
            if n == 0 || rbuf.len() > 16 * 1024 {
                return Err(ProbeStatus::Error);
            }
            rbuf.extend_from_slice(&tmp[..n]);
        };
        if !rbuf.starts_with(b"HTTP/1.1 101") {
            return Err(ProbeStatus::Error);
        }
        rbuf.drain(..end + 4);
        // HELLO (op 10)
        ws_wait_for(&mut s, &mut rbuf, "\"op\":10").await?;
        for _ in 0..heartbeats {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            ws_send_text(&mut s, br#"{"op":1,"d":null}"#).await?;
            ws_wait_for(&mut s, &mut rbuf, "\"op\":11").await?;
        }
        let _ = ws_send_close(&mut s).await;
        Ok(())
    };
    match tokio::time::timeout(total, work).await {
        Ok(Ok(())) => ProbeStatus::Ok,
        Ok(Err(st)) => st,
        Err(_) => ProbeStatus::Error,
    }
}

/// Read server frames until a text frame contains `needle`.
async fn ws_wait_for<S: AsyncReadExt + Unpin>(s: &mut S, rbuf: &mut Vec<u8>, needle: &str) -> Result<(), ProbeStatus> {
    let mut tmp = [0u8; 8192];
    loop {
        while let Some((opcode, payload, used)) = ws_parse(rbuf) {
            rbuf.drain(..used);
            match opcode {
                0x8 => return Err(ProbeStatus::Error), // closed by the server
                0x1 | 0x0 if String::from_utf8_lossy(&payload).replace(' ', "").contains(needle) => return Ok(()),
                _ => {}
            }
        }
        let n = s.read(&mut tmp).await.map_err(|_| ProbeStatus::Error)?;
        if n == 0 {
            return Err(ProbeStatus::Error);
        }
        rbuf.extend_from_slice(&tmp[..n]);
    }
}

/// One complete (unmasked) server frame: opcode, payload, bytes consumed.
fn ws_parse(b: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if b.len() < 2 {
        return None;
    }
    let opcode = b[0] & 0x0F;
    let (len, hdr) = match b[1] & 0x7F {
        126 if b.len() >= 4 => (usize::from(u16::from_be_bytes([b[2], b[3]])), 4),
        127 if b.len() >= 10 => (u64::from_be_bytes(b[2..10].try_into().ok()?) as usize, 10),
        126 | 127 => return None,
        n => (usize::from(n), 2),
    };
    let hdr = if b[1] & 0x80 != 0 { hdr + 4 } else { hdr };
    if b.len() < hdr + len {
        return None;
    }
    Some((opcode, b[hdr..hdr + len].to_vec(), hdr + len))
}

async fn ws_send_text<S: AsyncWriteExt + Unpin>(s: &mut S, text: &[u8]) -> Result<(), ProbeStatus> {
    let mut frame = vec![0x81, 0x80 | text.len() as u8];
    let key: [u8; 4] = rand::random();
    frame.extend_from_slice(&key);
    frame.extend(text.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
    s.write_all(&frame).await.map_err(|_| ProbeStatus::Error)
}

async fn ws_send_close<S: AsyncWriteExt + Unpin>(s: &mut S) -> std::io::Result<()> {
    let key: [u8; 4] = rand::random();
    let code = [0x03 ^ key[0], 0xE8 ^ key[1]];
    s.write_all(&[0x88, 0x82, key[0], key[1], key[2], key[3], code[0], code[1]]).await
}

/// Discord publishes its nearest voice regions with server IPs at `latency.discord.media/rtc`;
/// the same host also answers on the extra media ports (2053, 8443, ...) that strategies treat
/// separately. Returns the outcome and the voice server addresses of the nearest regions.
pub async fn discord_rtc_probe(port: u16, total: Duration) -> (ProbeStatus, Vec<String>) {
    let work = async {
        let host = "latency.discord.media";
        let tcp = resolve_connect(host, port, Duration::from_secs(3)).await?;
        let name = ServerName::try_from(host).map_err(|_| ProbeStatus::Error)?;
        let mut s = TlsConnector::from(tls::client_config()).connect(name, tcp).await.map_err(|e| classify(&e))?;
        let req = format!("GET /rtc HTTP/1.1\r\nHost: {host}\r\nUser-Agent: HeliBypass\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
        s.write_all(req.as_bytes()).await.map_err(|_| ProbeStatus::Error)?;
        let mut all = Vec::new();
        let _ = s.read_to_end(&mut all).await;
        let text = String::from_utf8_lossy(&all);
        let body = text.split_once("\r\n\r\n").map(|(h, b)| (h.starts_with("HTTP/1.1 200"), b)).filter(|(ok, _)| *ok).map(|(_, b)| b);
        let Some(body) = body else { return Err(ProbeStatus::Error) };
        let start = body.find('[').ok_or(ProbeStatus::Error)?;
        let end = body.rfind(']').ok_or(ProbeStatus::Error)?;
        let regions: serde_json::Value = serde_json::from_str(&body[start..=end]).map_err(|_| ProbeStatus::Error)?;
        let ips = regions
            .as_array()
            .into_iter()
            .flatten()
            .take(2)
            .flat_map(|r| r.get("ips").and_then(|v| v.as_array()).cloned().unwrap_or_default())
            .filter_map(|ip| ip.as_str().map(str::to_owned))
            .collect::<Vec<_>>();
        Ok(ips)
    };
    match tokio::time::timeout(total, work).await {
        Ok(Ok(ips)) => (ProbeStatus::Ok, ips),
        Ok(Err(st)) => (st, Vec::new()),
        Err(_) => (ProbeStatus::Error, Vec::new()),
    }
}

/// Whether any of the given addresses accepts a TCP connection on `port` (voice servers are
/// reached by IP, so this is where IP-level blocking shows up).
pub async fn any_tcp_reachable(ips: &[String], port: u16, each: Duration) -> ProbeStatus {
    let mut set = tokio::task::JoinSet::new();
    for ip in ips.iter().take(4).cloned() {
        set.spawn(async move { tokio::time::timeout(each, TcpStream::connect((ip.as_str(), port))).await.is_ok_and(|r| r.is_ok()) });
    }
    while let Some(r) = set.join_next().await {
        if r.unwrap_or(false) {
            return ProbeStatus::Ok;
        }
    }
    ProbeStatus::Error
}

// ───────────────────────────── DPI "16-20 KB freeze" check ─────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DpiStatus {
    Ok,
    Fail,
    Unsupported,
    /// Upload stalled and nothing came back: the classic signature of a censor cutting the
    /// connection after ~16-20 KB.
    LikelyBlocked,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DpiLine {
    pub label: String,
    pub status: DpiStatus,
    pub up_bytes: u64,
    pub down_bytes: u64,
    pub seconds: f64,
}

/// POST `payload` to `https://host` and see what comes back, bounded by `timeout`.
pub async fn dpi_probe(host: &str, label: &str, versions: TlsVersions, payload: &[u8], timeout: Duration) -> DpiLine {
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    let started = Instant::now();
    // shared with the timed future so the counts survive it being cut off
    let up = AtomicU64::new(0);
    let down = AtomicU64::new(0);

    let work = async {
        let tcp = resolve_connect(host, 443, timeout.min(Duration::from_secs(3))).await.map_err(|_| DpiStatus::Fail)?;
        let name = ServerName::try_from(host.to_owned()).map_err(|_| DpiStatus::Fail)?;
        let mut stream = match TlsConnector::from(tls::client_config_versioned(versions)).connect(name, tcp).await {
            Ok(s) => s,
            Err(e) => {
                return Err(if classify(&e) == ProbeStatus::Unsupported { DpiStatus::Unsupported } else { DpiStatus::Fail });
            }
        };
        let head = format!(
            "POST / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: HeliBypass\r\nAccept: */*\r\nRange: bytes=0-{}\r\n\
             Content-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len().saturating_sub(1),
            payload.len()
        );
        stream.write_all(head.as_bytes()).await.map_err(|_| DpiStatus::Fail)?;
        for chunk in payload.chunks(4096) {
            stream.write_all(chunk).await.map_err(|_| DpiStatus::Fail)?;
            up.fetch_add(chunk.len() as u64, Relaxed);
        }
        stream.flush().await.ok();
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => {
                down.fetch_add(n as u64, Relaxed);
                Ok(())
            }
            _ => Err(DpiStatus::Fail),
        }
    };
    let (result, timed_out) = match tokio::time::timeout(timeout, work).await {
        Ok(r) => (r, false),
        Err(_) => (Err(DpiStatus::Fail), true),
    };
    let (up, down) = (up.load(Relaxed), down.load(Relaxed));
    let status = match result {
        Ok(()) => DpiStatus::Ok,
        // stalled with data sent and nothing received until the deadline = a censor cutting us off
        Err(DpiStatus::Fail) if timed_out && up > 0 && down == 0 => DpiStatus::LikelyBlocked,
        Err(s) => s,
    };
    DpiLine { label: label.to_owned(), status, up_bytes: up, down_bytes: down, seconds: started.elapsed().as_secs_f64() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn http_probe_distinguishes_ok_error_and_dns() {
        // a local plain-HTTP server answering any request
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = l.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut b = [0u8; 256];
                    let _ = s.read(&mut b).await;
                    let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
                });
            }
        });
        // plain HTTP path is taken for port 80 only, so exercise read_status_line directly
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(read_status_line(tcp, "HEAD / HTTP/1.1\r\n\r\n").await, ProbeStatus::Ok);

        // a server that accepts and immediately closes
        let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port2 = l2.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (s, _) = l2.accept().await.unwrap();
            drop(s);
        });
        let tcp = TcpStream::connect(("127.0.0.1", port2)).await.unwrap();
        assert_eq!(read_status_line(tcp, "HEAD / HTTP/1.1\r\n\r\n").await, ProbeStatus::Error);

        assert_eq!(
            http_probe("nonexistent-host.invalid", 443, TlsVersions::Any, Duration::from_secs(3)).await,
            ProbeStatus::Dns
        );
    }

    #[tokio::test]
    async fn ping_loopback() {
        let rtt = ping("127.0.0.1", Duration::from_secs(1)).await;
        assert!(rtt.is_some_and(|d| d < Duration::from_millis(500)), "{rtt:?}");
    }

    #[tokio::test]
    #[ignore = "needs internet access"]
    async fn live_long_connection_and_discord_probes() {
        let (st, rate) = transfer_probe("www.youtube.com", 443, "/", 256 * 1024, Duration::from_secs(10)).await;
        assert_eq!(st, ProbeStatus::Ok);
        assert!(rate.unwrap() > 10_000.0, "{rate:?}");
        assert_eq!(discord_gateway_probe(2, Duration::from_secs(12)).await, ProbeStatus::Ok);
        let (st, ips) = discord_rtc_probe(8443, Duration::from_secs(6)).await;
        assert_eq!(st, ProbeStatus::Ok);
        assert!(!ips.is_empty());
        assert_eq!(discord_rtc_probe(2053, Duration::from_secs(6)).await.0, ProbeStatus::Ok);
    }

    #[test]
    fn websocket_frames_parse() {
        assert_eq!(ws_parse(&[0x81, 0x02, b'h', b'i']), Some((1, b"hi".to_vec(), 4)));
        assert_eq!(ws_parse(&[0x81, 0x05, b'h']), None, "incomplete");
        let mut long = vec![0x81, 126, 0x01, 0x00];
        long.extend(vec![b'x'; 256]);
        assert_eq!(ws_parse(&long).map(|(o, p, u)| (o, p.len(), u)), Some((1, 256, 260)));
    }

    #[tokio::test]
    #[ignore = "needs internet access"]
    async fn live_probes_against_the_internet() {
        for v in [TlsVersions::Any, TlsVersions::Tls12, TlsVersions::Tls13] {
            assert_eq!(http_probe("www.cloudflare.com", 443, v, Duration::from_secs(5)).await, ProbeStatus::Ok, "{v:?}");
        }
        assert!(tls_latency("www.google.com", Duration::from_secs(5)).await.is_some());
        assert!(ping("1.1.1.1", Duration::from_secs(2)).await.is_some());
        let payload = vec![0x5Au8; 16 * 1024];
        let line = dpi_probe("www.cloudflare.com", "TLS1.3", TlsVersions::Tls13, &payload, Duration::from_secs(5)).await;
        assert_eq!(line.status, DpiStatus::Ok, "{line:?}");
    }
}
