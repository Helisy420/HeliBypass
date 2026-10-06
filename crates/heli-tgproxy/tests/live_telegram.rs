//! Live end-to-end tests against the real Telegram network (run with `-- --ignored`).
//!
//! A tiny MTProto client connects to the proxy, performs the obfuscated2 handshake, sends an
//! unencrypted `req_pq_multi` and expects a `resPQ` that echoes its nonce. If that works, the
//! whole chain (handshake -> pool/fallback -> WebSocket or TCP -> re-encryption) is correct.

use std::time::Duration;

use cipher::StreamCipher;
use heli_tgproxy::ProxyConfig;
use heli_tgproxy::crypto::{new_ctr, random_bytes};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const RES_PQ: u32 = 0x0516_2463;
const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Returns true if Telegram answered the `req_pq_multi` through the proxy.
async fn pq_probe(port: u16, secret: [u8; 16], dc: i16, wait: Duration) -> Result<bool, String> {
    // --- obfuscated2 client init ---
    let mut init = loop {
        let c: [u8; 64] = random_bytes();
        if c[0] != 0xEF && c[4..8] != [0; 4] && !matches!(&c[..4], b"HEAD" | b"POST" | b"GET " | [0xEE, 0xEE, 0xEE, 0xEE]) {
            break c;
        }
    };
    let mut plain = init;
    plain[56..60].copy_from_slice(&[0xEF; 4]); // abridged
    plain[60..62].copy_from_slice(&dc.to_le_bytes());
    let key = sha256(&[&init[8..40], &secret]);
    let mut enc = new_ctr(&key, &init[40..56]);
    let mut wire = plain;
    enc.apply_keystream(&mut wire); // advances the stream past the 64 byte init
    init[56..64].copy_from_slice(&wire[56..64]);

    let mut rev = [0u8; 48];
    rev.copy_from_slice(&init[8..56]);
    rev.reverse();
    let dec_key = sha256(&[&rev[..32], &secret]);
    let mut dec = new_ctr(&dec_key, &rev[32..]);

    // --- unencrypted req_pq_multi: auth_key_id(0) msg_id len constructor nonce ---
    let nonce: [u8; 16] = random_bytes();
    let msg_id: u64 = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() << 32) | 4;
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0u8; 8]);
    msg.extend_from_slice(&msg_id.to_le_bytes());
    msg.extend_from_slice(&20u32.to_le_bytes());
    msg.extend_from_slice(&REQ_PQ_MULTI.to_le_bytes());
    msg.extend_from_slice(&nonce);
    assert_eq!(msg.len() % 4, 0);
    let mut packet = vec![(msg.len() / 4) as u8]; // abridged length prefix
    packet.extend_from_slice(&msg);
    enc.apply_keystream(&mut packet);

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
    stream.write_all(&init).await.map_err(|e| e.to_string())?;
    stream.write_all(&packet).await.map_err(|e| e.to_string())?;

    // --- read the reply: abridged length byte, then the packet ---
    let mut buf = vec![0u8; 512];
    let n = tokio::time::timeout(wait, stream.read(&mut buf))
        .await
        .map_err(|_| "timed out waiting for resPQ".to_string())?
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(false);
    }
    buf.truncate(n);
    dec.apply_keystream(&mut buf);
    let words = buf[0] as usize;
    if words == 1 {
        // a 4 byte transport error code (e.g. -404) instead of a packet
        return Err(format!("transport error {}", i32::from_le_bytes(buf[1..5].try_into().unwrap())));
    }
    // body = auth_key_id(8) msg_id(8) len(4) constructor(4) nonce(16) ...
    let body = &buf[1..];
    if body.len() < 40 {
        return Err(format!("short reply ({} bytes)", body.len()));
    }
    let ctor = u32::from_le_bytes(body[20..24].try_into().unwrap());
    Ok(ctor == RES_PQ && body[24..40] == nonce)
}

fn test_config(port: u16, pool_size: usize, cf: bool, tcp: bool) -> ProxyConfig {
    ProxyConfig {
        host: "127.0.0.1".into(),
        port,
        pool_size,
        fallback_cfproxy: cf,
        tcp_fallback: tcp,
        cf_domains_url: None,
        ..ProxyConfig::default()
    }
}

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

#[tokio::test]
#[ignore = "needs access to the Telegram network"]
async fn direct_websocket_path_reaches_telegram() {
    let port = free_port().await;
    let cfg = test_config(port, 2, false, false);
    let secret = cfg.secret;
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    // give the pool a moment to warm up so we exercise the pooled path
    tokio::time::sleep(Duration::from_secs(3)).await;
    let ok = pq_probe(port, secret, 2, Duration::from_secs(15)).await.expect("probe");
    let stats = proxy.stats();
    proxy.stop().await;
    assert!(ok, "resPQ not received; stats: {}", stats.summary());
    assert_eq!(stats.connections_ws, 1, "session should have used the WS pool: {}", stats.summary());
}

#[tokio::test]
#[ignore = "needs access to the Telegram network"]
async fn plain_tcp_fallback_reaches_telegram() {
    let port = free_port().await;
    let cfg = test_config(port, 0, false, true);
    let secret = cfg.secret;
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    let ok = pq_probe(port, secret, 2, Duration::from_secs(15)).await.expect("probe");
    let stats = proxy.stats();
    proxy.stop().await;
    assert!(ok, "resPQ not received; stats: {}", stats.summary());
    assert_eq!(stats.connections_tcp_fallback, 1, "{}", stats.summary());
}

#[tokio::test]
#[ignore = "needs access to the Telegram network"]
async fn media_dc_over_websocket() {
    let port = free_port().await;
    let cfg = test_config(port, 1, false, true);
    let secret = cfg.secret;
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let ok = pq_probe(port, secret, -2, Duration::from_secs(15)).await.expect("probe");
    let stats = proxy.stats();
    proxy.stop().await;
    assert!(ok, "resPQ not received for media DC; stats: {}", stats.summary());
}

#[tokio::test]
async fn wrong_secret_is_rejected_quietly() {
    let port = free_port().await;
    let cfg = test_config(port, 0, false, false);
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    let r = pq_probe(port, [9u8; 16], 2, Duration::from_secs(2)).await;
    // the proxy must not answer a client that does not know the secret
    assert!(matches!(r, Err(_) | Ok(false)), "unexpected success with the wrong secret: {r:?}");
    let stats = proxy.stats();
    proxy.stop().await;
    assert_eq!(stats.connections_bad, 1);
}

/// DCs without a configured gateway take the Cloudflare route; a second session reuses the
/// warm connection the first one left behind.
#[tokio::test]
#[ignore = "needs access to the Telegram network"]
async fn cloudflare_route_reaches_telegram_and_keeps_a_spare() {
    let port = free_port().await;
    let cfg = ProxyConfig { dc_redirects: Default::default(), ..test_config(port, 2, true, false) };
    let secret = cfg.secret;
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    let first = pq_probe(port, secret, 5, Duration::from_secs(25)).await.expect("probe");
    tokio::time::sleep(Duration::from_secs(4)).await; // the spare is opened in the background
    let second = pq_probe(port, secret, 5, Duration::from_secs(25)).await.expect("probe");
    let stats = proxy.stats();
    proxy.stop().await;
    assert!(first && second, "resPQ not received; stats: {}", stats.summary());
    assert_eq!(stats.connections_cfproxy, 2, "{}", stats.summary());
}

/// BETA: a media session on the Cloudflare route is carried over HTTP/2 (`/api`).
#[tokio::test]
#[ignore = "needs access to the Telegram network"]
async fn media_over_http2_booster_reaches_telegram() {
    let port = free_port().await;
    let cfg = ProxyConfig { dc_redirects: Default::default(), h2_media: true, ..test_config(port, 2, true, false) };
    let secret = cfg.secret;
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    let mut results = Vec::new();
    for dc in [-5i16, -2, -4] {
        results.push((dc, pq_probe(port, secret, dc, Duration::from_secs(25)).await));
    }
    let stats = proxy.stats();
    proxy.stop().await;
    for (dc, r) in &results {
        assert!(matches!(r, Ok(true)), "DC{dc} media over H2 failed: {r:?}; stats: {}", stats.summary());
    }
    assert_eq!(stats.connections_h2, 3, "sessions must use the H2 route: {}", stats.summary());
}

/// More simultaneous sessions than the pool holds all stay on the direct route.
#[tokio::test]
#[ignore = "needs access to the Telegram network"]
async fn sessions_beyond_the_pool_get_new_direct_connections() {
    let port = free_port().await;
    let cfg = test_config(port, 1, false, false);
    let secret = cfg.secret;
    let proxy = heli_tgproxy::start(cfg).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    let probes = (0..4).map(|_| pq_probe(port, secret, 2, Duration::from_secs(20)));
    let results = futures_util::future::join_all(probes).await;
    let stats = proxy.stats();
    proxy.stop().await;
    assert!(results.iter().all(|r| matches!(r, Ok(true))), "{results:?}; stats: {}", stats.summary());
    assert_eq!(stats.connections_ws, 4, "{}", stats.summary());
    assert!(stats.pool_fresh >= 1, "{}", stats.summary());
}
