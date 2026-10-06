//! Fake-TLS ("ee" secrets): the client opens what looks like a TLS 1.3 session to a decoy
//! domain, authenticated by an HMAC over the ClientHello keyed with the proxy secret.
//! Anything that fails the HMAC is transparently proxied to the real decoy site, so active
//! probing sees an ordinary web server.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_RECORD_CCS: u8 = 0x14;
const TLS_RECORD_APPDATA: u8 = 0x17;

const CLIENT_RANDOM_OFFSET: usize = 11;
const CLIENT_RANDOM_LEN: usize = 32;
const SESSION_ID_OFFSET: usize = 44;
const SESSION_ID_LEN: usize = 32;
const TIMESTAMP_TOLERANCE: i64 = 120;
const TLS_APPDATA_MAX: usize = 16384;

const CCS_FRAME: [u8; 6] = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];

const SH_RANDOM_OFF: usize = 11;
const SH_SESSID_OFF: usize = 44;
const SH_PUBKEY_OFF: usize = 89;

fn server_hello_template() -> [u8; 127] {
    let mut sh = [0u8; 127];
    let head: [u8; 11] = [0x16, 0x03, 0x03, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03];
    sh[..11].copy_from_slice(&head);
    sh[43] = 0x20; // session id length
    sh[76..79].copy_from_slice(&[0x13, 0x01, 0x00]); // cipher suite + compression
    sh[79..81].copy_from_slice(&[0x00, 0x2e]); // extensions length
    sh[81..89].copy_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]); // key_share header
    sh[121..127].copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]); // supported_versions
    sh
}

pub struct ClientHello {
    pub client_random: [u8; 32],
    pub session_id: [u8; 32],
    pub timestamp: u32,
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

pub fn verify_client_hello(data: &[u8], secret: &[u8; 16]) -> Option<ClientHello> {
    verify_client_hello_at(data, secret, unix_now())
}

pub fn verify_client_hello_at(data: &[u8], secret: &[u8; 16], now: i64) -> Option<ClientHello> {
    // 5 (record header) + 6 (handshake type/len/version) + 32 (random) = 43
    if data.len() < 43 || data[0] != TLS_RECORD_HANDSHAKE || data[5] != 0x01 {
        return None;
    }
    let client_random: [u8; 32] = data[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].try_into().ok()?;

    let mut zeroed = data.to_vec();
    zeroed[CLIENT_RANDOM_OFFSET..CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN].fill(0);
    let expected = hmac_sha256(secret, &[&zeroed]);

    if !bool::from(expected[..28].ct_eq(&client_random[..28])) {
        return None;
    }
    let mut ts_xor = [0u8; 4];
    for i in 0..4 {
        ts_xor[i] = client_random[28 + i] ^ expected[28 + i];
    }
    let timestamp = u32::from_le_bytes(ts_xor);
    if (now - i64::from(timestamp)).abs() > TIMESTAMP_TOLERANCE {
        return None;
    }

    let mut session_id = [0u8; SESSION_ID_LEN];
    if data.len() >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43] == 0x20 {
        session_id.copy_from_slice(&data[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]);
    }
    Some(ClientHello { client_random, session_id, timestamp })
}

pub fn build_server_hello(secret: &[u8; 16], client_random: &[u8; 32], session_id: &[u8; 32]) -> Vec<u8> {
    let mut sh = server_hello_template();
    sh[SH_SESSID_OFF..SH_SESSID_OFF + 32].copy_from_slice(session_id);
    let mut pubkey = [0u8; 32];
    rand::fill(&mut pubkey);
    sh[SH_PUBKEY_OFF..SH_PUBKEY_OFF + 32].copy_from_slice(&pubkey);

    let encrypted_size: usize = rand::random_range(1900..=2100);
    let mut encrypted = vec![0u8; encrypted_size];
    rand::fill(&mut encrypted[..]);

    let mut response = Vec::with_capacity(sh.len() + CCS_FRAME.len() + 5 + encrypted_size);
    response.extend_from_slice(&sh);
    response.extend_from_slice(&CCS_FRAME);
    response.extend_from_slice(&[0x17, 0x03, 0x03]);
    response.extend_from_slice(&(encrypted_size as u16).to_be_bytes());
    response.extend_from_slice(&encrypted);

    let server_random = hmac_sha256(secret, &[client_random, &response]);
    response[SH_RANDOM_OFF..SH_RANDOM_OFF + 32].copy_from_slice(&server_random);
    response
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Reads application-data payloads out of TLS records (change-cipher-spec records are skipped).
pub struct FakeTlsReader {
    inner: OwnedReadHalf,
    /// bytes of the current record that have not been read yet
    left: usize,
}

impl FakeTlsReader {
    pub fn new(inner: OwnedReadHalf) -> Self {
        Self { inner, left: 0 }
    }

    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.left == 0 {
                let mut hdr = [0u8; 5];
                self.inner.read_exact(&mut hdr).await?;
                let rec_len = usize::from(u16::from_be_bytes([hdr[3], hdr[4]]));
                match hdr[0] {
                    TLS_RECORD_CCS => {
                        let mut skip = vec![0u8; rec_len];
                        self.inner.read_exact(&mut skip).await?;
                        continue;
                    }
                    TLS_RECORD_APPDATA => self.left = rec_len,
                    _ => return Ok(0), // anything else ends the stream
                }
                if self.left == 0 {
                    continue;
                }
            }
            let want = self.left.min(buf.len());
            let n = self.inner.read(&mut buf[..want]).await?;
            self.left -= n;
            return Ok(n);
        }
    }
}

/// Wraps outgoing bytes into TLS application-data records.
pub struct FakeTlsWriter {
    inner: OwnedWriteHalf,
    scratch: Vec<u8>,
}

impl FakeTlsWriter {
    pub fn new(inner: OwnedWriteHalf) -> Self {
        Self { inner, scratch: Vec::with_capacity(TLS_APPDATA_MAX + 5) }
    }

    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.scratch.clear();
        for chunk in data.chunks(TLS_APPDATA_MAX) {
            self.scratch.extend_from_slice(&[0x17, 0x03, 0x03]);
            self.scratch.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            self.scratch.extend_from_slice(chunk);
        }
        self.inner.write_all(&self.scratch).await
    }

    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.inner.shutdown().await
    }
}

/// Relay a client whose Fake-TLS authentication failed to the real decoy site, so that a
/// prober sees exactly what a browser would see.
pub async fn proxy_to_masking_domain(
    mut client_r: OwnedReadHalf,
    mut client_w: OwnedWriteHalf,
    initial: &[u8],
    domain: &str,
) -> io::Result<()> {
    let upstream = tokio::time::timeout(std::time::Duration::from_secs(10), TcpStream::connect((domain, 443)))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "masking connect timed out"))??;
    let (mut up_r, mut up_w) = upstream.into_split();
    if !initial.is_empty() {
        up_w.write_all(initial).await?;
    }
    let a = async {
        let r = tokio::io::copy(&mut client_r, &mut up_w).await;
        let _ = up_w.shutdown().await;
        r
    };
    let b = async {
        let r = tokio::io::copy(&mut up_r, &mut client_w).await;
        let _ = client_w.shutdown().await;
        r
    };
    let (ra, rb) = tokio::join!(a, b);
    ra.and(rb).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a ClientHello the way an MTProxy client does (HMAC keyed with the secret).
    fn client_hello(secret: &[u8; 16], ts: u32) -> Vec<u8> {
        let mut h = vec![0x16, 0x03, 0x01, 0, 0, 0x01, 0, 0, 0, 0x03, 0x03];
        h.extend_from_slice(&[0u8; 32]); // random placeholder
        h.push(0x20);
        h.extend_from_slice(&[0x5A; 32]);
        h.extend_from_slice(&[0x11; 100]);
        let len = (h.len() - 5) as u16;
        h[3..5].copy_from_slice(&len.to_be_bytes());
        let mac = hmac_sha256(secret, &[&h]);
        let ts_x: Vec<u8> = ts.to_le_bytes().iter().zip(&mac[28..]).map(|(a, b)| a ^ b).collect();
        h[11..39].copy_from_slice(&mac[..28]);
        h[39..43].copy_from_slice(&ts_x);
        h
    }

    #[test]
    fn accepts_valid_hello_and_rejects_others() {
        let secret = [7u8; 16];
        let now = 1_700_000_000i64;
        let hello = client_hello(&secret, now as u32);
        let v = verify_client_hello_at(&hello, &secret, now).expect("valid");
        assert_eq!(v.timestamp, now as u32);
        assert_eq!(v.session_id, [0x5A; 32]);

        assert!(verify_client_hello_at(&hello, &[8u8; 16], now).is_none(), "wrong secret");
        assert!(verify_client_hello_at(&hello, &secret, now + 500).is_none(), "stale timestamp");
        let mut tampered = hello.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(verify_client_hello_at(&tampered, &secret, now).is_none(), "tampered body");
    }

    #[test]
    fn server_hello_has_expected_shape() {
        let secret = [7u8; 16];
        let sh = build_server_hello(&secret, &[1u8; 32], &[2u8; 32]);
        assert_eq!(&sh[..5], &[0x16, 0x03, 0x03, 0x00, 0x7a]);
        assert_eq!(&sh[44..76], &[2u8; 32]);
        assert_eq!(&sh[127..133], &CCS_FRAME);
        assert_eq!(sh[133], 0x17);
        let app_len = usize::from(u16::from_be_bytes([sh[136], sh[137]]));
        assert_eq!(sh.len(), 127 + 6 + 5 + app_len);
        assert!((1900..=2100).contains(&app_len));
        // the server random authenticates the response to the client
        let mut zeroed = sh.clone();
        zeroed[11..43].fill(0);
        assert_eq!(&sh[11..43], &hmac_sha256(&secret, &[&[1u8; 32], &zeroed]));
    }
}
