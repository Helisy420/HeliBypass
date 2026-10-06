//! Minimal client-side WebSocket (RFC 6455) tailored to Telegram's `/apiws` gateways.
//!
//! Only what the proxy needs: binary messages, ping/pong, close, fragmented messages.
//! Frames are parsed directly out of the socket read buffer and handed out as `BytesMut`
//! slices, so the hot path (WS -> decrypt -> client) does not copy payload bytes.
//! [`WsReader::recv_stream`] goes further and forwards a data frame's payload as it arrives
//! (cut-through) instead of buffering whole messages, which matters for media downloads where
//! Telegram sends frames of several hundred kilobytes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use heli_core::tls;

pub const MAX_MESSAGE_LEN: usize = 16 * 1024 * 1024;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("HTTP {status}: {line}")]
    Handshake { status: u16, line: String, location: Option<String> },
    #[error("timed out")]
    Timeout,
    #[error("invalid TLS server name {0:?}")]
    BadServerName(String),
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
}

impl WsError {
    pub fn is_redirect(&self) -> bool {
        matches!(self, WsError::Handshake { status, .. } if matches!(status, 301 | 302 | 303 | 307 | 308))
    }
}

/// Either a TLS or a plain TCP stream (plain is used for Cloudflare "no secure" mode).
pub enum WsIo {
    Tls(Box<TlsStream<TcpStream>>),
    Plain(TcpStream),
}

impl AsyncRead for WsIo {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WsIo::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            WsIo::Plain(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for WsIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            WsIo::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            WsIo::Plain(s) => Pin::new(s).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WsIo::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
            WsIo::Plain(s) => Pin::new(s).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            WsIo::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            WsIo::Plain(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectOpts<'a> {
    /// Address to open the TCP connection to (IP or host name).
    pub host: &'a str,
    /// Value of the `Host:` header and, unless `sni` is set, of the TLS SNI.
    pub domain: &'a str,
    pub path: &'a str,
    pub timeout: Duration,
    /// Domain fronting: use this SNI and skip host-name verification.
    pub sni: Option<&'a str>,
    /// `false` = plain TCP on port 80.
    pub secure: bool,
    /// Read-ahead size of the WebSocket reader.
    pub buffer_size: usize,
}

const MIN_READ: usize = 16 * 1024;
const MAX_READ: usize = 256 * 1024;

/// A connected WebSocket that has not been split yet (this is what the pool stores).
pub struct WsConn {
    io: WsIo,
    rbuf: BytesMut,
    read_size: usize,
}

impl WsConn {
    pub async fn connect(o: &ConnectOpts<'_>) -> Result<Self, WsError> {
        let connect_timeout = o.timeout.min(Duration::from_secs(10));
        let port = if o.secure { 443 } else { 80 };

        let io = tokio::time::timeout(connect_timeout, async {
            let tcp = TcpStream::connect((o.host, port)).await?;
            crate::net::tune_socket(&tcp);
            if !o.secure {
                return Ok::<_, WsError>(WsIo::Plain(tcp));
            }
            let (sni, cfg) = match o.sni {
                Some(s) => (s, tls::client_config_fronting()),
                None => (o.domain, tls::client_config()),
            };
            let name = ServerName::try_from(sni.to_owned()).map_err(|_| WsError::BadServerName(sni.to_owned()))?;
            let stream = TlsConnector::from(cfg).connect(name, tcp).await?;
            Ok(WsIo::Tls(Box::new(stream)))
        })
        .await
        .map_err(|_| WsError::Timeout)??;

        let read_size = o.buffer_size.clamp(MIN_READ, MAX_READ);
        let mut conn = WsConn { io, rbuf: BytesMut::with_capacity(read_size), read_size };
        tokio::time::timeout(o.timeout, conn.upgrade(o)).await.map_err(|_| WsError::Timeout)??;
        Ok(conn)
    }

    async fn upgrade(&mut self, o: &ConnectOpts<'_>) -> Result<(), WsError> {
        let mut key_raw = [0u8; 16];
        rand::fill(&mut key_raw);
        let key = base64_encode(&key_raw);
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
            o.path, o.domain
        );
        self.io.write_all(req.as_bytes()).await?;
        self.io.flush().await?;

        let header_end = loop {
            if let Some(p) = find_header_end(&self.rbuf) {
                break p;
            }
            if self.rbuf.len() > 32 * 1024 {
                return Err(WsError::Protocol("oversized handshake response"));
            }
            if self.io.read_buf(&mut self.rbuf).await? == 0 {
                return Err(WsError::Handshake { status: 0, line: "empty response".into(), location: None });
            }
        };
        let head = String::from_utf8_lossy(&self.rbuf[..header_end]).into_owned();
        self.rbuf.advance(header_end + 4);

        let mut lines = head.split("\r\n");
        let first = lines.next().unwrap_or("").to_owned();
        let status = first.split(' ').nth(1).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
        if status == 101 {
            return Ok(());
        }
        let location = lines.find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("location").then(|| v.trim().to_owned())
        });
        Err(WsError::Handshake { status, line: first, location })
    }

    /// Non-blocking liveness check for an idle (pooled) connection.
    pub fn is_alive(&mut self) -> bool {
        let waker = futures_util::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);
        let mut scratch = [0u8; 2048];
        loop {
            let mut rb = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.io).poll_read(&mut cx, &mut rb) {
                Poll::Pending => break,
                Poll::Ready(Ok(())) => {
                    if rb.filled().is_empty() {
                        return false; // EOF
                    }
                    self.rbuf.extend_from_slice(rb.filled());
                    if self.rbuf.len() > 64 * 1024 {
                        return false; // an idle gateway should not be talking this much
                    }
                }
                Poll::Ready(Err(_)) => return false,
            }
        }
        // A buffered close frame at the front means the server hung up at the WS level.
        !matches!(self.rbuf.first(), Some(b) if b & 0x0F == OP_CLOSE)
    }

    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let mut frame = Vec::with_capacity(data.len() + 14);
        encode_frame(&mut frame, OP_BINARY, data);
        self.io.write_all(&frame).await
    }

    pub fn split(self) -> (WsReader, WsWriter) {
        let (rd, wr) = tokio::io::split(self.io);
        let reader = WsReader { rd, buf: self.rbuf, frag: Vec::new(), read_size: self.read_size, left: 0, mask: None };
        (reader, WsWriter { wr, scratch: Vec::with_capacity(64 * 1024 + 14) })
    }

    pub async fn close(mut self) {
        let mut frame = Vec::with_capacity(8);
        encode_frame(&mut frame, OP_CLOSE, &[]);
        let _ = self.io.write_all(&frame).await;
        let _ = self.io.shutdown().await;
    }
}

pub enum Incoming {
    /// A complete binary message.
    Data(BytesMut),
    Ping(Vec<u8>),
    /// Server-initiated close (payload = status code + reason).
    Close(Vec<u8>),
}

pub struct WsReader {
    rd: ReadHalf<WsIo>,
    buf: BytesMut,
    frag: Vec<u8>,
    read_size: usize,
    /// `recv_stream`: payload bytes of the current data frame not handed out yet.
    left: usize,
    /// `recv_stream`: mask key of the current data frame and the offset into it.
    mask: Option<([u8; 4], usize)>,
}

struct FrameHeader {
    fin: bool,
    opcode: u8,
    mask: Option<[u8; 4]>,
    header_len: usize,
    payload_len: usize,
}

impl WsReader {
    async fn fill(&mut self) -> Result<(), WsError> {
        self.buf.reserve(self.read_size);
        if self.rd.read_buf(&mut self.buf).await? == 0 {
            return Err(WsError::Io(io::ErrorKind::UnexpectedEof.into()));
        }
        Ok(())
    }

    /// Next complete message (fragments are reassembled).
    pub async fn recv(&mut self) -> Result<Incoming, WsError> {
        debug_assert_eq!(self.left, 0, "recv() called in the middle of a streamed frame");
        loop {
            let Some((opcode, fin, payload)) = self.try_parse()? else {
                self.fill().await?;
                continue;
            };
            match opcode {
                OP_CLOSE => return Ok(Incoming::Close(payload.to_vec())),
                OP_PING => return Ok(Incoming::Ping(payload.to_vec())),
                OP_PONG => continue,
                OP_CONT | OP_TEXT | OP_BINARY => {
                    if fin && self.frag.is_empty() {
                        return Ok(Incoming::Data(payload));
                    }
                    self.frag.extend_from_slice(&payload);
                    if self.frag.len() > MAX_MESSAGE_LEN {
                        return Err(WsError::Protocol("message too large"));
                    }
                    if fin {
                        let msg = BytesMut::from(&self.frag[..]);
                        self.frag.clear();
                        return Ok(Incoming::Data(msg));
                    }
                }
                _ => continue,
            }
        }
    }

    /// Like [`recv`](Self::recv), but data is returned as soon as any payload bytes are
    /// buffered, without waiting for the rest of the frame or message. Message boundaries are
    /// lost, which is fine for the obfuscated MTProto byte stream going to the client.
    /// Do not mix with `recv` on the same reader.
    pub async fn recv_stream(&mut self) -> Result<Incoming, WsError> {
        loop {
            if self.left > 0 {
                if self.buf.is_empty() {
                    self.fill().await?;
                }
                let n = self.left.min(self.buf.len());
                let mut chunk = self.buf.split_to(n);
                if let Some((key, offset)) = self.mask.as_mut() {
                    apply_mask_at(&mut chunk, *key, *offset);
                    *offset = (*offset + n) & 3;
                }
                self.left -= n;
                return Ok(Incoming::Data(chunk));
            }
            let Some(h) = self.peek_header()? else {
                self.fill().await?;
                continue;
            };
            match h.opcode {
                OP_CONT | OP_TEXT | OP_BINARY => {
                    self.buf.advance(h.header_len);
                    self.left = h.payload_len;
                    self.mask = h.mask.map(|k| (k, 0));
                }
                // control frames are small and never fragmented: take them whole
                _ => match self.try_parse()? {
                    Some((OP_CLOSE, _, payload)) => return Ok(Incoming::Close(payload.to_vec())),
                    Some((OP_PING, _, payload)) => return Ok(Incoming::Ping(payload.to_vec())),
                    Some(_) => {}
                    None => self.fill().await?,
                },
            }
        }
    }

    fn peek_header(&self) -> Result<Option<FrameHeader>, WsError> {
        let b = &self.buf;
        if b.len() < 2 {
            return Ok(None);
        }
        let fin = b[0] & 0x80 != 0;
        let opcode = b[0] & 0x0F;
        let masked = b[1] & 0x80 != 0;
        let (len, mut hdr) = match b[1] & 0x7F {
            126 => {
                if b.len() < 4 {
                    return Ok(None);
                }
                (u16::from_be_bytes([b[2], b[3]]) as usize, 4)
            }
            127 => {
                if b.len() < 10 {
                    return Ok(None);
                }
                let l = u64::from_be_bytes(b[2..10].try_into().expect("8 bytes"));
                if l > MAX_MESSAGE_LEN as u64 {
                    return Err(WsError::Protocol("frame too large"));
                }
                (l as usize, 10)
            }
            n => (n as usize, 2),
        };
        if len > MAX_MESSAGE_LEN {
            return Err(WsError::Protocol("frame too large"));
        }
        let mask_off = hdr;
        if masked {
            hdr += 4;
        }
        if b.len() < hdr {
            return Ok(None);
        }
        let mask: Option<[u8; 4]> = masked.then(|| b[mask_off..mask_off + 4].try_into().expect("4 bytes"));
        Ok(Some(FrameHeader { fin, opcode, mask, header_len: hdr, payload_len: len }))
    }

    /// One whole frame, if it is completely buffered.
    fn try_parse(&mut self) -> Result<Option<(u8, bool, BytesMut)>, WsError> {
        let Some(h) = self.peek_header()? else { return Ok(None) };
        let total = h.header_len + h.payload_len;
        if self.buf.len() < total {
            self.buf.reserve(total - self.buf.len());
            return Ok(None);
        }
        self.buf.advance(h.header_len);
        let mut payload = self.buf.split_to(h.payload_len);
        if let Some(m) = h.mask {
            apply_mask(&mut payload, m);
        }
        Ok(Some((h.opcode, h.fin, payload)))
    }
}

pub struct WsWriter {
    wr: WriteHalf<WsIo>,
    scratch: Vec<u8>,
}

impl WsWriter {
    pub async fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.scratch.clear();
        encode_frame(&mut self.scratch, OP_BINARY, data);
        self.wr.write_all(&self.scratch).await
    }

    /// Several messages, one syscall.
    pub async fn send_batch<T: AsRef<[u8]>>(&mut self, parts: &[T]) -> io::Result<()> {
        self.scratch.clear();
        for p in parts {
            encode_frame(&mut self.scratch, OP_BINARY, p.as_ref());
        }
        self.wr.write_all(&self.scratch).await
    }

    pub async fn send_pong(&mut self, payload: &[u8]) -> io::Result<()> {
        self.scratch.clear();
        encode_frame(&mut self.scratch, OP_PONG, payload);
        self.wr.write_all(&self.scratch).await
    }

    pub async fn send_close(&mut self, payload: &[u8]) -> io::Result<()> {
        self.scratch.clear();
        encode_frame(&mut self.scratch, OP_CLOSE, &payload[..payload.len().min(2)]);
        self.wr.write_all(&self.scratch).await
    }

    pub async fn shutdown(&mut self) {
        let _ = self.wr.shutdown().await;
    }
}

/// Appends one masked client frame to `out`.
fn encode_frame(out: &mut Vec<u8>, opcode: u8, data: &[u8]) {
    let len = data.len();
    out.push(0x80 | opcode);
    match len {
        0..=125 => out.push(0x80 | len as u8),
        126..=65535 => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        }
        _ => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
    }
    let mut key = [0u8; 4];
    rand::fill(&mut key);
    out.extend_from_slice(&key);
    let start = out.len();
    out.extend_from_slice(data);
    apply_mask(&mut out[start..], key);
}

/// [`apply_mask`] for a slice that starts `offset` bytes into the masked payload.
fn apply_mask_at(data: &mut [u8], key: [u8; 4], offset: usize) {
    let o = offset & 3;
    apply_mask(data, [key[o], key[(o + 1) & 3], key[(o + 2) & 3], key[(o + 3) & 3]]);
}

/// XOR `data` with the repeating 4 byte `key`, 8 bytes at a time.
pub fn apply_mask(data: &mut [u8], key: [u8; 4]) {
    let k8 = u64::from_ne_bytes([key[0], key[1], key[2], key[3], key[0], key[1], key[2], key[3]]);
    let mut chunks = data.chunks_exact_mut(8);
    for c in &mut chunks {
        let v = u64::from_ne_bytes(c.try_into().expect("8 bytes")) ^ k8;
        c.copy_from_slice(&v.to_ne_bytes());
    }
    for (i, b) in chunks.into_remainder().iter_mut().enumerate() {
        *b ^= key[i & 3];
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_is_involutive_and_matches_bytewise() {
        let key = [0xA1, 0xB2, 0xC3, 0xD4];
        for len in [0usize, 1, 3, 7, 8, 9, 15, 16, 17, 1000] {
            let orig: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            let mut fast = orig.clone();
            apply_mask(&mut fast, key);
            let slow: Vec<u8> = orig.iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect();
            assert_eq!(fast, slow, "len {len}");
            apply_mask(&mut fast, key);
            assert_eq!(fast, orig);
        }
    }

    #[test]
    fn base64_matches_rfc4648_examples() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn frame_header_sizes() {
        let mut out = Vec::new();
        encode_frame(&mut out, OP_BINARY, &[1u8; 125]);
        assert_eq!(out.len(), 2 + 4 + 125);
        out.clear();
        encode_frame(&mut out, OP_BINARY, &vec![1u8; 126]);
        assert_eq!(out.len(), 4 + 4 + 126);
        out.clear();
        encode_frame(&mut out, OP_BINARY, &vec![1u8; 70_000]);
        assert_eq!(out.len(), 10 + 4 + 70_000);
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0xFF);
    }

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let client = tokio::spawn(async move { TcpStream::connect(addr).await.unwrap() });
        let (server, _) = l.accept().await.unwrap();
        (client.await.unwrap(), server)
    }

    /// Server frames (unmasked) are reassembled; control frames interleave with fragments.
    #[tokio::test]
    async fn reader_parses_fragments_and_control_frames() {
        let (client, mut server) = loopback_pair().await;
        tokio::spawn(async move {
            server.write_all(&[0x02, 0x05]).await.unwrap(); // binary, fin=0
            server.write_all(b"hello").await.unwrap();
            server.write_all(&[0x89, 0x01, b'p']).await.unwrap(); // ping inside the message
            server.write_all(&[0x80, 0x06]).await.unwrap(); // continuation, fin
            server.write_all(b" world").await.unwrap();
            server.write_all(&[0x82, 0x02, 9, 8]).await.unwrap(); // whole binary message
            server.write_all(&[0x88, 0x02, 0x03, 0xE8]).await.unwrap(); // close 1000
        });
        let (mut rd, _wr) = WsConn { io: WsIo::Plain(client), rbuf: BytesMut::new(), read_size: MIN_READ }.split();
        match rd.recv().await.unwrap() {
            Incoming::Ping(p) => assert_eq!(p, b"p"),
            _ => panic!("expected the ping first (message is still incomplete)"),
        }
        match rd.recv().await.unwrap() {
            Incoming::Data(d) => assert_eq!(&d[..], b"hello world"),
            _ => panic!("expected reassembled message"),
        }
        match rd.recv().await.unwrap() {
            Incoming::Data(d) => assert_eq!(&d[..], &[9, 8]),
            _ => panic!("expected data"),
        }
        match rd.recv().await.unwrap() {
            Incoming::Close(p) => assert_eq!(p, vec![0x03, 0xE8]),
            _ => panic!("expected close"),
        }
    }

    /// Cut-through: payload is handed out before the frame is complete; control frames between
    /// fragments still arrive; a masked frame split at odd offsets unmasks correctly.
    #[tokio::test]
    async fn stream_reader_forwards_partial_frames() {
        let (client, mut server) = loopback_pair().await;
        let (mut rd, _wr) = WsConn { io: WsIo::Plain(client), rbuf: BytesMut::new(), read_size: MIN_READ }.split();

        // a 70 000 byte binary frame, sent in two parts with a pause in between
        let body: Vec<u8> = (0..70_000u32).map(|i| (i * 7 + 3) as u8).collect();
        let mut frame = vec![0x82, 127];
        frame.extend_from_slice(&(body.len() as u64).to_be_bytes());
        frame.extend_from_slice(&body);
        let (first, rest) = frame.split_at(10 + 30_001);
        server.write_all(first).await.unwrap();
        let mut got = Vec::new();
        while got.len() < 30_001 {
            match rd.recv_stream().await.unwrap() {
                Incoming::Data(d) => got.extend_from_slice(&d),
                _ => panic!("expected data"),
            }
        }
        assert_eq!(got.len(), 30_001, "the first part must be delivered before the rest is sent");
        server.write_all(rest).await.unwrap();

        // fragmented + masked message with a ping in between
        let key = [0x11, 0x22, 0x33, 0x44];
        let mut part1 = b"hello".to_vec();
        apply_mask(&mut part1, key);
        let mut part2 = b" world".to_vec();
        apply_mask(&mut part2, key);
        let mut tail = vec![0x02, 0x80 | 5];
        tail.extend_from_slice(&key);
        tail.extend_from_slice(&part1);
        tail.extend_from_slice(&[0x89, 0x01, b'p']);
        tail.extend_from_slice(&[0x80, 0x80 | 6]);
        tail.extend_from_slice(&key);
        tail.extend_from_slice(&part2);
        tail.extend_from_slice(&[0x88, 0x02, 0x03, 0xE8]);
        for b in tail.chunks(3) {
            server.write_all(b).await.unwrap();
        }
        drop(server);

        let mut text = Vec::new();
        let mut pinged = false;
        loop {
            match rd.recv_stream().await.unwrap() {
                Incoming::Data(d) => {
                    if got.len() < body.len() {
                        got.extend_from_slice(&d);
                    } else {
                        text.extend_from_slice(&d);
                    }
                }
                Incoming::Ping(p) => {
                    assert_eq!(p, b"p");
                    pinged = true;
                }
                Incoming::Close(p) => {
                    assert_eq!(p, vec![0x03, 0xE8]);
                    break;
                }
            }
        }
        assert_eq!(got, body);
        assert_eq!(text, b"hello world");
        assert!(pinged);
    }

    #[test]
    fn mask_at_offset_matches_whole_mask() {
        let key = [9, 8, 7, 6];
        let orig: Vec<u8> = (0..41u8).collect();
        let mut whole = orig.clone();
        apply_mask(&mut whole, key);
        let mut pieces = orig.clone();
        let (a, rest) = pieces.split_at_mut(5);
        let (b, c) = rest.split_at_mut(13);
        apply_mask_at(a, key, 0);
        apply_mask_at(b, key, 5);
        apply_mask_at(c, key, 18);
        assert_eq!(pieces, whole);
    }

    #[tokio::test]
    async fn writer_output_is_masked_and_parseable() {
        let (client, mut server) = loopback_pair().await;
        let (_rd, mut wr) = WsConn { io: WsIo::Plain(client), rbuf: BytesMut::new(), read_size: MIN_READ }.split();
        wr.send_batch(&[b"abc".to_vec(), vec![7u8; 200]]).await.unwrap();
        let mut got = vec![0u8; 2 + 4 + 3 + 4 + 4 + 200];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got[0], 0x82);
        assert_eq!(got[1], 0x80 | 3);
        let key: [u8; 4] = got[2..6].try_into().unwrap();
        let mut body = got[6..9].to_vec();
        apply_mask(&mut body, key);
        assert_eq!(body, b"abc");
        assert_eq!(got[9], 0x82);
        assert_eq!(got[10], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([got[11], got[12]]), 200);
    }
}
