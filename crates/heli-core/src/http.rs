//! A deliberately small HTTP/1.1 client (GET only) on top of tokio-rustls.
//!
//! It exists instead of a full HTTP stack to keep the binary small and, more importantly,
//! to support *IP pinning*: `raw.githubusercontent.com` is frequently DNS-poisoned in the
//! regions this app targets, so well-known hosts are tried on a fixed address first.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::tls;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("invalid url: {0}")]
    BadUrl(String),
    #[error("timed out")]
    Timeout,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed http response: {0}")]
    Malformed(&'static str),
    #[error("too many redirects")]
    TooManyRedirects,
    #[error("response larger than {0} bytes")]
    TooLarge(usize),
    #[error("http status {0}")]
    Status(u16),
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn ok(self) -> Result<Self, HttpError> {
        if (200..300).contains(&self.status) { Ok(self) } else { Err(HttpError::Status(self.status)) }
    }
}

#[derive(Debug, Clone)]
pub struct GetOptions {
    pub timeout: Duration,
    pub max_body: usize,
    pub max_redirects: u8,
    pub user_agent: String,
    /// Extra `host -> ip` pins tried before regular DNS (in addition to the built-in ones).
    pub pins: Vec<(String, IpAddr)>,
    pub use_builtin_pins: bool,
}

impl Default for GetOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_body: 8 * 1024 * 1024,
            max_redirects: 5,
            user_agent: concat!("HeliBypass/", env!("CARGO_PKG_VERSION")).to_owned(),
            pins: Vec::new(),
            use_builtin_pins: true,
        }
    }
}

/// GitHub endpoints are served from this anycast address; used when DNS is poisoned.
const BUILTIN_PINS: &[(&str, [u8; 4])] = &[
    ("raw.githubusercontent.com", [185, 199, 109, 133]),
    ("release-assets.githubusercontent.com", [185, 199, 109, 133]),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Url {
    https: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Result<Url, HttpError> {
    let bad = || HttpError::BadUrl(url.to_owned());
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(bad());
    };
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) if rest.as_bytes()[i] == b'/' => (&rest[..i], rest[i..].to_owned()),
        Some(i) => (&rest[..i], format!("/{}", &rest[i..])),
        None => (rest, "/".to_owned()),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(bad());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
            (h.trim_matches(['[', ']']).to_owned(), p.parse::<u16>().map_err(|_| bad())?)
        }
        _ => (authority.to_owned(), if https { 443 } else { 80 }),
    };
    Ok(Url { https, host, port, path })
}

pub async fn get(url: &str) -> Result<Response, HttpError> {
    get_with(url, &GetOptions::default()).await
}

pub async fn get_with(url: &str, opts: &GetOptions) -> Result<Response, HttpError> {
    let mut current = parse_url(url)?;
    for _ in 0..=opts.max_redirects {
        let resp = tokio::time::timeout(opts.timeout, fetch_once(&current, opts))
            .await
            .map_err(|_| HttpError::Timeout)??;
        if matches!(resp.status, 301 | 302 | 303 | 307 | 308) {
            if let Some(loc) = resp.header("location") {
                current = resolve_redirect(&current, loc)?;
                continue;
            }
        }
        return Ok(resp);
    }
    Err(HttpError::TooManyRedirects)
}

fn resolve_redirect(base: &Url, location: &str) -> Result<Url, HttpError> {
    if location.starts_with("http://") || location.starts_with("https://") {
        return parse_url(location);
    }
    let mut next = base.clone();
    if location.starts_with('/') {
        next.path = location.to_owned();
    } else {
        let dir = base.path.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        next.path = format!("{dir}/{location}");
    }
    Ok(next)
}

fn pinned_addr(url: &Url, opts: &GetOptions) -> Option<SocketAddr> {
    if let Some((_, ip)) = opts.pins.iter().find(|(h, _)| h.eq_ignore_ascii_case(&url.host)) {
        return Some(SocketAddr::new(*ip, url.port));
    }
    if opts.use_builtin_pins {
        if let Some((_, ip)) = BUILTIN_PINS.iter().find(|(h, _)| h.eq_ignore_ascii_case(&url.host)) {
            return Some(SocketAddr::new(IpAddr::from(*ip), url.port));
        }
    }
    None
}

async fn connect(url: &Url, opts: &GetOptions) -> std::io::Result<TcpStream> {
    if let Some(addr) = pinned_addr(url, opts) {
        if let Ok(Ok(s)) = tokio::time::timeout(Duration::from_secs(4), TcpStream::connect(addr)).await {
            return Ok(s);
        }
    }
    TcpStream::connect((url.host.as_str(), url.port)).await
}

async fn fetch_once(url: &Url, opts: &GetOptions) -> Result<Response, HttpError> {
    let tcp = connect(url, opts).await?;
    tcp.set_nodelay(true).ok();
    if url.https {
        let name = ServerName::try_from(url.host.clone()).map_err(|_| HttpError::BadUrl(url.host.clone()))?;
        let tls = TlsConnector::from(tls::client_config()).connect(name, tcp).await?;
        exchange(tls, url, opts).await
    } else {
        exchange(tcp, url, opts).await
    }
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    url: &Url,
    opts: &GetOptions,
) -> Result<Response, HttpError> {
    let default_port = if url.https { 443 } else { 80 };
    let host_header =
        if url.port == default_port { url.host.clone() } else { format!("{}:{}", url.host, url.port) };
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: {}\r\nAccept: */*\r\n\
         Accept-Encoding: identity\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
        url.path, opts.user_agent
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;

    let mut raw = Vec::with_capacity(16 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    let header_end = loop {
        if let Some(pos) = find_subslice(&raw, b"\r\n\r\n") {
            break pos;
        }
        if raw.len() > 64 * 1024 {
            return Err(HttpError::Malformed("headers too large"));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(HttpError::Malformed("connection closed before headers"));
        }
        raw.extend_from_slice(&chunk[..n]);
    };

    let head = std::str::from_utf8(&raw[..header_end]).map_err(|_| HttpError::Malformed("non-utf8 headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpError::Malformed("empty response"))?;
    let status: u16 = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or(HttpError::Malformed("bad status line"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned())))
        .collect();

    let mut body: Vec<u8> = raw[header_end + 4..].to_vec();
    let chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"));
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok());

    // Read the remainder of the body (the server closes the connection when done).
    loop {
        if chunked {
            if let Some(decoded) = try_decode_chunked(&body)? {
                body = decoded;
                break;
            }
        } else if let Some(len) = content_length {
            if body.len() >= len {
                body.truncate(len);
                break;
            }
        }
        if body.len() > opts.max_body {
            return Err(HttpError::TooLarge(opts.max_body));
        }
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // Some servers drop the TLS session without close_notify after the body.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            if chunked {
                return Err(HttpError::Malformed("truncated chunked body"));
            }
            if content_length.is_some_and(|l| body.len() < l) {
                return Err(HttpError::Malformed("truncated body"));
            }
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    if body.len() > opts.max_body {
        return Err(HttpError::TooLarge(opts.max_body));
    }
    Ok(Response { status, headers, body })
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Returns `Ok(Some(body))` once the terminating zero chunk has been received.
fn try_decode_chunked(data: &[u8]) -> Result<Option<Vec<u8>>, HttpError> {
    let mut out = Vec::with_capacity(data.len());
    let mut pos = 0;
    loop {
        let Some(line_end) = find_subslice(&data[pos..], b"\r\n") else { return Ok(None) };
        let size_str = std::str::from_utf8(&data[pos..pos + line_end])
            .map_err(|_| HttpError::Malformed("bad chunk size"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16).map_err(|_| HttpError::Malformed("bad chunk size"))?;
        pos += line_end + 2;
        if size == 0 {
            return Ok(Some(out));
        }
        if data.len() < pos + size + 2 {
            return Ok(None);
        }
        out.extend_from_slice(&data[pos..pos + size]);
        pos += size + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let u = parse_url("https://raw.githubusercontent.com/a/b?x=1").unwrap();
        assert_eq!(u, Url { https: true, host: "raw.githubusercontent.com".into(), port: 443, path: "/a/b?x=1".into() });
        let u = parse_url("http://127.0.0.1:8080").unwrap();
        assert_eq!((u.port, u.path.as_str(), u.https), (8080, "/", false));
        assert!(parse_url("ftp://x").is_err());
    }

    #[test]
    fn decodes_chunked() {
        let body = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        assert_eq!(try_decode_chunked(body).unwrap().unwrap(), b"Wikipedia");
        assert!(try_decode_chunked(b"4\r\nWi").unwrap().is_none());
    }

    #[test]
    fn resolves_relative_redirects() {
        let base = parse_url("https://a.example/x/y.txt").unwrap();
        assert_eq!(resolve_redirect(&base, "/z").unwrap().path, "/z");
        assert_eq!(resolve_redirect(&base, "w.txt").unwrap().path, "/x/w.txt");
        assert_eq!(resolve_redirect(&base, "https://b.example/q").unwrap().host, "b.example");
    }
}
