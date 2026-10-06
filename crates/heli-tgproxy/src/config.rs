//! Runtime configuration of the proxy and the helpers that validate user input.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::net::link_host;

/// Upstream list of Cloudflare-proxied domains (names are encoded, see [`decode_cf_domain`]).
pub const CFPROXY_DOMAINS_URL: &str =
    "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";

const CFPROXY_ENCODED: &[&str] = &[
    "virkgj.com",
    "vmmzovy.com",
    "mkuosckvso.com",
    "zaewayzmplad.com",
    "twdmbzcm.com",
    "awzwsldi.com",
    "clngqrflngqin.com",
    "tjacxbqtj.com",
    "bxaxtxmrw.com",
    "dmohrsgmohcrwb.com",
    "vwbmtmoi.com",
    "khgrre.com",
    "ulihssf.com",
    "tmhqsdqmfpmk.com",
    "xwuwoqbm.com",
    "orgcnunpj.com",
    "zhkuldz.com",
    "zypoljnslxa.com",
    "efabnxaowuzs.com",
    "zaftuzsftqdq.com",
];

/// Decodes the obfuscated domain format used by the upstream list: names ending in `.com`
/// are Caesar-shifted by their own letter count and really end in `.co.uk`.
pub fn decode_cf_domain(s: &str) -> String {
    let Some(body) = s.strip_suffix(".com") else { return s.to_owned() };
    let n = body.chars().filter(|c| c.is_ascii_alphabetic()).count() as i32;
    let shifted: String = body
        .chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_ascii_lowercase() { b'a' } else { b'A' } as i32;
                ((c as i32 - base - n).rem_euclid(26) + base) as u8 as char
            } else {
                c
            }
        })
        .collect();
    format!("{shifted}.co.uk")
}

pub fn default_cf_domains() -> Vec<String> {
    CFPROXY_ENCODED.iter().map(|d| decode_cf_domain(d)).collect()
}

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
    pub secret: [u8; 16],
    /// DC number -> IPv4 of the Telegram gateway to connect to over WebSocket.
    pub dc_redirects: BTreeMap<u32, Ipv4Addr>,
    /// Read-ahead size for WebSocket reads (kernel socket buffers are left to auto-tuning).
    pub buffer_size: usize,
    /// Idle WebSocket connections kept warm per DC (0 disables direct WS).
    pub pool_size: usize,
    pub fallback_cfproxy: bool,
    /// BETA: carry media sessions on the Cloudflare route over shared HTTP/2 connections.
    pub h2_media: bool,
    /// Cap for all sessions together, per direction, in bytes per second (0 = unlimited).
    pub speed_limit: u64,
    pub cfproxy_user_domains: Vec<String>,
    pub cfproxy_worker_domains: Vec<String>,
    /// Last resort: plain TCP to the data center.
    pub tcp_fallback: bool,
    /// `true` = talk to Cloudflare on port 80 instead of TLS on 443.
    pub disable_secure: bool,
    pub fake_tls_domain: String,
    pub proxy_protocol: bool,
    pub force_test_dc: bool,
    /// Where the Cloudflare domain list is refreshed from; `None` disables refreshing.
    pub cf_domains_url: Option<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 1443,
            secret: crate::crypto::random_bytes::<16>(),
            dc_redirects: BTreeMap::from([
                (2, Ipv4Addr::new(149, 154, 167, 220)),
                (4, Ipv4Addr::new(149, 154, 167, 220)),
            ]),
            buffer_size: 256 * 1024,
            pool_size: 4,
            fallback_cfproxy: true,
            h2_media: false,
            speed_limit: 0,
            cfproxy_user_domains: Vec::new(),
            cfproxy_worker_domains: Vec::new(),
            tcp_fallback: true,
            disable_secure: false,
            fake_tls_domain: String::new(),
            proxy_protocol: false,
            force_test_dc: false,
            cf_domains_url: Some(CFPROXY_DOMAINS_URL.to_owned()),
        }
    }
}

impl ProxyConfig {
    pub fn secret_hex(&self) -> String {
        hex::encode(self.secret)
    }

    /// `tg://proxy?...` deep link understood by Telegram clients.
    pub fn tg_link(&self) -> String {
        let host = link_host(&self.host);
        if self.fake_tls_domain.is_empty() {
            format!("tg://proxy?server={host}&port={}&secret=dd{}", self.port, self.secret_hex())
        } else {
            format!(
                "tg://proxy?server={host}&port={}&secret=ee{}{}",
                self.port,
                self.secret_hex(),
                hex::encode(self.fake_tls_domain.as_bytes())
            )
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DcIpError {
    #[error("invalid DC rule {0:?}, expected DC:IP (for example 2:149.154.167.220)")]
    Format(String),
    #[error("invalid DC rule {0:?}: not a valid DC number or IPv4 address")]
    Invalid(String),
}

/// Parse `DC:IP` rules, one per entry. Blank entries are ignored.
pub fn parse_dc_ip_list<S: AsRef<str>>(rules: &[S]) -> Result<BTreeMap<u32, Ipv4Addr>, DcIpError> {
    let mut out = BTreeMap::new();
    for entry in rules {
        let entry = entry.as_ref().trim();
        if entry.is_empty() {
            continue;
        }
        let (dc, ip) = entry.split_once(':').ok_or_else(|| DcIpError::Format(entry.to_owned()))?;
        let dc: u32 = dc.trim().parse().map_err(|_| DcIpError::Invalid(entry.to_owned()))?;
        let ip: Ipv4Addr = ip.trim().parse().map_err(|_| DcIpError::Invalid(entry.to_owned()))?;
        out.insert(dc, ip);
    }
    Ok(out)
}

/// Split on whitespace/commas/semicolons, trim, drop duplicates (case-insensitive).
pub fn coerce_domain_list(value: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    value
        .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| seen.insert(s.to_ascii_lowercase()))
        .map(str::to_owned)
        .collect()
}

pub fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 || domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for l in &labels {
        if l.is_empty() || l.len() > 63 || l.starts_with('-') || l.ends_with('-') {
            return false;
        }
        if !l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }
    let tld = labels[labels.len() - 1];
    tld.len() >= 2 && tld.chars().any(|c| c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_default_domains() {
        let d = default_cf_domains();
        assert_eq!(d.len(), 20);
        assert!(d.iter().all(|x| x.ends_with(".co.uk") && is_valid_domain(x)), "{d:?}");
        // non-.com names pass through untouched
        assert_eq!(decode_cf_domain("example.org"), "example.org");
    }

    #[test]
    fn parses_dc_rules() {
        let m = parse_dc_ip_list(&["2:149.154.167.220", " 4:1.2.3.4 ", ""]).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[&4], Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(parse_dc_ip_list(&["nonsense"]), Err(DcIpError::Format("nonsense".into())));
        assert_eq!(parse_dc_ip_list(&["x:1.2.3.4"]), Err(DcIpError::Invalid("x:1.2.3.4".into())));
        assert_eq!(parse_dc_ip_list(&["2:999.1.1.1"]), Err(DcIpError::Invalid("2:999.1.1.1".into())));
    }

    #[test]
    fn coerces_domain_lists() {
        assert_eq!(coerce_domain_list("A.com, b.com;a.COM  c.com"), vec!["A.com", "b.com", "c.com"]);
    }

    #[test]
    fn builds_links() {
        let mut c = ProxyConfig { secret: [0xAB; 16], ..ProxyConfig::default() };
        assert_eq!(c.tg_link(), format!("tg://proxy?server=127.0.0.1&port=1443&secret=dd{}", "ab".repeat(16)));
        c.fake_tls_domain = "example.com".into();
        assert!(c.tg_link().ends_with(&format!("secret=ee{}{}", "ab".repeat(16), hex::encode("example.com"))));
    }
}
