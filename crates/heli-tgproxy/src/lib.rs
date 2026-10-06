//! Local MTProto proxy that carries Telegram traffic over WebSocket.
//!
//! This is a Rust port of [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy)
//! (MIT). Telegram Desktop connects to `127.0.0.1:<port>` as an MTProto proxy; the proxy
//! reads the DC from the obfuscated handshake and relays the session to Telegram's own
//! `/apiws` WebSocket gateways (direct, domain-fronted, via Cloudflare, or plain TCP).

pub mod balancer;
pub mod bridge;
pub mod client_io;
pub mod config;
pub mod consts;
pub mod crypto;
pub mod fake_tls;
pub mod h2media;
pub mod net;
pub mod pool;
pub mod ratelimit;
pub mod server;
pub mod sessions;
pub mod state;
pub mod stats;
pub mod ws;

pub use config::{ProxyConfig, parse_dc_ip_list};
pub use server::{ProxyHandle, measure_dc_latency, start};
pub use sessions::{Route, SessionInfo};
pub use stats::Snapshot as StatsSnapshot;
