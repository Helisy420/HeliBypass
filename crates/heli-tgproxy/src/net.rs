//! Socket tuning shared by every connection the proxy opens or accepts.

use tokio::net::TcpStream;

/// `TCP_NODELAY` only (failures are non-fatal).
///
/// The kernel buffers are deliberately left alone. On Windows, setting `SO_RCVBUF` turns off
/// receive-window auto-tuning for that socket and setting `SO_SNDBUF` turns off dynamic send
/// buffering, so a fixed 256 KB buffer caps one connection at 256 KB per round trip
/// (about 20 Mbit/s at 100 ms): far below what the same line does without the proxy.
/// Auto-tuning grows the window to whatever the path needs. Linux and macOS behave the same way.
pub fn tune_socket(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// The address other devices would use to reach this machine (for `0.0.0.0` listeners).
pub fn link_host(host: &str) -> String {
    if host != "0.0.0.0" {
        return host.to_owned();
    }
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("8.8.8.8:80").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_owned())
}
