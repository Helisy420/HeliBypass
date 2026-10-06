//! How fast one session can move data through the proxy's per-byte work: AES-256-CTR decrypt
//! (Telegram side) + encrypt (client side), as in `bridge::downstream_loop`.
//! Run with `cargo test --release -p heli-tgproxy --test throughput -- --ignored --nocapture`.

use std::time::Instant;

use cipher::StreamCipher;
use heli_tgproxy::crypto::new_ctr;

#[test]
#[ignore = "benchmark"]
fn per_session_crypto_throughput() {
    let mut a = new_ctr(&[1u8; 32], &[2u8; 16]);
    let mut b = new_ctr(&[3u8; 32], &[4u8; 16]);
    let mut buf = vec![0u8; 64 * 1024];
    let total = 1024 * 1024 * 1024usize;
    let started = Instant::now();
    for _ in 0..total / buf.len() {
        a.apply_keystream(&mut buf);
        b.apply_keystream(&mut buf);
    }
    let secs = started.elapsed().as_secs_f64();
    println!("one session re-encrypts {:.0} MB/s ({:.1} Gbit/s)", total as f64 / secs / 1e6, total as f64 * 8.0 / secs / 1e9);
}
