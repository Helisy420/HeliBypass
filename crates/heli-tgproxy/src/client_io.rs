//! The client-facing byte streams. A client is either a plain obfuscated2 TCP stream or one
//! wrapped in Fake-TLS records; the bridge code only sees [`ClientReader`] / [`ClientWriter`].

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::fake_tls::{FakeTlsReader, FakeTlsWriter};

pub enum ClientReader {
    Plain(OwnedReadHalf),
    FakeTls(FakeTlsReader),
}

pub enum ClientWriter {
    Plain(OwnedWriteHalf),
    FakeTls(FakeTlsWriter),
}

impl ClientReader {
    /// Reads some bytes; `Ok(0)` means the client closed the connection.
    pub async fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ClientReader::Plain(r) => r.read(buf).await,
            ClientReader::FakeTls(r) => r.read(buf).await,
        }
    }

    pub async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read(&mut buf[filled..]).await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += n;
        }
        Ok(())
    }
}

impl ClientWriter {
    pub async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            ClientWriter::Plain(w) => w.write_all(data).await,
            ClientWriter::FakeTls(w) => w.write_all(data).await,
        }
    }

    pub async fn shutdown(&mut self) {
        let _ = match self {
            ClientWriter::Plain(w) => w.shutdown().await,
            ClientWriter::FakeTls(w) => w.shutdown().await,
        };
    }
}
