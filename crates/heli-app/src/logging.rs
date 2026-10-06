//! File logging with size-based rotation. Host names are masked (see `heli_core::censor`) so a
//! shared log does not reveal a user's own Cloudflare domains.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

const MAX_BYTES: u64 = 5 * 1024 * 1024;

struct Inner {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    line: Vec<u8>,
}

impl Inner {
    fn open(&mut self) {
        self.written = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
    }

    fn rotate(&mut self) {
        self.file = None;
        let backup = self.path.with_extension("log.1");
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::rename(&self.path, backup);
        self.open();
    }

    fn emit(&mut self, text: &str) {
        if self.file.is_none() {
            self.open();
        }
        if self.written >= MAX_BYTES {
            self.rotate();
        }
        let masked = heli_core::censor::censor_domains(text);
        if let Some(f) = self.file.as_mut() {
            if f.write_all(masked.as_bytes()).is_ok() {
                self.written += masked.len() as u64;
            }
        }
    }
}

#[derive(Clone)]
pub struct LogFile(Arc<Mutex<Inner>>);

impl LogFile {
    pub fn new(path: PathBuf) -> Self {
        Self(Arc::new(Mutex::new(Inner { path, file: None, written: 0, line: Vec::new() })))
    }
}

pub struct LogWriter(LogFile);

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = (self.0).0.lock().unwrap_or_else(|e| e.into_inner());
        g.line.extend_from_slice(buf);
        // emit complete lines only so masking never sees half a host name
        while let Some(pos) = g.line.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = g.line.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line).into_owned();
            g.emit(&text);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(f) = (self.0).0.lock().unwrap_or_else(|e| e.into_inner()).file.as_mut() {
            f.flush()?;
        }
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for LogFile {
    type Writer = LogWriter;
    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self.clone())
    }
}

pub fn init(logs_dir: PathBuf, verbose: bool) {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Layer;

    let _ = std::fs::create_dir_all(&logs_dir);
    let level = if verbose { LevelFilter::DEBUG } else { LevelFilter::INFO };
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(false)
        .with_writer(LogFile::new(logs_dir.join("heli-bypass.log")))
        .with_filter(level);
    let _ = tracing_subscriber::registry().with(file_layer).try_init();
}
