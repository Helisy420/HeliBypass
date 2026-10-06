//! Runs `winws.exe` under supervision.

use std::collections::VecDeque;
use std::os::windows::process::CommandExt;
use std::process::Stdio;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use heli_core::activity;
use heli_core::paths::Paths;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::task::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};

use crate::bundle;
use crate::lists::GameFilter;
use crate::proc;
use crate::scm::{self, ServiceState};
use crate::strategy::{ArgContext, Strategy};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
pub const SERVICE_NAME: &str = "zapret";
const READY_MARKER: &str = "capture is started";
const OUTPUT_RING: usize = 80;

#[derive(Debug, Clone, PartialEq)]
pub enum EngineState {
    Stopped,
    Starting(String),
    Running { strategy: String, pid: u32, since: Instant },
    Failed(String),
}

impl EngineState {
    pub fn is_running(&self) -> bool {
        matches!(self, EngineState::Running { .. })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Administrator rights are required to run the bypass (WinDivert needs them).")]
    NotElevated,
    #[error("The Windows service \"zapret\" is running. Remove it first (Service page) or use it instead.")]
    ServiceRunning,
    #[error("Another winws.exe is already running (PID {0:?}). Stop it before starting the bypass.")]
    OtherInstance(Vec<u32>),
    #[error("Engine files are missing or modified and could not be restored: {0:?}")]
    EngineFilesInvalid(Vec<String>),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("winws.exe stopped right after launch{}", format_exit(.code, .hint, .output))]
    Exited { code: Option<i32>, hint: Option<&'static str>, output: String },
}

fn format_exit(code: &Option<i32>, hint: &Option<&'static str>, output: &str) -> String {
    let mut s = String::new();
    if let Some(c) = code {
        s.push_str(&format!(" (exit code {c})"));
    }
    if let Some(h) = hint {
        s.push_str(&format!(". {h}"));
    }
    if !output.is_empty() {
        s.push_str(&format!("\n{output}"));
    }
    s
}

struct JobHandle(HANDLE);
// SAFETY: a job handle is just a kernel object reference; it may be used from any thread.
unsafe impl Send for JobHandle {}
unsafe impl Sync for JobHandle {}

impl JobHandle {
    /// A job that kills every assigned process when the handle is closed (i.e. when we exit,
    /// even by crashing) so `winws.exe` can never be orphaned.
    fn kill_on_close() -> Option<Self> {
        // SAFETY: standard job-object setup; the struct is zero-initialised and fully owned.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(job);
                return None;
            }
            Some(Self(job))
        }
    }

    fn assign(&self, process: HANDLE) -> bool {
        // SAFETY: both handles are valid for the duration of the call.
        unsafe { AssignProcessToJobObject(self.0, process) != 0 }
    }
}

impl Drop for JobHandle {
    fn drop(&mut self) {
        // SAFETY: we own the handle; closing it triggers KILL_ON_JOB_CLOSE for any member.
        unsafe { CloseHandle(self.0) };
    }
}

struct Running {
    stop_tx: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
    _job: Option<JobHandle>,
}

/// Starts/stops the bypass and publishes its state.
pub struct Engine {
    paths: Paths,
    running: Mutex<Option<Running>>,
    state_tx: watch::Sender<EngineState>,
    output: Arc<StdMutex<VecDeque<String>>>,
}

impl Engine {
    pub fn new(paths: Paths) -> Arc<Self> {
        let (state_tx, _) = watch::channel(EngineState::Stopped);
        Arc::new(Self {
            paths,
            running: Mutex::new(None),
            state_tx,
            output: Arc::new(StdMutex::new(VecDeque::with_capacity(OUTPUT_RING))),
        })
    }

    pub fn state(&self) -> EngineState {
        self.state_tx.borrow().clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<EngineState> {
        self.state_tx.subscribe()
    }

    /// Last lines printed by `winws.exe`.
    pub fn recent_output(&self) -> Vec<String> {
        self.output.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect()
    }

    pub async fn start(&self, strategy: &Strategy, game: &GameFilter) -> Result<(), EngineError> {
        let mut slot = self.running.lock().await;
        if slot.is_some() {
            self.stop_locked(&mut slot).await;
        }
        self.state_tx.send_replace(EngineState::Starting(strategy.name.clone()));
        match self.start_inner(strategy, game).await {
            Ok(running) => {
                *slot = Some(running);
                Ok(())
            }
            Err(e) => {
                self.state_tx.send_replace(EngineState::Failed(e.to_string()));
                activity::error("bypass", format!("start failed: {}", first_line(&e.to_string())));
                Err(e)
            }
        }
    }

    async fn start_inner(&self, strategy: &Strategy, game: &GameFilter) -> Result<Running, EngineError> {
        if !heli_core::elevation::is_elevated() {
            return Err(EngineError::NotElevated);
        }
        match scm::query(SERVICE_NAME) {
            Ok(ServiceState::Running | ServiceState::StartPending) => return Err(EngineError::ServiceRunning),
            _ => {}
        }
        let foreign = proc::pids_by_name("winws.exe");
        if !foreign.is_empty() {
            return Err(EngineError::OtherInstance(foreign));
        }

        // Repair/verify the engine folder before running anything with admin rights.
        let paths = self.paths.clone();
        let (report, bad) = tokio::task::spawn_blocking(move || {
            let r = bundle::install(&paths);
            (r, bundle::verify_engine(&paths))
        })
        .await
        .map_err(std::io::Error::other)?;
        report?;
        if !bad.is_empty() {
            return Err(EngineError::EngineFilesInvalid(bad));
        }

        enable_tcp_timestamps().await;

        let ctx = ArgContext {
            bin_dir: self.paths.bin_dir(),
            lists_dir: self.paths.lists_dir(),
            game_tcp: game.tcp_arg(),
            game_udp: game.udp_arg(),
        };
        let args = strategy.args(&ctx);
        tracing::info!("starting winws.exe with strategy {:?} ({} args)", strategy.name, args.len());
        self.launch(self.paths.bin_dir().join("winws.exe"), args, self.paths.bin_dir(), strategy.name.clone()).await
    }

    /// Spawn `exe` under supervision and wait until it reports readiness (or fails).
    /// Separate from `start_inner` so the supervision logic can be exercised with a stand-in
    /// process in tests, without administrator rights.
    async fn launch(
        &self,
        exe: std::path::PathBuf,
        args: Vec<String>,
        cwd: std::path::PathBuf,
        name: String,
    ) -> Result<Running, EngineError> {
        self.output.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let mut child = Command::new(&exe)
            .args(&args)
            .current_dir(&cwd)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        let pid = child.id().unwrap_or(0);

        let job = JobHandle::kill_on_close();
        if let (Some(job), Some(handle)) = (&job, child.raw_handle()) {
            if !job.assign(handle as HANDLE) {
                tracing::debug!("could not assign winws.exe to the kill-on-close job");
            }
        }

        // pump output into the ring buffer and detect the ready marker
        let (ready_tx, mut ready_rx) = watch::channel(false);
        for stream in [
            child.stdout.take().map(|s| Box::new(BufReader::new(s)) as Box<dyn tokio::io::AsyncBufRead + Send + Unpin>),
            child.stderr.take().map(|s| Box::new(BufReader::new(s)) as Box<dyn tokio::io::AsyncBufRead + Send + Unpin>),
        ]
        .into_iter()
        .flatten()
        {
            let ring = Arc::clone(&self.output);
            let ready = ready_tx.clone();
            tokio::spawn(async move {
                let mut lines = stream.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let line = line.trim_end().to_owned();
                    if line.is_empty() {
                        continue;
                    }
                    tracing::debug!(target: "winws", "{line}");
                    if line.contains(READY_MARKER) {
                        let _ = ready.send(true);
                    }
                    let mut r = ring.lock().unwrap_or_else(|e| e.into_inner());
                    if r.len() == OUTPUT_RING {
                        r.pop_front();
                    }
                    r.push_back(line);
                }
            });
        }
        drop(ready_tx);

        // supervisor: owns the child, reports unexpected exits, honours stop requests
        let (stop_tx, mut stop_rx) = oneshot::channel::<()>();
        let (exit_tx, mut exit_rx) = oneshot::channel::<Option<i32>>();
        let state_tx = self.state_tx.clone();
        let task = tokio::spawn(async move {
            tokio::select! {
                status = child.wait() => {
                    let code = status.ok().and_then(|s| s.code());
                    let _ = exit_tx.send(code);
                    if !matches!(*state_tx.borrow(), EngineState::Starting(_)) {
                        let msg = format!("winws.exe exited unexpectedly (code {})", code.map_or("?".into(), |c| c.to_string()));
                        activity::error("bypass", msg.clone());
                        state_tx.send_replace(EngineState::Failed(msg));
                    }
                }
                _ = &mut stop_rx => {
                    let _ = child.start_kill();
                    let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                }
            }
        });

        // wait for "capture is started", an early exit, or give up waiting after a grace period
        let started = Instant::now();
        let outcome = loop {
            tokio::select! {
                code = &mut exit_rx => break Err(code.ok().flatten()),
                changed = ready_rx.changed() => {
                    if changed.is_ok() && *ready_rx.borrow() { break Ok(()); }
                    // sender dropped (streams closed): fall through to the time check
                }
                _ = tokio::time::sleep(Duration::from_millis(100)) => {}
            }
            if started.elapsed() > Duration::from_millis(2500) {
                break Ok(()); // alive and quiet: older winws builds print no marker
            }
        };
        match outcome {
            Ok(()) => {
                self.state_tx.send_replace(EngineState::Running { strategy: name.clone(), pid, since: Instant::now() });
                activity::push("bypass", format!("started · {name}"));
                Ok(Running { stop_tx: Some(stop_tx), task, _job: job })
            }
            Err(code) => {
                let output = self.recent_output().join("\n");
                let hint = hint_for(&output, code);
                Err(EngineError::Exited { code, hint, output: last_lines(&output, 4) })
            }
        }
    }

    pub async fn stop(&self) {
        let mut slot = self.running.lock().await;
        self.stop_locked(&mut slot).await;
    }

    async fn stop_locked(&self, slot: &mut Option<Running>) {
        let Some(mut running) = slot.take() else {
            self.state_tx.send_replace(EngineState::Stopped);
            return;
        };
        if let Some(tx) = running.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = tokio::time::timeout(Duration::from_secs(5), &mut running.task).await;
        self.state_tx.send_replace(EngineState::Stopped);
        activity::push("bypass", "stopped");
        // release the WinDivert driver so its file can be updated; harmless if still in use
        tokio::task::spawn_blocking(|| {
            if !proc::is_running("winws.exe") {
                let _ = scm::stop("WinDivert", Duration::from_secs(2));
            }
        })
        .await
        .ok();
    }
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or(s)
}

fn last_lines(s: &str, n: usize) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Turn winws/WinDivert failure output into advice a person can act on.
pub fn hint_for(output: &str, code: Option<i32>) -> Option<&'static str> {
    let o = output.to_ascii_lowercase();
    if o.contains("1275") || o.contains("blocked from loading") || o.contains("driver has been blocked") {
        Some("Windows or an antivirus blocked the WinDivert driver (error 1275). Allow WinDivert64.sys or disable Memory Integrity / driver blocklist and retry.")
    } else if o.contains("577") || o.contains("signature") {
        Some("The WinDivert driver signature was rejected (error 577). Check that Secure Boot/driver signing policy allows it.")
    } else if o.contains("error code 5") || o.contains("access is denied") || o.contains("access denied") {
        Some("Access denied: run HeliBypass as administrator.")
    } else if o.contains("error code 2") || o.contains("cannot find") || o.contains("not found") {
        Some("A required file is missing (WinDivert64.sys or a payload .bin). Use Diagnostics to repair the engine files.")
    } else if o.contains("filter") && o.contains("error") {
        Some("The filter was rejected by WinDivert. Another bypass tool may be using it - check Diagnostics for conflicts.")
    } else if code == Some(0xC0000135u32 as i32) || code == Some(-1073741515) {
        Some("A required DLL is missing next to winws.exe (cygwin1.dll). Use Diagnostics to repair the engine files.")
    } else {
        None
    }
}

/// `--dpi-desync-fooling=ts` and several fakes only work with TCP timestamps enabled.
async fn enable_tcp_timestamps() {
    let _ = tokio::task::spawn_blocking(|| {
        std::process::Command::new("netsh")
            .args(["interface", "tcp", "set", "global", "timestamps=enabled"])
            .creation_flags(CREATE_NO_WINDOW)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
    })
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hints_cover_the_common_windivert_failures() {
        assert!(hint_for("windivert: error opening filter: 1275", None).unwrap().contains("blocked"));
        assert!(hint_for("WinDivertOpen failed, error code 5", None).unwrap().contains("administrator"));
        assert!(hint_for("something else entirely", Some(1)).is_none());
        assert!(hint_for("", Some(-1073741515)).unwrap().contains("DLL"));
    }

    fn test_engine(tag: &str) -> Arc<Engine> {
        Engine::new(Paths::at(std::env::temp_dir().join(format!("heli-engine-{tag}-{}", std::process::id()))))
    }

    fn cmd_exe() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".into()))
    }

    #[tokio::test]
    async fn supervises_a_process_until_stopped() {
        let engine = test_engine("ok");
        // prints the readiness marker, then stays alive for a while (like winws.exe does)
        let args = vec!["/C".into(), "echo windivert initialized. capture is started.& ping -n 30 127.0.0.1 >nul".into()];
        let started = Instant::now();
        let running = engine.launch(cmd_exe(), args, std::env::temp_dir(), "stand-in".into()).await.expect("launch");
        assert!(started.elapsed() < Duration::from_secs(2), "ready marker must short-circuit the grace period");
        assert!(engine.recent_output().iter().any(|l| l.contains("capture is started")));
        assert!(engine.state().is_running());
        // the state change itself is published by `start`; here we only check the live process
        let pid = match engine.state() {
            EngineState::Running { pid, .. } => pid,
            other => panic!("unexpected state {other:?}"),
        };
        assert!(pid > 0 && proc::pids_by_name("cmd.exe").contains(&pid));

        *engine.running.lock().await = Some(running);
        engine.stop().await;
        assert_eq!(engine.state(), EngineState::Stopped);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!proc::pids_by_name("cmd.exe").contains(&pid), "process must be killed on stop");
    }

    #[tokio::test]
    async fn reports_early_exit_with_output_and_hint() {
        let engine = test_engine("fail");
        let args = vec!["/C".into(), "echo WinDivertOpen failed, error code 5& exit 3".into()];
        let err = match engine.launch(cmd_exe(), args, std::env::temp_dir(), "broken".into()).await {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        match err {
            EngineError::Exited { code, hint, output } => {
                assert_eq!(code, Some(3));
                assert!(hint.unwrap().contains("administrator"));
                assert!(output.contains("error code 5"));
            }
            other => panic!("unexpected error {other}"),
        }
    }

    #[tokio::test]
    async fn refuses_to_start_without_admin_rights() {
        if heli_core::elevation::is_elevated() {
            return; // this check is only meaningful for unelevated runs
        }
        let paths = Paths::at(std::env::temp_dir().join(format!("heli-engine-{}", std::process::id())));
        let engine = Engine::new(paths);
        let s = crate::bundle::builtin_strategies().remove(0);
        let err = engine.start(&s, &GameFilter::default()).await.unwrap_err();
        assert!(matches!(err, EngineError::NotElevated), "{err}");
        assert!(matches!(engine.state(), EngineState::Failed(_)));
    }
}
