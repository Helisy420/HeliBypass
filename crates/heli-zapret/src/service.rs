//! Install the bypass as a Windows service (starts at boot, no app or UAC prompt needed).
//!
//! The service is called `zapret` and records the chosen strategy under
//! `HKLM\System\CurrentControlSet\Services\zapret\zapret-discord-youtube`, exactly like the
//! upstream `service.bat`, so the two tools recognise each other's installation.

use std::io;
use std::time::Duration;

use heli_core::activity;
use heli_core::paths::Paths;
use winreg::RegKey;
use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE};

use crate::bundle;
use crate::engine::SERVICE_NAME;
use crate::lists::GameFilter;
use crate::proc;
use crate::scm::{self, ServiceState};
use crate::strategy::{ArgContext, Strategy, quote_arg};

const REG_PATH: &str = r"SYSTEM\CurrentControlSet\Services\zapret";
const REG_VALUE: &str = "zapret-discord-youtube";

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("Administrator rights are required to manage the service.")]
    NotElevated,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("Engine files are missing or modified: {0:?}")]
    EngineFilesInvalid(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub service: ServiceState,
    /// Strategy the service was installed with.
    pub strategy: Option<String>,
    pub windivert: ServiceState,
    pub winws_running: bool,
}

pub fn status() -> ServiceStatus {
    ServiceStatus {
        service: scm::query(SERVICE_NAME).unwrap_or(ServiceState::NotInstalled),
        strategy: installed_strategy(),
        windivert: scm::query("WinDivert").unwrap_or(ServiceState::NotInstalled),
        winws_running: proc::is_running("winws.exe"),
    }
}

pub fn installed_strategy() -> Option<String> {
    let key = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(REG_PATH, KEY_QUERY_VALUE).ok()?;
    key.get_value::<String, _>(REG_VALUE).ok().filter(|s| !s.is_empty())
}

/// Install (or reinstall) and start the service with `strategy`.
pub fn install(paths: &Paths, strategy: &Strategy, game: &GameFilter) -> Result<(), ServiceError> {
    if !heli_core::elevation::is_elevated() {
        return Err(ServiceError::NotElevated);
    }
    bundle::install(paths)?;
    let bad = bundle::verify_engine(paths);
    if !bad.is_empty() {
        return Err(ServiceError::EngineFilesInvalid(bad));
    }

    // stop whatever is running: an older service instance or a standalone winws.exe
    let _ = scm::stop(SERVICE_NAME, Duration::from_secs(5));
    let _ = scm::delete(SERVICE_NAME);
    proc::kill_by_name("winws.exe");

    let ctx = ArgContext {
        bin_dir: paths.bin_dir(),
        lists_dir: paths.lists_dir(),
        game_tcp: game.tcp_arg(),
        game_udp: game.udp_arg(),
    };
    let exe = paths.bin_dir().join("winws.exe");
    let command = format!("{} {}", quote_arg(&exe.to_string_lossy()), strategy.command_line(&ctx));
    scm::create_auto_start(SERVICE_NAME, "zapret", "Zapret DPI bypass software", &command)?;

    if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(REG_PATH, KEY_SET_VALUE) {
        let _ = key.set_value(REG_VALUE, &strategy.name);
    }
    scm::start(SERVICE_NAME)?;
    activity::push("bypass", format!("service installed · {}", strategy.name));
    Ok(())
}

/// Stop and delete the service, kill stray `winws.exe` processes and unload WinDivert.
pub fn remove() -> Result<(), ServiceError> {
    if !heli_core::elevation::is_elevated() {
        return Err(ServiceError::NotElevated);
    }
    let _ = scm::stop(SERVICE_NAME, Duration::from_secs(5));
    scm::delete(SERVICE_NAME)?;
    proc::kill_by_name("winws.exe");
    for name in ["WinDivert", "WinDivert14"] {
        let _ = scm::stop(name, Duration::from_secs(3));
        let _ = scm::delete(name);
    }
    activity::push("bypass", "service removed");
    Ok(())
}
