//! Thin, safe wrappers over the Windows Service Control Manager.
//!
//! Using the native API instead of `sc.exe` keeps this locale-independent (no parsing of
//! translated output), quick, and free of flashing console windows.

use std::io;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, ERROR_MORE_DATA, ERROR_SERVICE_DOES_NOT_EXIST};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, ENUM_SERVICE_STATUS_PROCESSW,
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_ENUM_PROCESS_INFO, SC_HANDLE,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE,
    SERVICE_AUTO_START, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS, SERVICE_START,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_WIN32, SERVICE_WIN32_OWN_PROCESS, StartServiceW,
    ChangeServiceConfig2W, SERVICE_CONFIG_DESCRIPTION, SERVICE_DESCRIPTIONW, SERVICE_STATE_ALL,
    SERVICE_DRIVER,
};

const DELETE: u32 = 0x0001_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    Other(u32),
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Handle(SC_HANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from OpenSCManager/OpenService/CreateService.
            unsafe { CloseServiceHandle(self.0) };
        }
    }
}

fn open_manager(access: u32) -> io::Result<Handle> {
    // SAFETY: null machine/database names select the local active database.
    let h = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), access) };
    if h.is_null() { Err(io::Error::last_os_error()) } else { Ok(Handle(h)) }
}

fn open_service(mgr: &Handle, name: &str, access: u32) -> io::Result<Option<Handle>> {
    let n = wide(name);
    // SAFETY: `n` is NUL terminated and outlives the call.
    let h = unsafe { OpenServiceW(mgr.0, n.as_ptr(), access) };
    if h.is_null() {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) { Ok(None) } else { Err(e) }
    } else {
        Ok(Some(Handle(h)))
    }
}

fn status_of(svc: &Handle) -> io::Result<SERVICE_STATUS> {
    // SAFETY: `status` is a valid out-pointer for the call.
    unsafe {
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        if QueryServiceStatus(svc.0, &mut status) == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(status)
    }
}

pub fn query(name: &str) -> io::Result<ServiceState> {
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let Some(svc) = open_service(&mgr, name, SERVICE_QUERY_STATUS)? else { return Ok(ServiceState::NotInstalled) };
    Ok(match status_of(&svc)?.dwCurrentState {
        1 => ServiceState::Stopped,
        2 => ServiceState::StartPending,
        3 => ServiceState::StopPending,
        4 => ServiceState::Running,
        other => ServiceState::Other(other),
    })
}

/// Create an auto-start service running `command_line` (executable path plus arguments).
pub fn create_auto_start(name: &str, display: &str, description: &str, command_line: &str) -> io::Result<()> {
    let mgr = open_manager(SC_MANAGER_CREATE_SERVICE)?;
    let (n, d, c) = (wide(name), wide(display), wide(command_line));
    // SAFETY: all strings are NUL terminated and outlive the call; optional parameters are null.
    let h = unsafe {
        CreateServiceW(
            mgr.0,
            n.as_ptr(),
            d.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            c.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    let svc = Handle(h);
    let mut desc = wide(description);
    let info = SERVICE_DESCRIPTIONW { lpDescription: desc.as_mut_ptr() };
    // SAFETY: `info` points at a live, NUL terminated wide string.
    unsafe {
        ChangeServiceConfig2W(svc.0, SERVICE_CONFIG_DESCRIPTION, (&info as *const SERVICE_DESCRIPTIONW).cast());
    }
    Ok(())
}

pub fn start(name: &str) -> io::Result<()> {
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let svc = open_service(&mgr, name, SERVICE_START)?.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    // SAFETY: no start arguments.
    if unsafe { StartServiceW(svc.0, 0, std::ptr::null()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Ask the service to stop and wait until it has (or `timeout` passes).
pub fn stop(name: &str, timeout: Duration) -> io::Result<()> {
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let Some(svc) = open_service(&mgr, name, SERVICE_STOP | SERVICE_QUERY_STATUS)? else { return Ok(()) };
    // SAFETY: valid out-pointer for the status.
    unsafe {
        let mut status: SERVICE_STATUS = std::mem::zeroed();
        // ERROR_SERVICE_NOT_ACTIVE just means it is already stopped
        if ControlService(svc.0, SERVICE_CONTROL_STOP, &mut status) == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(1062) {
                return Err(e);
            }
        }
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if status_of(&svc)?.dwCurrentState == 1 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "service did not stop in time"))
}

pub fn delete(name: &str) -> io::Result<()> {
    let mgr = open_manager(SC_MANAGER_CONNECT)?;
    let Some(svc) = open_service(&mgr, name, DELETE)? else { return Ok(()) };
    // SAFETY: handle opened with DELETE access.
    if unsafe { DeleteService(svc.0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: String,
}

/// Currently running Win32 services (the same population `sc query` shows by default).
pub fn running_services() -> io::Result<Vec<ServiceInfo>> {
    enumerate(SERVICE_WIN32, SERVICE_ACTIVE)
}

/// All installed services and drivers regardless of state (used to look for conflicts).
pub fn installed_services() -> io::Result<Vec<ServiceInfo>> {
    enumerate(SERVICE_WIN32 | SERVICE_DRIVER, SERVICE_STATE_ALL)
}

fn enumerate(service_type: u32, state: u32) -> io::Result<Vec<ServiceInfo>> {
    let mgr = open_manager(SC_MANAGER_ENUMERATE_SERVICE)?;
    let mut out = Vec::new();
    let mut buf: Vec<u8> = vec![0; 64 * 1024];
    let mut resume = 0u32;
    loop {
        let (mut needed, mut returned) = (0u32, 0u32);
        // SAFETY: `buf` is large enough for `buf.len()` bytes and the out-pointers are valid.
        let ok = unsafe {
            EnumServicesStatusExW(
                mgr.0,
                SC_ENUM_PROCESS_INFO,
                service_type,
                state,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut needed,
                &mut returned,
                &mut resume,
                std::ptr::null(),
            )
        };
        let err = if ok == 0 { io::Error::last_os_error() } else { io::Error::from_raw_os_error(0) };
        if ok == 0 && !matches!(err.raw_os_error(), Some(c) if c == ERROR_MORE_DATA as i32) {
            if matches!(err.raw_os_error(), Some(c) if c == ERROR_INSUFFICIENT_BUFFER as i32) {
                buf.resize(needed as usize + 1024, 0);
                continue;
            }
            return Err(err);
        }
        // SAFETY: on success/ERROR_MORE_DATA the buffer starts with `returned` entries whose
        // string pointers point into the same buffer.
        let entries = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>(), returned as usize)
        };
        for e in entries {
            out.push(ServiceInfo { name: read_wide(e.lpServiceName), display_name: read_wide(e.lpDisplayName) });
        }
        if ok != 0 {
            return Ok(out);
        }
    }
}

fn read_wide(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: the SCM returns NUL terminated strings inside the enumeration buffer.
    unsafe {
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_known_and_unknown_services() {
        assert_eq!(query("HeliBypassNoSuchService").unwrap(), ServiceState::NotInstalled);
        // The Windows event log service exists on every installation and is running.
        assert_eq!(query("EventLog").unwrap(), ServiceState::Running);
    }

    #[test]
    fn enumerates_running_services() {
        let all = running_services().unwrap();
        assert!(all.len() > 20, "found {}", all.len());
        assert!(all.iter().any(|s| s.name.eq_ignore_ascii_case("EventLog")));
        let installed = installed_services().unwrap();
        assert!(installed.len() >= all.len());
    }
}
