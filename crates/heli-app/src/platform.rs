//! Small Windows-specific helpers: shell open, clipboard, window styling, single instance,
//! and "launch at login".

use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE, POINT, RECT};
use windows_sys::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWA_WINDOW_CORNER_PREFERENCE};
use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST};
use windows_sys::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
use windows_sys::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows_sys::Win32::System::Threading::{CreateEventW, CreateMutexW, SetEvent, WaitForSingleObject, INFINITE};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, GetForegroundWindow, GetWindowLongPtrW, SetForegroundWindow, SetLayeredWindowAttributes, SetWindowLongPtrW, GWL_EXSTYLE, LWA_ALPHA, SW_SHOWNORMAL, WS_EX_LAYERED, WS_EX_TRANSPARENT};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn wide(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// Open a URL, file or folder with its default handler (also used for `tg://` links).
pub fn open(target: &str) -> bool {
    let (verb, file) = (wide("open"), wide(target));
    // SAFETY: NUL-terminated wide strings that outlive the call.
    let r = unsafe { ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL) };
    (r as isize) > 32
}

/// Show a file in Explorer with it selected.
pub fn reveal_in_explorer(path: &std::path::Path) {
    let _ = std::process::Command::new("explorer").arg(format!("/select,{}", path.display())).spawn();
}

pub fn copy_to_clipboard(text: &str) -> bool {
    const CF_UNICODETEXT: u32 = 13;
    let data: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: standard clipboard sequence; ownership of the global memory passes to the
    // clipboard on a successful SetClipboardData.
    unsafe {
        if OpenClipboard(std::ptr::null_mut()) == 0 {
            return false;
        }
        EmptyClipboard();
        let bytes = data.len() * 2;
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes);
        let ok = if mem.is_null() {
            false
        } else {
            let dst = GlobalLock(mem).cast::<u16>();
            if dst.is_null() {
                false
            } else {
                std::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
                GlobalUnlock(mem);
                !SetClipboardData(CF_UNICODETEXT, mem as HANDLE).is_null()
            }
        };
        CloseClipboard();
        ok
    }
}

pub fn cursor_position() -> (i32, i32) {
    let mut p = POINT { x: 0, y: 0 };
    // SAFETY: valid out pointer.
    unsafe { GetCursorPos(&mut p) };
    (p.x, p.y)
}

/// Usable desktop rectangle (without the taskbar) of the monitor under `point`.
pub fn work_area_at(point: (i32, i32)) -> (i32, i32, i32, i32) {
    // SAFETY: MONITORINFO is initialised with its size as the API requires.
    unsafe {
        let mon = MonitorFromPoint(POINT { x: point.0, y: point.1 }, MONITOR_DEFAULTTONEAREST);
        let mut info: MONITORINFO = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        if GetMonitorInfoW(mon, &mut info) != 0 {
            let RECT { left, top, right, bottom } = info.rcWork;
            (left, top, right, bottom)
        } else {
            (0, 0, 1920, 1040)
        }
    }
}

pub fn foreground_window() -> isize {
    // SAFETY: no arguments.
    unsafe { GetForegroundWindow() as isize }
}

pub fn focus_window(hwnd: isize) {
    // SAFETY: handle came from a live window.
    unsafe { SetForegroundWindow(hwnd as HANDLE) };
}

/// The native handle of a Slint window.
pub fn hwnd_of(window: &slint::Window) -> Option<isize> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match window.window_handle().window_handle().ok()?.as_raw() {
        RawWindowHandle::Win32(h) => Some(h.hwnd.get()),
        _ => None,
    }
}

/// Dark title colours, rounded corners (Windows 11) and a border in the design's colour.
pub fn style_window(hwnd: isize) {
    let set = |attr: u32, value: u32| {
        // SAFETY: attribute values are plain 32-bit integers; failures (older Windows) are fine.
        unsafe { DwmSetWindowAttribute(hwnd as HANDLE, attr, (&value as *const u32).cast(), 4) };
    };
    set(DWMWA_USE_IMMERSIVE_DARK_MODE as u32, 1);
    set(DWMWA_WINDOW_CORNER_PREFERENCE as u32, 2); // DWMWCP_ROUND
    set(DWMWA_BORDER_COLOR as u32, 0x0052_2D24); // #242D52 as COLORREF (0x00BBGGRR)
}

/// Returns `None` if another instance already runs (and pokes it to show its window).
pub struct SingleInstance {
    _mutex: HANDLE,
    activate: HANDLE,
}

impl SingleInstance {
    pub fn acquire() -> Option<Self> {
        // Isolated runs (HELIBYPASS_HOME set: development, tests) get their own lock.
        let suffix: String = std::env::var("HELIBYPASS_HOME")
            .map(|h| h.bytes().fold(0xcbf2_9ce4u32, |a, b| (a ^ u32::from(b)).wrapping_mul(0x0100_0193)))
            .map(|h| format!("_{h:08x}"))
            .unwrap_or_default();
        let mutex_name = wide(&format!("Local\\HeliBypass_SingleInstance{suffix}"));
        let event_name = wide(&format!("Local\\HeliBypass_Activate{suffix}"));
        // SAFETY: named kernel objects; handles are kept for the process lifetime.
        unsafe {
            let mutex = CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr());
            let already = GetLastError() == ERROR_ALREADY_EXISTS;
            let activate = CreateEventW(std::ptr::null(), 0, 0, event_name.as_ptr());
            if already {
                if !activate.is_null() {
                    SetEvent(activate);
                    CloseHandle(activate);
                }
                CloseHandle(mutex);
                return None;
            }
            Some(Self { _mutex: mutex, activate })
        }
    }

    /// Calls `on_activate` (on a helper thread) whenever a second instance asks us to show up.
    pub fn watch(&self, on_activate: impl Fn() + Send + 'static) {
        let handle = self.activate as usize;
        std::thread::spawn(move || loop {
            // SAFETY: the event handle lives as long as the process.
            let r = unsafe { WaitForSingleObject(handle as HANDLE, INFINITE) };
            if r != 0 {
                break;
            }
            on_activate();
        });
    }
}

const TASK_NAME: &str = "HeliBypass";

fn schtasks(args: &[&str]) -> std::io::Result<std::process::Output> {
    std::process::Command::new("schtasks").args(args).creation_flags(CREATE_NO_WINDOW).output()
}

/// Run at login with the highest privileges (no UAC prompt) via the Task Scheduler.
pub fn set_autostart(enabled: bool, minimized: bool) -> Result<(), String> {
    if !enabled {
        let _ = schtasks(&["/Delete", "/TN", TASK_NAME, "/F"]);
        return Ok(());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut command = format!("\"{}\"", exe.display());
    if minimized {
        command.push_str(" --minimized");
    }
    let out = schtasks(&["/Create", "/TN", TASK_NAME, "/SC", "ONLOGON", "/RL", "HIGHEST", "/TR", &command, "/F"])
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// Development aid: let mouse input pass through the window (used for unattended screenshots).
#[cfg(debug_assertions)]
pub fn make_click_through(hwnd: isize) {
    // SAFETY: plain style change on a live window handle.
    unsafe {
        let h = hwnd as HANDLE;
        let ex = GetWindowLongPtrW(h, GWL_EXSTYLE);
        SetWindowLongPtrW(h, GWL_EXSTYLE, ex | (WS_EX_LAYERED | WS_EX_TRANSPARENT) as isize);
        SetLayeredWindowAttributes(h, 0, 255, LWA_ALPHA);
    }
}
