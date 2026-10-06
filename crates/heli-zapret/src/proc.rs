//! Process helpers built on the ToolHelp snapshot API (no `tasklist` subprocess).

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

/// PIDs of all processes whose executable name equals `exe_name` (case-insensitive).
pub fn pids_by_name(exe_name: &str) -> Vec<u32> {
    let mut found = Vec::new();
    // SAFETY: the snapshot handle is closed on every path; `entry` is a properly sized,
    // zero-initialised PROCESSENTRY32W as the API requires.
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return found;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut ok = Process32FirstW(snap, &mut entry) != 0;
        while ok {
            let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
            if name.eq_ignore_ascii_case(exe_name) {
                found.push(entry.th32ProcessID);
            }
            ok = Process32NextW(snap, &mut entry) != 0;
        }
        CloseHandle(snap);
    }
    found
}

pub fn is_running(exe_name: &str) -> bool {
    !pids_by_name(exe_name).is_empty()
}

/// Forcefully terminate a process; returns whether it was terminated.
pub fn kill(pid: u32) -> bool {
    // SAFETY: plain open/terminate/close sequence on a process id.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if h.is_null() {
            return false;
        }
        let ok = TerminateProcess(h, 1) != 0;
        CloseHandle(h);
        ok
    }
}

/// Kill every process with that name; returns how many were terminated.
pub fn kill_by_name(exe_name: &str) -> usize {
    pids_by_name(exe_name).into_iter().filter(|p| kill(*p)).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_own_process() {
        let me = std::env::current_exe().unwrap();
        let name = me.file_name().unwrap().to_string_lossy().into_owned();
        assert!(pids_by_name(&name).contains(&std::process::id()));
        assert!(pids_by_name("definitely-not-a-process.exe").is_empty());
    }
}
