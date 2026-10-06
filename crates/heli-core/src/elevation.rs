//! Administrator rights: detection and "restart elevated".

/// `true` when the current process runs with an elevated token.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // SAFETY: standard token query; the handle is closed before returning and the output
    // buffer is a correctly sized TOKEN_ELEVATION.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

/// Relaunch this executable through the UAC prompt. Returns `true` if the new process was
/// started (the caller should then exit); `false` if the user declined or it failed.
#[cfg(windows)]
pub fn relaunch_elevated(extra_args: &[&str]) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let Ok(exe) = std::env::current_exe() else { return false };
    let wide = |s: &std::ffi::OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let verb = wide("runas".as_ref());
    let file = wide(exe.as_os_str());
    let params = wide(extra_args.join(" ").as_ref());
    // SAFETY: all pointers are NUL-terminated UTF-16 buffers that outlive the call.
    let result = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), file.as_ptr(), params.as_ptr(), std::ptr::null(), SW_SHOWNORMAL)
    };
    // ShellExecute returns a value > 32 on success.
    (result as isize) > 32
}

#[cfg(not(windows))]
pub fn relaunch_elevated(_extra_args: &[&str]) -> bool {
    false
}
