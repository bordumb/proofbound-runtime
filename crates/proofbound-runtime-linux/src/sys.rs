//! Contains the raw Linux calls needed by capability probes.

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;

pub(crate) fn landlock_abi() -> io::Result<u32> {
    // SAFETY: A version query requires a null attributes pointer and zero size.
    // The kernel does not dereference the null pointer for this flag.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            core::ptr::null::<libc::c_void>(),
            0,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        u32::try_from(result).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }
}

pub(crate) fn seccomp_mode() -> io::Result<u32> {
    // SAFETY: PR_GET_SECCOMP takes no pointer arguments. All unused arguments
    // are zero as required by prctl(2).
    let result = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        u32::try_from(result).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
    }
}

pub(crate) fn no_new_privileges_supported() -> io::Result<bool> {
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer arguments. All unused
    // arguments are zero as required by prctl(2).
    let result = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    match result {
        0 => Ok(true),
        1 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

pub(crate) fn path_is_writable(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: The CString owns a NUL-terminated path for the duration of the
    // call. access(2) does not retain the pointer.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}
