//! Contains the raw Linux calls needed by capability probes.

use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(crate) const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

pub(crate) fn open_directory(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `path` is NUL-terminated and remains alive for the call. The
    // returned descriptor is uniquely owned when `open` succeeds.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `open` returned a new descriptor and ownership transfers to
        // this `OwnedFd` exactly once.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

pub(crate) fn openat2_file(directory: RawFd, path: &Path, resolution: u64) -> io::Result<OwnedFd> {
    openat2(
        directory,
        path,
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NONBLOCK,
        resolution,
    )
}

pub(crate) fn openat2_directory(
    directory: RawFd,
    path: &Path,
    resolution: u64,
) -> io::Result<OwnedFd> {
    openat2(
        directory,
        path,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        resolution,
    )
}

pub(crate) fn openat2_path(directory: RawFd, path: &Path, resolution: u64) -> io::Result<OwnedFd> {
    openat2(
        directory,
        path,
        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        resolution,
    )
}

fn openat2(
    directory: RawFd,
    path: &Path,
    flags: libc::c_int,
    resolution: u64,
) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: u64::try_from(flags).expect("open flags fit u64"),
        mode: 0,
        resolve: resolution,
    };
    // SAFETY: `path` and `how` remain valid for the call, `how` has the kernel
    // ABI layout, and a successful syscall returns a fresh descriptor.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            directory,
            path.as_ptr(),
            &raw const how,
            core::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        let descriptor =
            i32::try_from(descriptor).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY: `openat2` returned a new descriptor and ownership transfers
        // to this `OwnedFd` exactly once.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

pub(crate) fn create_directory_at(
    directory: RawFd,
    name: &Path,
    mode: libc::mode_t,
) -> io::Result<()> {
    let name = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `name` is NUL-terminated and remains alive for the call. The
    // caller owns a live parent directory descriptor.
    let result = unsafe { libc::mkdirat(directory, name.as_ptr(), mode) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

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
