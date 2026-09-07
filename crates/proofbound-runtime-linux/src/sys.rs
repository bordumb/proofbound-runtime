//! Contains the raw Linux calls needed by capability probes.

use std::ffi::CString;
use std::io;
use std::os::fd::{FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_IS_SET: libc::c_ulong = 1;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
pub(crate) const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
pub(crate) const RESOLVE_NO_SYMLINKS: u64 = 0x04;
pub(crate) const RESOLVE_BENEATH: u64 = 0x08;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: i32,
}

#[derive(Clone, Copy, Default)]
#[repr(C)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CapabilitySets {
    pub(crate) effective: u64,
    pub(crate) permitted: u64,
    pub(crate) inheritable: u64,
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

pub(crate) fn openat2_write(directory: RawFd, path: &Path, resolution: u64) -> io::Result<OwnedFd> {
    openat2(
        directory,
        path,
        libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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

pub(crate) fn remove_directory_at(directory: RawFd, name: &Path) -> io::Result<()> {
    let name = CString::new(name.as_os_str().as_bytes())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `name` is NUL-terminated and remains alive for the call. The
    // `AT_REMOVEDIR` flag restricts removal to the exact child directory.
    let result = unsafe { libc::unlinkat(directory, name.as_ptr(), libc::AT_REMOVEDIR) };
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

pub(crate) fn create_landlock_ruleset(handled_access_fs: u64) -> io::Result<OwnedFd> {
    let attributes = LandlockRulesetAttr { handled_access_fs };
    // SAFETY: `attributes` has the versioned Linux ABI layout and remains live
    // for the call. A successful syscall returns a fresh descriptor.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &raw const attributes,
            core::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        let descriptor =
            i32::try_from(descriptor).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY: the syscall returned a new descriptor and ownership
        // transfers to this `OwnedFd` exactly once.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }
}

pub(crate) fn add_landlock_path_rule(
    ruleset: RawFd,
    parent: RawFd,
    allowed_access: u64,
) -> io::Result<()> {
    let attributes = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: parent,
    };
    // SAFETY: `attributes` has the Linux path-beneath ABI layout and remains
    // live for the call. Both descriptors are borrowed and remain open.
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset,
            LANDLOCK_RULE_PATH_BENEATH,
            &raw const attributes,
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn restrict_with_landlock(ruleset: RawFd) -> io::Result<()> {
    // SAFETY: the ruleset descriptor remains open for the duration of the
    // syscall and the versioned flags argument is zero.
    let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
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

pub(crate) fn set_no_new_privileges() -> io::Result<()> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only. The required
    // value is one and every unused argument is zero.
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn no_new_privileges_enabled() -> io::Result<bool> {
    // SAFETY: PR_GET_NO_NEW_PRIVS takes no pointer arguments and all unused
    // arguments are zero.
    let result = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    match result {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

pub(crate) fn process_ids() -> io::Result<(u32, u32, u32, u32, u32, u32)> {
    let (mut real_uid, mut effective_uid, mut saved_uid) = (0, 0, 0);
    let (mut real_gid, mut effective_gid, mut saved_gid) = (0, 0, 0);
    // SAFETY: Each pointer refers to live writable storage for the duration of
    // `getresuid`, and the call does not retain the pointers.
    let uid_result = unsafe {
        libc::getresuid(
            &raw mut real_uid,
            &raw mut effective_uid,
            &raw mut saved_uid,
        )
    };
    if uid_result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Each pointer refers to live writable storage for the duration of
    // `getresgid`, and the call does not retain the pointers.
    let gid_result = unsafe {
        libc::getresgid(
            &raw mut real_gid,
            &raw mut effective_gid,
            &raw mut saved_gid,
        )
    };
    if gid_result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        real_uid,
        effective_uid,
        saved_uid,
        real_gid,
        effective_gid,
        saved_gid,
    ))
}

pub(crate) fn capability_sets() -> io::Result<CapabilitySets> {
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapabilityData::default(); 2];
    // SAFETY: `header` and both data words use the Linux capability ABI layout,
    // remain live for the call, and the kernel writes only within those words.
    let result = unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(CapabilitySets {
        effective: u64::from(data[0].effective) | (u64::from(data[1].effective) << 32),
        permitted: u64::from(data[0].permitted) | (u64::from(data[1].permitted) << 32),
        inheritable: u64::from(data[0].inheritable) | (u64::from(data[1].inheritable) << 32),
    })
}

pub(crate) fn clear_capability_sets() -> io::Result<()> {
    let mut header = CapabilityHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [CapabilityData::default(); 2];
    // SAFETY: `header` and both zeroed data words use the Linux capability ABI
    // layout and remain live for the call. `capset` does not retain pointers.
    let result = unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn clear_ambient_capabilities() -> io::Result<()> {
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL takes integer arguments only. Every
    // unused argument is zero.
    let result = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn ambient_capability_is_set(capability: u32) -> io::Result<bool> {
    // SAFETY: PR_CAP_AMBIENT_IS_SET takes only the integer capability index and
    // zeroed unused arguments.
    let result = unsafe {
        libc::prctl(
            PR_CAP_AMBIENT,
            PR_CAP_AMBIENT_IS_SET,
            libc::c_ulong::from(capability),
            0,
            0,
        )
    };
    match result {
        0 => Ok(false),
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
