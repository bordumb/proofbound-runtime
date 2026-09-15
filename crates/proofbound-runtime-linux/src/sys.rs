//! Contains the raw Linux calls needed by capability probes.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;
use std::process::Command;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
const PR_CAP_AMBIENT: libc::c_int = 47;
const PR_CAP_AMBIENT_IS_SET: libc::c_ulong = 1;
const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_O_TRACESYSGOOD: u32 = 0x0000_0001;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_O_TRACEFORK: u32 = 0x0000_0002;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_O_TRACEVFORK: u32 = 0x0000_0004;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_O_TRACECLONE: u32 = 0x0000_0008;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_O_TRACEEXEC: u32 = 0x0000_0010;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_O_EXITKILL: u32 = 0x0010_0000;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_EVENT_FORK: u32 = 1;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_EVENT_VFORK: u32 = 2;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_EVENT_CLONE: u32 = 3;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_EVENT_EXEC: u32 = 4;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_GETEVENTMSG: libc::c_uint = 0x4201;
#[cfg(feature = "diagnostic-observer")]
const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;
#[cfg(feature = "diagnostic-observer")]
const REQUIRED_DIAGNOSTIC_TRACE_OPTIONS: u32 = PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_EXITKILL;
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

#[repr(C)]
struct BpfProgram {
    length: u16,
    instructions: *const crate::seccomp::BpfInstruction,
}

#[cfg(feature = "diagnostic-observer")]
#[repr(C)]
struct RawSyscallInfo {
    operation: u8,
    _padding: [u8; 3],
    architecture: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u8; 64],
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

pub(crate) fn install_seccomp_filter(
    instructions: &[crate::seccomp::BpfInstruction],
) -> io::Result<()> {
    const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
    const SECCOMP_FILTER_FLAG_TSYNC: libc::c_uint = 1;

    let length = u16::try_from(instructions.len())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let program = BpfProgram {
        length,
        instructions: instructions.as_ptr(),
    };
    // SAFETY: `program` and its instruction slice remain live for the syscall,
    // use the classic-BPF kernel ABI layout, and are read-only to the kernel.
    let result = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_TSYNC,
            &raw const program,
        )
    };
    if result == 0 {
        Ok(())
    } else if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Err(io::Error::other("seccomp synchronization failed"))
    }
}

pub(crate) fn private_socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut descriptors = [-1; 2];
    // SAFETY: `descriptors` contains space for the two descriptors written by
    // socketpair. Each successful descriptor becomes uniquely owned below.
    let result = unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            descriptors.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two new descriptors and ownership transfers
    // to these values exactly once.
    let first = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: see the ownership argument for `first` above.
    let second = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    Ok((first, second))
}

pub(crate) fn send_packet(descriptor: RawFd, bytes: &[u8]) -> io::Result<()> {
    // SAFETY: `bytes` remains readable for the call and `descriptor` is
    // borrowed by the caller. SOCK_SEQPACKET preserves this write as one
    // packet. The seccomp profile permits write for this acknowledgement.
    let written = unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) };
    if written < 0 {
        Err(io::Error::last_os_error())
    } else if usize::try_from(written).ok() == Some(bytes.len()) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "private protocol packet was not sent atomically",
        ))
    }
}

pub(crate) fn receive_packet(descriptor: RawFd, buffer: &mut [u8]) -> io::Result<usize> {
    // SAFETY: `buffer` remains writable for the call and `descriptor` is
    // borrowed by the caller. The caller supplies one extra byte so a packet
    // above its bound remains observable. `read` stays available after the
    // launcher installs the deny-network seccomp filter.
    let received = unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
    if received < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(received).map_err(|_| io::Error::other("negative receive size"))
    }
}

pub(crate) fn wait_readable(descriptor: RawFd, timeout: std::time::Duration) -> io::Result<bool> {
    let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
    let mut poll_descriptor = libc::pollfd {
        fd: descriptor,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll_descriptor` is valid writable storage for one poll entry.
    let result = unsafe { libc::poll(&raw mut poll_descriptor, 1, milliseconds) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result > 0)
    }
}

pub(crate) fn take_inherited_descriptor(descriptor: RawFd) -> io::Result<OwnedFd> {
    let duplicate = duplicate_descriptor(descriptor)?;
    // SAFETY: close takes only an integer descriptor. The new duplicate above
    // remains independently owned.
    let result = unsafe { libc::close(descriptor) };
    if result == 0 {
        Ok(duplicate)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn inherit_descriptors_for_exec(command: &mut Command, descriptors: Vec<RawFd>) {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: the closure runs after fork and before exec. It calls only fcntl,
    // performs no allocation, and returns an io::Error created from errno.
    unsafe {
        command.pre_exec(move || {
            for descriptor in &descriptors {
                if libc::fcntl(*descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn prepare_traced_exec(command: &mut Command, descriptors: Vec<RawFd>) {
    use std::os::unix::process::CommandExt as _;

    // SAFETY: the closure runs after fork and before exec. It calls only
    // fcntl and ptrace, performs no allocation, and returns an io::Error
    // created from errno. PTRACE_TRACEME affects only this future child.
    unsafe {
        command.pre_exec(move || {
            for descriptor in &descriptors {
                if libc::fcntl(*descriptor, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::ptrace(
                libc::PTRACE_TRACEME,
                0,
                core::ptr::null_mut::<libc::c_void>(),
                core::ptr::null_mut::<libc::c_void>(),
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(feature = "diagnostic-observer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceWaitStatus {
    Stopped { signal: i32, event: u32 },
    Exited { code: i32 },
    Signaled { signal: i32 },
}

#[cfg(feature = "diagnostic-observer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TraceWaitObservation {
    pub(crate) process_id: u32,
    pub(crate) status: TraceWaitStatus,
}

#[cfg(feature = "diagnostic-observer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceSyscallStop {
    Entry {
        architecture: u32,
        instruction_pointer: u64,
        stack_pointer: u64,
        number: u64,
        arguments: [u64; 6],
    },
    Exit {
        result: i64,
        is_error: bool,
    },
    Seccomp,
    None,
}

#[cfg(feature = "diagnostic-observer")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceProcessCreationEvent {
    Fork,
    Vfork,
    Clone,
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_wait_nonblocking(process_id: u32) -> io::Result<Option<TraceWaitStatus>> {
    const WAIT_ALL_TRACED: libc::c_int = 0x4000_0000;

    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut status = 0;
    // SAFETY: `status` is valid writable storage and waitpid is scoped to the
    // exact traced child. The flags request stopped tracees without blocking.
    let result = unsafe {
        libc::waitpid(
            process_id,
            &raw mut status,
            libc::WUNTRACED | libc::WNOHANG | WAIT_ALL_TRACED,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Ok(None);
    }
    if result != process_id {
        return Err(io::Error::other("wait returned an unexpected process"));
    }
    if libc::WIFSTOPPED(status) {
        let status_bits =
            u32::try_from(status).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        return Ok(Some(TraceWaitStatus::Stopped {
            signal: libc::WSTOPSIG(status),
            event: (status_bits >> 16) & 0xffff,
        }));
    }
    if libc::WIFEXITED(status) {
        return Ok(Some(TraceWaitStatus::Exited {
            code: libc::WEXITSTATUS(status),
        }));
    }
    if libc::WIFSIGNALED(status) {
        return Ok(Some(TraceWaitStatus::Signaled {
            signal: libc::WTERMSIG(status),
        }));
    }
    Err(io::Error::other("unexpected traced wait status"))
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_wait_event_nonblocking(
    process_id: u32,
) -> io::Result<Option<TraceWaitObservation>> {
    const WAIT_ALL_TRACED: libc::c_int = 0x4000_0000;

    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut status = 0;
    // SAFETY: `status` is valid writable storage. `waitpid` is scoped to one
    // known tracee. Linux can report a different positive identifier only
    // when a non-leader thread changes identity during `exec`; the safe trace
    // state validates that transition before it accepts the observation.
    let result = unsafe {
        libc::waitpid(
            process_id,
            &raw mut status,
            libc::WUNTRACED | libc::WNOHANG | WAIT_ALL_TRACED,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    if result == 0 {
        return Ok(None);
    }
    let reported_process =
        u32::try_from(result).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    let status = if libc::WIFSTOPPED(status) {
        let status_bits =
            u32::try_from(status).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        TraceWaitStatus::Stopped {
            signal: libc::WSTOPSIG(status),
            event: (status_bits >> 16) & 0xffff,
        }
    } else if libc::WIFEXITED(status) {
        TraceWaitStatus::Exited {
            code: libc::WEXITSTATUS(status),
        }
    } else if libc::WIFSIGNALED(status) {
        TraceWaitStatus::Signaled {
            signal: libc::WTERMSIG(status),
        }
    } else {
        return Err(io::Error::other("unexpected traced wait status"));
    };
    Ok(Some(TraceWaitObservation {
        process_id: reported_process,
        status,
    }))
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_event_process(process_id: u32) -> io::Result<u32> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut message: libc::c_ulong = 0;
    // SAFETY: ptrace receives one stopped tracee and writable storage for the
    // event message selected by the kernel for that exact stop.
    let result = unsafe {
        libc::ptrace(
            PTRACE_GETEVENTMSG,
            process_id,
            core::ptr::null_mut::<libc::c_void>(),
            &raw mut message,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    u32::try_from(message).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_syscall_stop(process_id: u32) -> io::Result<TraceSyscallStop> {
    const SYSCALL_INFO_NONE: u8 = 0;
    const SYSCALL_INFO_ENTRY: u8 = 1;
    const SYSCALL_INFO_EXIT: u8 = 2;
    const SYSCALL_INFO_SECCOMP: u8 = 3;

    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut information = RawSyscallInfo {
        operation: 0,
        _padding: [0; 3],
        architecture: 0,
        instruction_pointer: 0,
        stack_pointer: 0,
        data: [0; 64],
    };
    // SAFETY: ptrace receives one stopped tracee and a pointer to the complete
    // Linux `ptrace_syscall_info` storage. The supplied size is the exact
    // storage size, and the kernel returns the number of available bytes.
    let result = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            process_id,
            core::mem::size_of::<RawSyscallInfo>(),
            &raw mut information,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let available =
        usize::try_from(result).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    if available < 24 {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    match information.operation {
        SYSCALL_INFO_NONE => Ok(TraceSyscallStop::None),
        SYSCALL_INFO_ENTRY => {
            if available < 80 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let number = trace_read_u64(&information.data, 0)?;
            let mut arguments = [0_u64; 6];
            for (index, argument) in arguments.iter_mut().enumerate() {
                let start = 8 + index * 8;
                *argument = trace_read_u64(&information.data, start)?;
            }
            Ok(TraceSyscallStop::Entry {
                architecture: information.architecture,
                instruction_pointer: information.instruction_pointer,
                stack_pointer: information.stack_pointer,
                number,
                arguments,
            })
        }
        SYSCALL_INFO_EXIT => {
            if available < 33 {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let result = trace_read_i64(&information.data, 0)?;
            match information.data[8] {
                0 => Ok(TraceSyscallStop::Exit {
                    result,
                    is_error: false,
                }),
                1 => Ok(TraceSyscallStop::Exit {
                    result,
                    is_error: true,
                }),
                _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
            }
        }
        SYSCALL_INFO_SECCOMP => Ok(TraceSyscallStop::Seccomp),
        _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
    }
}

#[cfg(feature = "diagnostic-observer")]
fn trace_read_u64(bytes: &[u8], start: usize) -> io::Result<u64> {
    let end = start
        .checked_add(core::mem::size_of::<u64>())
        .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
    let field = bytes
        .get(start..end)
        .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
    let field =
        <[u8; 8]>::try_from(field).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(u64::from_ne_bytes(field))
}

#[cfg(feature = "diagnostic-observer")]
fn trace_read_i64(bytes: &[u8], start: usize) -> io::Result<i64> {
    let end = start
        .checked_add(core::mem::size_of::<i64>())
        .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
    let field = bytes
        .get(start..end)
        .ok_or(io::Error::from(io::ErrorKind::InvalidData))?;
    let field =
        <[u8; 8]>::try_from(field).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
    Ok(i64::from_ne_bytes(field))
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) const fn trace_event_is_exec(event: u32) -> bool {
    event == PTRACE_EVENT_EXEC
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) const fn trace_process_creation_event(event: u32) -> Option<TraceProcessCreationEvent> {
    match event {
        PTRACE_EVENT_FORK => Some(TraceProcessCreationEvent::Fork),
        PTRACE_EVENT_VFORK => Some(TraceProcessCreationEvent::Vfork),
        PTRACE_EVENT_CLONE => Some(TraceProcessCreationEvent::Clone),
        _ => None,
    }
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_open_process_handle(process_id: u32) -> io::Result<OwnedFd> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: pidfd_open receives one positive thread-group leader identity
    // and zero flags. A successful call returns one new close-on-exec file
    // descriptor whose identity cannot change through PID reuse.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, process_id, 0) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        let descriptor =
            i32::try_from(descriptor).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        // SAFETY: pidfd_open returned one new descriptor and ownership
        // transfers to this value exactly once.
        let handle = unsafe { OwnedFd::from_raw_fd(descriptor) };
        trace_signal_process_handle(handle.as_raw_fd(), 0)?;
        Ok(handle)
    }
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_kill_process_handle(process_handle: RawFd) -> io::Result<()> {
    match trace_signal_process_handle(process_handle, libc::SIGKILL) {
        Ok(()) => Ok(()),
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "diagnostic-observer")]
fn trace_signal_process_handle(process_handle: RawFd, signal: libc::c_int) -> io::Result<()> {
    // SAFETY: pidfd_send_signal receives one owned process handle, SIGKILL,
    // or the side-effect-free signal zero, no siginfo pointer, and zero flags.
    // The handle prevents PID reuse from redirecting a nonzero signal to a
    // different process.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            process_handle,
            signal,
            core::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_continue(process_id: u32) -> io::Result<()> {
    ptrace_resume(libc::PTRACE_CONT, process_id)
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_syscall(process_id: u32) -> io::Result<()> {
    ptrace_resume(libc::PTRACE_SYSCALL, process_id)
}

#[cfg(feature = "diagnostic-observer")]
fn ptrace_resume(request: libc::c_uint, process_id: u32) -> io::Result<()> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: ptrace receives one traced process ID. Null address and data
    // request continuation without changing registers or injecting a signal.
    let result = unsafe {
        libc::ptrace(
            request,
            process_id,
            core::ptr::null_mut::<libc::c_void>(),
            core::ptr::null_mut::<libc::c_void>(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn trace_stop(process_id: u32) -> io::Result<()> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: kill receives only a process ID and SIGSTOP. The trace adapter
    // consumes this exact stop without delivering it to target code.
    let result = unsafe { libc::kill(process_id, libc::SIGSTOP) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(feature = "diagnostic-observer")]
pub(crate) fn install_diagnostic_trace_options(process_id: u32) -> io::Result<u32> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: ptrace receives one stopped traced process ID, a null address,
    // and the exact closed option bit set encoded in the data word.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            process_id,
            core::ptr::null_mut::<libc::c_void>(),
            REQUIRED_DIAGNOSTIC_TRACE_OPTIONS as usize as *mut libc::c_void,
        )
    };
    if result == 0 {
        Ok(REQUIRED_DIAGNOSTIC_TRACE_OPTIONS)
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn pause_current_process() -> io::Result<()> {
    // SAFETY: raise sends SIGSTOP to the current process. The call has no
    // pointer arguments and returns after a supervisor sends SIGCONT.
    let result = unsafe { libc::raise(libc::SIGSTOP) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn duplicate_descriptor(descriptor: RawFd) -> io::Result<OwnedFd> {
    // SAFETY: fcntl does not borrow memory. A successful result is one new
    // close-on-exec descriptor with unique ownership.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: fcntl returned one new descriptor and ownership transfers
        // to this value exactly once.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

pub(crate) fn set_descriptor_close_on_exec(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: fcntl receives only an integer descriptor and the FD_CLOEXEC
    // flag. The descriptor remains open for the launcher setup phase.
    let result = unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn close_descriptors_except(keep: &[RawFd]) -> io::Result<()> {
    let mut keep = keep
        .iter()
        .copied()
        .map(|descriptor| {
            u32::try_from(descriptor).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
        })
        .collect::<io::Result<Vec<_>>>()?;
    keep.sort_unstable();
    keep.dedup();
    if keep.iter().any(|descriptor| *descriptor < 3) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    let mut first = 3_u32;
    for descriptor in keep {
        if first < descriptor {
            close_descriptor_range(first, descriptor - 1)?;
        }
        first = descriptor
            .checked_add(1)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    close_descriptor_range(first, u32::MAX)
}

fn close_descriptor_range(first: u32, last: u32) -> io::Result<()> {
    // SAFETY: close_range receives only integer bounds and zero flags.
    let result = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn continue_process(process_id: u32) -> io::Result<()> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: kill receives only a process ID and SIGCONT.
    let result = unsafe { libc::kill(process_id, libc::SIGCONT) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn process_is_stopped(process_id: u32) -> io::Result<bool> {
    let process_id =
        i32::try_from(process_id).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut status = 0;
    // SAFETY: `status` is valid writable storage and waitpid is scoped to the
    // exact child process.
    let result =
        unsafe { libc::waitpid(process_id, &raw mut status, libc::WUNTRACED | libc::WNOHANG) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else if result == 0 {
        Ok(false)
    } else if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
        Ok(true)
    } else {
        Err(io::Error::other("launcher did not stop with SIGSTOP"))
    }
}

pub(crate) fn change_directory(descriptor: RawFd) -> io::Result<()> {
    // SAFETY: fchdir borrows a valid directory descriptor for the call.
    let result = unsafe { libc::fchdir(descriptor) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub(crate) fn execveat(
    descriptor: RawFd,
    arguments: &[CString],
    environment: &[CString],
) -> io::Result<()> {
    let empty_path = c"";
    let mut argument_pointers = arguments
        .iter()
        .map(|item| item.as_ptr())
        .collect::<Vec<_>>();
    argument_pointers.push(core::ptr::null());
    let mut environment_pointers = environment
        .iter()
        .map(|item| item.as_ptr())
        .collect::<Vec<_>>();
    environment_pointers.push(core::ptr::null());
    // SAFETY: all strings are NUL-terminated and all pointer arrays end with a
    // null pointer. Their storage remains live for the call. AT_EMPTY_PATH
    // selects the already-open executable descriptor.
    let result = unsafe {
        libc::syscall(
            libc::SYS_execveat,
            descriptor,
            empty_path.as_ptr(),
            argument_pointers.as_ptr(),
            environment_pointers.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
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
