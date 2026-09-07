//! Installs the closed version 1 seccomp deny-network profile.

use core::fmt;

use proofbound_runtime_core::SeccompPolicy;

use crate::{Architecture, LandlockBoundary, LockedPrivileges};

#[cfg(any(test, target_os = "linux"))]
const BPF_LOAD_WORD_ABSOLUTE: u16 = 0x20;
#[cfg(any(test, target_os = "linux"))]
const BPF_JUMP_EQUAL_CONSTANT: u16 = 0x15;
#[cfg(any(test, target_os = "linux"))]
const BPF_JUMP_GREATER_OR_EQUAL_CONSTANT: u16 = 0x35;
#[cfg(any(test, target_os = "linux"))]
const BPF_RETURN_CONSTANT: u16 = 0x06;
#[cfg(any(test, target_os = "linux"))]
const SECCOMP_DATA_NUMBER_OFFSET: u32 = 0;
#[cfg(any(test, target_os = "linux"))]
const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
#[cfg(any(test, target_os = "linux"))]
const SECCOMP_RETURN_KILL_PROCESS: u32 = 0x8000_0000;
#[cfg(any(test, target_os = "linux"))]
const SECCOMP_RETURN_ERRNO: u32 = 0x0005_0000;
#[cfg(any(test, target_os = "linux"))]
const SECCOMP_RETURN_ALLOW: u32 = 0x7fff_0000;
#[cfg(any(test, target_os = "linux"))]
const ERRNO_PERMISSION: u32 = 1;
#[cfg(any(test, target_os = "linux"))]
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
#[cfg(any(test, target_os = "linux"))]
const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
#[cfg(any(test, target_os = "linux"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

#[cfg(any(test, target_os = "linux"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct BpfInstruction {
    code: u16,
    jump_true: u8,
    jump_false: u8,
    value: u32,
}

#[cfg(any(test, target_os = "linux"))]
impl BpfInstruction {
    const fn new(code: u16, jump_true: u8, jump_false: u8, value: u32) -> Self {
        Self {
            code,
            jump_true,
            jump_false,
            value,
        }
    }
}

/// Witnesses installation and read-back of the deny-network filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeccompBoundary {
    architecture: Architecture,
    denied_syscall_count: usize,
    instruction_count: usize,
}

impl SeccompBoundary {
    /// Returns the audit architecture enforced by the filter preamble.
    #[must_use]
    pub const fn architecture(self) -> Architecture {
        self.architecture
    }

    /// Returns the complete registered denied-syscall count.
    #[must_use]
    pub const fn denied_syscall_count(self) -> usize {
        self.denied_syscall_count
    }

    /// Returns the exact classic-BPF instruction count.
    #[must_use]
    pub const fn instruction_count(self) -> usize {
        self.instruction_count
    }
}

/// Installs the deny-network filter after privilege and filesystem boundaries.
pub fn install_deny_network(
    policy: SeccompPolicy,
    architecture: Architecture,
    _locked: &LockedPrivileges,
    _landlock: &LandlockBoundary,
) -> Result<SeccompBoundary, SeccompError> {
    #[cfg(target_os = "linux")]
    {
        let SeccompPolicy::DenyNetworkV1 = policy;
        let denied_syscalls = denied_syscalls();
        let filter = build_filter(architecture, &denied_syscalls)?;
        crate::sys::install_seccomp_filter(&filter)
            .map_err(|_| SeccompError::InstallationFailed)?;
        if crate::sys::seccomp_mode().map_err(|_| SeccompError::VerificationFailed)? != 2 {
            return Err(SeccompError::VerificationFailed);
        }
        Ok(SeccompBoundary {
            architecture,
            denied_syscall_count: denied_syscalls.len(),
            instruction_count: filter.len(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (policy, architecture);
        Err(SeccompError::UnsupportedOperatingSystem)
    }
}

/// Identifies one fail-closed seccomp installation result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeccompError {
    /// The host operating system is not Linux.
    UnsupportedOperatingSystem,
    /// A syscall number or filter jump could not fit the classic-BPF contract.
    FilterInvalid,
    /// The kernel rejected filter installation or thread synchronization.
    InstallationFailed,
    /// `PR_GET_SECCOMP` did not report filter mode after installation.
    VerificationFailed,
}

impl SeccompError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "seccomp.os.unsupported",
            Self::FilterInvalid => "seccomp.filter.invalid",
            Self::InstallationFailed => "seccomp.installation.failed",
            Self::VerificationFailed => "seccomp.verification.failed",
        }
    }
}

impl fmt::Display for SeccompError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SeccompError {}

#[cfg(target_os = "linux")]
fn denied_syscalls() -> Vec<u32> {
    let mut syscalls = [
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_connect,
        libc::SYS_getpeername,
        libc::SYS_getsockname,
        libc::SYS_getsockopt,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_io_uring_setup,
        libc::SYS_listen,
        libc::SYS_recvfrom,
        libc::SYS_recvmmsg,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_sendmsg,
        libc::SYS_sendto,
        libc::SYS_setsockopt,
        libc::SYS_shutdown,
        libc::SYS_socket,
        libc::SYS_socketpair,
    ]
    .into_iter()
    .map(|number| u32::try_from(number).expect("supported syscall numbers are nonnegative u32"))
    .collect::<Vec<_>>();
    syscalls.sort_unstable();
    syscalls.dedup();
    syscalls
}

#[cfg(any(test, target_os = "linux"))]
fn build_filter(
    architecture: Architecture,
    denied_syscalls: &[u32],
) -> Result<Vec<BpfInstruction>, SeccompError> {
    if denied_syscalls.is_empty() || denied_syscalls.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(SeccompError::FilterInvalid);
    }
    let audit_architecture = match architecture {
        Architecture::X86_64 => AUDIT_ARCH_X86_64,
        Architecture::Aarch64 => AUDIT_ARCH_AARCH64,
    };
    let mut filter = vec![
        BpfInstruction::new(BPF_LOAD_WORD_ABSOLUTE, 0, 0, SECCOMP_DATA_ARCH_OFFSET),
        BpfInstruction::new(BPF_JUMP_EQUAL_CONSTANT, 1, 0, audit_architecture),
        BpfInstruction::new(BPF_RETURN_CONSTANT, 0, 0, SECCOMP_RETURN_KILL_PROCESS),
        BpfInstruction::new(BPF_LOAD_WORD_ABSOLUTE, 0, 0, SECCOMP_DATA_NUMBER_OFFSET),
    ];
    if architecture == Architecture::X86_64 {
        filter.push(BpfInstruction::new(
            BPF_JUMP_GREATER_OR_EQUAL_CONSTANT,
            0,
            1,
            X32_SYSCALL_BIT,
        ));
        filter.push(BpfInstruction::new(
            BPF_RETURN_CONSTANT,
            0,
            0,
            SECCOMP_RETURN_KILL_PROCESS,
        ));
    }
    for syscall in denied_syscalls {
        filter.push(BpfInstruction::new(BPF_JUMP_EQUAL_CONSTANT, 0, 1, *syscall));
        filter.push(BpfInstruction::new(
            BPF_RETURN_CONSTANT,
            0,
            0,
            SECCOMP_RETURN_ERRNO | ERRNO_PERMISSION,
        ));
    }
    filter.push(BpfInstruction::new(
        BPF_RETURN_CONSTANT,
        0,
        0,
        SECCOMP_RETURN_ALLOW,
    ));
    if filter.len() > usize::from(u16::MAX) {
        return Err(SeccompError::FilterInvalid);
    }
    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ATTACK_CATALOG: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/attacks/seccomp/network-v1.toml"
    ));

    fn evaluate(filter: &[BpfInstruction], architecture: u32, syscall: u32) -> u32 {
        let mut accumulator = 0;
        let mut program_counter = 0;
        loop {
            let instruction = filter[program_counter];
            match instruction.code {
                BPF_LOAD_WORD_ABSOLUTE => {
                    accumulator = match instruction.value {
                        SECCOMP_DATA_NUMBER_OFFSET => syscall,
                        SECCOMP_DATA_ARCH_OFFSET => architecture,
                        _ => panic!("unexpected absolute load offset"),
                    };
                    program_counter += 1;
                }
                BPF_JUMP_EQUAL_CONSTANT => {
                    let jump = if accumulator == instruction.value {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    program_counter += usize::from(jump) + 1;
                }
                BPF_JUMP_GREATER_OR_EQUAL_CONSTANT => {
                    let jump = if accumulator >= instruction.value {
                        instruction.jump_true
                    } else {
                        instruction.jump_false
                    };
                    program_counter += usize::from(jump) + 1;
                }
                BPF_RETURN_CONSTANT => return instruction.value,
                _ => panic!("unexpected BPF instruction"),
            }
        }
    }

    #[test]
    fn filter_denies_each_registered_syscall_and_allows_others() {
        let denied = [41, 42, 43];
        for (architecture, audit) in [
            (Architecture::X86_64, AUDIT_ARCH_X86_64),
            (Architecture::Aarch64, AUDIT_ARCH_AARCH64),
        ] {
            let filter = build_filter(architecture, &denied).expect("valid filter");
            for syscall in denied {
                assert_eq!(evaluate(&filter, audit, syscall), SECCOMP_RETURN_ERRNO | 1);
            }
            assert_eq!(evaluate(&filter, audit, 1), SECCOMP_RETURN_ALLOW);
            assert_eq!(evaluate(&filter, 0, 1), SECCOMP_RETURN_KILL_PROCESS);
        }
    }

    #[test]
    fn x86_filter_kills_x32_syscall_numbers() {
        let filter = build_filter(Architecture::X86_64, &[41]).expect("valid filter");
        assert_eq!(
            evaluate(&filter, AUDIT_ARCH_X86_64, X32_SYSCALL_BIT | 41),
            SECCOMP_RETURN_KILL_PROCESS
        );
    }

    #[test]
    fn filter_rejects_empty_duplicate_and_unsorted_denial_sets() {
        assert_eq!(
            build_filter(Architecture::X86_64, &[]),
            Err(SeccompError::FilterInvalid)
        );
        assert_eq!(
            build_filter(Architecture::X86_64, &[1, 1]),
            Err(SeccompError::FilterInvalid)
        );
        assert_eq!(
            build_filter(Architecture::X86_64, &[2, 1]),
            Err(SeccompError::FilterInvalid)
        );
    }

    #[test]
    fn frozen_seccomp_attack_catalog_is_closed() {
        let expected_ids = [
            "wrong-audit-architecture",
            "x32-syscall-confusion",
            "socket-create",
            "socket-connect",
            "socket-pair",
            "descriptor-message-receive",
            "io-uring-network-bypass",
            "filter-installation-omitted",
        ];
        assert!(ATTACK_CATALOG.starts_with("schema = \"proofbound-runtime-seccomp-attacks/1\""));
        assert_eq!(
            ATTACK_CATALOG.matches("[[attack]]").count(),
            expected_ids.len()
        );
        for id in expected_ids {
            assert!(ATTACK_CATALOG.contains(&format!("id = \"{id}\"")));
        }
    }

    #[test]
    fn error_codes_are_unique_and_stable() {
        let errors = [
            SeccompError::UnsupportedOperatingSystem,
            SeccompError::FilterInvalid,
            SeccompError::InstallationFailed,
            SeccompError::VerificationFailed,
        ];
        let mut codes = errors.map(SeccompError::code);
        codes.sort_unstable();
        assert!(codes.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
