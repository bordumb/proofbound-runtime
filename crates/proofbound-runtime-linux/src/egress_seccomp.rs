//! Closed seccomp filter for the single-threaded declared-egress proxy.

use crate::seccomp::{BpfInstruction, encode_filter};
use crate::{Architecture, SeccompError};

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const AND_K: u16 = 0x54;
const RET_K: u16 = 0x06;
const KILL: u32 = 0x8000_0000;
const DENY: u32 = 0x0005_0001;
const ALLOW: u32 = 0x7fff_0000;
const ARCH_OFFSET: u32 = 4;
const NUMBER_OFFSET: u32 = 0;
const ARG0_OFFSET: u32 = 16;
const ARG1_OFFSET: u32 = 24;
const ARG2_OFFSET: u32 = 32;
const X32_BIT: u32 = 0x4000_0000;

fn instruction(code: u16, yes: u8, no: u8, value: u32) -> BpfInstruction {
    BpfInstruction::new(code, yes, no, value)
}

/// The exact bytes installed by `install_proxy_seccomp`. Host policy must
/// bind this program, including its architecture preamble.
pub fn compile_proxy_seccomp(architecture: Architecture) -> Result<Vec<u8>, SeccompError> {
    Ok(encode_filter(&proxy_filter(architecture)?))
}

pub fn install_proxy_seccomp(architecture: Architecture) -> Result<Vec<u8>, SeccompError> {
    let filter = proxy_filter(architecture)?;
    let bytes = encode_filter(&filter);
    crate::sys::install_seccomp_filter(&filter).map_err(|_| SeccompError::InstallationFailed)?;
    if crate::sys::seccomp_mode().map_err(|_| SeccompError::VerificationFailed)? != 2 {
        return Err(SeccompError::VerificationFailed);
    }
    Ok(bytes)
}

fn proxy_filter(architecture: Architecture) -> Result<Vec<BpfInstruction>, SeccompError> {
    let native = if cfg!(target_arch = "x86_64") {
        Architecture::X86_64
    } else if cfg!(target_arch = "aarch64") {
        Architecture::Aarch64
    } else {
        return Err(SeccompError::FilterInvalid);
    };
    if architecture != native {
        return Err(SeccompError::FilterInvalid);
    }
    let audit_arch = match architecture {
        Architecture::X86_64 => 0xc000_003e,
        Architecture::Aarch64 => 0xc000_00b7,
    };
    let mut filter = vec![
        instruction(LD_W_ABS, 0, 0, ARCH_OFFSET),
        instruction(JEQ_K, 1, 0, audit_arch),
        instruction(RET_K, 0, 0, KILL),
        instruction(LD_W_ABS, 0, 0, NUMBER_OFFSET),
    ];
    if architecture == Architecture::X86_64 {
        filter.push(instruction(JGE_K, 0, 1, X32_BIT));
        filter.push(instruction(RET_K, 0, 0, KILL));
    }
    let mut denied = [
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_socketpair,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_clone,
        libc::SYS_clone3,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_kcmp,
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ]
    .into_iter()
    .map(|number| u32::try_from(number).map_err(|_| SeccompError::FilterInvalid))
    .collect::<Result<Vec<_>, _>>()?;
    if architecture == Architecture::X86_64 {
        denied.extend([57_u32, 58_u32]); // fork and vfork are x86-64 only.
    }
    denied.sort_unstable();
    denied.dedup();
    for syscall in denied {
        filter.push(instruction(JEQ_K, 0, 1, syscall));
        filter.push(instruction(RET_K, 0, 0, DENY));
    }
    let socket_block = [
        instruction(LD_W_ABS, 0, 0, ARG0_OFFSET),
        instruction(JEQ_K, 2, 0, libc::AF_INET as u32),
        instruction(JEQ_K, 1, 0, libc::AF_INET6 as u32),
        instruction(RET_K, 0, 0, DENY),
        instruction(LD_W_ABS, 0, 0, ARG1_OFFSET),
        instruction(
            AND_K,
            0,
            0,
            !(libc::SOCK_NONBLOCK as u32 | libc::SOCK_CLOEXEC as u32),
        ),
        instruction(JEQ_K, 1, 0, libc::SOCK_STREAM as u32),
        instruction(RET_K, 0, 0, DENY),
        instruction(LD_W_ABS, 0, 0, ARG2_OFFSET),
        instruction(JEQ_K, 2, 0, 0),
        instruction(JEQ_K, 1, 0, libc::IPPROTO_TCP as u32),
        instruction(RET_K, 0, 0, DENY),
        instruction(RET_K, 0, 0, ALLOW),
    ];
    filter.push(instruction(
        JEQ_K,
        0,
        u8::try_from(socket_block.len()).map_err(|_| SeccompError::FilterInvalid)?,
        u32::try_from(libc::SYS_socket).map_err(|_| SeccompError::FilterInvalid)?,
    ));
    filter.extend(socket_block);
    filter.push(instruction(RET_K, 0, 0, ALLOW));
    Ok(filter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluate(program: &[u8], arch: u32, number: u32, args: [u32; 3]) -> u32 {
        let mut pc = 0;
        let mut accumulator = 0_u32;
        loop {
            let instruction = &program[pc * 8..pc * 8 + 8];
            let code = u16::from_le_bytes([instruction[0], instruction[1]]);
            let yes = usize::from(instruction[2]);
            let no = usize::from(instruction[3]);
            let value = u32::from_le_bytes(instruction[4..8].try_into().unwrap());
            match code {
                LD_W_ABS => {
                    accumulator = match value {
                        ARCH_OFFSET => arch,
                        NUMBER_OFFSET => number,
                        ARG0_OFFSET => args[0],
                        ARG1_OFFSET => args[1],
                        ARG2_OFFSET => args[2],
                        _ => panic!("unexpected seccomp-data offset"),
                    };
                    pc += 1;
                }
                JEQ_K => pc += 1 + if accumulator == value { yes } else { no },
                JGE_K => pc += 1 + if accumulator >= value { yes } else { no },
                AND_K => {
                    accumulator &= value;
                    pc += 1;
                }
                RET_K => return value,
                _ => panic!("unexpected BPF opcode"),
            }
        }
    }

    #[test]
    fn proxy_filter_is_architecture_bound_and_contains_socket_guard() {
        let native = if cfg!(target_arch = "x86_64") {
            Architecture::X86_64
        } else {
            Architecture::Aarch64
        };
        let other = if native == Architecture::X86_64 {
            Architecture::Aarch64
        } else {
            Architecture::X86_64
        };
        let program = compile_proxy_seccomp(native).unwrap();
        assert_eq!(
            compile_proxy_seccomp(other),
            Err(SeccompError::FilterInvalid)
        );
        assert_eq!(program.len() % 8, 0);
        assert!(program.len() > 100);
        let audit = if native == Architecture::X86_64 {
            0xc000_003e
        } else {
            0xc000_00b7
        };
        let socket = u32::try_from(libc::SYS_socket).unwrap();
        assert_eq!(
            evaluate(
                &program,
                audit,
                socket,
                [libc::AF_INET as u32, libc::SOCK_STREAM as u32, 0]
            ),
            ALLOW
        );
        assert_eq!(
            evaluate(
                &program,
                audit,
                socket,
                [
                    libc::AF_INET6 as u32,
                    (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u32,
                    libc::IPPROTO_TCP as u32
                ]
            ),
            ALLOW
        );
        for args in [
            [libc::AF_UNIX as u32, libc::SOCK_STREAM as u32, 0],
            [libc::AF_INET as u32, libc::SOCK_DGRAM as u32, 0],
            [libc::AF_INET as u32, libc::SOCK_STREAM as u32, 262],
        ] {
            assert_eq!(evaluate(&program, audit, socket, args), DENY);
        }
        assert_eq!(
            evaluate(
                &program,
                audit,
                u32::try_from(libc::SYS_execve).unwrap(),
                [0; 3]
            ),
            DENY
        );
        assert_eq!(
            evaluate(
                &program,
                audit,
                u32::try_from(libc::SYS_socketpair).unwrap(),
                [0; 3]
            ),
            DENY
        );
        assert_eq!(
            evaluate(
                &program,
                0,
                socket,
                [libc::AF_INET as u32, libc::SOCK_STREAM as u32, 0]
            ),
            KILL
        );
        if native == Architecture::X86_64 {
            assert_eq!(
                evaluate(
                    &program,
                    audit,
                    X32_BIT | socket,
                    [libc::AF_INET as u32, libc::SOCK_STREAM as u32, 0]
                ),
                KILL
            );
        }
    }

    #[test]
    fn installed_filter_denies_unix_and_datagram_sockets() {
        const CHILD: &str = "PBR_EGRESS_SECCOMP_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            crate::sys::set_no_new_privileges().unwrap();
            let native = if cfg!(target_arch = "x86_64") {
                Architecture::X86_64
            } else {
                Architecture::Aarch64
            };
            install_proxy_seccomp(native).unwrap();
            assert_eq!(crate::sys::seccomp_mode().unwrap(), 2);
            assert_eq!(
                std::os::unix::net::UnixStream::pair()
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(
                std::net::UdpSocket::bind("127.0.0.1:0")
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::EPERM)
            );
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD, "1")
            .arg("--exact")
            .arg("egress_seccomp::tests::installed_filter_denies_unix_and_datagram_sockets")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
