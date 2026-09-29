//! Closed socket and process filter for an egress child namespace.

use crate::seccomp::{BpfInstruction, encode_filter};
use crate::{Architecture, SeccompError};

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const AND_K: u16 = 0x54;
const RET_K: u16 = 0x06;
const KILL: u32 = 0x8000_0000;
const DENY: u32 = 0x0005_0001;
const NO_SYS: u32 = 0x0005_0026;
const ALLOW: u32 = 0x7fff_0000;
const ARCH_OFFSET: u32 = 4;
const NUMBER_OFFSET: u32 = 0;
const ARG0_OFFSET: u32 = 16;
const ARG1_OFFSET: u32 = 24;
const ARG2_OFFSET: u32 = 32;
const X32_BIT: u32 = 0x4000_0000;
const CLONE_NAMESPACE_FLAGS: u32 = 0x7e02_0080;

fn instruction(code: u16, yes: u8, no: u8, value: u32) -> BpfInstruction {
    BpfInstruction::new(code, yes, no, value)
}

pub fn compile_child_seccomp(architecture: Architecture) -> Result<Vec<u8>, SeccompError> {
    Ok(encode_filter(&child_filter(architecture)?))
}

pub fn install_child_seccomp(architecture: Architecture) -> Result<Vec<u8>, SeccompError> {
    let filter = child_filter(architecture)?;
    let bytes = encode_filter(&filter);
    crate::sys::install_seccomp_filter(&filter).map_err(|_| SeccompError::InstallationFailed)?;
    if crate::sys::seccomp_mode().map_err(|_| SeccompError::VerificationFailed)? != 2 {
        return Err(SeccompError::VerificationFailed);
    }
    Ok(bytes)
}

fn child_filter(architecture: Architecture) -> Result<Vec<BpfInstruction>, SeccompError> {
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
    denied.sort_unstable();
    denied.dedup();
    for syscall in denied {
        filter.push(instruction(JEQ_K, 0, 1, syscall));
        filter.push(instruction(RET_K, 0, 0, DENY));
    }
    filter.push(instruction(
        JEQ_K,
        0,
        1,
        u32::try_from(libc::SYS_clone3).map_err(|_| SeccompError::FilterInvalid)?,
    ));
    filter.push(instruction(RET_K, 0, 0, NO_SYS));

    // clone(flags) retains ordinary fork/thread creation but rejects every
    // namespace-creation bit before the kernel sees the call.
    let clone_block = [
        instruction(LD_W_ABS, 0, 0, ARG0_OFFSET),
        instruction(AND_K, 0, 0, CLONE_NAMESPACE_FLAGS),
        instruction(JEQ_K, 1, 0, 0),
        instruction(RET_K, 0, 0, DENY),
        instruction(RET_K, 0, 0, ALLOW),
    ];
    filter.push(instruction(
        JEQ_K,
        0,
        u8::try_from(clone_block.len()).map_err(|_| SeccompError::FilterInvalid)?,
        u32::try_from(libc::SYS_clone).map_err(|_| SeccompError::FilterInvalid)?,
    ));
    filter.extend(clone_block);

    // socketpair is confined to AF_UNIX. Landlock's abstract-socket scope
    // and pathname rule limit where such a socket can reach.
    let socketpair_block = [
        instruction(LD_W_ABS, 0, 0, ARG0_OFFSET),
        instruction(JEQ_K, 1, 0, libc::AF_UNIX as u32),
        instruction(RET_K, 0, 0, DENY),
        instruction(RET_K, 0, 0, ALLOW),
    ];
    filter.push(instruction(
        JEQ_K,
        0,
        u8::try_from(socketpair_block.len()).map_err(|_| SeccompError::FilterInvalid)?,
        u32::try_from(libc::SYS_socketpair).map_err(|_| SeccompError::FilterInvalid)?,
    ));
    filter.extend(socketpair_block);

    // Family, type (ignoring only CLOEXEC/NONBLOCK), and protocol are all
    // checked. The Unix branch requires protocol zero.
    let socket_block = [
        instruction(LD_W_ABS, 0, 0, ARG0_OFFSET),
        instruction(JEQ_K, 3, 0, libc::AF_UNIX as u32),
        instruction(JEQ_K, 10, 0, libc::AF_INET as u32),
        instruction(JEQ_K, 9, 0, libc::AF_INET6 as u32),
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
        instruction(JEQ_K, 1, 0, 0),
        instruction(RET_K, 0, 0, DENY),
        instruction(RET_K, 0, 0, ALLOW),
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

    fn evaluate(program: &[u8], architecture: u32, syscall: u32, args: [u32; 3]) -> u32 {
        let mut pc = 0;
        let mut value = 0_u32;
        loop {
            let row = &program[pc * 8..pc * 8 + 8];
            let code = u16::from_le_bytes(row[..2].try_into().unwrap());
            let constant = u32::from_le_bytes(row[4..8].try_into().unwrap());
            let yes = usize::from(row[2]);
            let no = usize::from(row[3]);
            match code {
                LD_W_ABS => {
                    value = match constant {
                        ARCH_OFFSET => architecture,
                        NUMBER_OFFSET => syscall,
                        ARG0_OFFSET => args[0],
                        ARG1_OFFSET => args[1],
                        ARG2_OFFSET => args[2],
                        _ => panic!("unexpected seccomp-data offset"),
                    };
                    pc += 1;
                }
                JEQ_K => pc += 1 + if value == constant { yes } else { no },
                JGE_K => pc += 1 + if value >= constant { yes } else { no },
                AND_K => {
                    value &= constant;
                    pc += 1;
                }
                RET_K => return constant,
                _ => panic!("unexpected BPF opcode"),
            }
        }
    }

    #[test]
    fn child_filter_allows_only_declared_socket_shapes() {
        let native = if cfg!(target_arch = "x86_64") {
            Architecture::X86_64
        } else {
            Architecture::Aarch64
        };
        let audit = if native == Architecture::X86_64 {
            0xc000_003e
        } else {
            0xc000_00b7
        };
        let program = compile_child_seccomp(native).unwrap();
        let socket = u32::try_from(libc::SYS_socket).unwrap();
        for allowed in [
            [libc::AF_UNIX as u32, libc::SOCK_STREAM as u32, 0],
            [libc::AF_INET as u32, libc::SOCK_STREAM as u32, 0],
            [
                libc::AF_INET6 as u32,
                (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u32,
                libc::IPPROTO_TCP as u32,
            ],
        ] {
            assert_eq!(evaluate(&program, audit, socket, allowed), ALLOW);
        }
        for denied in [
            [libc::AF_UNIX as u32, libc::SOCK_DGRAM as u32, 0],
            [libc::AF_INET as u32, libc::SOCK_DGRAM as u32, 0],
            [libc::AF_NETLINK as u32, libc::SOCK_STREAM as u32, 0],
            [libc::AF_INET as u32, libc::SOCK_STREAM as u32, 262],
        ] {
            assert_eq!(evaluate(&program, audit, socket, denied), DENY);
        }
        let pair = u32::try_from(libc::SYS_socketpair).unwrap();
        assert_eq!(
            evaluate(&program, audit, pair, [libc::AF_UNIX as u32, 0, 0]),
            ALLOW
        );
        assert_eq!(
            evaluate(&program, audit, pair, [libc::AF_INET as u32, 0, 0]),
            DENY
        );
        let clone = u32::try_from(libc::SYS_clone).unwrap();
        assert_eq!(evaluate(&program, audit, clone, [0, 0, 0]), ALLOW);
        assert_eq!(
            evaluate(&program, audit, clone, [libc::CLONE_NEWNET as u32, 0, 0]),
            DENY
        );
        assert_eq!(
            evaluate(
                &program,
                audit,
                u32::try_from(libc::SYS_clone3).unwrap(),
                [0; 3]
            ),
            NO_SYS
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
    }
}
