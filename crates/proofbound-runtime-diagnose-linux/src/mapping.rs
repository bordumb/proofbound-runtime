//! Maps complete Linux trace events into diagnostic artifact events.

use core::fmt;

use proofbound_runtime_core::{Architecture, ObservationResolution};
use proofbound_runtime_diagnose::artifact::{
    DiagnosticArtifactError, DiagnosticEvent, DiagnosticEventClass, ObservationOperands,
    ObservationOutcome, ObservedSocketAddress, SocketAddressFamily,
};
use proofbound_runtime_linux::{
    ActiveTraceEvent, TraceCapturedOperands, TraceProcessId, TraceSyscallClass,
    TraceSyscallInvocation,
};

const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const MAX_LINUX_ERRNO: u32 = 4095;

/// Assigns contiguous sequence values to retained diagnostic syscall events.
#[derive(Debug, Default)]
pub struct DiagnosticEventMapper {
    next_sequence: u64,
}

impl DiagnosticEventMapper {
    /// Creates one mapper whose first retained event has sequence zero.
    #[must_use]
    pub const fn new() -> Self {
        Self { next_sequence: 0 }
    }

    /// Maps one complete trace event without claiming object resolution.
    ///
    /// Process lifecycle events do not create diagnostic syscall records. A
    /// successful image replacement creates a record only when the trace
    /// retained its matching system-call entry.
    pub fn map(
        &mut self,
        event: &ActiveTraceEvent,
    ) -> Result<Option<DiagnosticEvent>, DiagnosticEventMapError> {
        let mapped = match event {
            ActiveTraceEvent::SyscallCompleted {
                process,
                invocation,
                result,
                is_error,
            } => Some(map_invocation(
                self.next_sequence,
                *process,
                invocation,
                *result,
                *is_error,
            )?),
            ActiveTraceEvent::ImageReplaced {
                process,
                invocation: Some(invocation),
                ..
            } => {
                if !matches!(
                    invocation.class(),
                    TraceSyscallClass::Execve | TraceSyscallClass::Execveat
                ) {
                    return Err(DiagnosticEventMapError::ExecInvocationInvalid);
                }
                Some(map_invocation(
                    self.next_sequence,
                    *process,
                    invocation,
                    0,
                    false,
                )?)
            }
            ActiveTraceEvent::ProcessCreated { .. }
            | ActiveTraceEvent::ImageReplaced {
                invocation: None, ..
            }
            | ActiveTraceEvent::ProcessExited { .. }
            | ActiveTraceEvent::UnexpectedStop { .. } => None,
        };
        if mapped.is_some() {
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or(DiagnosticEventMapError::SequenceOverflow)?;
        }
        Ok(mapped)
    }

    /// Returns the sequence assigned to the next retained event.
    #[must_use]
    pub const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }
}

fn map_invocation(
    sequence: u64,
    process: TraceProcessId,
    invocation: &TraceSyscallInvocation,
    result: i64,
    is_error: bool,
) -> Result<DiagnosticEvent, DiagnosticEventMapError> {
    map_parts(
        sequence,
        process,
        invocation.architecture(),
        invocation.class(),
        invocation.operands(),
        result,
        is_error,
    )
}

fn map_parts(
    sequence: u64,
    process: TraceProcessId,
    audit_architecture: u32,
    class: TraceSyscallClass,
    operands: &TraceCapturedOperands,
    result: i64,
    is_error: bool,
) -> Result<DiagnosticEvent, DiagnosticEventMapError> {
    DiagnosticEvent::new(
        sequence,
        process.get(),
        map_architecture(audit_architecture)?,
        map_class(class),
        map_operands(operands)?,
        map_outcome(result, is_error)?,
        ObservationResolution::Unresolved,
        None,
        None,
        None,
    )
    .map_err(DiagnosticEventMapError::Artifact)
}

const fn map_architecture(value: u32) -> Result<Architecture, DiagnosticEventMapError> {
    match value {
        AUDIT_ARCH_X86_64 => Ok(Architecture::X86_64),
        AUDIT_ARCH_AARCH64 => Ok(Architecture::Aarch64),
        _ => Err(DiagnosticEventMapError::ArchitectureUnsupported),
    }
}

const fn map_class(value: TraceSyscallClass) -> DiagnosticEventClass {
    match value {
        TraceSyscallClass::Bind => DiagnosticEventClass::Bind,
        TraceSyscallClass::Clone => DiagnosticEventClass::Clone,
        TraceSyscallClass::Connect => DiagnosticEventClass::Connect,
        TraceSyscallClass::Creat => DiagnosticEventClass::Creat,
        TraceSyscallClass::Execve => DiagnosticEventClass::Execve,
        TraceSyscallClass::Execveat => DiagnosticEventClass::Execveat,
        TraceSyscallClass::Fork => DiagnosticEventClass::Fork,
        TraceSyscallClass::Newfstatat => DiagnosticEventClass::Newfstatat,
        TraceSyscallClass::Open => DiagnosticEventClass::Open,
        TraceSyscallClass::Openat => DiagnosticEventClass::Openat,
        TraceSyscallClass::Openat2 => DiagnosticEventClass::Openat2,
        TraceSyscallClass::Readlink => DiagnosticEventClass::Readlink,
        TraceSyscallClass::Readlinkat => DiagnosticEventClass::Readlinkat,
        TraceSyscallClass::Sendto => DiagnosticEventClass::Sendto,
        TraceSyscallClass::Socket => DiagnosticEventClass::Socket,
        TraceSyscallClass::Statx => DiagnosticEventClass::Statx,
        TraceSyscallClass::Vfork => DiagnosticEventClass::Vfork,
    }
}

fn map_operands(
    value: &TraceCapturedOperands,
) -> Result<ObservationOperands, DiagnosticEventMapError> {
    match value {
        TraceCapturedOperands::Path {
            buffer_bytes,
            directory_fd,
            flags,
            mask,
            mode,
            path,
            resolve,
        } => Ok(ObservationOperands::Path {
            buffer_bytes: *buffer_bytes,
            directory_fd: *directory_fd,
            flags: *flags,
            mask: *mask,
            mode: *mode,
            path: Some(
                String::from_utf8(path.clone())
                    .map_err(|_| DiagnosticEventMapError::PathEncodingInvalid)?,
            ),
            resolve: *resolve,
            symlink_hops: None,
        }),
        TraceCapturedOperands::ProcessCreate { flags } => {
            Ok(ObservationOperands::ProcessCreate { flags: *flags })
        }
        TraceCapturedOperands::SocketAddress {
            address,
            descriptor,
            payload_bytes,
        } => Ok(ObservationOperands::SocketAddress {
            address: address
                .as_ref()
                .map(|bytes| {
                    ObservedSocketAddress::new(socket_address_family(bytes), bytes.clone())
                })
                .transpose()
                .map_err(DiagnosticEventMapError::Artifact)?,
            descriptor: *descriptor,
            payload_bytes: *payload_bytes,
        }),
        TraceCapturedOperands::SocketCreate {
            domain,
            protocol,
            socket_type,
        } => Ok(ObservationOperands::SocketCreate {
            domain: *domain,
            protocol: *protocol,
            socket_type: *socket_type,
        }),
    }
}

fn map_outcome(result: i64, is_error: bool) -> Result<ObservationOutcome, DiagnosticEventMapError> {
    if is_error {
        let errno = result
            .checked_neg()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| (1..=MAX_LINUX_ERRNO).contains(value))
            .ok_or(DiagnosticEventMapError::OutcomeInvalid)?;
        return Ok(ObservationOutcome::Failed(errno));
    }
    let result = u64::try_from(result).map_err(|_| DiagnosticEventMapError::OutcomeInvalid)?;
    Ok(ObservationOutcome::Returned(result))
}

fn socket_address_family(bytes: &[u8]) -> SocketAddressFamily {
    let Some(family) = bytes
        .get(..2)
        .and_then(|value| <[u8; 2]>::try_from(value).ok())
        .map(u16::from_le_bytes)
    else {
        return SocketAddressFamily::Other;
    };
    match family {
        1 => SocketAddressFamily::Unix,
        2 => SocketAddressFamily::Inet,
        10 => SocketAddressFamily::Inet6,
        16 => SocketAddressFamily::Netlink,
        _ => SocketAddressFamily::Other,
    }
}

/// Identifies one fail-closed trace-to-artifact mapping error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticEventMapError {
    /// The Linux audit architecture is outside the closed mapping.
    ArchitectureUnsupported,
    /// A successful image replacement has the wrong invocation class.
    ExecInvocationInvalid,
    /// A retained Linux path is not valid UTF-8 for the version 1 artifact.
    PathEncodingInvalid,
    /// The Linux result and error marker are inconsistent.
    OutcomeInvalid,
    /// The retained event sequence cannot advance.
    SequenceOverflow,
    /// The mapped artifact event is internally invalid.
    Artifact(DiagnosticArtifactError),
}

impl DiagnosticEventMapError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ArchitectureUnsupported => "diagnostic.event-map.architecture-unsupported",
            Self::ExecInvocationInvalid => "diagnostic.event-map.exec-invocation-invalid",
            Self::PathEncodingInvalid => "diagnostic.event-map.path-encoding-invalid",
            Self::OutcomeInvalid => "diagnostic.event-map.outcome-invalid",
            Self::SequenceOverflow => "diagnostic.event-map.sequence-overflow",
            Self::Artifact(error) => error.code(),
        }
    }
}

impl fmt::Display for DiagnosticEventMapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for DiagnosticEventMapError {}

#[cfg(test)]
mod tests {
    use super::{
        AUDIT_ARCH_AARCH64, AUDIT_ARCH_X86_64, DiagnosticEventMapError, MAX_LINUX_ERRNO,
        map_architecture, map_class, map_outcome, map_parts, socket_address_family,
    };
    use proofbound_runtime_core::Architecture;
    use proofbound_runtime_diagnose::artifact::{
        DiagnosticEventClass, ObservationOperands, ObservationOutcome, SocketAddressFamily,
    };
    use proofbound_runtime_linux::{
        ActiveTraceEvent, TraceCapturedOperands, TraceProcessCreationKind, TraceProcessId,
        TraceSyscallClass, TraceTermination,
    };

    #[test]
    fn architecture_and_class_mappings_are_closed() {
        assert_eq!(
            map_architecture(AUDIT_ARCH_X86_64),
            Ok(Architecture::X86_64)
        );
        assert_eq!(
            map_architecture(AUDIT_ARCH_AARCH64),
            Ok(Architecture::Aarch64)
        );
        assert_eq!(
            map_architecture(0),
            Err(DiagnosticEventMapError::ArchitectureUnsupported)
        );

        let mappings = [
            (TraceSyscallClass::Bind, DiagnosticEventClass::Bind),
            (TraceSyscallClass::Clone, DiagnosticEventClass::Clone),
            (TraceSyscallClass::Connect, DiagnosticEventClass::Connect),
            (TraceSyscallClass::Creat, DiagnosticEventClass::Creat),
            (TraceSyscallClass::Execve, DiagnosticEventClass::Execve),
            (TraceSyscallClass::Execveat, DiagnosticEventClass::Execveat),
            (TraceSyscallClass::Fork, DiagnosticEventClass::Fork),
            (
                TraceSyscallClass::Newfstatat,
                DiagnosticEventClass::Newfstatat,
            ),
            (TraceSyscallClass::Open, DiagnosticEventClass::Open),
            (TraceSyscallClass::Openat, DiagnosticEventClass::Openat),
            (TraceSyscallClass::Openat2, DiagnosticEventClass::Openat2),
            (TraceSyscallClass::Readlink, DiagnosticEventClass::Readlink),
            (
                TraceSyscallClass::Readlinkat,
                DiagnosticEventClass::Readlinkat,
            ),
            (TraceSyscallClass::Sendto, DiagnosticEventClass::Sendto),
            (TraceSyscallClass::Socket, DiagnosticEventClass::Socket),
            (TraceSyscallClass::Statx, DiagnosticEventClass::Statx),
            (TraceSyscallClass::Vfork, DiagnosticEventClass::Vfork),
        ];
        for (source, expected) in mappings {
            assert_eq!(map_class(source), expected);
        }
    }

    #[test]
    fn result_mapping_rejects_inconsistent_linux_outcomes() {
        assert_eq!(map_outcome(7, false), Ok(ObservationOutcome::Returned(7)));
        assert_eq!(map_outcome(-13, true), Ok(ObservationOutcome::Failed(13)));
        for (result, is_error) in [
            (-1, false),
            (0, true),
            (1, true),
            (-i64::from(MAX_LINUX_ERRNO) - 1, true),
            (i64::MIN, true),
        ] {
            assert_eq!(
                map_outcome(result, is_error),
                Err(DiagnosticEventMapError::OutcomeInvalid)
            );
        }
    }

    #[test]
    fn unresolved_mapping_preserves_bounded_entry_operands() {
        let event = map_parts(
            4,
            TraceProcessId::new(99).expect("positive process"),
            AUDIT_ARCH_X86_64,
            TraceSyscallClass::Openat2,
            &TraceCapturedOperands::Path {
                buffer_bytes: None,
                directory_fd: Some(-100),
                flags: Some(2),
                mask: None,
                mode: Some(0o600),
                path: b"relative/file".to_vec(),
                resolve: Some(8),
            },
            -13,
            true,
        )
        .expect("valid unresolved event");
        assert_eq!(event.sequence(), 4);
        assert_eq!(event.process(), 99);
        assert_eq!(event.class(), DiagnosticEventClass::Openat2);
        assert_eq!(event.outcome(), ObservationOutcome::Failed(13));
        assert_eq!(event.resolved_path(), None);
        assert!(matches!(
            event.operands(),
            ObservationOperands::Path {
                directory_fd: Some(-100),
                flags: Some(2),
                mode: Some(0o600),
                path: Some(path),
                resolve: Some(8),
                symlink_hops: None,
                ..
            } if path == "relative/file"
        ));
    }

    #[test]
    fn invalid_path_encoding_fails_closed() {
        let error = map_parts(
            0,
            TraceProcessId::new(1).expect("positive process"),
            AUDIT_ARCH_X86_64,
            TraceSyscallClass::Open,
            &TraceCapturedOperands::Path {
                buffer_bytes: None,
                directory_fd: None,
                flags: None,
                mask: None,
                mode: None,
                path: vec![0xff],
                resolve: None,
            },
            -2,
            true,
        )
        .expect_err("non-UTF-8 cannot enter the JSON artifact");
        assert_eq!(error, DiagnosticEventMapError::PathEncodingInvalid);
    }

    #[test]
    fn lifecycle_events_do_not_consume_artifact_sequences() {
        let parent = TraceProcessId::new(1).expect("positive parent");
        let child = TraceProcessId::new(2).expect("positive child");
        let events = [
            ActiveTraceEvent::ProcessCreated {
                parent,
                child,
                kind: TraceProcessCreationKind::Clone,
            },
            ActiveTraceEvent::ImageReplaced {
                former_process: child,
                process: parent,
                superseded_processes: vec![child],
                invocation: None,
            },
            ActiveTraceEvent::ProcessExited {
                process: parent,
                termination: TraceTermination::Exit(0),
            },
            ActiveTraceEvent::UnexpectedStop {
                process: parent,
                signal: 5,
                event: 0,
            },
        ];
        let mut mapper = super::DiagnosticEventMapper::new();
        for event in events {
            assert_eq!(mapper.map(&event), Ok(None));
        }
        assert_eq!(mapper.next_sequence(), 0);
    }

    #[test]
    fn socket_family_mapping_uses_closed_linux_values() {
        assert_eq!(socket_address_family(&[1, 0]), SocketAddressFamily::Unix);
        assert_eq!(socket_address_family(&[2, 0]), SocketAddressFamily::Inet);
        assert_eq!(socket_address_family(&[10, 0]), SocketAddressFamily::Inet6);
        assert_eq!(
            socket_address_family(&[16, 0]),
            SocketAddressFamily::Netlink
        );
        assert_eq!(socket_address_family(&[0xff]), SocketAddressFamily::Other);
    }
}
