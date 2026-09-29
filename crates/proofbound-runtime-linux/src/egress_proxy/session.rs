//! Incremental, bounded admission for one client socket.

use proofbound_runtime_core::{EgressAuthority, TcpPort, TunnelDecision, TunnelTarget};

use super::observation::TargetKind;
use super::{
    AwaitSni, MAX_CLIENT_HELLO_BYTES, MAX_CLIENT_HELLO_RECORDS, MAX_CONNECT_HEAD_BYTES,
    ProxyAdmission, RequestRejection, SniResult, admit_connect, admit_sni, parse_connect_head,
};

const MAX_SNI_BUFFER_BYTES: usize = MAX_CLIENT_HELLO_BYTES + 5 * MAX_CLIENT_HELLO_RECORDS;

#[derive(Clone, Debug, Eq, PartialEq)]
enum SessionState {
    ReadingHead(Vec<u8>),
    ReadingSni {
        awaiting: AwaitSni,
        payload: Vec<u8>,
    },
    Finished,
}

/// An event is emitted once; a completed session cannot be admitted twice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RejectedRequest {
    pub reason: RequestRejection,
    pub target_kind: TargetKind,
    pub port: Option<TcpPort>,
    pub exact_target_bytes: Vec<u8>,
}

/// An event is emitted once; a completed session cannot be admitted twice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SessionEvent {
    NeedMore,
    /// The caller must send HTTP 200 before reading or advancing the SNI gate.
    EstablishedAwaitSni {
        endpoint_index: usize,
    },
    Rejected(RejectedRequest),
    SniDenied(SniResult),
    /// `payload` is the original tunneled byte sequence, without rewriting.
    Ready {
        endpoint_index: usize,
        decision: TunnelDecision,
        payload: Vec<u8>,
        sni_matched: bool,
    },
    AlreadyFinished,
}

/// Holds only the bounded request head and first ClientHello, never a stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxySession {
    state: SessionState,
}

impl Default for ProxySession {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxySession {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: SessionState::ReadingHead(Vec::new()),
        }
    }

    /// `connection_id` becomes the ledger index after endpoint admission.
    /// The caller may pass an empty slice to advance buffered TLS bytes after
    /// it sends HTTP 200 for `EstablishedAwaitSni`.
    pub fn push(
        &mut self,
        authority: &EgressAuthority,
        bytes: &[u8],
        connection_id: u64,
        now_ms: u64,
    ) -> SessionEvent {
        let state = std::mem::replace(&mut self.state, SessionState::Finished);
        match state {
            SessionState::ReadingHead(mut head) => {
                let Some(new_len) = head.len().checked_add(bytes.len()) else {
                    return SessionEvent::Rejected(rejected(
                        RequestRejection::RequestHeadTooLarge,
                        &head,
                    ));
                };
                // An admitted head may carry up to one bounded ClientHello in
                // the same read. The parser separately enforces the head bound.
                if new_len > MAX_CONNECT_HEAD_BYTES + MAX_SNI_BUFFER_BYTES {
                    return SessionEvent::Rejected(rejected(
                        RequestRejection::RequestHeadTooLarge,
                        &head,
                    ));
                }
                head.extend_from_slice(bytes);
                match admit_connect(authority, &head, connection_id, now_ms) {
                    ProxyAdmission::Incomplete => {
                        self.state = SessionState::ReadingHead(head);
                        SessionEvent::NeedMore
                    }
                    ProxyAdmission::Rejected(reason) => {
                        SessionEvent::Rejected(rejected(reason, &head))
                    }
                    ProxyAdmission::AwaitSni(awaiting) => {
                        let endpoint_index = awaiting.endpoint_index();
                        let payload = head.split_off(awaiting.payload_offset());
                        self.state = SessionState::ReadingSni { awaiting, payload };
                        SessionEvent::EstablishedAwaitSni { endpoint_index }
                    }
                    ProxyAdmission::Destination(decision) => {
                        let Ok(parsed) = parse_connect_head(&head) else {
                            return SessionEvent::Rejected(rejected(
                                RequestRejection::RequestMalformed,
                                &head,
                            ));
                        };
                        SessionEvent::Ready {
                            endpoint_index: decision_endpoint(&decision),
                            decision,
                            payload: head.split_off(parsed.payload_offset),
                            sni_matched: false,
                        }
                    }
                }
            }
            SessionState::ReadingSni {
                awaiting,
                mut payload,
            } => {
                let endpoint_index = awaiting.endpoint_index();
                let Some(new_len) = payload.len().checked_add(bytes.len()) else {
                    return SessionEvent::SniDenied(SniResult::DeniedTooLarge);
                };
                if new_len > MAX_SNI_BUFFER_BYTES {
                    return SessionEvent::SniDenied(SniResult::DeniedTooLarge);
                }
                payload.extend_from_slice(bytes);
                match admit_sni(authority, &awaiting, &payload, connection_id, now_ms) {
                    Err(SniResult::Incomplete) => {
                        self.state = SessionState::ReadingSni { awaiting, payload };
                        SessionEvent::NeedMore
                    }
                    Err(reason) => SessionEvent::SniDenied(reason),
                    Ok(decision) => SessionEvent::Ready {
                        endpoint_index,
                        decision,
                        payload,
                        sni_matched: true,
                    },
                }
            }
            SessionState::Finished => SessionEvent::AlreadyFinished,
        }
    }
}

fn decision_endpoint(decision: &TunnelDecision) -> usize {
    match decision {
        TunnelDecision::NeedsResolution { endpoint_index }
        | TunnelDecision::Attempts { endpoint_index, .. } => *endpoint_index,
        TunnelDecision::Denied(_) => unreachable!("admitted request has a declared endpoint"),
    }
}

fn rejected(reason: RequestRejection, head: &[u8]) -> RejectedRequest {
    if reason == RequestRejection::EndpointUndeclared
        && let Ok(parsed) = parse_connect_head(head)
    {
        let target_kind = match parsed.target {
            TunnelTarget::DnsName(_) => TargetKind::DnsName,
            TunnelTarget::Ipv4(_) => TargetKind::Ipv4,
            TunnelTarget::Ipv6(_) => TargetKind::Ipv6,
        };
        return RejectedRequest {
            reason,
            target_kind,
            port: Some(parsed.port),
            exact_target_bytes: target_token(head),
        };
    }
    RejectedRequest {
        reason,
        target_kind: TargetKind::Unparsed,
        port: None,
        exact_target_bytes: target_token(head),
    }
}

fn target_token(head: &[u8]) -> Vec<u8> {
    let request = head
        .split(|byte| *byte == b'\r' || *byte == b'\n')
        .next()
        .unwrap_or_default();
    let mut words = request.split(|byte| *byte == b' ');
    let _method = words.next();
    let target = words.next().unwrap_or_default();
    if target.len() > MAX_CONNECT_HEAD_BYTES {
        Vec::new()
    } else {
        target.to_vec()
    }
}
