//! Bounded private packets from the proxy to its supervisor.

use std::net::IpAddr;

use serde_json::{Value, json};

use super::engine::ProxyReportEvent;
use super::observation::{AttemptResult, CloseReason, SniObservation, TargetKind};

pub const MAX_PROXY_REPORT_BYTES: usize = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyReportError {
    Encoding,
    TooLarge,
}

/// Encodes one closed event as a single packet. The supervisor must validate
/// its grammar and recompute counters before using it in a receipt.
pub fn encode_proxy_report(event: &ProxyReportEvent) -> Result<Vec<u8>, ProxyReportError> {
    let value = match event {
        ProxyReportEvent::Rejection {
            sequence,
            reason,
            retained,
            total,
        } => json!({
            "kind": "rejection",
            "sequence": sequence,
            "reason": reason.as_str(),
            "total": total,
            "retained": retained.as_ref().map(|fact| json!({
                "sequence": fact.sequence,
                "time_ms": fact.time_ms,
                "reason": fact.reason.as_str(),
                "target_kind": target_kind(fact.target_kind),
                "port": fact.port.map(|port| port.get()),
                "target_length": fact.target_length,
                "target_sha256": fact.target_sha256.to_hex(),
            })),
        }),
        ProxyReportEvent::Resolution(fact) => json!({
            "kind": "resolution",
            "index": fact.index,
            "name": fact.name.as_str(),
            "triggering_connection": fact.triggering_connection,
            "started_ms": fact.started_ms,
            "finished_ms": fact.finished_ms,
            "messages": fact.messages.iter().map(|message| json!({
                "sha256": message.identity.to_hex(),
                "size": message.size,
                "finished_ms": message.finished_ms,
            })).collect::<Vec<_>>(),
            "cname_links": fact.cname_chain.iter().map(|link| json!({
                "owner": link.owner.as_str(),
                "target": link.target.as_str(),
                "ttl": link.ttl_seconds,
                "expiry_ms": link.expiry_ms,
                "message_sha256": link.message_identity.to_hex(),
            })).collect::<Vec<_>>(),
            "answers": fact.answers.iter().map(|answer| json!({
                "address": address(answer.address),
                "ttl": answer.ttl_seconds,
                "record_expiry_ms": answer.record_expiry_ms,
                "effective_expiry_ms": answer.effective_expiry_ms,
                "message_sha256": answer.message_identity.to_hex(),
                "admissible": answer.admissible,
            })).collect::<Vec<_>>(),
            "outcome": fact.outcome.as_str(),
        }),
        ProxyReportEvent::Connection(fact) => json!({
            "kind": "connection",
            "index": fact.index,
            "endpoint_index": fact.endpoint_index,
            "open_sequence": fact.open_sequence,
            "close_sequence": fact.close_sequence,
            "accepted_ms": fact.accepted_ms,
            "resolution_index": fact.resolution_index,
            "sni_result": sni_result(fact.sni_result),
            "attempts": fact.attempts.iter().map(|attempt| json!({
                "answer_index": attempt.answer_index,
                "address": address(attempt.address),
                "started_ms": attempt.started_ms,
                "result": attempt_result(attempt.result),
            })).collect::<Vec<_>>(),
            "selected_attempt": fact.selected_attempt,
            "client_to_remote_bytes": fact.client_to_remote_bytes,
            "remote_to_client_bytes": fact.remote_to_client_bytes,
            "close_reason": close_reason(fact.close_reason),
        }),
        ProxyReportEvent::Final {
            event_sequence,
            totals,
            rejection_total,
            rejection_reason_counts,
            limit_events,
            phases,
        } => json!({
            "kind": "final",
            "event_sequence": event_sequence,
            "connections": totals.connections,
            "active": totals.active,
            "resolutions": totals.resolutions,
            "dns_messages": totals.dns_messages,
            "client_to_remote_bytes": totals.client_bytes,
            "remote_to_client_bytes": totals.remote_bytes,
            "rejections": rejection_total,
            "rejection_reason_counts": rejection_reason_counts,
            "limit_events": limit_events.iter().map(|limit| limit.event()).collect::<Vec<_>>(),
            "phases": phases.iter().map(|phase| phase.as_str()).collect::<Vec<_>>(),
        }),
    };
    let bytes = serde_json::to_vec(&value).map_err(|_| ProxyReportError::Encoding)?;
    if bytes.len() > MAX_PROXY_REPORT_BYTES {
        Err(ProxyReportError::TooLarge)
    } else {
        Ok(bytes)
    }
}

fn address(value: IpAddr) -> Value {
    match value {
        IpAddr::V4(value) => json!({"family": "ipv4", "bytes": value.octets()}),
        IpAddr::V6(value) => json!({"family": "ipv6", "bytes": value.octets()}),
    }
}

const fn target_kind(value: TargetKind) -> &'static str {
    match value {
        TargetKind::DnsName => "dns-name",
        TargetKind::Ipv4 => "ipv4",
        TargetKind::Ipv6 => "ipv6",
        TargetKind::Unparsed => "unparsed",
    }
}

const fn sni_result(value: SniObservation) -> &'static str {
    match value {
        SniObservation::NotInspected => "not-inspected",
        SniObservation::Matched => "matched",
        SniObservation::DeniedAbsent => "denied-absent",
        SniObservation::DeniedMismatch => "denied-mismatch",
        SniObservation::DeniedEch => "denied-ech",
        SniObservation::DeniedMalformed => "denied-malformed",
        SniObservation::DeniedTooLarge => "denied-too-large",
    }
}

const fn attempt_result(value: AttemptResult) -> &'static str {
    match value {
        AttemptResult::Connected => "connected",
        AttemptResult::Refused => "refused",
        AttemptResult::TimedOut => "timed-out",
        AttemptResult::Unreachable => "unreachable",
        AttemptResult::Failed => "failed",
    }
}

const fn close_reason(value: CloseReason) -> &'static str {
    match value {
        CloseReason::ClientClosed => "client-closed",
        CloseReason::RemoteClosed => "remote-closed",
        CloseReason::Reset => "reset",
        CloseReason::IdleTimeout => "idle-timeout",
        CloseReason::ClientByteLimit => "client-byte-limit",
        CloseReason::RemoteByteLimit => "remote-byte-limit",
        CloseReason::ProxyDraining => "proxy-draining",
        CloseReason::SniDenied => "sni-denied",
        CloseReason::ResolutionFailed => "resolution-failed",
        CloseReason::NoAdmissibleAnswer => "no-admissible-answer",
        CloseReason::ConnectFailed => "connect-failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress_proxy::{ProxyPhase, ProxyTotals};

    #[test]
    fn final_packet_has_exact_closed_counters() {
        let event = ProxyReportEvent::Final {
            event_sequence: 2,
            totals: ProxyTotals {
                connections: 1,
                active: 0,
                resolutions: 0,
                dns_messages: 0,
                client_bytes: 4,
                remote_bytes: 0,
            },
            rejection_total: 0,
            rejection_reason_counts: [0; 10],
            limit_events: Vec::new(),
            phases: vec![
                ProxyPhase::Created,
                ProxyPhase::Ready,
                ProxyPhase::Serving,
                ProxyPhase::Draining,
                ProxyPhase::Closed,
            ],
        };
        let packet = encode_proxy_report(&event).unwrap();
        let parsed: Value = serde_json::from_slice(&packet).unwrap();
        assert_eq!(parsed["kind"], "final");
        assert_eq!(parsed["client_to_remote_bytes"], 4);
        assert_eq!(parsed["phases"][4], "closed");
    }
}
