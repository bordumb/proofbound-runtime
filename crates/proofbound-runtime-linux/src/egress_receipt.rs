//! Bounded supervisor-side collection of private proxy reports.

use std::collections::BTreeMap;

use proofbound_runtime_core::{EgressReceiptFlags, Sha256Digest, encode_egress_observation_json};
use serde_json::{Value, json};

const MAX_PACKET: usize = 32_768;
const REASONS: [&str; 10] = [
    "method-not-connect",
    "request-malformed",
    "request-head-too-large",
    "target-noncanonical",
    "endpoint-undeclared",
    "limit-connections",
    "limit-concurrent-connections",
    "limit-resolutions",
    "limit-dns-messages",
    "limit-bytes-exhausted",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressReceiptError {
    ObservationIncomplete,
    SizeExceeded,
    CounterOverflow,
    ReportInvalid,
}

impl EgressReceiptError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ObservationIncomplete => "receipt.network.egress.observation-incomplete",
            Self::SizeExceeded => "receipt.network.egress.size-exceeded",
            Self::CounterOverflow => "receipt.network.egress.counter-overflow",
            Self::ReportInvalid => "network.egress.proxy.report-invalid",
        }
    }
}

fn fields<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, EgressReceiptError> {
    let object = value.as_object().ok_or(EgressReceiptError::ReportInvalid)?;
    if object.len() != keys.len() || object.keys().any(|key| !keys.contains(&key.as_str())) {
        return Err(EgressReceiptError::ReportInvalid);
    }
    Ok(object)
}

fn unsigned(value: &Value, key: &str) -> Result<u64, EgressReceiptError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(EgressReceiptError::ReportInvalid)
}

fn ordered(records: BTreeMap<u64, Value>) -> Result<Vec<Value>, EgressReceiptError> {
    records
        .into_iter()
        .enumerate()
        .map(|(expected, (index, value))| {
            if index == expected as u64 + 1 {
                Ok(value)
            } else {
                Err(EgressReceiptError::ObservationIncomplete)
            }
        })
        .collect()
}

/// A single-use collector. Every packet is parsed and bounded before the
/// supervisor converts the terminal report into a receipt observation.
#[derive(Default)]
pub struct EgressReportCollector {
    ready: Option<Value>,
    resolutions: BTreeMap<u64, Value>,
    connections: BTreeMap<u64, Value>,
    rejections: Vec<Value>,
    rejection_total: u64,
    rejection_counts: [u64; 10],
    final_report: Option<Value>,
}

impl EgressReportCollector {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes the recorded non-reuse reasons from the same bounded reports
    /// that form the observation. The verifier rederives these independently.
    #[must_use]
    pub fn flags(&self) -> EgressReceiptFlags {
        let sni_denied = self.connections.values().any(|connection| {
            connection
                .get("sni_result")
                .and_then(Value::as_str)
                .is_some_and(|result| result == "denied")
        });
        let limit_reached = self
            .final_report
            .as_ref()
            .and_then(|report| report.get("limit_events"))
            .and_then(Value::as_array)
            .is_some_and(|events| !events.is_empty());
        EgressReceiptFlags {
            authority_rejection: self.rejection_total != 0,
            sni_denied,
            limit_reached,
            proxy_failed: false,
            cleanup_incomplete: false,
        }
    }

    pub fn ingest(&mut self, packet: &[u8]) -> Result<(), EgressReceiptError> {
        if packet.is_empty() || packet.len() > MAX_PACKET || self.final_report.is_some() {
            return Err(EgressReceiptError::ReportInvalid);
        }
        let value: Value =
            serde_json::from_slice(packet).map_err(|_| EgressReceiptError::ReportInvalid)?;
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .ok_or(EgressReceiptError::ReportInvalid)?;
        if self.ready.is_none() && kind != "ready" {
            return Err(EgressReceiptError::ObservationIncomplete);
        }
        match kind {
            "ready" if self.ready.is_none() => {
                fields(
                    &value,
                    &[
                        "kind",
                        "execution_id",
                        "policy_sha256",
                        "generation",
                        "plan_sha256",
                        "proxy_sha256",
                        "runtime_closure_sha256",
                        "resolver_configuration_sha256",
                        "child_netns_device",
                        "child_netns_inode",
                        "landlock_abi",
                        "landlock_handled_filesystem",
                        "landlock_handled_network",
                        "landlock_scoped",
                        "proxy_filter_sha256",
                        "readiness_binding",
                    ],
                )?;
                self.ready = Some(value);
            }
            "resolution" => {
                fields(
                    &value,
                    &[
                        "kind",
                        "index",
                        "name",
                        "triggering_connection",
                        "started_ms",
                        "finished_ms",
                        "messages",
                        "cname_links",
                        "answers",
                        "outcome",
                    ],
                )?;
                let index = unsigned(&value, "index")?;
                if index == 0 || index > 1024 || self.resolutions.insert(index, value).is_some() {
                    return Err(EgressReceiptError::ReportInvalid);
                }
            }
            "connection" => {
                fields(
                    &value,
                    &[
                        "kind",
                        "index",
                        "endpoint_index",
                        "open_sequence",
                        "close_sequence",
                        "accepted_ms",
                        "resolution_index",
                        "sni_result",
                        "attempts",
                        "selected_attempt",
                        "client_to_remote_bytes",
                        "remote_to_client_bytes",
                        "close_reason",
                    ],
                )?;
                let index = unsigned(&value, "index")?;
                if index == 0 || index > 8192 || self.connections.insert(index, value).is_some() {
                    return Err(EgressReceiptError::ReportInvalid);
                }
            }
            "rejection" => {
                fields(&value, &["kind", "sequence", "reason", "total", "retained"])?;
                let total = unsigned(&value, "total")?;
                if total
                    != self
                        .rejection_total
                        .checked_add(1)
                        .ok_or(EgressReceiptError::CounterOverflow)?
                {
                    return Err(EgressReceiptError::ReportInvalid);
                }
                let reason = value
                    .get("reason")
                    .and_then(Value::as_str)
                    .ok_or(EgressReceiptError::ReportInvalid)?;
                let index = REASONS
                    .iter()
                    .position(|candidate| *candidate == reason)
                    .ok_or(EgressReceiptError::ReportInvalid)?;
                self.rejection_counts[index] = self.rejection_counts[index]
                    .checked_add(1)
                    .ok_or(EgressReceiptError::CounterOverflow)?;
                self.rejection_total = total;
                if self.rejections.len() < 256 {
                    let retained = value
                        .get("retained")
                        .filter(|retained| !retained.is_null())
                        .ok_or(EgressReceiptError::ObservationIncomplete)?;
                    fields(
                        retained,
                        &[
                            "sequence",
                            "time_ms",
                            "reason",
                            "target_kind",
                            "port",
                            "target_length",
                            "target_sha256",
                        ],
                    )?;
                    if retained.get("reason") != value.get("reason")
                        || retained.get("sequence") != value.get("sequence")
                    {
                        return Err(EgressReceiptError::ReportInvalid);
                    }
                    self.rejections.push(retained.clone());
                } else if !value.get("retained").is_some_and(Value::is_null) {
                    return Err(EgressReceiptError::ReportInvalid);
                }
            }
            "final" => {
                fields(
                    &value,
                    &[
                        "kind",
                        "event_sequence",
                        "connections",
                        "active",
                        "resolutions",
                        "dns_messages",
                        "client_to_remote_bytes",
                        "remote_to_client_bytes",
                        "rejections",
                        "rejection_reason_counts",
                        "limit_events",
                        "phases",
                    ],
                )?;
                self.final_report = Some(value);
            }
            _ => return Err(EgressReceiptError::ReportInvalid),
        }
        Ok(())
    }

    /// Reconciles terminal counters and emits one deterministic CBOR fragment.
    /// Authority, boundary, artifacts, and cleanup are supplied by the
    /// supervisor's separately validated preflight and kernel observations.
    pub fn finish(
        self,
        authority: Value,
        policy_sha256: Sha256Digest,
        boundary: Value,
        artifacts: Value,
        cleanup: Value,
    ) -> Result<Vec<u8>, EgressReceiptError> {
        let ready = self
            .ready
            .ok_or(EgressReceiptError::ObservationIncomplete)?;
        let final_report = self
            .final_report
            .ok_or(EgressReceiptError::ObservationIncomplete)?;
        let final_counts = final_report
            .get("rejection_reason_counts")
            .and_then(Value::as_array)
            .ok_or(EgressReceiptError::ReportInvalid)?;
        let event_count = (self.connections.len() as u64)
            .checked_mul(2)
            .and_then(|count| count.checked_add(self.rejection_total))
            .ok_or(EgressReceiptError::CounterOverflow)?;
        if final_counts.len() != 10
            || final_counts
                .iter()
                .zip(self.rejection_counts)
                .any(|(recorded, actual)| recorded.as_u64() != Some(actual))
            || unsigned(&final_report, "rejections")? != self.rejection_total
            || unsigned(&final_report, "connections")? != self.connections.len() as u64
            || unsigned(&final_report, "resolutions")? != self.resolutions.len() as u64
            || unsigned(&final_report, "active")? != 0
            || unsigned(&final_report, "event_sequence")? != event_count
            || ready.get("policy_sha256").and_then(Value::as_str)
                != Some(policy_sha256.to_hex().as_str())
        {
            return Err(EgressReceiptError::ObservationIncomplete);
        }
        let resolutions = ordered(self.resolutions)?;
        let connections = ordered(self.connections)?;
        let dns_messages = resolutions.iter().try_fold(0_u64, |sum, item| {
            sum.checked_add(
                item.get("messages")
                    .and_then(Value::as_array)
                    .ok_or(EgressReceiptError::ReportInvalid)?
                    .len() as u64,
            )
            .ok_or(EgressReceiptError::CounterOverflow)
        })?;
        let client_bytes = connections.iter().try_fold(0_u64, |sum, item| {
            sum.checked_add(unsigned(item, "client_to_remote_bytes")?)
                .ok_or(EgressReceiptError::CounterOverflow)
        })?;
        let remote_bytes = connections.iter().try_fold(0_u64, |sum, item| {
            sum.checked_add(unsigned(item, "remote_to_client_bytes")?)
                .ok_or(EgressReceiptError::CounterOverflow)
        })?;
        if unsigned(&final_report, "dns_messages")? != dns_messages
            || unsigned(&final_report, "client_to_remote_bytes")? != client_bytes
            || unsigned(&final_report, "remote_to_client_bytes")? != remote_bytes
        {
            return Err(EgressReceiptError::ObservationIncomplete);
        }
        let reasons = REASONS
            .into_iter()
            .enumerate()
            .map(|(index, reason)| (reason.to_owned(), json!(self.rejection_counts[index])))
            .collect::<serde_json::Map<_, _>>();
        let artifact_fields = fields(
            &artifacts,
            &["executable", "runtime_closure", "resolver_configuration"],
        )?;
        if ready.get("proxy_sha256")
            != artifact_fields
                .get("executable")
                .and_then(|item| item.get("sha256"))
            || ready.get("resolver_configuration_sha256")
                != artifact_fields
                    .get("resolver_configuration")
                    .and_then(|item| item.get("sha256"))
        {
            return Err(EgressReceiptError::ReportInvalid);
        }
        let proxy = json!({
            "executable": artifact_fields["executable"],
            "runtime_closure": artifact_fields["runtime_closure"],
            "resolver_configuration": artifact_fields["resolver_configuration"],
            "generation": ready["generation"],
            "readiness_binding": ready["readiness_binding"],
            "phases": final_report["phases"],
            "terminal_reason": "closed",
            "failure_reason": null,
        });
        let observation = json!({
            "schema": "proofbound-runtime-egress-observation/1",
            "authority": authority,
            "policy_sha256": policy_sha256.to_hex(),
            "boundary": boundary,
            "proxy": proxy,
            "resolutions": resolutions.into_iter().map(|mut item| { item.as_object_mut().unwrap().remove("kind"); item }).collect::<Vec<_>>(),
            "connections": connections.into_iter().map(|mut item| { item.as_object_mut().unwrap().remove("kind"); item }).collect::<Vec<_>>(),
            "rejections": self.rejections,
            "counters": {
                "connections": unsigned(&final_report, "connections")?,
                "resolutions": unsigned(&final_report, "resolutions")?,
                "dns_messages": dns_messages,
                "client_to_remote_bytes": client_bytes,
                "remote_to_client_bytes": remote_bytes,
                "rejections": self.rejection_total,
                "rejection_reason_counts": reasons,
            },
            "limit_events": final_report["limit_events"],
            "cleanup": cleanup,
        });
        encode_egress_observation_json(&observation).map_err(|_| EgressReceiptError::SizeExceeded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).unwrap()
    }

    fn ready() -> Value {
        let digest = "11".repeat(32);
        json!({
            "kind": "ready",
            "execution_id": "22".repeat(16),
            "policy_sha256": digest,
            "generation": 1,
            "plan_sha256": "33".repeat(32),
            "proxy_sha256": "44".repeat(32),
            "runtime_closure_sha256": "55".repeat(32),
            "resolver_configuration_sha256": "66".repeat(32),
            "child_netns_device": 1,
            "child_netns_inode": 2,
            "landlock_abi": 9,
            "landlock_handled_filesystem": 1,
            "landlock_handled_network": 3,
            "landlock_scoped": 3,
            "proxy_filter_sha256": "77".repeat(32),
            "readiness_binding": "88".repeat(32),
        })
    }

    #[test]
    fn reports_require_readiness_and_a_single_terminal_packet() {
        let mut collector = EgressReportCollector::new();
        assert_eq!(
            collector.ingest(&packet(json!({"kind": "final"}))),
            Err(EgressReceiptError::ObservationIncomplete)
        );
        collector.ingest(&packet(ready())).unwrap();
        assert_eq!(
            collector.ingest(&packet(ready())),
            Err(EgressReceiptError::ReportInvalid)
        );
        let terminal = json!({
            "kind": "final", "event_sequence": 0, "connections": 0,
            "active": 0, "resolutions": 0, "dns_messages": 0,
            "client_to_remote_bytes": 0, "remote_to_client_bytes": 0,
            "rejections": 0, "rejection_reason_counts": [0,0,0,0,0,0,0,0,0,0],
            "limit_events": [], "phases": ["created", "ready", "serving", "draining", "closed"],
        });
        collector.ingest(&packet(terminal.clone())).unwrap();
        assert_eq!(
            collector.ingest(&packet(terminal)),
            Err(EgressReceiptError::ReportInvalid)
        );
    }

    #[test]
    fn report_indices_are_one_based_and_cannot_be_replayed() {
        let mut collector = EgressReportCollector::new();
        collector.ingest(&packet(ready())).unwrap();
        let resolution = json!({
            "kind": "resolution", "index": 0, "name": "api.example",
            "triggering_connection": 1, "started_ms": 1, "finished_ms": 2,
            "messages": [], "cname_links": [], "answers": [], "outcome": "failed",
        });
        assert_eq!(
            collector.ingest(&packet(resolution)),
            Err(EgressReceiptError::ReportInvalid)
        );
        let resolution = json!({
            "kind": "resolution", "index": 1, "name": "api.example",
            "triggering_connection": 1, "started_ms": 1, "finished_ms": 2,
            "messages": [], "cname_links": [], "answers": [], "outcome": "failed",
        });
        collector.ingest(&packet(resolution.clone())).unwrap();
        assert_eq!(
            collector.ingest(&packet(resolution)),
            Err(EgressReceiptError::ReportInvalid)
        );
    }

    #[test]
    fn proxy_packets_reconstruct_the_registered_observation_bytes() {
        fn projection_to_json(value: &mut Value, key: &str) {
            match value {
                Value::Object(fields) => {
                    for (name, item) in fields {
                        projection_to_json(item, name);
                    }
                }
                Value::Array(items) => {
                    for item in items {
                        projection_to_json(item, "");
                    }
                }
                Value::String(text) if text.starts_with("hex:") => {
                    let hex = text.strip_prefix("hex:").unwrap();
                    if key == "bytes" || key == "address" {
                        let octets = hex
                            .as_bytes()
                            .chunks_exact(2)
                            .map(|pair| {
                                u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap()
                            })
                            .collect::<Vec<_>>();
                        *value = json!(octets);
                    } else {
                        *value = json!(hex);
                    }
                }
                Value::String(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
                    *value = json!(text.parse::<u64>().unwrap());
                }
                _ => {}
            }
        }

        let mut golden: Value = serde_json::from_str(include_str!(
            "../../../schemas/vectors/v3/egress-observation.projection.json"
        ))
        .unwrap();
        projection_to_json(&mut golden, "");
        let policy_hex = golden["policy_sha256"].as_str().unwrap();
        let policy = Sha256Digest::parse_hex(policy_hex).unwrap();
        let proxy = &golden["proxy"];
        let ready = json!({
            "kind": "ready", "execution_id": "22".repeat(16),
            "policy_sha256": policy_hex, "generation": proxy["generation"],
            "plan_sha256": "33".repeat(32),
            "proxy_sha256": proxy["executable"]["sha256"],
            "runtime_closure_sha256": "55".repeat(32),
            "resolver_configuration_sha256": proxy["resolver_configuration"]["sha256"],
            "child_netns_device": golden["boundary"]["child_network_namespace"]["device"],
            "child_netns_inode": golden["boundary"]["child_network_namespace"]["inode"],
            "landlock_abi": golden["boundary"]["landlock_abi"],
            "landlock_handled_filesystem": 1, "landlock_handled_network": 3,
            "landlock_scoped": 3,
            "proxy_filter_sha256": golden["boundary"]["proxy_filter_sha256"],
            "readiness_binding": proxy["readiness_binding"],
        });
        let retained = golden["rejections"][0].clone();
        let rejection = json!({
            "kind": "rejection", "sequence": retained["sequence"],
            "reason": retained["reason"], "total": 1, "retained": retained,
        });
        let final_packet = json!({
            "kind": "final", "event_sequence": 1,
            "connections": 0, "active": 0, "resolutions": 0,
            "dns_messages": 0, "client_to_remote_bytes": 0,
            "remote_to_client_bytes": 0, "rejections": 1,
            "rejection_reason_counts": REASONS.map(|reason| golden["counters"]["rejection_reason_counts"][reason].as_u64().unwrap()),
            "limit_events": [], "phases": proxy["phases"],
        });
        let mut collector = EgressReportCollector::new();
        for report in [ready, rejection, final_packet] {
            collector.ingest(&packet(report)).unwrap();
        }
        let actual = collector
            .finish(
                golden["authority"].clone(),
                policy,
                golden["boundary"].clone(),
                json!({
                    "executable": proxy["executable"],
                    "runtime_closure": proxy["runtime_closure"],
                    "resolver_configuration": proxy["resolver_configuration"],
                }),
                golden["cleanup"].clone(),
            )
            .unwrap();
        let expected = include_str!("../../../schemas/vectors/v3/egress-observation.cbor.hex")
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}
