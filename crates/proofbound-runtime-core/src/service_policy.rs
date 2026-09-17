use crate::wire_v2::{self, Value};
use crate::{
    AddressOrder, AuthenticatedServiceSession, AuthorityError, CompiledPolicy, FileAccess,
    LocalChannelProtocol, MinimumTlsVersion, PathRole, PolicyEncodingError, ResolverAddress,
    RevocationPolicy, ServiceExecutionPlan, ServiceNameVerification, compile_policy,
    normalize_authority,
};

const POLICY_MODEL_VERSION_V2: &str = "proofbound-runtime-linux-policy/2";

/// Selects the child network filter for an authenticated service session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSeccompPolicy {
    /// Denies network creation and retains only the registered byte channel.
    ChannelOnlyV1,
}

/// Contains one proposed compiled authenticated-service-session policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledServicePolicy {
    child: CompiledPolicy,
    service_session: AuthenticatedServiceSession,
    child_network: ServiceSeccompPolicy,
}

impl CompiledServicePolicy {
    /// Returns the compiled direct-child boundary.
    #[must_use]
    pub const fn child(&self) -> &CompiledPolicy {
        &self.child
    }

    /// Returns the connector-owned service-session authority.
    #[must_use]
    pub const fn service_session(&self) -> &AuthenticatedServiceSession {
        &self.service_session
    }

    /// Returns the required child network filter.
    #[must_use]
    pub const fn child_network(&self) -> ServiceSeccompPolicy {
        self.child_network
    }

    /// Encodes the proposed policy as deterministic CBOR.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, PolicyEncodingError> {
        wire_v2::encode(&self.wire_value()?).map_err(|_| PolicyEncodingError::CanonicalEncoding)
    }

    /// Reports whether this policy adds no modeled authority to its plan.
    #[must_use]
    pub fn is_no_more_permissive_than(&self, plan: &ServiceExecutionPlan) -> bool {
        let Ok(normalized) = normalize_authority(plan.base().authority().clone()) else {
            return false;
        };
        self.child.is_no_more_permissive_than(&normalized)
            && self
                .service_session
                .is_no_more_permissive_than(plan.service_session())
            && self.child_network == ServiceSeccompPolicy::ChannelOnlyV1
    }

    fn wire_value(&self) -> Result<Value, PolicyEncodingError> {
        let limits = self.child.cgroup().limits();
        let memory = limits
            .memory()
            .ok_or(PolicyEncodingError::UnsupportedVersion)?;
        let swap = limits
            .swap()
            .ok_or(PolicyEncodingError::UnsupportedVersion)?;
        Ok(map(vec![
            ("schema", text(POLICY_MODEL_VERSION_V2)),
            (
                "cgroup",
                map(vec![
                    (
                        "pids.max",
                        Value::Unsigned(u64::from(limits.processes().get())),
                    ),
                    ("memory.max", Value::Unsigned(memory.get())),
                    ("memory.oom.group", Value::Unsigned(1)),
                    ("memory.swap.max", Value::Unsigned(swap.get())),
                    ("stderr_bytes", Value::Unsigned(limits.stderr().get())),
                    ("stdout_bytes", Value::Unsigned(limits.stdout().get())),
                    (
                        "wall_time_ms",
                        Value::Unsigned(limits.wall_time().milliseconds()),
                    ),
                ]),
            ),
            ("network", service_session_value(&self.service_session)),
            (
                "filesystem",
                Value::Array(
                    self.child
                        .filesystem()
                        .rules()
                        .iter()
                        .map(|rule| {
                            map(vec![
                                ("path", text(rule.path().as_str())),
                                ("role", text(path_role_name(rule.role()))),
                                ("access", text(file_access_name(rule.access()))),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "environment",
                Value::Array(
                    self.child
                        .environment()
                        .iter()
                        .map(|name| text(name.as_str()))
                        .collect(),
                ),
            ),
            ("no_new_privileges", Value::Bool(true)),
        ]))
    }
}

/// Compiles a proposed service-session plan without authorizing execution.
///
/// This pure function does not install a connector or a Linux boundary. The
/// production execution parser continues to reject this profile.
pub fn compile_service_policy(
    plan: &ServiceExecutionPlan,
) -> Result<CompiledServicePolicy, AuthorityError> {
    let child = compile_policy(normalize_authority(plan.base().authority().clone())?);
    Ok(CompiledServicePolicy {
        child,
        service_session: plan.service_session().clone(),
        child_network: ServiceSeccompPolicy::ChannelOnlyV1,
    })
}

fn service_session_value(session: &AuthenticatedServiceSession) -> Value {
    let resolution = session.resolution();
    let endpoint = resolution.endpoint();
    let (family, address) = match endpoint.address() {
        ResolverAddress::Ipv4(bytes) => ("ipv4", bytes.to_vec()),
        ResolverAddress::Ipv6(bytes) => ("ipv6", bytes.to_vec()),
    };
    let tls = session.tls();
    let limits = session.limits();
    let credential = session.credential_source().map_or(Value::Null, |source| {
        map(vec![
            ("id", text(source.id().as_str())),
            ("service", text(source.service().as_str())),
            ("environment", text(source.environment().as_str())),
        ])
    });
    map(vec![
        ("mode", text("authenticated-service-session-v1")),
        (
            "service",
            map(vec![
                ("name", text(session.service().as_str())),
                ("port", Value::Unsigned(u64::from(session.port().get()))),
            ]),
        ),
        (
            "resolver",
            map(vec![
                (
                    "address",
                    map(vec![
                        ("family", text(family)),
                        ("bytes", Value::Bytes(address)),
                    ]),
                ),
                ("port", Value::Unsigned(u64::from(endpoint.port().get()))),
                ("configuration", text(resolution.configuration().as_str())),
                (
                    "maximum_cname_depth",
                    Value::Unsigned(u64::from(resolution.maximum_cname_depth())),
                ),
                (
                    "maximum_answer_count",
                    Value::Unsigned(u64::from(resolution.maximum_answer_count())),
                ),
                (
                    "maximum_response_bytes",
                    Value::Unsigned(resolution.maximum_response_bytes()),
                ),
                (
                    "resolution_deadline_ms",
                    Value::Unsigned(resolution.resolution_deadline_ms()),
                ),
                (
                    "attempt_deadline_ms",
                    Value::Unsigned(resolution.attempt_deadline_ms()),
                ),
                (
                    "address_order",
                    text(match resolution.address_order() {
                        AddressOrder::Ipv4ThenIpv6Lexicographic => "ipv4-then-ipv6-lexicographic",
                    }),
                ),
            ]),
        ),
        (
            "tls",
            map(vec![
                ("trust_root_set", text(tls.trust_root_set().as_str())),
                (
                    "minimum_version",
                    text(match tls.minimum_version() {
                        MinimumTlsVersion::Tls12 => "tls-1.2",
                        MinimumTlsVersion::Tls13 => "tls-1.3",
                    }),
                ),
                (
                    "service_name_verification",
                    text(match tls.service_name_verification() {
                        ServiceNameVerification::DnsSanExact => "dns-san-exact",
                    }),
                ),
                (
                    "revocation",
                    text(match tls.revocation() {
                        RevocationPolicy::NotCheckedRecordedAssumption => {
                            "not-checked-recorded-assumption"
                        }
                    }),
                ),
                ("session_resumption", text("deny")),
                ("early_data", text("deny")),
            ]),
        ),
        (
            "limits",
            map(vec![
                ("setup_time_ms", Value::Unsigned(limits.setup_time_ms())),
                ("session_time_ms", Value::Unsigned(limits.session_time_ms())),
                (
                    "child_to_service_bytes",
                    Value::Unsigned(limits.child_to_service_bytes()),
                ),
                (
                    "service_to_child_bytes",
                    Value::Unsigned(limits.service_to_child_bytes()),
                ),
                (
                    "dns_messages",
                    Value::Unsigned(u64::from(limits.dns_messages())),
                ),
                (
                    "endpoint_attempts",
                    Value::Unsigned(u64::from(limits.endpoint_attempts())),
                ),
                (
                    "tls_handshake_bytes",
                    Value::Unsigned(limits.tls_handshake_bytes()),
                ),
            ]),
        ),
        (
            "connector_executable",
            text(session.connector_executable().as_str()),
        ),
        (
            "connector_runtime_read",
            Value::Array(
                session
                    .connector_runtime_read()
                    .iter()
                    .map(|path| text(path.as_str()))
                    .collect(),
            ),
        ),
        (
            "local_channel",
            map(vec![
                (
                    "protocol",
                    text(match session.local_channel() {
                        LocalChannelProtocol::UnixStreamV1 => "unix-stream-v1",
                    }),
                ),
                (
                    "child_descriptor",
                    Value::Unsigned(u64::from(session.child_descriptor().get())),
                ),
            ]),
        ),
        ("credential_source", credential),
    ])
}

fn map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

const fn file_access_name(access: FileAccess) -> &'static str {
    match access {
        FileAccess::Read => "read",
        FileAccess::Write => "write",
        FileAccess::Execute => "execute",
    }
}

const fn path_role_name(role: PathRole) -> &'static str {
    match role {
        PathRole::ProjectInput => "project-input",
        PathRole::OutputRoot => "output-root",
        PathRole::RuntimeExecutable => "runtime-executable",
        PathRole::RuntimeLoaderExecutable => "runtime-loader-executable",
        PathRole::RuntimeLibrary => "runtime-library",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkMode, parse_service_execution_plan};

    fn decode_hex(input: &str) -> Vec<u8> {
        input
            .trim()
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = core::str::from_utf8(pair).expect("fixture is ASCII");
                u8::from_str_radix(text, 16).expect("fixture is hexadecimal")
            })
            .collect()
    }

    #[test]
    fn compilation_preserves_service_authority_and_child_network_denial() {
        let plan = parse_service_execution_plan(&decode_hex(include_str!(
            "../../../schemas/vectors/v2/execution-plan-service-session.cbor.hex"
        )))
        .expect("service fixture is valid");
        let compiled = compile_service_policy(&plan).expect("service policy compiles");

        assert_eq!(
            compiled.child().network(),
            crate::SeccompPolicy::DenyNetworkV1
        );
        assert_eq!(plan.base().authority().network(), NetworkMode::Deny);
        assert_eq!(
            compiled.child_network(),
            ServiceSeccompPolicy::ChannelOnlyV1
        );
        assert_eq!(compiled.service_session(), plan.service_session());
        assert!(compiled.is_no_more_permissive_than(&plan));
        assert_eq!(
            compiled.canonical_bytes().expect("service policy encodes"),
            decode_hex(include_str!(
                "../../../schemas/vectors/v2/compiled-policy-service-session.cbor.hex"
            ))
        );
    }
}
