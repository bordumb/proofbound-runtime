//! Validated construction of a declared-egress version 3 plan.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::{
    Cbor, PlanV2Input, ResolverAddressV2Input, SdkError, canonical_absolute_path, encode,
    require_unique, text_array, valid_plan_id, valid_required_text, validate_plan_input,
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AddressScopeV3Input {
    Global,
    GlobalOrPrivate,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EgressDestinationV3Input {
    DnsName {
        name: String,
        scope: AddressScopeV3Input,
    },
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SniV3Input {
    NotInspected,
    Required(String),
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EgressEndpointV3Input {
    pub destination: EgressDestinationV3Input,
    pub port: u16,
    pub tls_sni: SniV3Input,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolverV3Input {
    pub address: ResolverAddressV2Input,
    pub port: u16,
    pub configuration: String,
    pub maximum_cname_depth: u16,
    pub maximum_answer_count: u16,
    pub maximum_response_bytes: u64,
    pub resolution_deadline_ms: u64,
    pub attempt_deadline_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressLimitsV3Input {
    pub connections: u16,
    pub concurrent_connections: u16,
    pub attempts_per_connection: u8,
    pub resolutions: u16,
    pub dns_messages: u16,
    pub client_to_remote_bytes: u64,
    pub remote_to_client_bytes: u64,
    pub connection_idle_ms: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressV3Input {
    pub endpoints: Vec<EgressEndpointV3Input>,
    pub resolver: ResolverV3Input,
    pub limits: EgressLimitsV3Input,
    pub proxy_executable: String,
    pub proxy_runtime_read: Vec<String>,
    pub proxy_environment: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanV3Input {
    pub base: PlanV2Input,
    pub egress: EgressV3Input,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanV3 {
    bytes: Vec<u8>,
}

impl PlanV3 {
    /// Validates the closed input and returns deterministic CBOR plan bytes.
    pub fn new(mut input: PlanV3Input) -> Result<Self, SdkError> {
        validate_v3(&input)?;
        input.base.execute.sort();
        input.egress.endpoints.sort();
        input.egress.proxy_runtime_read.sort();
        input.egress.proxy_runtime_read.dedup();
        let base = input.base;
        let network = encode_network(input.egress);
        let value = Cbor::Map(vec![
            ("id", Cbor::Text(base.id)),
            ("schema", Cbor::Text("proofbound-runtime-plan/3".to_owned())),
            (
                "limits",
                Cbor::Map(vec![
                    ("processes", Cbor::Unsigned(u64::from(base.processes))),
                    ("wall_time_ms", Cbor::Unsigned(base.wall_time_ms)),
                    ("stdout_bytes", Cbor::Unsigned(base.stdout_bytes)),
                    ("stderr_bytes", Cbor::Unsigned(base.stderr_bytes)),
                    ("memory_bytes", Cbor::Unsigned(base.memory_bytes)),
                    ("swap_bytes", Cbor::Unsigned(base.swap_bytes)),
                ]),
            ),
            (
                "command",
                Cbor::Map(vec![
                    ("executable", Cbor::Text(base.executable)),
                    ("arguments", text_array(base.arguments)),
                    ("working_directory", Cbor::Text(base.working_directory)),
                ]),
            ),
            (
                "authority",
                Cbor::Map(vec![
                    ("read", text_array(base.read)),
                    ("runtime_read", text_array(base.runtime_read)),
                    ("write", text_array(base.write)),
                    ("execute", text_array(base.execute)),
                    ("environment", text_array(base.environment)),
                    ("network", network),
                ]),
            ),
        ]);
        let mut bytes = Vec::new();
        encode(&value, &mut bytes)?;
        Ok(Self { bytes })
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

fn validate_v3(input: &PlanV3Input) -> Result<(), SdkError> {
    let base = &input.base;
    if !valid_plan_id(&base.id) {
        return Err(SdkError::PlanId);
    }
    if base.execute.is_empty()
        || base.execute.len() > 64
        || !base.execute.contains(&base.executable)
        || base.execute.iter().any(|path| !valid_required_text(path))
    {
        return Err(SdkError::PlanShape);
    }
    require_unique(&base.execute)?;
    let mut singleton = base.clone();
    singleton.execute = vec![base.executable.clone()];
    validate_plan_input(&singleton)?;
    let network = &input.egress;
    if network.endpoints.is_empty()
        || network.endpoints.len() > 256
        || !canonical_absolute_path(&network.proxy_executable)
        || network
            .proxy_runtime_read
            .iter()
            .any(|path| !canonical_absolute_path(path))
    {
        return Err(SdkError::PlanNetwork);
    }
    let resolver = &network.resolver;
    if resolver.port == 0
        || !canonical_absolute_path(&resolver.configuration)
        || !(1..=4).contains(&resolver.maximum_cname_depth)
        || !(1..=16).contains(&resolver.maximum_answer_count)
        || !(1..=65_535).contains(&resolver.maximum_response_bytes)
        || !(1..=60_000).contains(&resolver.resolution_deadline_ms)
        || resolver.attempt_deadline_ms == 0
        || resolver.attempt_deadline_ms > resolver.resolution_deadline_ms
    {
        return Err(SdkError::PlanNetwork);
    }
    let limits = network.limits;
    if !(1..=8192).contains(&limits.connections)
        || !(1..=512).contains(&limits.concurrent_connections)
        || !(1..=4).contains(&limits.attempts_per_connection)
        || u16::from(limits.attempts_per_connection) > resolver.maximum_answer_count
        || !(1..=1024).contains(&limits.resolutions)
        || !(2..=8192).contains(&limits.dns_messages)
        || !(1..=1_u64 << 40).contains(&limits.client_to_remote_bytes)
        || !(1..=1_u64 << 40).contains(&limits.remote_to_client_bytes)
        || !(1..=3_600_000).contains(&limits.connection_idle_ms)
    {
        return Err(SdkError::PlanNetwork);
    }
    if network.proxy_environment.is_empty()
        || network.proxy_environment.len() > 6
        || !network
            .proxy_environment
            .windows(2)
            .all(|pair| pair[0] < pair[1])
        || network.proxy_environment.iter().any(|name| {
            !matches!(
                name.as_str(),
                "ALL_PROXY"
                    | "HTTP_PROXY"
                    | "HTTPS_PROXY"
                    | "all_proxy"
                    | "http_proxy"
                    | "https_proxy"
            )
        })
        || base.environment.iter().any(|name| {
            matches!(
                name.to_ascii_uppercase().as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        })
    {
        return Err(SdkError::PlanNetwork);
    }
    let mut endpoint_keys = std::collections::BTreeSet::new();
    let mut name_scopes = std::collections::BTreeMap::new();
    for endpoint in &network.endpoints {
        if endpoint.port == 0 {
            return Err(SdkError::PlanNetwork);
        }
        match &endpoint.destination {
            EgressDestinationV3Input::DnsName { name, scope } => {
                if !valid_egress_name(name) {
                    return Err(SdkError::PlanNetwork);
                }
                if name_scopes
                    .insert(name, scope)
                    .is_some_and(|prior| prior != scope)
                {
                    return Err(SdkError::PlanNetwork);
                }
            }
            EgressDestinationV3Input::Ipv4(bytes) => {
                let address = Ipv4Addr::from(*bytes);
                if address.is_unspecified() || address.is_multicast() || *bytes == [255; 4] {
                    return Err(SdkError::PlanNetwork);
                }
            }
            EgressDestinationV3Input::Ipv6(bytes) => {
                let address = Ipv6Addr::from(*bytes);
                if address.is_unspecified()
                    || address.is_multicast()
                    || address.to_ipv4_mapped().is_some()
                    || (bytes[..12] == [0; 12] && !address.is_loopback())
                {
                    return Err(SdkError::PlanNetwork);
                }
            }
        }
        if !endpoint_keys.insert((&endpoint.destination, endpoint.port)) {
            return Err(SdkError::PlanNetwork);
        }
        if let SniV3Input::Required(name) = &endpoint.tls_sni
            && (!valid_egress_name(name)
                || matches!(&endpoint.destination,
                    EgressDestinationV3Input::DnsName { name: target, .. } if target != name))
        {
            return Err(SdkError::PlanNetwork);
        }
    }
    Ok(())
}

fn valid_egress_name(value: &str) -> bool {
    let labels = value.split('.').collect::<Vec<_>>();
    !value.is_empty()
        && value.len() <= 253
        && !value.ends_with('.')
        && labels.len() >= 2
        && labels
            .last()
            .is_some_and(|label| !label.bytes().all(|byte| byte.is_ascii_digit()))
        && labels.iter().all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes[0] != b'-'
                && bytes[bytes.len() - 1] != b'-'
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
}

fn encode_network(network: EgressV3Input) -> Cbor {
    let resolver = network.resolver;
    let (family, address) = match resolver.address {
        ResolverAddressV2Input::Ipv4(bytes) => ("ipv4", bytes.to_vec()),
        ResolverAddressV2Input::Ipv6(bytes) => ("ipv6", bytes.to_vec()),
    };
    let limits = network.limits;
    Cbor::Map(vec![
        ("mode", Cbor::Text("declared-egress".to_owned())),
        (
            "endpoints",
            Cbor::Array(network.endpoints.into_iter().map(encode_endpoint).collect()),
        ),
        (
            "resolver",
            Cbor::Map(vec![
                (
                    "address",
                    Cbor::Map(vec![
                        ("family", Cbor::Text(family.to_owned())),
                        ("bytes", Cbor::Bytes(address)),
                    ]),
                ),
                ("port", Cbor::Unsigned(u64::from(resolver.port))),
                ("configuration", Cbor::Text(resolver.configuration)),
                (
                    "maximum_cname_depth",
                    Cbor::Unsigned(u64::from(resolver.maximum_cname_depth)),
                ),
                (
                    "maximum_answer_count",
                    Cbor::Unsigned(u64::from(resolver.maximum_answer_count)),
                ),
                (
                    "maximum_response_bytes",
                    Cbor::Unsigned(resolver.maximum_response_bytes),
                ),
                (
                    "resolution_deadline_ms",
                    Cbor::Unsigned(resolver.resolution_deadline_ms),
                ),
                (
                    "attempt_deadline_ms",
                    Cbor::Unsigned(resolver.attempt_deadline_ms),
                ),
                (
                    "address_order",
                    Cbor::Text("ipv4-then-ipv6-lexicographic".to_owned()),
                ),
            ]),
        ),
        (
            "limits",
            Cbor::Map(vec![
                ("connections", Cbor::Unsigned(u64::from(limits.connections))),
                (
                    "concurrent_connections",
                    Cbor::Unsigned(u64::from(limits.concurrent_connections)),
                ),
                (
                    "attempts_per_connection",
                    Cbor::Unsigned(u64::from(limits.attempts_per_connection)),
                ),
                ("resolutions", Cbor::Unsigned(u64::from(limits.resolutions))),
                (
                    "dns_messages",
                    Cbor::Unsigned(u64::from(limits.dns_messages)),
                ),
                (
                    "client_to_remote_bytes",
                    Cbor::Unsigned(limits.client_to_remote_bytes),
                ),
                (
                    "remote_to_client_bytes",
                    Cbor::Unsigned(limits.remote_to_client_bytes),
                ),
                (
                    "connection_idle_ms",
                    Cbor::Unsigned(u64::from(limits.connection_idle_ms)),
                ),
            ]),
        ),
        ("proxy_executable", Cbor::Text(network.proxy_executable)),
        ("proxy_runtime_read", text_array(network.proxy_runtime_read)),
        ("proxy_environment", text_array(network.proxy_environment)),
    ])
}

fn encode_endpoint(endpoint: EgressEndpointV3Input) -> Cbor {
    let destination = match endpoint.destination {
        EgressDestinationV3Input::DnsName { name, scope } => Cbor::Map(vec![
            ("kind", Cbor::Text("dns-name".to_owned())),
            ("name", Cbor::Text(name)),
            (
                "address_scope",
                Cbor::Text(
                    match scope {
                        AddressScopeV3Input::Global => "global",
                        AddressScopeV3Input::GlobalOrPrivate => "global-or-private",
                    }
                    .to_owned(),
                ),
            ),
        ]),
        EgressDestinationV3Input::Ipv4(bytes) => Cbor::Map(vec![
            ("kind", Cbor::Text("ipv4".to_owned())),
            ("bytes", Cbor::Bytes(bytes.to_vec())),
        ]),
        EgressDestinationV3Input::Ipv6(bytes) => Cbor::Map(vec![
            ("kind", Cbor::Text("ipv6".to_owned())),
            ("bytes", Cbor::Bytes(bytes.to_vec())),
        ]),
    };
    let sni = match endpoint.tls_sni {
        SniV3Input::NotInspected => Cbor::Text("not-inspected".to_owned()),
        SniV3Input::Required(name) => Cbor::Map(vec![
            ("mode", Cbor::Text("required".to_owned())),
            ("name", Cbor::Text(name)),
        ]),
    };
    Cbor::Map(vec![
        ("destination", destination),
        ("port", Cbor::Unsigned(u64::from(endpoint.port))),
        ("protocol", Cbor::Text("tcp".to_owned())),
        ("tls_sni", sni),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vector_input() -> PlanV3Input {
        PlanV3Input {
            base: PlanV2Input {
                id: "golden-egress-v3".to_owned(),
                executable: "/bin/tool".to_owned(),
                arguments: vec![],
                working_directory: "/tmp".to_owned(),
                read: vec![],
                runtime_read: vec![],
                write: vec!["/tmp".to_owned()],
                execute: vec!["/bin/plugin".to_owned(), "/bin/tool".to_owned()],
                environment: vec![],
                processes: 8,
                wall_time_ms: 60_000,
                stdout_bytes: 0,
                stderr_bytes: 0,
                memory_bytes: 65_536,
                swap_bytes: 0,
            },
            egress: EgressV3Input {
                endpoints: vec![EgressEndpointV3Input {
                    destination: EgressDestinationV3Input::DnsName {
                        name: "api.example".to_owned(),
                        scope: AddressScopeV3Input::Global,
                    },
                    port: 443,
                    tls_sni: SniV3Input::Required("api.example".to_owned()),
                }],
                resolver: ResolverV3Input {
                    address: ResolverAddressV2Input::Ipv4([8, 8, 8, 8]),
                    port: 53,
                    configuration: "/etc/resolv.conf".to_owned(),
                    maximum_cname_depth: 4,
                    maximum_answer_count: 16,
                    maximum_response_bytes: 65_535,
                    resolution_deadline_ms: 60_000,
                    attempt_deadline_ms: 10_000,
                },
                limits: EgressLimitsV3Input {
                    connections: 10,
                    concurrent_connections: 2,
                    attempts_per_connection: 2,
                    resolutions: 10,
                    dns_messages: 20,
                    client_to_remote_bytes: 100_000,
                    remote_to_client_bytes: 100_000,
                    connection_idle_ms: 1000,
                },
                proxy_executable: "/usr/bin/pbr-egress-proxy".to_owned(),
                proxy_runtime_read: vec![],
                proxy_environment: vec!["HTTPS_PROXY".to_owned(), "https_proxy".to_owned()],
            },
        }
    }

    #[test]
    fn sdk_plan_matches_the_independent_version_three_vector() {
        let plan = PlanV3::new(vector_input()).unwrap();
        let vector = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v3/execution-plan-egress.cbor.hex"
        ));
        let vector = vector
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect::<String>();
        let expected = vector
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(plan.as_bytes(), expected);
    }

    #[test]
    fn sdk_rejects_egress_authority_expansion_and_proxy_override() {
        let mut input = vector_input();
        input.egress.endpoints[0].destination = EgressDestinationV3Input::DnsName {
            name: "other.example".to_owned(),
            scope: AddressScopeV3Input::Global,
        };
        assert_eq!(PlanV3::new(input), Err(SdkError::PlanNetwork));
        let mut input = vector_input();
        input.base.environment.push("no_proxy".to_owned());
        assert_eq!(PlanV3::new(input), Err(SdkError::PlanNetwork));
    }

    #[test]
    fn sdk_decodes_only_the_explicit_version_three_result() {
        let vector = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/vectors/v3/run-result.projection.json"
        ));
        assert!(super::super::RunResultProjection::from_json_v3(vector.as_bytes()).is_ok());
        assert_eq!(
            super::super::RunResultProjection::from_json(vector.as_bytes()),
            Err(SdkError::ResultSchema)
        );
    }
}
