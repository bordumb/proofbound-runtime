use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{NetworkSupportPath, ResolutionPolicy, TcpPort};

/// Identifies a rejected declared egress authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressError {
    EndpointCount,
    EndpointConflict,
    NameInvalid,
    AddressInvalid,
    SniMismatch,
    ScopeConflict,
    LimitRange,
    ResolverBound,
    ProxyEnvironmentInvalid,
    ProxyEnvironmentConflict,
}

impl EgressError {
    /// Returns the stable plan error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EndpointCount => "plan.authority.network.egress.endpoint-count",
            Self::EndpointConflict => "plan.authority.network.egress.endpoint-conflict",
            Self::NameInvalid => "plan.authority.network.egress.name-invalid",
            Self::AddressInvalid => "plan.authority.network.egress.address-invalid",
            Self::SniMismatch => "plan.authority.network.egress.sni-mismatch",
            Self::ScopeConflict => "plan.authority.network.egress.scope-conflict",
            Self::LimitRange => "plan.authority.network.egress.limit-range",
            Self::ResolverBound => "plan.authority.network.egress.resolver-bound",
            Self::ProxyEnvironmentInvalid => {
                "plan.authority.network.egress.proxy-environment-invalid"
            }
            Self::ProxyEnvironmentConflict => {
                "plan.authority.network.egress.proxy-environment-conflict"
            }
        }
    }
}

/// Contains one lower-case ASCII DNS name with at least two labels.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EgressName(String);

impl EgressName {
    /// Validates the exact name grammar of Specification 0017.
    pub fn new(value: impl Into<String>) -> Result<Self, EgressError> {
        let value = value.into();
        if value.is_empty() || value.len() > 253 || value.ends_with('.') {
            return Err(EgressError::NameInvalid);
        }
        let labels: Vec<&str> = value.split('.').collect();
        if labels.len() < 2
            || labels
                .last()
                .is_some_and(|label| label.bytes().all(|b| b.is_ascii_digit()))
            || labels.iter().any(|label| {
                let b = label.as_bytes();
                b.is_empty()
                    || b.len() > 63
                    || b[0] == b'-'
                    || b[b.len() - 1] == b'-'
                    || !b
                        .iter()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
            })
        {
            return Err(EgressError::NameInvalid);
        }
        Ok(Self(value))
    }

    /// Returns the canonical name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Selects which DNS answer classes a named endpoint permits.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AddressScope {
    Global,
    GlobalOrPrivate,
}

/// Identifies one declared destination.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EgressDestination {
    DnsName {
        name: EgressName,
        scope: AddressScope,
    },
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

impl EgressDestination {
    /// Rejects numeric destinations that cannot identify a permitted peer.
    pub fn validate(&self) -> Result<(), EgressError> {
        match self {
            Self::DnsName { .. } => Ok(()),
            Self::Ipv4(b) => {
                let a = Ipv4Addr::from(*b);
                if a.is_unspecified() || a.is_multicast() || *b == [255; 4] {
                    Err(EgressError::AddressInvalid)
                } else {
                    Ok(())
                }
            }
            Self::Ipv6(b) => {
                let a = Ipv6Addr::from(*b);
                if a.is_unspecified()
                    || a.is_multicast()
                    || a.to_ipv4_mapped().is_some()
                    || (b[..12] == [0; 12] && !a.is_loopback())
                {
                    Err(EgressError::AddressInvalid)
                } else {
                    Ok(())
                }
            }
        }
    }
}

/// States whether the proxy must compare the first ClientHello name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SniBinding {
    NotInspected,
    Required(EgressName),
}

/// Contains one exact declared TCP destination.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct EgressEndpoint {
    pub destination: EgressDestination,
    pub port: TcpPort,
    pub tls_sni: SniBinding,
}

/// Bounds proxy work and retained observations for one execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressLimits {
    pub connections: u16,
    pub concurrent_connections: u16,
    pub attempts_per_connection: u8,
    pub resolutions: u16,
    pub dns_messages: u16,
    pub client_to_remote_bytes: u64,
    pub remote_to_client_bytes: u64,
    pub connection_idle_ms: u32,
}

impl EgressLimits {
    /// Validates every Specification 0017 limit.
    pub fn validate(self) -> Result<(), EgressError> {
        if !(1..=8192).contains(&self.connections)
            || !(1..=512).contains(&self.concurrent_connections)
            || !(1..=4).contains(&self.attempts_per_connection)
            || !(1..=1024).contains(&self.resolutions)
            || !(2..=8192).contains(&self.dns_messages)
            || !(1..=1_u64 << 40).contains(&self.client_to_remote_bytes)
            || !(1..=1_u64 << 40).contains(&self.remote_to_client_bytes)
            || !(1..=3_600_000).contains(&self.connection_idle_ms)
        {
            return Err(EgressError::LimitRange);
        }
        Ok(())
    }

    /// Compares every bound with a reference.
    #[must_use]
    pub const fn is_no_more_permissive_than(self, r: Self) -> bool {
        self.connections <= r.connections
            && self.concurrent_connections <= r.concurrent_connections
            && self.attempts_per_connection <= r.attempts_per_connection
            && self.resolutions <= r.resolutions
            && self.dns_messages <= r.dns_messages
            && self.client_to_remote_bytes <= r.client_to_remote_bytes
            && self.remote_to_client_bytes <= r.remote_to_client_bytes
            && self.connection_idle_ms <= r.connection_idle_ms
    }
}

/// Names one variable that the Runtime sets to the proxy URL.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProxyVariable {
    AllProxy,
    AllProxyLower,
    HttpProxy,
    HttpProxyLower,
    HttpsProxy,
    HttpsProxyLower,
}

impl ProxyVariable {
    /// Returns the exact variable name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllProxy => "ALL_PROXY",
            Self::AllProxyLower => "all_proxy",
            Self::HttpProxy => "HTTP_PROXY",
            Self::HttpProxyLower => "http_proxy",
            Self::HttpsProxy => "HTTPS_PROXY",
            Self::HttpsProxyLower => "https_proxy",
        }
    }
}

/// Contains normalized proposed egress authority. It does not authorize execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressAuthority {
    endpoints: Vec<EgressEndpoint>,
    resolver: ResolutionPolicy,
    limits: EgressLimits,
    proxy_executable: NetworkSupportPath,
    proxy_runtime_read: Vec<NetworkSupportPath>,
    proxy_environment: Vec<ProxyVariable>,
}

impl EgressAuthority {
    /// Validates and normalizes all authority fields.
    pub fn new(
        mut endpoints: Vec<EgressEndpoint>,
        resolver: ResolutionPolicy,
        limits: EgressLimits,
        proxy_executable: NetworkSupportPath,
        mut proxy_runtime_read: Vec<NetworkSupportPath>,
        proxy_environment: Vec<ProxyVariable>,
        child_environment: &[String],
    ) -> Result<Self, EgressError> {
        if endpoints.is_empty() || endpoints.len() > 256 {
            return Err(EgressError::EndpointCount);
        }
        limits.validate()?;
        if resolver.maximum_cname_depth() > 4
            || resolver.maximum_answer_count() > 16
            || resolver.maximum_response_bytes() > 65_535
            || resolver.resolution_deadline_ms() > 60_000
            || u16::from(limits.attempts_per_connection) > resolver.maximum_answer_count()
        {
            return Err(EgressError::ResolverBound);
        }
        if proxy_environment.is_empty()
            || proxy_environment.len() > 6
            || !proxy_environment
                .windows(2)
                .all(|w| w[0].as_str() < w[1].as_str())
        {
            return Err(EgressError::ProxyEnvironmentInvalid);
        }
        if child_environment.iter().any(|n| {
            matches!(
                n.to_ascii_uppercase().as_str(),
                "HTTP_PROXY" | "HTTPS_PROXY" | "ALL_PROXY" | "NO_PROXY"
            )
        }) {
            return Err(EgressError::ProxyEnvironmentConflict);
        }
        endpoints.sort();
        endpoints.dedup();
        for endpoint in &endpoints {
            endpoint.destination.validate()?;
            if let (EgressDestination::DnsName { name, .. }, SniBinding::Required(sni)) =
                (&endpoint.destination, &endpoint.tls_sni)
                && name != sni
            {
                return Err(EgressError::SniMismatch);
            }
        }
        for (i, left) in endpoints.iter().enumerate() {
            for right in &endpoints[i + 1..] {
                if left.destination == right.destination && left.port == right.port {
                    return Err(EgressError::EndpointConflict);
                }
                if let (
                    EgressDestination::DnsName { name: a, scope: sa },
                    EgressDestination::DnsName { name: b, scope: sb },
                ) = (&left.destination, &right.destination)
                    && a == b
                    && sa != sb
                {
                    return Err(EgressError::ScopeConflict);
                }
            }
        }
        proxy_runtime_read.sort();
        proxy_runtime_read.dedup();
        Ok(Self {
            endpoints,
            resolver,
            limits,
            proxy_executable,
            proxy_runtime_read,
            proxy_environment,
        })
    }

    #[must_use]
    pub fn endpoints(&self) -> &[EgressEndpoint] {
        &self.endpoints
    }
    #[must_use]
    pub const fn resolver(&self) -> &ResolutionPolicy {
        &self.resolver
    }
    #[must_use]
    pub const fn limits(&self) -> EgressLimits {
        self.limits
    }
    #[must_use]
    pub const fn proxy_executable(&self) -> &NetworkSupportPath {
        &self.proxy_executable
    }
    #[must_use]
    pub fn proxy_runtime_read(&self) -> &[NetworkSupportPath] {
        &self.proxy_runtime_read
    }
    #[must_use]
    pub fn proxy_environment(&self) -> &[ProxyVariable] {
        &self.proxy_environment
    }

    /// Compares all authority fields without resolving a name.
    #[must_use]
    pub fn is_no_more_permissive_than(&self, r: &Self) -> bool {
        self.endpoints.iter().all(|e| r.endpoints.contains(e))
            && self.resolver == r.resolver
            && self.proxy_executable == r.proxy_executable
            && self
                .proxy_runtime_read
                .iter()
                .all(|p| r.proxy_runtime_read.contains(p))
            && self
                .proxy_environment
                .iter()
                .all(|p| r.proxy_environment.contains(p))
            && self.limits.is_no_more_permissive_than(r.limits)
    }
}

/// Describes the fixed child listener without granting a remote address.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressListener {
    pub address: [u8; 4],
    pub port: u16,
    pub backlog: u16,
}

/// Contains the pure network roles of a proposed version 3 policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledEgressPolicy {
    pub network: &'static str,
    pub child_network: &'static str,
    pub listener: EgressListener,
    pub egress: EgressAuthority,
    pub child_landlock_connect_port: u16,
    pub proxy_landlock_connect_ports: Vec<u16>,
    pub address_classes: &'static str,
}

impl CompiledEgressPolicy {
    /// Reports whether the compiled policy adds no modeled network authority.
    #[must_use]
    pub fn is_no_more_permissive_than(&self, authority: &EgressAuthority) -> bool {
        self.network == "deny-network-v1"
            && self.child_network == "egress-namespace-v1"
            && self.listener
                == EgressListener {
                    address: [127, 0, 0, 1],
                    port: 3128,
                    backlog: 128,
                }
            && self.child_landlock_connect_port == 3128
            && self.address_classes == "address-class-table-v1"
            && self.egress.is_no_more_permissive_than(authority)
            && self.proxy_landlock_connect_ports == declared_ports(authority)
    }
}

fn declared_ports(authority: &EgressAuthority) -> Vec<u16> {
    let mut ports: Vec<u16> = authority.endpoints.iter().map(|e| e.port.get()).collect();
    ports.push(authority.resolver.endpoint().port().get());
    ports.sort_unstable();
    ports.dedup();
    ports
}

/// Compiles a proposed policy model without enabling execution.
#[must_use]
pub fn compile_egress_policy(authority: &EgressAuthority) -> CompiledEgressPolicy {
    CompiledEgressPolicy {
        network: "deny-network-v1",
        child_network: "egress-namespace-v1",
        listener: EgressListener {
            address: [127, 0, 0, 1],
            port: 3128,
            backlog: 128,
        },
        egress: authority.clone(),
        child_landlock_connect_port: 3128,
        proxy_landlock_connect_ports: declared_ports(authority),
        address_classes: "address-class-table-v1",
    }
}

/// Classifies a DNS answer under the fixed Specification 0017 table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressClass {
    Special,
    Private,
    Global,
}

/// Classifies one answer without consulting host routing.
#[must_use]
pub fn classify_answer(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(a) => {
            let b = a.octets();
            if b[0] == 0
                || b[0] == 127
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2))
                || (b[0] == 198 && (b[1] == 18 || b[1] == 19))
                || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                || (b[0] == 203 && b[1] == 0 && b[2] == 113)
                || b[0] >= 224
            {
                AddressClass::Special
            } else if b[0] == 10
                || (b[0] == 100 && (64..=127).contains(&b[1]))
                || (b[0] == 172 && (16..=31).contains(&b[1]))
                || (b[0] == 192 && b[1] == 168)
            {
                AddressClass::Private
            } else {
                AddressClass::Global
            }
        }
        IpAddr::V6(a) => {
            let b = a.octets();
            if a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || a.to_ipv4_mapped().is_some()
                || (b[..4] == [0x00, 0x64, 0xff, 0x9b] && b[4..12] == [0; 8])
                || (b[0] == 0x01 && b[1..8] == [0; 7])
                || (b[0] == 0x20 && b[1] == 0x01 && b[2] <= 0x01)
                || b[..4] == [0x20, 0x01, 0x0d, 0xb8]
                || (b[0] == 0xfe && b[1] & 0xc0 == 0x80)
            {
                AddressClass::Special
            } else if b[0] & 0xfe == 0xfc {
                AddressClass::Private
            } else {
                AddressClass::Global
            }
        }
    }
}

/// Reports whether the named endpoint may use an answer.
#[must_use]
pub fn answer_is_admissible(address: IpAddr, scope: AddressScope) -> bool {
    match classify_answer(address) {
        AddressClass::Special => false,
        AddressClass::Private => scope == AddressScope::GlobalOrPrivate,
        AddressClass::Global => true,
    }
}

/// Names the target supplied by one canonical CONNECT request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelTarget {
    DnsName(EgressName),
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
}

/// Records one answer and its effective expiry in milliseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedAnswer {
    pub address: IpAddr,
    pub effective_expiry_ms: u64,
}

/// Contains one proxy-owned resolution for a declared name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinnedResolution {
    pub name: EgressName,
    pub answers: Vec<PinnedAnswer>,
    pub triggering_connection: u64,
}

/// Lists the possible pure tunnel decisions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TunnelDecision {
    Denied(TunnelDenial),
    NeedsResolution {
        endpoint_index: usize,
    },
    Attempts {
        endpoint_index: usize,
        addresses: Vec<IpAddr>,
    },
}

/// Identifies a rejected tunnel request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelDenial {
    Undeclared,
    SniDenied,
    ResolutionMismatch,
    NoAdmissibleAnswer,
}

/// Selects only declared endpoints and admissible address attempts.
///
/// The caller must validate the CONNECT head and ClientHello before this call.
/// A missing resolution authorizes a lookup only for a declared name.
#[must_use]
pub fn decide_tunnel(
    authority: &EgressAuthority,
    connection_id: u64,
    target: &TunnelTarget,
    port: TcpPort,
    client_hello_sni: Option<&EgressName>,
    resolution: Option<&PinnedResolution>,
    attempt_start_ms: u64,
) -> TunnelDecision {
    let endpoint = authority
        .endpoints
        .iter()
        .enumerate()
        .find(|(_, endpoint)| {
            endpoint.port == port
                && match (&endpoint.destination, target) {
                    (EgressDestination::DnsName { name, .. }, TunnelTarget::DnsName(request)) => {
                        name == request
                    }
                    (EgressDestination::Ipv4(a), TunnelTarget::Ipv4(b)) => a == b,
                    (EgressDestination::Ipv6(a), TunnelTarget::Ipv6(b)) => a == b,
                    _ => false,
                }
        });
    let Some((index, endpoint)) = endpoint else {
        return TunnelDecision::Denied(TunnelDenial::Undeclared);
    };
    if let SniBinding::Required(expected) = &endpoint.tls_sni
        && client_hello_sni != Some(expected)
    {
        return TunnelDecision::Denied(TunnelDenial::SniDenied);
    }
    match &endpoint.destination {
        EgressDestination::Ipv4(bytes) => TunnelDecision::Attempts {
            endpoint_index: index,
            addresses: vec![IpAddr::V4(Ipv4Addr::from(*bytes))],
        },
        EgressDestination::Ipv6(bytes) => TunnelDecision::Attempts {
            endpoint_index: index,
            addresses: vec![IpAddr::V6(Ipv6Addr::from(*bytes))],
        },
        EgressDestination::DnsName { name, scope } => {
            let Some(resolution) = resolution else {
                return TunnelDecision::NeedsResolution {
                    endpoint_index: index,
                };
            };
            if resolution.name != *name {
                return TunnelDecision::Denied(TunnelDenial::ResolutionMismatch);
            }
            if resolution.answers.len() > usize::from(authority.resolver.maximum_answer_count()) {
                return TunnelDecision::Denied(TunnelDenial::ResolutionMismatch);
            }
            let mut addresses: Vec<IpAddr> = resolution
                .answers
                .iter()
                .filter(|answer| {
                    answer_is_admissible(answer.address, *scope)
                        && (resolution.triggering_connection == connection_id
                            || attempt_start_ms <= answer.effective_expiry_ms)
                })
                .map(|answer| answer.address)
                .collect();
            addresses.sort_by_key(|address| match address {
                IpAddr::V4(a) => (0, a.octets().to_vec()),
                IpAddr::V6(a) => (1, a.octets().to_vec()),
            });
            addresses.dedup();
            addresses.truncate(usize::from(authority.limits.attempts_per_connection));
            if addresses.is_empty() {
                TunnelDecision::Denied(TunnelDenial::NoAdmissibleAnswer)
            } else {
                TunnelDecision::Attempts {
                    endpoint_index: index,
                    addresses,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressOrder, ResolverAddress, ResolverEndpoint};

    fn authority() -> EgressAuthority {
        let endpoint = EgressEndpoint {
            destination: EgressDestination::DnsName {
                name: EgressName::new("api.example").unwrap(),
                scope: AddressScope::Global,
            },
            port: TcpPort::new(443).unwrap(),
            tls_sni: SniBinding::Required(EgressName::new("api.example").unwrap()),
        };
        let resolver = ResolutionPolicy::new(
            ResolverEndpoint::new(
                ResolverAddress::Ipv4([8, 8, 8, 8]),
                TcpPort::new(53).unwrap(),
            ),
            NetworkSupportPath::new("/etc/resolv.conf").unwrap(),
            4,
            16,
            65_535,
            60_000,
            10_000,
            AddressOrder::Ipv4ThenIpv6Lexicographic,
        )
        .unwrap();
        EgressAuthority::new(
            vec![endpoint],
            resolver,
            EgressLimits {
                connections: 10,
                concurrent_connections: 2,
                attempts_per_connection: 2,
                resolutions: 10,
                dns_messages: 20,
                client_to_remote_bytes: 100,
                remote_to_client_bytes: 100,
                connection_idle_ms: 1000,
            },
            NetworkSupportPath::new("/usr/bin/pbr-egress-proxy").unwrap(),
            vec![],
            vec![ProxyVariable::HttpsProxy],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn names_and_answer_classes_reject_bypass_inputs() {
        for name in [
            "localhost",
            "EXAMPLE.com",
            "example.42",
            "*.example",
            "-x.example",
            "example.",
            "192.0.2.1",
        ] {
            assert_eq!(EgressName::new(name), Err(EgressError::NameInvalid));
        }
        for address in [
            "127.0.0.1",
            "169.254.1.1",
            "192.0.2.1",
            "2001:db8::1",
            "64:ff9b::1",
            "::1",
        ] {
            assert_eq!(
                classify_answer(address.parse().unwrap()),
                AddressClass::Special
            );
        }
        assert!(!answer_is_admissible(
            "10.0.0.1".parse().unwrap(),
            AddressScope::Global
        ));
        assert!(answer_is_admissible(
            "10.0.0.1".parse().unwrap(),
            AddressScope::GlobalOrPrivate
        ));
        assert_eq!(
            EgressDestination::Ipv6(Ipv6Addr::LOCALHOST.octets()).validate(),
            Ok(())
        );
        assert_eq!(
            EgressDestination::Ipv6("::2".parse::<Ipv6Addr>().unwrap().octets()).validate(),
            Err(EgressError::AddressInvalid)
        );
    }

    #[test]
    fn tunnel_decision_never_resolves_undeclared_name() {
        let authority = authority();
        let other = TunnelTarget::DnsName(EgressName::new("other.example").unwrap());
        assert_eq!(
            decide_tunnel(
                &authority,
                1,
                &other,
                TcpPort::new(443).unwrap(),
                None,
                None,
                0
            ),
            TunnelDecision::Denied(TunnelDenial::Undeclared)
        );
        let declared = TunnelTarget::DnsName(EgressName::new("api.example").unwrap());
        assert_eq!(
            decide_tunnel(
                &authority,
                1,
                &declared,
                TcpPort::new(443).unwrap(),
                None,
                None,
                0
            ),
            TunnelDecision::Denied(TunnelDenial::SniDenied)
        );
        let sni = EgressName::new("api.example").unwrap();
        assert_eq!(
            decide_tunnel(
                &authority,
                1,
                &declared,
                TcpPort::new(443).unwrap(),
                Some(&sni),
                None,
                0
            ),
            TunnelDecision::NeedsResolution { endpoint_index: 0 }
        );
    }

    #[test]
    fn tunnel_decision_filters_special_and_expired_answers() {
        let authority = authority();
        let name = EgressName::new("api.example").unwrap();
        let target = TunnelTarget::DnsName(name.clone());
        let resolution = PinnedResolution {
            name: name.clone(),
            triggering_connection: 2,
            answers: vec![
                PinnedAnswer {
                    address: "127.0.0.1".parse().unwrap(),
                    effective_expiry_ms: 100,
                },
                PinnedAnswer {
                    address: "8.8.8.8".parse().unwrap(),
                    effective_expiry_ms: 10,
                },
                PinnedAnswer {
                    address: "1.1.1.1".parse().unwrap(),
                    effective_expiry_ms: 100,
                },
            ],
        };
        assert_eq!(
            decide_tunnel(
                &authority,
                1,
                &target,
                TcpPort::new(443).unwrap(),
                Some(&name),
                Some(&resolution),
                20
            ),
            TunnelDecision::Attempts {
                endpoint_index: 0,
                addresses: vec!["1.1.1.1".parse().unwrap()]
            }
        );
    }

    #[test]
    fn zero_ttl_is_usable_only_by_the_triggering_connection() {
        let authority = authority();
        let name = EgressName::new("api.example").unwrap();
        let target = TunnelTarget::DnsName(name.clone());
        let resolution = PinnedResolution {
            name: name.clone(),
            triggering_connection: 7,
            answers: vec![PinnedAnswer {
                address: "8.8.8.8".parse().unwrap(),
                effective_expiry_ms: 0,
            }],
        };
        assert_eq!(
            decide_tunnel(
                &authority,
                7,
                &target,
                TcpPort::new(443).unwrap(),
                Some(&name),
                Some(&resolution),
                10,
            ),
            TunnelDecision::Attempts {
                endpoint_index: 0,
                addresses: vec!["8.8.8.8".parse().unwrap()],
            }
        );
        assert_eq!(
            decide_tunnel(
                &authority,
                8,
                &target,
                TcpPort::new(443).unwrap(),
                Some(&name),
                Some(&resolution),
                10,
            ),
            TunnelDecision::Denied(TunnelDenial::NoAdmissibleAnswer)
        );
    }

    #[test]
    fn endpoint_conflicts_and_scope_changes_fail_validation() {
        let base = authority();
        let endpoint = base.endpoints()[0].clone();
        let make = |endpoints| {
            EgressAuthority::new(
                endpoints,
                base.resolver().clone(),
                base.limits(),
                base.proxy_executable().clone(),
                base.proxy_runtime_read().to_vec(),
                base.proxy_environment().to_vec(),
                &[],
            )
        };
        let duplicate = make(vec![endpoint.clone(), endpoint.clone()]).unwrap();
        assert_eq!(duplicate.endpoints().len(), 1);

        let mut different_sni = endpoint.clone();
        different_sni.tls_sni = SniBinding::NotInspected;
        assert_eq!(
            make(vec![endpoint.clone(), different_sni]),
            Err(EgressError::EndpointConflict)
        );

        let mut different_scope = endpoint.clone();
        different_scope.destination = EgressDestination::DnsName {
            name: EgressName::new("api.example").unwrap(),
            scope: AddressScope::GlobalOrPrivate,
        };
        different_scope.port = TcpPort::new(8443).unwrap();
        assert_eq!(
            make(vec![endpoint, different_scope]),
            Err(EgressError::ScopeConflict)
        );
    }

    #[test]
    fn authority_subset_keeps_resolver_and_proxy_identity() {
        let base = authority();
        assert!(base.is_no_more_permissive_than(&base));
        let compiled = compile_egress_policy(&base);
        assert!(compiled.is_no_more_permissive_than(&base));
        assert_eq!(compiled.proxy_landlock_connect_ports, vec![53, 443]);
        let mut other = base.clone();
        other.proxy_executable = NetworkSupportPath::new("/tmp/proxy").unwrap();
        assert!(!other.is_no_more_permissive_than(&base));
        other = base.clone();
        other.limits.connections += 1;
        assert!(!other.is_no_more_permissive_than(&base));
    }
}
