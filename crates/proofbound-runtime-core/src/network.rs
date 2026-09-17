use core::fmt;
use std::net::IpAddr;

use crate::{AuthorityPath, EnvironmentName};

/// Contains one validated lower-case ASCII DNS service name.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ServiceName(String);

impl ServiceName {
    /// Validates one DNS service name.
    pub fn new(value: impl Into<String>) -> Result<Self, NetworkAuthorityError> {
        let value = value.into();
        if value.is_empty() || value.len() > 253 || value.ends_with('.') {
            return Err(NetworkAuthorityError::InvalidServiceName);
        }
        if value.parse::<IpAddr>().is_ok()
            || value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b'.')
        {
            return Err(NetworkAuthorityError::ServiceNameIsAddress);
        }
        for label in value.split('.') {
            let bytes = label.as_bytes();
            if bytes.is_empty()
                || bytes.len() > 63
                || bytes.first() == Some(&b'-')
                || bytes.last() == Some(&b'-')
                || !bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
            {
                return Err(NetworkAuthorityError::InvalidServiceName);
            }
        }
        Ok(Self(value))
    }

    /// Returns the validated service name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Contains one nonzero TCP port.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TcpPort(u16);

impl TcpPort {
    /// Validates one TCP port.
    pub fn new(value: u16) -> Result<Self, NetworkAuthorityError> {
        if value == 0 {
            return Err(NetworkAuthorityError::ZeroTcpPort);
        }
        Ok(Self(value))
    }

    /// Returns the validated port.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Identifies one numeric resolver address.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ResolverAddress {
    /// Contains one IPv4 address in network-byte order.
    Ipv4([u8; 4]),
    /// Contains one IPv6 address in network-byte order.
    Ipv6([u8; 16]),
}

/// Contains one declared numeric resolver endpoint.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ResolverEndpoint {
    address: ResolverAddress,
    port: TcpPort,
}

impl ResolverEndpoint {
    /// Creates one declared resolver endpoint.
    #[must_use]
    pub const fn new(address: ResolverAddress, port: TcpPort) -> Self {
        Self { address, port }
    }

    /// Returns the numeric resolver address.
    #[must_use]
    pub const fn address(self) -> ResolverAddress {
        self.address
    }

    /// Returns the resolver TCP port.
    #[must_use]
    pub const fn port(self) -> TcpPort {
        self.port
    }
}

/// Selects the only address-attempt order in the first service profile.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AddressOrder {
    /// Tries canonical IPv4 answers before canonical IPv6 answers.
    Ipv4ThenIpv6Lexicographic,
}

/// Contains bounded resolver behavior for one service session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolutionPolicy {
    endpoint: ResolverEndpoint,
    configuration: AuthorityPath,
    maximum_cname_depth: u16,
    maximum_answer_count: u16,
    maximum_response_bytes: u64,
    resolution_deadline_ms: u64,
    attempt_deadline_ms: u64,
    address_order: AddressOrder,
}

impl ResolutionPolicy {
    /// Creates one complete bounded resolver policy.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: ResolverEndpoint,
        configuration: AuthorityPath,
        maximum_cname_depth: u16,
        maximum_answer_count: u16,
        maximum_response_bytes: u64,
        resolution_deadline_ms: u64,
        attempt_deadline_ms: u64,
        address_order: AddressOrder,
    ) -> Result<Self, NetworkAuthorityError> {
        if maximum_cname_depth == 0
            || maximum_answer_count == 0
            || maximum_response_bytes == 0
            || resolution_deadline_ms == 0
            || attempt_deadline_ms == 0
        {
            return Err(NetworkAuthorityError::ZeroResolverBound);
        }
        if attempt_deadline_ms > resolution_deadline_ms {
            return Err(NetworkAuthorityError::AttemptDeadlineExceedsResolution);
        }
        Ok(Self {
            endpoint,
            configuration,
            maximum_cname_depth,
            maximum_answer_count,
            maximum_response_bytes,
            resolution_deadline_ms,
            attempt_deadline_ms,
            address_order,
        })
    }

    /// Returns the declared resolver endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> ResolverEndpoint {
        self.endpoint
    }

    /// Returns the resolver-configuration path.
    #[must_use]
    pub const fn configuration(&self) -> &AuthorityPath {
        &self.configuration
    }

    /// Returns the maximum CNAME depth.
    #[must_use]
    pub const fn maximum_cname_depth(&self) -> u16 {
        self.maximum_cname_depth
    }

    /// Returns the maximum answer count.
    #[must_use]
    pub const fn maximum_answer_count(&self) -> u16 {
        self.maximum_answer_count
    }

    /// Returns the maximum DNS response size in bytes.
    #[must_use]
    pub const fn maximum_response_bytes(&self) -> u64 {
        self.maximum_response_bytes
    }

    /// Returns the total resolution deadline in milliseconds.
    #[must_use]
    pub const fn resolution_deadline_ms(&self) -> u64 {
        self.resolution_deadline_ms
    }

    /// Returns the per-attempt deadline in milliseconds.
    #[must_use]
    pub const fn attempt_deadline_ms(&self) -> u64 {
        self.attempt_deadline_ms
    }

    /// Returns the address-attempt order.
    #[must_use]
    pub const fn address_order(&self) -> AddressOrder {
        self.address_order
    }

    fn is_no_more_permissive_than(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint
            && self.configuration == other.configuration
            && self.address_order == other.address_order
            && self.maximum_cname_depth <= other.maximum_cname_depth
            && self.maximum_answer_count <= other.maximum_answer_count
            && self.maximum_response_bytes <= other.maximum_response_bytes
            && self.resolution_deadline_ms <= other.resolution_deadline_ms
            && self.attempt_deadline_ms <= other.attempt_deadline_ms
    }
}

/// Selects the minimum admitted TLS version.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MinimumTlsVersion {
    /// Requires TLS version 1.2 or later.
    Tls12,
    /// Requires TLS version 1.3.
    Tls13,
}

/// Identifies the required service-name verification rule.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ServiceNameVerification {
    /// Requires an exact DNS subject-alternative-name match.
    DnsSanExact,
}

/// Identifies the first profile's certificate-revocation behavior.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RevocationPolicy {
    /// Performs no revocation check and records that assumption.
    NotCheckedRecordedAssumption,
}

/// Contains the complete TLS policy for one service session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsPolicy {
    trust_root_set: AuthorityPath,
    minimum_version: MinimumTlsVersion,
    service_name_verification: ServiceNameVerification,
    revocation: RevocationPolicy,
}

impl TlsPolicy {
    /// Creates the first profile's TLS policy.
    #[must_use]
    pub const fn new(
        trust_root_set: AuthorityPath,
        minimum_version: MinimumTlsVersion,
        service_name_verification: ServiceNameVerification,
        revocation: RevocationPolicy,
    ) -> Self {
        Self {
            trust_root_set,
            minimum_version,
            service_name_verification,
            revocation,
        }
    }

    /// Returns the trust-root-set path.
    #[must_use]
    pub const fn trust_root_set(&self) -> &AuthorityPath {
        &self.trust_root_set
    }

    /// Returns the minimum TLS version.
    #[must_use]
    pub const fn minimum_version(&self) -> MinimumTlsVersion {
        self.minimum_version
    }

    /// Returns the service-name verification rule.
    #[must_use]
    pub const fn service_name_verification(&self) -> ServiceNameVerification {
        self.service_name_verification
    }

    /// Returns the revocation behavior.
    #[must_use]
    pub const fn revocation(&self) -> RevocationPolicy {
        self.revocation
    }
}

/// Contains all service-session limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSessionLimits {
    setup_time_ms: u64,
    session_time_ms: u64,
    child_to_service_bytes: u64,
    service_to_child_bytes: u64,
    dns_messages: u16,
    endpoint_attempts: u16,
    tls_handshake_bytes: u64,
}

impl ServiceSessionLimits {
    /// Creates one complete nonzero service-session limit set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        setup_time_ms: u64,
        session_time_ms: u64,
        child_to_service_bytes: u64,
        service_to_child_bytes: u64,
        dns_messages: u16,
        endpoint_attempts: u16,
        tls_handshake_bytes: u64,
        maximum_answer_count: u16,
    ) -> Result<Self, NetworkAuthorityError> {
        if setup_time_ms == 0
            || session_time_ms == 0
            || child_to_service_bytes == 0
            || service_to_child_bytes == 0
            || dns_messages == 0
            || endpoint_attempts == 0
            || tls_handshake_bytes == 0
        {
            return Err(NetworkAuthorityError::ZeroSessionBound);
        }
        if endpoint_attempts > maximum_answer_count {
            return Err(NetworkAuthorityError::AttemptCountExceedsAnswers);
        }
        Ok(Self {
            setup_time_ms,
            session_time_ms,
            child_to_service_bytes,
            service_to_child_bytes,
            dns_messages,
            endpoint_attempts,
            tls_handshake_bytes,
        })
    }

    /// Returns the setup-time limit in milliseconds.
    #[must_use]
    pub const fn setup_time_ms(self) -> u64 {
        self.setup_time_ms
    }

    /// Returns the session-time limit in milliseconds.
    #[must_use]
    pub const fn session_time_ms(self) -> u64 {
        self.session_time_ms
    }

    /// Returns the child-to-service byte limit.
    #[must_use]
    pub const fn child_to_service_bytes(self) -> u64 {
        self.child_to_service_bytes
    }

    /// Returns the service-to-child byte limit.
    #[must_use]
    pub const fn service_to_child_bytes(self) -> u64 {
        self.service_to_child_bytes
    }

    /// Returns the DNS message-count limit.
    #[must_use]
    pub const fn dns_messages(self) -> u16 {
        self.dns_messages
    }

    /// Returns the endpoint-attempt limit.
    #[must_use]
    pub const fn endpoint_attempts(self) -> u16 {
        self.endpoint_attempts
    }

    /// Returns the TLS handshake byte limit.
    #[must_use]
    pub const fn tls_handshake_bytes(self) -> u64 {
        self.tls_handshake_bytes
    }

    /// Reports whether every bound is no larger than another limit set.
    #[must_use]
    pub const fn is_no_more_permissive_than(self, other: Self) -> bool {
        self.setup_time_ms <= other.setup_time_ms
            && self.session_time_ms <= other.session_time_ms
            && self.child_to_service_bytes <= other.child_to_service_bytes
            && self.service_to_child_bytes <= other.service_to_child_bytes
            && self.dns_messages <= other.dns_messages
            && self.endpoint_attempts <= other.endpoint_attempts
            && self.tls_handshake_bytes <= other.tls_handshake_bytes
    }
}

/// Selects the local byte-channel protocol.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LocalChannelProtocol {
    /// Uses one private Unix stream socket pair.
    UnixStreamV1,
}

/// Contains the child descriptor reserved for the local channel.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ChildChannelDescriptor(u16);

impl ChildChannelDescriptor {
    /// Validates a non-standard-stream descriptor.
    pub fn new(value: u16) -> Result<Self, NetworkAuthorityError> {
        if value < 3 {
            return Err(NetworkAuthorityError::ReservedChildDescriptor);
        }
        Ok(Self(value))
    }

    /// Returns the descriptor number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Contains one stable credential-source identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CredentialSourceId(String);

impl CredentialSourceId {
    /// Validates one non-secret source identifier.
    pub fn new(value: impl Into<String>) -> Result<Self, NetworkAuthorityError> {
        let value = value.into();
        let bytes = value.as_bytes();
        if bytes.is_empty()
            || bytes.len() > 128
            || !bytes.first().is_some_and(|byte| byte.is_ascii_lowercase())
            || !bytes
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || !bytes.iter().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
            })
        {
            return Err(NetworkAuthorityError::InvalidCredentialSourceId);
        }
        Ok(Self(value))
    }

    /// Returns the non-secret source identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Identifies one optional credential source without retaining its value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialSource {
    id: CredentialSourceId,
    service: ServiceName,
    environment: EnvironmentName,
}

impl CredentialSource {
    /// Creates one service-bound credential-source descriptor.
    pub fn new(
        id: CredentialSourceId,
        service: ServiceName,
        environment: EnvironmentName,
        declared_service: &ServiceName,
    ) -> Result<Self, NetworkAuthorityError> {
        if &service != declared_service {
            return Err(NetworkAuthorityError::CredentialServiceMismatch);
        }
        Ok(Self {
            id,
            service,
            environment,
        })
    }

    /// Returns the source identifier.
    #[must_use]
    pub const fn id(&self) -> &CredentialSourceId {
        &self.id
    }

    /// Returns the bound service name.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// Returns the environment name that supplies the value.
    #[must_use]
    pub const fn environment(&self) -> &EnvironmentName {
        &self.environment
    }
}

/// Contains one complete authenticated-service-session authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedServiceSession {
    service: ServiceName,
    port: TcpPort,
    resolution: ResolutionPolicy,
    tls: TlsPolicy,
    limits: ServiceSessionLimits,
    connector_executable: AuthorityPath,
    connector_runtime_read: Vec<AuthorityPath>,
    local_channel: LocalChannelProtocol,
    child_descriptor: ChildChannelDescriptor,
    credential_source: Option<CredentialSource>,
}

impl AuthenticatedServiceSession {
    /// Creates one complete authenticated-service-session authority.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        service: ServiceName,
        port: TcpPort,
        resolution: ResolutionPolicy,
        tls: TlsPolicy,
        limits: ServiceSessionLimits,
        connector_executable: AuthorityPath,
        mut connector_runtime_read: Vec<AuthorityPath>,
        local_channel: LocalChannelProtocol,
        child_descriptor: ChildChannelDescriptor,
        credential_source: Option<CredentialSource>,
    ) -> Result<Self, NetworkAuthorityError> {
        if resolution.resolution_deadline_ms() > limits.setup_time_ms() {
            return Err(NetworkAuthorityError::ResolutionDeadlineExceedsSetup);
        }
        if credential_source
            .as_ref()
            .is_some_and(|source| source.service() != &service)
        {
            return Err(NetworkAuthorityError::CredentialServiceMismatch);
        }
        connector_runtime_read.sort();
        connector_runtime_read.dedup();
        Ok(Self {
            service,
            port,
            resolution,
            tls,
            limits,
            connector_executable,
            connector_runtime_read,
            local_channel,
            child_descriptor,
            credential_source,
        })
    }

    /// Returns the declared service name.
    #[must_use]
    pub const fn service(&self) -> &ServiceName {
        &self.service
    }

    /// Returns the declared service port.
    #[must_use]
    pub const fn port(&self) -> TcpPort {
        self.port
    }

    /// Returns the resolver policy.
    #[must_use]
    pub const fn resolution(&self) -> &ResolutionPolicy {
        &self.resolution
    }

    /// Returns the TLS policy.
    #[must_use]
    pub const fn tls(&self) -> &TlsPolicy {
        &self.tls
    }

    /// Returns the service-session limits.
    #[must_use]
    pub const fn limits(&self) -> ServiceSessionLimits {
        self.limits
    }

    /// Returns the connector executable path.
    #[must_use]
    pub const fn connector_executable(&self) -> &AuthorityPath {
        &self.connector_executable
    }

    /// Returns the connector runtime-read closure.
    #[must_use]
    pub fn connector_runtime_read(&self) -> &[AuthorityPath] {
        &self.connector_runtime_read
    }

    /// Returns the local-channel protocol.
    #[must_use]
    pub const fn local_channel(&self) -> LocalChannelProtocol {
        self.local_channel
    }

    /// Returns the reserved child descriptor.
    #[must_use]
    pub const fn child_descriptor(&self) -> ChildChannelDescriptor {
        self.child_descriptor
    }

    /// Returns the optional non-secret credential-source descriptor.
    #[must_use]
    pub fn credential_source(&self) -> Option<&CredentialSource> {
        self.credential_source.as_ref()
    }

    /// Reports whether this session grants no more authority than another.
    #[must_use]
    pub fn is_no_more_permissive_than(&self, other: &Self) -> bool {
        self.service == other.service
            && self.port == other.port
            && self
                .resolution
                .is_no_more_permissive_than(&other.resolution)
            && self.tls == other.tls
            && self.limits.is_no_more_permissive_than(other.limits)
            && self.connector_executable == other.connector_executable
            && self
                .connector_runtime_read
                .iter()
                .all(|path| other.connector_runtime_read.contains(path))
            && self.local_channel == other.local_channel
            && self.child_descriptor == other.child_descriptor
            && self.credential_source == other.credential_source
    }
}

/// Identifies invalid network-authority input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkAuthorityError {
    /// The service name is not one canonical lower-case ASCII DNS name.
    InvalidServiceName,
    /// The service name is a numeric IP address.
    ServiceNameIsAddress,
    /// The TCP port is zero.
    ZeroTcpPort,
    /// A resolver bound is zero.
    ZeroResolverBound,
    /// The per-attempt deadline exceeds the resolution deadline.
    AttemptDeadlineExceedsResolution,
    /// The total resolution deadline exceeds the service setup deadline.
    ResolutionDeadlineExceedsSetup,
    /// A service-session bound is zero.
    ZeroSessionBound,
    /// The endpoint-attempt limit exceeds the DNS answer limit.
    AttemptCountExceedsAnswers,
    /// The local-channel descriptor overlaps a standard stream.
    ReservedChildDescriptor,
    /// The credential-source identifier is invalid.
    InvalidCredentialSourceId,
    /// The credential source is bound to another service.
    CredentialServiceMismatch,
}

impl NetworkAuthorityError {
    /// Returns the stable machine code for this error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidServiceName => "plan.authority.network.service-name.invalid",
            Self::ServiceNameIsAddress => "plan.authority.network.service-name.address",
            Self::ZeroTcpPort => "plan.authority.network.service-port.zero",
            Self::ZeroResolverBound => "plan.authority.network.resolver.bound.zero",
            Self::AttemptDeadlineExceedsResolution => {
                "plan.authority.network.resolver.attempt-deadline.exceeds-resolution"
            }
            Self::ResolutionDeadlineExceedsSetup => {
                "plan.authority.network.resolver.deadline.exceeds-setup"
            }
            Self::ZeroSessionBound => "plan.authority.network.session.bound.zero",
            Self::AttemptCountExceedsAnswers => {
                "plan.authority.network.session.attempts.exceed-answers"
            }
            Self::ReservedChildDescriptor => "plan.authority.network.channel.descriptor.reserved",
            Self::InvalidCredentialSourceId => {
                "plan.authority.network.credential-source.id.invalid"
            }
            Self::CredentialServiceMismatch => {
                "plan.authority.network.credential-source.service-mismatch"
            }
        }
    }
}

impl fmt::Display for NetworkAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for NetworkAuthorityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_are_canonical_dns_names() {
        assert_eq!(
            ServiceName::new("api.example.com")
                .expect("fixture is valid")
                .as_str(),
            "api.example.com"
        );
        for invalid in [
            "",
            "API.example.com",
            "api.example.com.",
            "-api.example.com",
            "api-.example.com",
            "127.0.0.1",
            "001.002.003.004",
            "::1",
        ] {
            assert!(ServiceName::new(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn limits_only_get_smaller() {
        let narrow =
            ServiceSessionLimits::new(1, 1, 1, 1, 1, 1, 1, 2).expect("fixture limits are valid");
        let broad =
            ServiceSessionLimits::new(2, 2, 2, 2, 2, 2, 2, 2).expect("fixture limits are valid");
        assert!(narrow.is_no_more_permissive_than(broad));
        assert!(!broad.is_no_more_permissive_than(narrow));
    }
}
