use core::fmt;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use proofbound_runtime_core::{
    MinimumTlsVersion, ServiceName, ServiceSessionLimits, Sha256Digest, TlsPolicy,
};
use rustls::client::{ClientConfig, ClientConnection, Resumption};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject as _};
use rustls::{HandshakeKind, ProtocolVersion, RootCertStore, StreamOwned};
use sha2::{Digest as _, Sha256};

use crate::{DnsAnswer, DnsResolution};

const TLS_IMPLEMENTATION: &[u8] = b"rustls/0.23.45/ring";
const PROXY_BUFFER_BYTES: usize = 16 * 1024;
const PROXY_IDLE_SLEEP: Duration = Duration::from_millis(1);

/// Identifies the result of one ordered TCP endpoint attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointAttemptResult {
    /// The remote endpoint refused the connection.
    Refused,
    /// The endpoint attempt reached its monotonic deadline.
    TimedOut,
    /// The endpoint attempt failed for another input/output reason.
    Failed,
    /// The endpoint accepted the one selected TCP connection.
    Connected,
}

/// Records one canonical endpoint attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointAttempt {
    ordinal: u32,
    endpoint: SocketAddr,
    result: EndpointAttemptResult,
    started_ns: u64,
    finished_ns: u64,
}

impl EndpointAttempt {
    /// Returns the one-based attempt ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the attempted endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    /// Returns the closed attempt result.
    #[must_use]
    pub const fn result(&self) -> EndpointAttemptResult {
        self.result
    }

    /// Returns the connector-relative monotonic start time.
    #[must_use]
    pub const fn started_ns(&self) -> u64 {
        self.started_ns
    }

    /// Returns the connector-relative monotonic finish time.
    #[must_use]
    pub const fn finished_ns(&self) -> u64 {
        self.finished_ns
    }
}

/// Identifies the negotiated TLS protocol version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsVersion {
    /// TLS version 1.2.
    Tls12,
    /// TLS version 1.3.
    Tls13,
}

/// Records the authenticated TLS facts without retaining certificate bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsObservation {
    implementation_identity: Sha256Digest,
    version: TlsVersion,
    certificate_chain_identity: Sha256Digest,
    handshake_bytes: u64,
    authenticated_ns: u64,
}

impl TlsObservation {
    /// Returns the logical TLS implementation identity.
    #[must_use]
    pub const fn implementation_identity(&self) -> Sha256Digest {
        self.implementation_identity
    }

    /// Returns the negotiated TLS version.
    #[must_use]
    pub const fn version(&self) -> TlsVersion {
        self.version
    }

    /// Returns the length-delimited peer-certificate-chain identity.
    #[must_use]
    pub const fn certificate_chain_identity(&self) -> Sha256Digest {
        self.certificate_chain_identity
    }

    /// Returns total TLS handshake bytes in both directions.
    #[must_use]
    pub const fn handshake_bytes(&self) -> u64 {
        self.handshake_bytes
    }

    /// Returns the connector-relative authentication time.
    #[must_use]
    pub const fn authenticated_ns(&self) -> u64 {
        self.authenticated_ns
    }
}

/// Owns one authenticated TLS session and its plaintext bounds.
pub struct AuthenticatedTlsSession {
    stream: StreamOwned<ClientConnection, MeteredTcpStream>,
    selected_answer: DnsAnswer,
    attempts: Vec<EndpointAttempt>,
    observation: TlsObservation,
    active_at: Instant,
    session_limit: Duration,
    child_to_service_limit: u64,
    service_to_child_limit: u64,
    child_to_service_bytes: u64,
    service_to_child_bytes: u64,
}

impl AuthenticatedTlsSession {
    /// Returns the selected, unexpired DNS answer.
    #[must_use]
    pub const fn selected_answer(&self) -> &DnsAnswer {
        &self.selected_answer
    }

    /// Returns every canonical endpoint attempt in order.
    #[must_use]
    pub fn attempts(&self) -> &[EndpointAttempt] {
        &self.attempts
    }

    /// Returns the authenticated TLS observation.
    #[must_use]
    pub const fn observation(&self) -> &TlsObservation {
        &self.observation
    }

    /// Returns the accepted child-to-service plaintext byte count.
    #[must_use]
    pub const fn child_to_service_bytes(&self) -> u64 {
        self.child_to_service_bytes
    }

    /// Returns the delivered service-to-child plaintext byte count.
    #[must_use]
    pub const fn service_to_child_bytes(&self) -> u64 {
        self.service_to_child_bytes
    }

    /// Writes bounded opaque application bytes to the authenticated service.
    pub fn write_application(&mut self, bytes: &[u8]) -> Result<usize, TlsError> {
        self.require_active()?;
        let remaining = self
            .child_to_service_limit
            .checked_sub(self.child_to_service_bytes)
            .ok_or(TlsError::ChildToServiceLimit)?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if remaining == 0 {
            return Err(TlsError::ChildToServiceLimit);
        }
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > remaining {
            return Err(TlsError::ChildToServiceLimit);
        }
        let written = self.stream.write(bytes).map_err(map_session_io)?;
        self.child_to_service_bytes = self
            .child_to_service_bytes
            .checked_add(u64::try_from(written).map_err(|_| TlsError::ChildToServiceLimit)?)
            .ok_or(TlsError::ChildToServiceLimit)?;
        Ok(written)
    }

    /// Reads bounded opaque application bytes from the authenticated service.
    pub fn read_application(&mut self, output: &mut [u8]) -> Result<usize, TlsError> {
        self.require_active()?;
        let remaining = self
            .service_to_child_limit
            .checked_sub(self.service_to_child_bytes)
            .ok_or(TlsError::ServiceToChildLimit)?;
        if output.is_empty() {
            return Ok(0);
        }
        if remaining == 0 {
            let mut excess = [0_u8; 1];
            return match self.stream.read(&mut excess).map_err(map_session_io)? {
                0 => Ok(0),
                _ => Err(TlsError::ServiceToChildLimit),
            };
        }
        let permitted = output
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let read = self
            .stream
            .read(&mut output[..permitted])
            .map_err(map_session_io)?;
        self.service_to_child_bytes = self
            .service_to_child_bytes
            .checked_add(u64::try_from(read).map_err(|_| TlsError::ServiceToChildLimit)?)
            .ok_or(TlsError::ServiceToChildLimit)?;
        Ok(read)
    }

    /// Sends one TLS close notification for terminal shutdown.
    pub fn close_notify(&mut self) -> Result<(), TlsError> {
        self.stream.conn.send_close_notify();
        self.stream.flush().map_err(map_session_io)
    }

    fn require_active(&self) -> Result<(), TlsError> {
        if self.active_at.elapsed() >= self.session_limit {
            Err(TlsError::SessionDeadline)
        } else {
            Ok(())
        }
    }
}

/// Records bounded plaintext traffic and terminal channel time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TrafficObservation {
    child_to_service_bytes: u64,
    service_to_child_bytes: u64,
    active_ns: u64,
    closed_ns: u64,
}

impl TrafficObservation {
    /// Returns accepted child-to-service plaintext bytes.
    #[must_use]
    pub const fn child_to_service_bytes(self) -> u64 {
        self.child_to_service_bytes
    }

    /// Returns delivered service-to-child plaintext bytes.
    #[must_use]
    pub const fn service_to_child_bytes(self) -> u64 {
        self.service_to_child_bytes
    }

    /// Returns the connector-relative TLS activation time.
    #[must_use]
    pub const fn active_ns(self) -> u64 {
        self.active_ns
    }

    /// Returns the connector-relative channel close time.
    #[must_use]
    pub const fn closed_ns(self) -> u64 {
        self.closed_ns
    }
}

/// Identifies one fail-closed local-channel or proxy error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelError {
    /// The current platform does not supply a Unix stream channel.
    UnsupportedOperatingSystem,
    /// The private child channel could not be configured.
    Configuration,
    /// Reading opaque child bytes failed.
    ChildRead,
    /// Writing opaque service bytes to the child failed.
    ChildWrite,
    /// The authenticated TLS transport failed.
    Tls(TlsError),
}

impl ChannelError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedOperatingSystem => "network.channel.os.unsupported",
            Self::Configuration => "network.channel.configuration-failed",
            Self::ChildRead => "network.channel.child-read-failed",
            Self::ChildWrite => "network.channel.child-write-failed",
            Self::Tls(error) => error.code(),
        }
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ChannelError {}

/// Proxies opaque bounded bytes over one authenticated session.
///
/// This function does not parse application framing, methods, paths, headers,
/// prompts, or responses. It performs no reconnect and opens no second socket.
#[cfg(unix)]
pub fn proxy_authenticated_channel(
    mut session: AuthenticatedTlsSession,
    mut channel: UnixStream,
) -> Result<TrafficObservation, ChannelError> {
    channel
        .set_nonblocking(true)
        .map_err(|_| ChannelError::Configuration)?;
    session
        .stream
        .sock
        .inner
        .set_nonblocking(true)
        .map_err(|_| ChannelError::Configuration)?;

    let active_ns = session.observation.authenticated_ns();
    let mut child_open = true;
    let mut peer_open = true;
    let mut close_notify_sent = false;
    let mut child_input = [0_u8; PROXY_BUFFER_BYTES];
    let mut service_input = [0_u8; PROXY_BUFFER_BYTES];
    let mut pending_child = Vec::with_capacity(PROXY_BUFFER_BYTES);
    let mut pending_offset = 0_usize;

    loop {
        session.require_active().map_err(ChannelError::Tls)?;
        let mut progressed = false;

        if pending_offset < pending_child.len() {
            match channel.write(&pending_child[pending_offset..]) {
                Ok(0) => return Err(ChannelError::ChildWrite),
                Ok(count) => {
                    pending_offset += count;
                    session.service_to_child_bytes = session
                        .service_to_child_bytes
                        .checked_add(
                            u64::try_from(count)
                                .map_err(|_| ChannelError::Tls(TlsError::ServiceToChildLimit))?,
                        )
                        .ok_or(ChannelError::Tls(TlsError::ServiceToChildLimit))?;
                    progressed = true;
                    if pending_offset == pending_child.len() {
                        pending_child.clear();
                        pending_offset = 0;
                    }
                }
                Err(error) if nonblocking(&error) => {}
                Err(_) => return Err(ChannelError::ChildWrite),
            }
        }

        if child_open {
            match channel.read(&mut child_input) {
                Ok(0) => {
                    child_open = false;
                    progressed = true;
                }
                Ok(count) => {
                    let count_u64 = u64::try_from(count)
                        .map_err(|_| ChannelError::Tls(TlsError::ChildToServiceLimit))?;
                    if session
                        .child_to_service_bytes
                        .checked_add(count_u64)
                        .is_none_or(|total| total > session.child_to_service_limit)
                    {
                        return Err(ChannelError::Tls(TlsError::ChildToServiceLimit));
                    }
                    let accepted = session
                        .stream
                        .conn
                        .writer()
                        .write(&child_input[..count])
                        .map_err(|_| ChannelError::Tls(TlsError::SessionIo))?;
                    if accepted != count {
                        return Err(ChannelError::Tls(TlsError::SessionIo));
                    }
                    session.child_to_service_bytes += count_u64;
                    progressed = true;
                }
                Err(error) if nonblocking(&error) => {}
                Err(_) => return Err(ChannelError::ChildRead),
            }
        }

        if !child_open && !close_notify_sent {
            session.stream.conn.send_close_notify();
            close_notify_sent = true;
            progressed = true;
        }

        while session.stream.conn.wants_write() {
            match session.stream.conn.write_tls(&mut session.stream.sock) {
                Ok(0) => break,
                Ok(_) => progressed = true,
                Err(error) if nonblocking(&error) => break,
                Err(_) => return Err(ChannelError::Tls(TlsError::SessionIo)),
            }
        }

        if peer_open {
            match session.stream.conn.read_tls(&mut session.stream.sock) {
                Ok(0) => {
                    peer_open = false;
                    progressed = true;
                }
                Ok(_) => {
                    let state = session
                        .stream
                        .conn
                        .process_new_packets()
                        .map_err(|_| ChannelError::Tls(TlsError::Authentication))?;
                    peer_open = !state.peer_has_closed();
                    progressed = true;
                }
                Err(error) if nonblocking(&error) => {}
                Err(_) => return Err(ChannelError::Tls(TlsError::SessionIo)),
            }
        }

        if pending_child.is_empty() {
            let remaining = session
                .service_to_child_limit
                .checked_sub(session.service_to_child_bytes)
                .ok_or(ChannelError::Tls(TlsError::ServiceToChildLimit))?;
            let permitted = if remaining == 0 {
                1
            } else {
                PROXY_BUFFER_BYTES.min(usize::try_from(remaining).unwrap_or(usize::MAX))
            };
            match session
                .stream
                .conn
                .reader()
                .read(&mut service_input[..permitted])
            {
                Ok(0) => {}
                Ok(count) if remaining == 0 => {
                    let _ = count;
                    return Err(ChannelError::Tls(TlsError::ServiceToChildLimit));
                }
                Ok(count) => {
                    pending_child.extend_from_slice(&service_input[..count]);
                    progressed = true;
                }
                Err(error) if nonblocking(&error) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(ChannelError::Tls(TlsError::PrematureClose));
                }
                Err(_) => return Err(ChannelError::Tls(TlsError::SessionIo)),
            }
        }

        if !peer_open && pending_child.is_empty() {
            channel
                .shutdown(Shutdown::Write)
                .map_err(|_| ChannelError::ChildWrite)?;
            return Ok(TrafficObservation {
                child_to_service_bytes: session.child_to_service_bytes,
                service_to_child_bytes: session.service_to_child_bytes,
                active_ns,
                closed_ns: active_ns.saturating_add(
                    u64::try_from(session.active_at.elapsed().as_nanos()).unwrap_or(u64::MAX),
                ),
            });
        }

        if !progressed {
            std::thread::sleep(PROXY_IDLE_SLEEP);
        }
    }
}

/// Reports unsupported operation on a non-Unix host.
#[cfg(not(unix))]
pub fn proxy_authenticated_channel(
    _session: AuthenticatedTlsSession,
    _channel: (),
) -> Result<TrafficObservation, ChannelError> {
    Err(ChannelError::UnsupportedOperatingSystem)
}

/// Identifies one fail-closed endpoint or TLS error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsError {
    /// No declared endpoint established a TCP connection.
    EndpointUnavailable,
    /// The declared endpoint-attempt bound was exhausted.
    EndpointAttemptLimit,
    /// The total setup deadline expired.
    SetupDeadline,
    /// The selected DNS answer expired before authentication.
    AnswerExpired,
    /// The trust-root set was empty, malformed, or rejected.
    TrustRootSetInvalid,
    /// The declared DNS service name could not be used for TLS authentication.
    ServiceNameInvalid,
    /// TLS configuration failed closed.
    Configuration,
    /// TLS authentication failed.
    Authentication,
    /// The server resumed a TLS session.
    Resumption,
    /// The negotiated TLS version violated the declared minimum.
    Version,
    /// The TLS handshake byte bound was exhausted.
    HandshakeLimit,
    /// The peer did not supply a certificate chain.
    CertificateChainMissing,
    /// The authenticated session exceeded its duration.
    SessionDeadline,
    /// Child-to-service plaintext exceeded its bound.
    ChildToServiceLimit,
    /// Service-to-child plaintext exceeded its bound.
    ServiceToChildLimit,
    /// Authenticated stream input or output failed.
    SessionIo,
    /// The peer closed TCP without a TLS close notification.
    PrematureClose,
}

impl TlsError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EndpointUnavailable => "network.endpoint.unavailable",
            Self::EndpointAttemptLimit => "network.limit.endpoint-attempts",
            Self::SetupDeadline => "network.limit.setup-time",
            Self::AnswerExpired => "network.endpoint.answer-expired",
            Self::TrustRootSetInvalid => "network.tls.trust-root-set-invalid",
            Self::ServiceNameInvalid => "network.tls.service-name-invalid",
            Self::Configuration => "network.tls.configuration-failed",
            Self::Authentication => "network.tls.authentication-failed",
            Self::Resumption => "network.tls.resumption-rejected",
            Self::Version => "network.tls.version-rejected",
            Self::HandshakeLimit => "network.limit.tls-handshake-bytes",
            Self::CertificateChainMissing => "network.tls.certificate-chain-missing",
            Self::SessionDeadline => "network.limit.session-time",
            Self::ChildToServiceLimit => "network.limit.child-to-service-bytes",
            Self::ServiceToChildLimit => "network.limit.service-to-child-bytes",
            Self::SessionIo => "network.tls.session-io-failed",
            Self::PrematureClose => "network.tls.premature-close",
        }
    }
}

impl fmt::Display for TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for TlsError {}

/// Retains ordered endpoint evidence when authentication fails.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticateError {
    kind: TlsError,
    attempts: Vec<EndpointAttempt>,
}

impl AuthenticateError {
    /// Returns the stable failure class.
    #[must_use]
    pub const fn kind(&self) -> TlsError {
        self.kind
    }

    /// Returns every endpoint attempt completed before failure.
    #[must_use]
    pub fn attempts(&self) -> &[EndpointAttempt] {
        &self.attempts
    }
}

impl fmt::Display for AuthenticateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.kind.fmt(formatter)
    }
}

impl std::error::Error for AuthenticateError {}

/// Connects to the first canonical endpoint and authenticates the exact service.
///
/// The function disables session resumption and early data. A TLS failure after
/// one TCP connection is terminal and never advances to another endpoint.
pub fn authenticate_service(
    service: &ServiceName,
    tls: &TlsPolicy,
    limits: ServiceSessionLimits,
    resolution: &DnsResolution,
    trust_root_bytes: &[u8],
) -> Result<AuthenticatedTlsSession, AuthenticateError> {
    let mut attempts = Vec::new();
    let config = build_config(tls, trust_root_bytes).map_err(|kind| AuthenticateError {
        kind,
        attempts: attempts.clone(),
    })?;
    let setup_deadline_ns = limits
        .setup_time_ms()
        .checked_mul(1_000_000)
        .ok_or_else(|| AuthenticateError {
            kind: TlsError::SetupDeadline,
            attempts: attempts.clone(),
        })?;

    let mut connected = None;
    for (index, answer) in resolution
        .answers()
        .iter()
        .take(usize::from(limits.endpoint_attempts()))
        .enumerate()
    {
        let started_ns = resolution.elapsed_ns();
        let timeout = connection_timeout(
            resolution,
            answer,
            setup_deadline_ns,
            resolution.attempt_deadline_ms(),
        )
        .ok_or_else(|| AuthenticateError {
            kind: if resolution.elapsed_ns() >= answer.expires_ns() {
                TlsError::AnswerExpired
            } else {
                TlsError::SetupDeadline
            },
            attempts: attempts.clone(),
        })?;
        let endpoint = answer.endpoint(resolution.port());
        match TcpStream::connect_timeout(&endpoint, timeout) {
            Ok(stream) => {
                let finished_ns = resolution.elapsed_ns();
                attempts.push(EndpointAttempt {
                    ordinal: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    endpoint,
                    result: EndpointAttemptResult::Connected,
                    started_ns,
                    finished_ns,
                });
                connected = Some((answer.clone(), stream));
                break;
            }
            Err(error) => {
                attempts.push(EndpointAttempt {
                    ordinal: u32::try_from(index + 1).unwrap_or(u32::MAX),
                    endpoint,
                    result: classify_connect_error(&error),
                    started_ns,
                    finished_ns: resolution.elapsed_ns(),
                });
            }
        }
    }
    let Some((selected_answer, stream)) = connected else {
        let kind = if attempts.len() >= usize::from(limits.endpoint_attempts())
            && resolution.answers().len() > attempts.len()
        {
            TlsError::EndpointAttemptLimit
        } else {
            TlsError::EndpointUnavailable
        };
        return Err(AuthenticateError { kind, attempts });
    };

    let remaining = connection_timeout(
        resolution,
        &selected_answer,
        setup_deadline_ns,
        resolution.attempt_deadline_ms(),
    )
    .ok_or_else(|| AuthenticateError {
        kind: TlsError::AnswerExpired,
        attempts: attempts.clone(),
    })?;
    stream
        .set_read_timeout(Some(remaining))
        .and_then(|()| stream.set_write_timeout(Some(remaining)))
        .map_err(|_| AuthenticateError {
            kind: TlsError::Authentication,
            attempts: attempts.clone(),
        })?;
    let server_name =
        ServerName::try_from(service.as_str().to_owned()).map_err(|_| AuthenticateError {
            kind: TlsError::ServiceNameInvalid,
            attempts: attempts.clone(),
        })?;
    let mut connection =
        ClientConnection::new(Arc::new(config), server_name).map_err(|_| AuthenticateError {
            kind: TlsError::Configuration,
            attempts: attempts.clone(),
        })?;
    let mut socket = MeteredTcpStream::new(stream, limits.tls_handshake_bytes());
    while connection.is_handshaking() {
        connection
            .complete_io(&mut socket)
            .map_err(|error| AuthenticateError {
                kind: if error.kind() == io::ErrorKind::OutOfMemory {
                    TlsError::HandshakeLimit
                } else {
                    TlsError::Authentication
                },
                attempts: attempts.clone(),
            })?;
        if resolution.elapsed_ns() >= setup_deadline_ns {
            return Err(AuthenticateError {
                kind: TlsError::SetupDeadline,
                attempts,
            });
        }
        if resolution.elapsed_ns() >= selected_answer.expires_ns() {
            return Err(AuthenticateError {
                kind: TlsError::AnswerExpired,
                attempts,
            });
        }
    }
    if connection.handshake_kind() == Some(HandshakeKind::Resumed) {
        return Err(AuthenticateError {
            kind: TlsError::Resumption,
            attempts,
        });
    }
    let version = negotiated_version(&connection, tls.minimum_version()).map_err(|kind| {
        AuthenticateError {
            kind,
            attempts: attempts.clone(),
        }
    })?;
    let certificates = connection
        .peer_certificates()
        .ok_or_else(|| AuthenticateError {
            kind: TlsError::CertificateChainMissing,
            attempts: attempts.clone(),
        })?;
    if certificates.is_empty() {
        return Err(AuthenticateError {
            kind: TlsError::CertificateChainMissing,
            attempts,
        });
    }
    let handshake_bytes = socket.total_bytes().ok_or_else(|| AuthenticateError {
        kind: TlsError::HandshakeLimit,
        attempts: attempts.clone(),
    })?;
    if handshake_bytes == 0 || handshake_bytes > limits.tls_handshake_bytes() {
        return Err(AuthenticateError {
            kind: TlsError::HandshakeLimit,
            attempts,
        });
    }
    socket.remove_limit();
    let authenticated_ns = resolution.elapsed_ns();
    let observation = TlsObservation {
        implementation_identity: digest(TLS_IMPLEMENTATION),
        version,
        certificate_chain_identity: certificate_chain_identity(certificates),
        handshake_bytes,
        authenticated_ns,
    };
    Ok(AuthenticatedTlsSession {
        stream: StreamOwned::new(connection, socket),
        selected_answer,
        attempts,
        observation,
        active_at: Instant::now(),
        session_limit: Duration::from_millis(limits.session_time_ms()),
        child_to_service_limit: limits.child_to_service_bytes(),
        service_to_child_limit: limits.service_to_child_bytes(),
        child_to_service_bytes: 0,
        service_to_child_bytes: 0,
    })
}

fn build_config(tls: &TlsPolicy, trust_root_bytes: &[u8]) -> Result<ClientConfig, TlsError> {
    let certificates = CertificateDer::pem_slice_iter(trust_root_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TlsError::TrustRootSetInvalid)?;
    if certificates.is_empty() {
        return Err(TlsError::TrustRootSetInvalid);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| TlsError::TrustRootSetInvalid)?;
    }
    let versions = match tls.minimum_version() {
        MinimumTlsVersion::Tls12 => &[&rustls::version::TLS13, &rustls::version::TLS12][..],
        MinimumTlsVersion::Tls13 => &[&rustls::version::TLS13][..],
    };
    let mut config = ClientConfig::builder_with_protocol_versions(versions)
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.alpn_protocols.clear();
    Ok(config)
}

fn negotiated_version(
    connection: &ClientConnection,
    minimum: MinimumTlsVersion,
) -> Result<TlsVersion, TlsError> {
    match (connection.protocol_version(), minimum) {
        (Some(ProtocolVersion::TLSv1_3), _) => Ok(TlsVersion::Tls13),
        (Some(ProtocolVersion::TLSv1_2), MinimumTlsVersion::Tls12) => Ok(TlsVersion::Tls12),
        _ => Err(TlsError::Version),
    }
}

fn connection_timeout(
    resolution: &DnsResolution,
    answer: &DnsAnswer,
    setup_deadline_ns: u64,
    attempt_ms: u64,
) -> Option<Duration> {
    let attempt = Duration::from_millis(attempt_ms);
    let setup = resolution.remaining_until(setup_deadline_ns)?;
    let expiry = resolution.remaining_until(answer.expires_ns())?;
    Some(attempt.min(setup).min(expiry)).filter(|duration| !duration.is_zero())
}

fn classify_connect_error(error: &io::Error) -> EndpointAttemptResult {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => EndpointAttemptResult::Refused,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => EndpointAttemptResult::TimedOut,
        _ => EndpointAttemptResult::Failed,
    }
}

fn map_session_io(error: io::Error) -> TlsError {
    if error.kind() == io::ErrorKind::TimedOut || error.kind() == io::ErrorKind::WouldBlock {
        TlsError::SessionDeadline
    } else {
        TlsError::SessionIo
    }
}

fn nonblocking(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn certificate_chain_identity(certificates: &[CertificateDer<'_>]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"proofbound-runtime-tls-certificate-chain/1\0");
    for certificate in certificates {
        let bytes = certificate.as_ref();
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
    }
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

struct MeteredTcpStream {
    inner: TcpStream,
    read_bytes: u64,
    written_bytes: u64,
    limit: Option<u64>,
}

impl MeteredTcpStream {
    fn new(inner: TcpStream, limit: u64) -> Self {
        Self {
            inner,
            read_bytes: 0,
            written_bytes: 0,
            limit: Some(limit),
        }
    }

    fn total_bytes(&self) -> Option<u64> {
        self.read_bytes.checked_add(self.written_bytes)
    }

    fn remove_limit(&mut self) {
        self.limit = None;
    }

    fn remaining(&self) -> io::Result<usize> {
        let Some(limit) = self.limit else {
            return Ok(usize::MAX);
        };
        let total = self.total_bytes().ok_or_else(handshake_limit_error)?;
        let remaining = limit.checked_sub(total).ok_or_else(handshake_limit_error)?;
        if remaining == 0 {
            Err(handshake_limit_error())
        } else {
            Ok(usize::try_from(remaining).unwrap_or(usize::MAX))
        }
    }
}

impl Read for MeteredTcpStream {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let permitted = output.len().min(self.remaining()?);
        let read = self.inner.read(&mut output[..permitted])?;
        self.read_bytes = self
            .read_bytes
            .checked_add(u64::try_from(read).map_err(|_| handshake_limit_error())?)
            .ok_or_else(handshake_limit_error)?;
        Ok(read)
    }
}

impl Write for MeteredTcpStream {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let permitted = input.len().min(self.remaining()?);
        let written = self.inner.write(&input[..permitted])?;
        self.written_bytes = self
            .written_bytes
            .checked_add(u64::try_from(written).map_err(|_| handshake_limit_error())?)
            .ok_or_else(handshake_limit_error)?;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn handshake_limit_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "TLS handshake byte limit exhausted",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_error_codes_are_closed_and_distinct() {
        let errors = [
            TlsError::EndpointUnavailable,
            TlsError::EndpointAttemptLimit,
            TlsError::SetupDeadline,
            TlsError::AnswerExpired,
            TlsError::TrustRootSetInvalid,
            TlsError::ServiceNameInvalid,
            TlsError::Configuration,
            TlsError::Authentication,
            TlsError::Resumption,
            TlsError::Version,
            TlsError::HandshakeLimit,
            TlsError::CertificateChainMissing,
            TlsError::SessionDeadline,
            TlsError::ChildToServiceLimit,
            TlsError::ServiceToChildLimit,
            TlsError::SessionIo,
            TlsError::PrematureClose,
        ];
        let codes = errors.map(TlsError::code);
        for (index, code) in codes.iter().enumerate() {
            assert!(!code.is_empty());
            assert!(!codes[..index].contains(code));
        }
    }

    #[test]
    fn empty_trust_store_fails_closed() {
        let tls = TlsPolicy::new(
            proofbound_runtime_core::NetworkSupportPath::new("/roots.pem").expect("valid path"),
            MinimumTlsVersion::Tls13,
            proofbound_runtime_core::ServiceNameVerification::DnsSanExact,
            proofbound_runtime_core::RevocationPolicy::NotCheckedRecordedAssumption,
        );
        assert!(matches!(
            build_config(&tls, b""),
            Err(TlsError::TrustRootSetInvalid)
        ));
    }

    #[test]
    fn connect_error_mapping_is_closed() {
        assert_eq!(
            classify_connect_error(&io::Error::from(io::ErrorKind::ConnectionRefused)),
            EndpointAttemptResult::Refused
        );
        assert_eq!(
            classify_connect_error(&io::Error::from(io::ErrorKind::TimedOut)),
            EndpointAttemptResult::TimedOut
        );
        assert_eq!(
            classify_connect_error(&io::Error::from(io::ErrorKind::Other)),
            EndpointAttemptResult::Failed
        );
    }
}
