//! One-thread socket reactor for the proposed egress proxy process.

use std::collections::VecDeque;
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::time::{Duration, Instant};

use proofbound_runtime_core::{
    EgressAuthority, EgressDestination, ResolverAddress, TunnelDecision, TunnelTarget,
    decide_tunnel,
};

use super::budget::{ProxyBudget, ProxyLimit, ProxyTotals};
use super::lifecycle::{ProxyLifecycle, ProxyPhase, ProxyPhaseError};
use super::observation::{
    AttemptFact, AttemptResult, CloseReason, ConnectionFact, ConnectionTerminal, OpenConnection,
    ProxyObservationLedger, ProxyRecordError, RejectionFact, RejectionReason, SniObservation,
    TargetKind,
};
use super::relay::{RelayPair, RelayReady, RelayStep};
use super::resolution::{
    DnsResolutionError, DnsResolutionFacts, DnsResolutionMachine, DnsResolutionOutcome,
    ResolutionCoordinator, ResolutionRequest,
};
use super::session::{ProxySession, SessionEvent};
use super::transport::{DnsTcpExchange, PendingTcpConnect};
use super::{ProxyStatus, SniResult};

const CLIENT_READ_BYTES: usize = 8192;
const MAX_PENDING_REPORT_EVENTS: usize = 1024;

/// A typed event emitted once after its producer ledger record is complete.
#[derive(Clone, Debug)]
pub enum ProxyReportEvent {
    Rejection {
        sequence: u64,
        reason: RejectionReason,
        retained: Option<RejectionFact>,
        total: u64,
    },
    Resolution(DnsResolutionFacts),
    Connection(ConnectionFact),
    Final {
        event_sequence: u64,
        totals: ProxyTotals,
        rejection_total: u64,
        rejection_reason_counts: [u64; 10],
        limit_events: Vec<ProxyLimit>,
        phases: Vec<ProxyPhase>,
    },
}

#[derive(Debug)]
pub enum EgressProxyEngineError {
    Io(io::Error),
    Record(ProxyRecordError),
    Phase(ProxyPhaseError),
    Dns(DnsResolutionError),
    ReportQueueFull,
}

impl From<io::Error> for EgressProxyEngineError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<ProxyRecordError> for EgressProxyEngineError {
    fn from(error: ProxyRecordError) -> Self {
        Self::Record(error)
    }
}

impl From<ProxyPhaseError> for EgressProxyEngineError {
    fn from(error: ProxyPhaseError) -> Self {
        Self::Phase(error)
    }
}

impl From<DnsResolutionError> for EgressProxyEngineError {
    fn from(error: DnsResolutionError) -> Self {
        Self::Dns(error)
    }
}

#[derive(Debug)]
enum AfterStatus {
    Sni(ProxySession),
    Relay(TcpStream),
    Close(CloseReason),
}

#[derive(Debug)]
enum ClientStage {
    Head(ProxySession),
    Sni(ProxySession),
    Status {
        status: ProxyStatus,
        sent: usize,
        after: AfterStatus,
    },
    WaitingResolution,
    Connecting {
        addresses: Vec<IpAddr>,
        next: usize,
        pending: PendingTcpConnect,
        started_ms: u64,
    },
    Relay(RelayPair),
    Finished,
}

#[derive(Debug)]
struct Client {
    stream: Option<TcpStream>,
    stage: ClientStage,
    open: Option<OpenConnection>,
    endpoint_index: Option<usize>,
    accepted_ms: u64,
    last_activity_ms: u64,
    payload: Vec<u8>,
    sni_result: SniObservation,
    resolution_index: Option<u16>,
    resolution_answers: Vec<IpAddr>,
    attempts: Vec<AttemptFact>,
    selected_attempt: Option<u16>,
    terminal_reason: Option<CloseReason>,
}

impl Client {
    fn new(stream: TcpStream, accepted_ms: u64) -> Self {
        Self {
            stream: Some(stream),
            stage: ClientStage::Head(ProxySession::new()),
            open: None,
            endpoint_index: None,
            accepted_ms,
            last_activity_ms: accepted_ms,
            payload: Vec::new(),
            sni_result: SniObservation::NotInspected,
            resolution_index: None,
            resolution_answers: Vec::new(),
            attempts: Vec::new(),
            selected_attempt: None,
            terminal_reason: None,
        }
    }

    fn connection_id(&self) -> u64 {
        self.open.as_ref().map_or(0, |open| u64::from(open.index()))
    }
}

#[derive(Clone, Copy, Debug)]
enum PollTag {
    Listener,
    Client(usize),
    Connect(usize),
    RelayClient(usize),
    RelayRemote(usize),
    Dns(usize),
}

#[derive(Debug)]
struct DnsTask {
    machine: DnsResolutionMachine,
    exchange: DnsTcpExchange,
}

/// The listener and all accepted sockets are advanced in one poll set. The
/// supervisor owns confinement, readiness binding, report framing, and drain.
#[derive(Debug)]
pub struct EgressProxyEngine {
    authority: EgressAuthority,
    listener: TcpListener,
    origin: Instant,
    budget: ProxyBudget,
    observations: ProxyObservationLedger,
    lifecycle: ProxyLifecycle,
    clients: Vec<Option<Client>>,
    coordinator: ResolutionCoordinator,
    dns_tasks: Vec<Option<DnsTask>>,
    byte_exhaustion: Option<CloseReason>,
    reports: VecDeque<ProxyReportEvent>,
}

impl EgressProxyEngine {
    pub fn new(authority: EgressAuthority, listener: TcpListener) -> io::Result<Self> {
        listener.set_nonblocking(true)?;
        Ok(Self {
            budget: ProxyBudget::new(authority.limits()),
            authority,
            listener,
            origin: Instant::now(),
            observations: ProxyObservationLedger::new(),
            lifecycle: ProxyLifecycle::new(),
            clients: Vec::new(),
            coordinator: ResolutionCoordinator::new(),
            dns_tasks: Vec::new(),
            byte_exhaustion: None,
            reports: VecDeque::new(),
        })
    }

    /// May be called only after the process installs and reports confinement.
    pub fn mark_ready_and_serving(&mut self) -> Result<(), EgressProxyEngineError> {
        self.lifecycle.transition(ProxyPhase::Ready)?;
        self.lifecycle.transition(ProxyPhase::Serving)?;
        Ok(())
    }

    #[must_use]
    pub fn observations(&self) -> &ProxyObservationLedger {
        &self.observations
    }

    #[must_use]
    pub fn lifecycle(&self) -> &ProxyLifecycle {
        &self.lifecycle
    }

    /// The process writes these events to its bounded report channel after
    /// every reactor step. An undrained channel eventually fails closed.
    pub fn take_reports(&mut self) -> Vec<ProxyReportEvent> {
        self.reports.drain(..).collect()
    }

    fn enqueue(&mut self, event: ProxyReportEvent) -> Result<(), EgressProxyEngineError> {
        if self.reports.len() == MAX_PENDING_REPORT_EVENTS {
            return Err(EgressProxyEngineError::ReportQueueFull);
        }
        self.reports.push_back(event);
        Ok(())
    }

    fn record_rejection(
        &mut self,
        now_ms: u64,
        reason: RejectionReason,
        target_kind: TargetKind,
        port: Option<proofbound_runtime_core::TcpPort>,
        exact_target_bytes: &[u8],
    ) -> Result<(), EgressProxyEngineError> {
        let retained = self.observations.record_rejection(
            now_ms,
            reason,
            target_kind,
            port,
            exact_target_bytes,
        )?;
        self.enqueue(ProxyReportEvent::Rejection {
            sequence: self.observations.event_sequence(),
            reason,
            retained,
            total: self.observations.rejection_total(),
        })
    }

    fn record_resolution(
        &mut self,
        facts: DnsResolutionFacts,
    ) -> Result<(), EgressProxyEngineError> {
        self.observations.record_resolution(facts.clone());
        self.enqueue(ProxyReportEvent::Resolution(facts))
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Advances every ready descriptor once; no client can block another.
    pub fn step(&mut self, maximum_wait: Duration) -> Result<(), EgressProxyEngineError> {
        if self.lifecycle.current() != ProxyPhase::Serving {
            return Err(EgressProxyEngineError::Phase(
                ProxyPhaseError::InvalidTransition,
            ));
        }
        let mut interests = Vec::new();
        let mut tags = Vec::new();
        if self.clients.iter().filter(|slot| slot.is_some()).count()
            <= usize::from(self.budget.limits().concurrent_connections)
        {
            interests.push(crate::sys::PollInterest {
                descriptor: self.listener.as_raw_fd(),
                readable: true,
                writable: false,
            });
            tags.push(PollTag::Listener);
        }
        for (index, slot) in self.clients.iter().enumerate() {
            let Some(client) = slot else { continue };
            match &client.stage {
                ClientStage::Head(_) | ClientStage::Sni(_) => {
                    if let Some(stream) = &client.stream {
                        interests.push(crate::sys::PollInterest {
                            descriptor: stream.as_raw_fd(),
                            readable: true,
                            writable: false,
                        });
                        tags.push(PollTag::Client(index));
                    }
                }
                ClientStage::Status { .. } => {
                    if let Some(stream) = &client.stream {
                        interests.push(crate::sys::PollInterest {
                            descriptor: stream.as_raw_fd(),
                            readable: false,
                            writable: true,
                        });
                        tags.push(PollTag::Client(index));
                    }
                }
                ClientStage::Connecting { pending, .. } => {
                    interests.push(crate::sys::PollInterest {
                        descriptor: pending.descriptor(),
                        readable: false,
                        writable: true,
                    });
                    tags.push(PollTag::Connect(index));
                }
                ClientStage::Relay(relay) => {
                    for ((descriptor, readable, writable), tag) in relay
                        .interests()
                        .into_iter()
                        .zip([PollTag::RelayClient(index), PollTag::RelayRemote(index)])
                    {
                        interests.push(crate::sys::PollInterest {
                            descriptor,
                            readable,
                            writable,
                        });
                        tags.push(tag);
                    }
                }
                ClientStage::WaitingResolution | ClientStage::Finished => {}
            }
        }
        for (index, task) in self.dns_tasks.iter().enumerate() {
            if let Some(interest) = task.as_ref().and_then(|task| task.exchange.interest()) {
                interests.push(interest);
                tags.push(PollTag::Dns(index));
            }
        }
        let readiness =
            crate::sys::poll_many(&interests, maximum_wait.min(Duration::from_millis(100)))?;
        let now_ms = self.now_ms();
        let mut relay_ready =
            vec![(RelayReady::default(), RelayReady::default()); self.clients.len()];
        for (tag, ready) in tags.into_iter().zip(readiness) {
            match tag {
                PollTag::Listener if ready.readable => self.accept(now_ms)?,
                PollTag::Listener => {}
                PollTag::Client(index) => self.advance_client(index, ready, now_ms)?,
                PollTag::Connect(index) => self.advance_connect(index, ready, now_ms)?,
                PollTag::Dns(index) => self.advance_dns(index, ready, now_ms)?,
                PollTag::RelayClient(index) => {
                    relay_ready[index].0 = RelayReady {
                        readable: ready.readable,
                        writable: ready.writable,
                        error: ready.error,
                        hangup: ready.hangup,
                    }
                }
                PollTag::RelayRemote(index) => {
                    relay_ready[index].1 = RelayReady {
                        readable: ready.readable,
                        writable: ready.writable,
                        error: ready.error,
                        hangup: ready.hangup,
                    }
                }
            }
        }
        for (index, (client_ready, remote_ready)) in relay_ready.into_iter().enumerate() {
            if let Some(Some(client)) = self.clients.get_mut(index)
                && let ClientStage::Relay(relay) = &mut client.stage
            {
                match relay.advance(client_ready, remote_ready, now_ms, &mut self.budget)? {
                    RelayStep::Open => {}
                    RelayStep::Closed(reason) => self.close_client(index, reason)?,
                }
            }
        }
        if self.budget.events().contains(&ProxyLimit::ClientBytes) {
            self.byte_exhaustion = Some(CloseReason::ClientByteLimit);
        } else if self.budget.events().contains(&ProxyLimit::RemoteBytes) {
            self.byte_exhaustion = Some(CloseReason::RemoteByteLimit);
        }
        if let Some(reason) = self.byte_exhaustion {
            for index in 0..self.clients.len() {
                if self.clients[index]
                    .as_ref()
                    .is_some_and(|client| client.open.is_some())
                {
                    self.close_client(index, reason)?;
                }
            }
        }
        self.expire_attempts(now_ms)?;
        self.expire_idle(now_ms)?;
        Ok(())
    }

    fn accept(&mut self, now_ms: u64) -> Result<(), EgressProxyEngineError> {
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(true)?;
                    let mut client = Client::new(stream, now_ms);
                    let live = self.clients.iter().filter(|slot| slot.is_some()).count();
                    if self.byte_exhaustion.is_some() {
                        self.record_rejection(
                            now_ms,
                            RejectionReason::LimitBytesExhausted,
                            TargetKind::Unparsed,
                            None,
                            b"",
                        )?;
                        client.stage = ClientStage::Status {
                            status: ProxyStatus::TooManyRequests,
                            sent: 0,
                            after: AfterStatus::Close(CloseReason::ClientClosed),
                        };
                    } else if live >= usize::from(self.budget.limits().concurrent_connections) {
                        self.budget.note_limit(ProxyLimit::Concurrent);
                        self.record_rejection(
                            now_ms,
                            RejectionReason::LimitConcurrentConnections,
                            TargetKind::Unparsed,
                            None,
                            b"",
                        )?;
                        client.stage = ClientStage::Status {
                            status: ProxyStatus::TooManyRequests,
                            sent: 0,
                            after: AfterStatus::Close(CloseReason::ClientClosed),
                        };
                    }
                    if let Some(slot) = self.clients.iter_mut().find(|slot| slot.is_none()) {
                        *slot = Some(client);
                    } else {
                        self.clients.push(Some(client));
                    }
                    if live >= usize::from(self.budget.limits().concurrent_connections) {
                        return Ok(());
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn advance_client(
        &mut self,
        index: usize,
        ready: crate::sys::PollReady,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        let Some(mut client) = self.clients.get_mut(index).and_then(Option::take) else {
            return Ok(());
        };
        if ready.error || ready.hangup {
            return self.finish_taken(index, client, CloseReason::ClientClosed);
        }
        let stage = std::mem::replace(&mut client.stage, ClientStage::Finished);
        match stage {
            ClientStage::Head(mut session) | ClientStage::Sni(mut session) => {
                let awaiting_sni = client.open.is_some();
                let mut buffer = [0u8; CLIENT_READ_BYTES];
                let read = match client
                    .stream
                    .as_mut()
                    .expect("client stream during admission")
                    .read(&mut buffer)
                {
                    Ok(0) => return self.finish_taken(index, client, CloseReason::ClientClosed),
                    Ok(count) => count,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        client.stage = if awaiting_sni {
                            ClientStage::Sni(session)
                        } else {
                            ClientStage::Head(session)
                        };
                        self.clients[index] = Some(client);
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                };
                client.last_activity_ms = now_ms;
                let event = session.push(
                    &self.authority,
                    &buffer[..read],
                    client.connection_id(),
                    now_ms,
                );
                self.handle_session(index, &mut client, session, event, now_ms)?;
            }
            ClientStage::Status {
                status,
                mut sent,
                after,
            } => {
                let wire = status.bytes();
                match client
                    .stream
                    .as_mut()
                    .expect("status stream")
                    .write(&wire[sent..])
                {
                    Ok(0) => return self.finish_taken(index, client, CloseReason::ClientClosed),
                    Ok(count) => {
                        sent += count;
                        client.last_activity_ms = now_ms;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error.into()),
                }
                if sent == wire.len() {
                    match after {
                        AfterStatus::Close(reason) => {
                            return self.finish_taken(index, client, reason);
                        }
                        AfterStatus::Sni(mut session) => {
                            let event =
                                session.push(&self.authority, b"", client.connection_id(), now_ms);
                            self.handle_session(index, &mut client, session, event, now_ms)?;
                        }
                        AfterStatus::Relay(remote) => {
                            let stream = client.stream.take().expect("tunnel client stream");
                            let mut relay = RelayPair::new(stream, remote, now_ms)?;
                            relay.seed_client_bytes(&client.payload)?;
                            client.payload.clear();
                            client.stage = ClientStage::Relay(relay);
                        }
                    }
                } else {
                    client.stage = ClientStage::Status {
                        status,
                        sent,
                        after,
                    };
                }
            }
            other => client.stage = other,
        }
        if matches!(client.stage, ClientStage::Finished) {
            let reason = client.terminal_reason.unwrap_or(CloseReason::ConnectFailed);
            return self.finish_taken(index, client, reason);
        }
        self.clients[index] = Some(client);
        Ok(())
    }

    fn handle_session(
        &mut self,
        _index: usize,
        client: &mut Client,
        session: ProxySession,
        event: SessionEvent,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        if self.byte_exhaustion.is_some() && !matches!(event, SessionEvent::NeedMore) {
            self.record_rejection(
                now_ms,
                RejectionReason::LimitBytesExhausted,
                TargetKind::Unparsed,
                None,
                b"",
            )?;
            client.stage = ClientStage::Status {
                status: ProxyStatus::TooManyRequests,
                sent: 0,
                after: AfterStatus::Close(CloseReason::ClientClosed),
            };
            return Ok(());
        }
        match event {
            SessionEvent::NeedMore => {
                client.stage = if client.open.is_some() {
                    ClientStage::Sni(session)
                } else {
                    ClientStage::Head(session)
                }
            }
            SessionEvent::Rejected(rejected) => {
                self.record_rejection(
                    now_ms,
                    RejectionReason::from(rejected.reason),
                    rejected.target_kind,
                    rejected.port,
                    &rejected.exact_target_bytes,
                )?;
                client.stage = ClientStage::Status {
                    status: ProxyStatus::from_rejection(rejected.reason),
                    sent: 0,
                    after: AfterStatus::Close(CloseReason::ClientClosed),
                };
            }
            SessionEvent::EstablishedAwaitSni { endpoint_index } => {
                if !self.open_client(client, endpoint_index, now_ms)? {
                    return Ok(());
                }
                client.sni_result = SniObservation::DeniedAbsent;
                client.stage = ClientStage::Status {
                    status: ProxyStatus::Established,
                    sent: 0,
                    after: AfterStatus::Sni(session),
                };
            }
            SessionEvent::SniDenied(reason) => {
                client.sni_result = sni_observation(reason);
                client.terminal_reason = Some(CloseReason::SniDenied);
                client.stage = ClientStage::Finished;
            }
            SessionEvent::Ready {
                endpoint_index,
                decision,
                payload,
                sni_matched,
            } => {
                if client.open.is_none() && !self.open_client(client, endpoint_index, now_ms)? {
                    return Ok(());
                }
                if sni_matched {
                    client.sni_result = SniObservation::Matched;
                }
                client.payload = payload;
                match decision {
                    TunnelDecision::Attempts { addresses, .. } => {
                        self.start_attempt(client, addresses, 0, now_ms)?;
                    }
                    TunnelDecision::NeedsResolution { .. } => {
                        self.start_name_resolution(client, now_ms)?;
                    }
                    TunnelDecision::Denied(_) => {
                        client.terminal_reason = Some(CloseReason::ConnectFailed);
                        client.stage = ClientStage::Finished;
                    }
                }
            }
            SessionEvent::AlreadyFinished => client.stage = ClientStage::Finished,
        }
        Ok(())
    }

    fn open_client(
        &mut self,
        client: &mut Client,
        endpoint_index: usize,
        now_ms: u64,
    ) -> Result<bool, EgressProxyEngineError> {
        match self.observations.open_connection(
            &mut self.budget,
            endpoint_index,
            self.authority.endpoints().len(),
            client.accepted_ms,
        )? {
            Ok(open) => {
                client.open = Some(open);
                client.endpoint_index = Some(endpoint_index);
                Ok(true)
            }
            Err(limit) => {
                self.record_rejection(
                    now_ms,
                    RejectionReason::from(limit),
                    TargetKind::Unparsed,
                    None,
                    b"",
                )?;
                client.stage = ClientStage::Status {
                    status: ProxyStatus::TooManyRequests,
                    sent: 0,
                    after: AfterStatus::Close(CloseReason::ClientClosed),
                };
                Ok(false)
            }
        }
    }

    fn resolver_socket(&self) -> SocketAddr {
        let endpoint = self.authority.resolver().endpoint();
        let address = match endpoint.address() {
            ResolverAddress::Ipv4(bytes) => IpAddr::V4(Ipv4Addr::from(bytes)),
            ResolverAddress::Ipv6(bytes) => IpAddr::V6(Ipv6Addr::from(bytes)),
        };
        SocketAddr::new(address, endpoint.port().get())
    }

    fn start_name_resolution(
        &mut self,
        client: &mut Client,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        let endpoint_index = client.endpoint_index.expect("declared endpoint");
        let EgressDestination::DnsName { name, scope } =
            &self.authority.endpoints()[endpoint_index].destination
        else {
            return Err(EgressProxyEngineError::Io(io::Error::other(
                "resolution for numeric destination",
            )));
        };
        let name = name.clone();
        let scope = *scope;
        let connection = client.open.as_ref().expect("opened connection").index();
        match self.coordinator.request(&name, connection, now_ms) {
            ResolutionRequest::Reuse(facts) => self.apply_resolution(client, &facts, now_ms)?,
            ResolutionRequest::Wait => client.stage = ClientStage::WaitingResolution,
            ResolutionRequest::Start => {
                let mut machine = match DnsResolutionMachine::new(
                    name.clone(),
                    scope,
                    u64::from(connection),
                    now_ms,
                    self.authority.resolver(),
                    &mut self.budget,
                ) {
                    Ok(machine) => machine,
                    Err(DnsResolutionError::ResolutionLimit) => {
                        let _ = self.coordinator.abort(&name);
                        self.limit_after_open(client, RejectionReason::LimitResolutions, now_ms)?;
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                };
                self.coordinator.started(&name, machine.index())?;
                let query = match machine.issue_query(
                    crate::sys::random_u16()?,
                    now_ms,
                    &mut self.budget,
                ) {
                    Ok(query) => query,
                    Err(DnsResolutionError::MessageLimit) => {
                        self.limit_after_open(client, RejectionReason::LimitDnsMessages, now_ms)?;
                        let facts = machine.fail(now_ms);
                        self.coordinator.complete(facts.clone())?;
                        self.record_resolution(facts)?;
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                };
                let exchange = match DnsTcpExchange::start(
                    self.resolver_socket(),
                    &query,
                    self.authority.resolver().maximum_response_bytes(),
                    machine.deadline_ms(),
                ) {
                    Ok(exchange) => exchange,
                    Err(_) => {
                        let facts = machine.fail(now_ms);
                        self.coordinator.complete(facts.clone())?;
                        self.record_resolution(facts.clone())?;
                        self.apply_resolution(client, &facts, now_ms)?;
                        return Ok(());
                    }
                };
                self.dns_tasks.push(Some(DnsTask { machine, exchange }));
                client.stage = ClientStage::WaitingResolution;
            }
        }
        Ok(())
    }

    fn limit_after_open(
        &mut self,
        client: &mut Client,
        reason: RejectionReason,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        self.record_rejection(now_ms, reason, TargetKind::Unparsed, None, b"")?;
        if client.sni_result == SniObservation::Matched {
            client.terminal_reason = Some(CloseReason::ResolutionFailed);
            client.stage = ClientStage::Finished;
        } else {
            client.stage = ClientStage::Status {
                status: ProxyStatus::TooManyRequests,
                sent: 0,
                after: AfterStatus::Close(CloseReason::ResolutionFailed),
            };
        }
        Ok(())
    }

    fn apply_resolution(
        &mut self,
        client: &mut Client,
        facts: &DnsResolutionFacts,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        client.resolution_index = Some(facts.index);
        if facts.outcome != DnsResolutionOutcome::Answered {
            self.resolution_failure(client, facts.outcome);
            return Ok(());
        }
        let endpoint_index = client.endpoint_index.expect("declared endpoint");
        let endpoint = &self.authority.endpoints()[endpoint_index];
        let EgressDestination::DnsName { name, .. } = &endpoint.destination else {
            return Err(EgressProxyEngineError::Io(io::Error::other(
                "resolution destination mismatch",
            )));
        };
        let target = TunnelTarget::DnsName(name.clone());
        let sni = if client.sni_result == SniObservation::Matched {
            Some(name)
        } else {
            None
        };
        let decision = decide_tunnel(
            &self.authority,
            client.connection_id(),
            &target,
            endpoint.port,
            sni,
            Some(&facts.pinned()),
            now_ms,
        );
        match decision {
            TunnelDecision::Attempts { addresses, .. } => {
                client.resolution_answers =
                    facts.answers.iter().map(|answer| answer.address).collect();
                self.start_attempt(client, addresses, 0, now_ms)?;
            }
            TunnelDecision::Denied(_) => {
                self.resolution_failure(client, DnsResolutionOutcome::NoAdmissibleAnswer);
            }
            TunnelDecision::NeedsResolution { .. } => {
                return Err(EgressProxyEngineError::Io(io::Error::other(
                    "completed resolution requested again",
                )));
            }
        }
        Ok(())
    }

    fn resolution_failure(&self, client: &mut Client, outcome: DnsResolutionOutcome) {
        let reason = match outcome {
            DnsResolutionOutcome::Failed => CloseReason::ResolutionFailed,
            DnsResolutionOutcome::NoAdmissibleAnswer | DnsResolutionOutcome::Answered => {
                CloseReason::NoAdmissibleAnswer
            }
        };
        client.stage = if client.sni_result == SniObservation::Matched {
            client.terminal_reason = Some(reason);
            ClientStage::Finished
        } else {
            ClientStage::Status {
                status: ProxyStatus::BadGateway,
                sent: 0,
                after: AfterStatus::Close(reason),
            }
        };
    }

    fn start_attempt(
        &mut self,
        client: &mut Client,
        addresses: Vec<IpAddr>,
        next: usize,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        let endpoint_index = client.endpoint_index.expect("declared endpoint");
        let port = self.authority.endpoints()[endpoint_index].port.get();
        if next >= addresses.len() {
            if client.sni_result == SniObservation::Matched {
                client.terminal_reason = Some(CloseReason::ConnectFailed);
                client.stage = ClientStage::Finished;
            } else {
                client.stage = ClientStage::Status {
                    status: ProxyStatus::BadGateway,
                    sent: 0,
                    after: AfterStatus::Close(CloseReason::ConnectFailed),
                };
            }
            return Ok(());
        }
        let address = addresses[next];
        match PendingTcpConnect::start(SocketAddr::new(address, port)) {
            Ok(pending) => {
                client.stage = ClientStage::Connecting {
                    addresses,
                    next,
                    pending,
                    started_ms: now_ms,
                };
            }
            Err(error) => {
                client.attempts.push(AttemptFact {
                    answer_index: answer_index(client, address)?,
                    address,
                    started_ms: now_ms,
                    result: classify_attempt(&error),
                });
                self.start_attempt(client, addresses, next + 1, now_ms)?;
            }
        }
        Ok(())
    }

    fn advance_connect(
        &mut self,
        index: usize,
        ready: crate::sys::PollReady,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        let Some(mut client) = self.clients.get_mut(index).and_then(Option::take) else {
            return Ok(());
        };
        let stage = std::mem::replace(&mut client.stage, ClientStage::Finished);
        let ClientStage::Connecting {
            addresses,
            next,
            pending,
            started_ms,
        } = stage
        else {
            self.clients[index] = Some(client);
            return Ok(());
        };
        if !(ready.writable || ready.error || ready.hangup) {
            client.stage = ClientStage::Connecting {
                addresses,
                next,
                pending,
                started_ms,
            };
            self.clients[index] = Some(client);
            return Ok(());
        }
        let result = if now_ms.saturating_sub(started_ms)
            >= self.authority.resolver().attempt_deadline_ms()
        {
            Err(io::Error::new(io::ErrorKind::TimedOut, "attempt deadline"))
        } else {
            pending.result()
        };
        let address = addresses[next];
        if let Ok(()) = result {
            client.attempts.push(AttemptFact {
                answer_index: answer_index(&client, address)?,
                address,
                started_ms,
                result: AttemptResult::Connected,
            });
            client.selected_attempt = u16::try_from(client.attempts.len() - 1).ok();
            let remote = pending.into_stream();
            if client.sni_result == SniObservation::NotInspected {
                client.stage = ClientStage::Status {
                    status: ProxyStatus::Established,
                    sent: 0,
                    after: AfterStatus::Relay(remote),
                };
            } else {
                let stream = client.stream.take().expect("matched-SNI client stream");
                let mut relay = RelayPair::new(stream, remote, now_ms)?;
                relay.seed_client_bytes(&client.payload)?;
                client.payload.clear();
                client.stage = ClientStage::Relay(relay);
            }
        } else if let Err(error) = result {
            client.attempts.push(AttemptFact {
                answer_index: answer_index(&client, address)?,
                address,
                started_ms,
                result: classify_attempt(&error),
            });
            self.start_attempt(&mut client, addresses, next + 1, now_ms)?;
        }
        if matches!(client.stage, ClientStage::Finished) {
            self.finish_taken(index, client, CloseReason::ConnectFailed)?;
        } else {
            self.clients[index] = Some(client);
        }
        Ok(())
    }

    fn expire_attempts(&mut self, now_ms: u64) -> Result<(), EgressProxyEngineError> {
        for index in 0..self.clients.len() {
            let expired = self.clients[index].as_ref().is_some_and(|client| {
                matches!(
                    &client.stage,
                    ClientStage::Connecting { started_ms, .. }
                        if now_ms.saturating_sub(*started_ms)
                            >= self.authority.resolver().attempt_deadline_ms()
                )
            });
            if !expired {
                continue;
            }
            let mut client = self.clients[index].take().expect("expired attempt slot");
            let stage = std::mem::replace(&mut client.stage, ClientStage::Finished);
            let ClientStage::Connecting {
                addresses,
                next,
                pending: _,
                started_ms,
            } = stage
            else {
                unreachable!("expiry predicate checked connecting stage")
            };
            let address = addresses[next];
            client.attempts.push(AttemptFact {
                answer_index: answer_index(&client, address)?,
                address,
                started_ms,
                result: AttemptResult::TimedOut,
            });
            self.start_attempt(&mut client, addresses, next + 1, now_ms)?;
            if matches!(client.stage, ClientStage::Finished) {
                self.finish_taken(index, client, CloseReason::ConnectFailed)?;
            } else {
                self.clients[index] = Some(client);
            }
        }
        Ok(())
    }

    fn expire_idle(&mut self, now_ms: u64) -> Result<(), EgressProxyEngineError> {
        let idle_ms = u64::from(self.budget.limits().connection_idle_ms);
        for index in 0..self.clients.len() {
            let expired = self.clients[index].as_ref().is_some_and(|client| {
                !matches!(client.stage, ClientStage::Relay(_))
                    && now_ms.saturating_sub(client.last_activity_ms) >= idle_ms
            });
            if !expired {
                continue;
            }
            let Some(client) = self.clients[index].take() else {
                continue;
            };
            if client.open.is_none() && matches!(client.stage, ClientStage::Head(_)) {
                self.record_rejection(
                    now_ms,
                    RejectionReason::RequestMalformed,
                    TargetKind::Unparsed,
                    None,
                    b"",
                )?;
            }
            self.finish_taken(index, client, CloseReason::IdleTimeout)?;
        }
        Ok(())
    }

    fn advance_dns(
        &mut self,
        index: usize,
        ready: crate::sys::PollReady,
        now_ms: u64,
    ) -> Result<(), EgressProxyEngineError> {
        let Some(mut task) = self.dns_tasks.get_mut(index).and_then(Option::take) else {
            return Ok(());
        };
        match task.exchange.on_ready(now_ms, ready) {
            Ok(None) => self.dns_tasks[index] = Some(task),
            Err(_) => {
                self.complete_resolution(task.machine.fail(now_ms), now_ms, None)?;
            }
            Ok(Some(response)) => {
                if task
                    .machine
                    .accept_response(&response, now_ms, &mut self.budget)
                    .is_err()
                {
                    self.complete_resolution(task.machine.fail(now_ms), now_ms, None)?;
                } else if task.machine.is_complete() {
                    let facts = task
                        .machine
                        .finish()
                        .unwrap_or_else(|_| task.machine.fail(now_ms));
                    self.complete_resolution(facts, now_ms, None)?;
                } else {
                    let query = match task.machine.issue_query(
                        crate::sys::random_u16()?,
                        now_ms,
                        &mut self.budget,
                    ) {
                        Ok(query) => query,
                        Err(DnsResolutionError::MessageLimit) => {
                            self.complete_resolution(
                                task.machine.fail(now_ms),
                                now_ms,
                                Some(RejectionReason::LimitDnsMessages),
                            )?;
                            return Ok(());
                        }
                        Err(_) => {
                            self.complete_resolution(task.machine.fail(now_ms), now_ms, None)?;
                            return Ok(());
                        }
                    };
                    match DnsTcpExchange::start(
                        self.resolver_socket(),
                        &query,
                        self.authority.resolver().maximum_response_bytes(),
                        task.machine.deadline_ms(),
                    ) {
                        Ok(exchange) => {
                            task.exchange = exchange;
                            self.dns_tasks[index] = Some(task);
                        }
                        Err(_) => {
                            self.complete_resolution(task.machine.fail(now_ms), now_ms, None)?
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn complete_resolution(
        &mut self,
        facts: DnsResolutionFacts,
        now_ms: u64,
        limit: Option<RejectionReason>,
    ) -> Result<(), EgressProxyEngineError> {
        let waiters = self.coordinator.complete(facts.clone())?;
        self.record_resolution(facts.clone())?;
        for connection in waiters {
            let Some(index) = self.clients.iter().position(|slot| {
                slot.as_ref()
                    .and_then(|client| client.open.as_ref())
                    .is_some_and(|open| open.index() == connection)
            }) else {
                continue;
            };
            let mut client = self.clients[index].take().expect("waiter slot");
            if let Some(reason) = limit {
                client.resolution_index = Some(facts.index);
                self.limit_after_open(&mut client, reason, now_ms)?;
            } else {
                self.apply_resolution(&mut client, &facts, now_ms)?;
            }
            if matches!(client.stage, ClientStage::Finished) {
                let reason = client
                    .terminal_reason
                    .unwrap_or(CloseReason::ResolutionFailed);
                self.finish_taken(index, client, reason)?;
            } else {
                self.clients[index] = Some(client);
            }
        }
        Ok(())
    }

    fn close_client(
        &mut self,
        index: usize,
        reason: CloseReason,
    ) -> Result<(), EgressProxyEngineError> {
        let Some(client) = self.clients.get_mut(index).and_then(Option::take) else {
            return Ok(());
        };
        self.finish_taken(index, client, reason)
    }

    fn finish_taken(
        &mut self,
        _index: usize,
        mut client: Client,
        reason: CloseReason,
    ) -> Result<(), EgressProxyEngineError> {
        let (client_bytes, remote_bytes) = if let ClientStage::Relay(relay) = &client.stage {
            relay.bytes()
        } else {
            (0, 0)
        };
        if let Some(open) = client.open.take() {
            let close_reason = if client.sni_result.is_denied() {
                CloseReason::SniDenied
            } else {
                reason
            };
            let fact = self.observations.close_connection(
                &mut self.budget,
                open,
                ConnectionTerminal {
                    resolution_index: client.resolution_index,
                    sni_result: client.sni_result,
                    attempts: client.attempts,
                    selected_attempt: client.selected_attempt,
                    client_to_remote_bytes: client_bytes,
                    remote_to_client_bytes: remote_bytes,
                    close_reason,
                },
            )?;
            self.enqueue(ProxyReportEvent::Connection(fact))?;
        }
        Ok(())
    }

    /// Stops intake and closes every live tunnel before final accounting.
    pub fn drain(
        mut self,
    ) -> Result<
        (
            ProxyObservationLedger,
            ProxyLifecycle,
            Vec<ProxyReportEvent>,
        ),
        EgressProxyEngineError,
    > {
        self.lifecycle.transition(ProxyPhase::Draining)?;
        for index in 0..self.clients.len() {
            self.close_client(index, CloseReason::ProxyDraining)?;
        }
        self.observations.verify_totals(&self.budget)?;
        self.lifecycle.transition(ProxyPhase::Closed)?;
        let final_report = ProxyReportEvent::Final {
            event_sequence: self.observations.event_sequence(),
            totals: self.observations.totals(&self.budget),
            rejection_total: self.observations.rejection_total(),
            rejection_reason_counts: *self.observations.rejection_reason_counts(),
            limit_events: self
                .observations
                .limit_events(&self.budget)
                .into_iter()
                .collect(),
            phases: self.lifecycle.phases().to_vec(),
        };
        self.enqueue(final_report)?;
        Ok((
            self.observations,
            self.lifecycle,
            self.reports.into_iter().collect(),
        ))
    }
}

fn sni_observation(result: SniResult) -> SniObservation {
    match result {
        SniResult::DeniedAbsent => SniObservation::DeniedAbsent,
        SniResult::DeniedMismatch => SniObservation::DeniedMismatch,
        SniResult::DeniedEch => SniObservation::DeniedEch,
        SniResult::DeniedMalformed | SniResult::Incomplete => SniObservation::DeniedMalformed,
        SniResult::DeniedTooLarge => SniObservation::DeniedTooLarge,
        SniResult::Matched => SniObservation::Matched,
    }
}

fn answer_index(client: &Client, address: IpAddr) -> Result<Option<u16>, EgressProxyEngineError> {
    if client.resolution_index.is_none() {
        return Ok(None);
    }
    let index = client
        .resolution_answers
        .iter()
        .position(|candidate| *candidate == address)
        .ok_or_else(|| EgressProxyEngineError::Io(io::Error::other("attempt lacks answer")))?;
    Ok(Some(u16::try_from(index).map_err(|_| {
        EgressProxyEngineError::Io(io::Error::other("answer index overflow"))
    })?))
}

fn classify_attempt(error: &io::Error) -> AttemptResult {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => AttemptResult::Refused,
        io::ErrorKind::TimedOut => AttemptResult::TimedOut,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => {
            AttemptResult::Unreachable
        }
        _ => AttemptResult::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::{
        AddressOrder, AddressScope, EgressDestination, EgressEndpoint, EgressName,
        NetworkSupportPath, ResolutionPolicy, ResolverEndpoint, SniBinding, TcpPort,
    };

    #[test]
    fn literal_connect_relay_and_drain_are_counted() {
        let remote_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        remote_listener.set_nonblocking(true).unwrap();
        let remote_port = remote_listener.local_addr().unwrap().port();
        let original = super::super::tests::golden_authority();
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::Ipv4([127, 0, 0, 1]),
                port: TcpPort::new(remote_port).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            original.resolver().clone(),
            original.limits(),
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, proxy_listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut child = TcpStream::connect(proxy_address).unwrap();
        child.set_nonblocking(true).unwrap();
        child
            .write_all(format!("CONNECT 127.0.0.1:{remote_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut status = [0u8; 64];
        let mut established = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            match child.read(&mut status) {
                Ok(count) if count != 0 => {
                    assert_eq!(&status[..count], ProxyStatus::Established.bytes());
                    established = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                other => panic!("unexpected proxy response: {other:?}"),
            }
        }
        assert!(established);
        let (mut remote, _) = remote_listener.accept().unwrap();
        remote.set_nonblocking(true).unwrap();
        child.write_all(b"ping").unwrap();
        let mut payload = [0u8; 4];
        let mut relayed = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            match remote.read(&mut payload) {
                Ok(4) => {
                    relayed = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                other => panic!("unexpected relayed read: {other:?}"),
            }
        }
        assert!(relayed);
        assert_eq!(&payload, b"ping");
        let (observations, lifecycle, reports) = engine.drain().unwrap();
        assert_eq!(observations.connections().len(), 1);
        assert_eq!(observations.connections()[0].client_to_remote_bytes, 4);
        assert_eq!(lifecycle.current(), ProxyPhase::Closed);
        assert!(matches!(reports.as_slice(), [
            ProxyReportEvent::Connection(connection),
            ProxyReportEvent::Final { totals, rejection_total: 0, phases, .. }
        ] if connection == &observations.connections()[0]
            && totals.connections == 1
            && totals.client_bytes == 4
            && phases == lifecycle.phases()));
    }

    #[test]
    fn required_sni_absence_never_opens_remote_socket() {
        let remote_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        remote_listener.set_nonblocking(true).unwrap();
        let remote_port = remote_listener.local_addr().unwrap().port();
        let original = super::super::tests::golden_authority();
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::Ipv4([127, 0, 0, 1]),
                port: TcpPort::new(remote_port).unwrap(),
                tls_sni: SniBinding::Required(EgressName::new("api.example").unwrap()),
            }],
            original.resolver().clone(),
            original.limits(),
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, proxy_listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut child = TcpStream::connect(proxy_address).unwrap();
        child.set_nonblocking(true).unwrap();
        child
            .write_all(format!("CONNECT 127.0.0.1:{remote_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut status = [0_u8; 64];
        let mut established = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(count) = child.read(&mut status)
                && count != 0
            {
                assert_eq!(&status[..count], ProxyStatus::Established.bytes());
                established = true;
                break;
            }
        }
        assert!(established);
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0, 0, 0]);
        let mut hello = vec![1, 0, 0, u8::try_from(body.len()).unwrap()];
        hello.extend_from_slice(&body);
        let mut record = vec![22, 3, 1];
        record.extend_from_slice(&u16::try_from(hello.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&hello);
        child.write_all(&record).unwrap();
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            if engine.observations().connections().len() == 1 {
                break;
            }
        }
        assert!(
            matches!(remote_listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
        let (observations, _, reports) = engine.drain().unwrap();
        let connection = &observations.connections()[0];
        assert_eq!(connection.sni_result, SniObservation::DeniedAbsent);
        assert!(connection.attempts.is_empty());
        assert_eq!(connection.close_reason, CloseReason::SniDenied);
        assert!(matches!(
            reports.first(),
            Some(ProxyReportEvent::Connection(_))
        ));
    }

    #[test]
    fn aggregate_byte_limit_closes_tunnel_and_rejects_later_requests() {
        let remote_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        remote_listener.set_nonblocking(true).unwrap();
        let remote_port = remote_listener.local_addr().unwrap().port();
        let original = super::super::tests::golden_authority();
        let mut limits = original.limits();
        limits.client_to_remote_bytes = 4;
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::Ipv4([127, 0, 0, 1]),
                port: TcpPort::new(remote_port).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            original.resolver().clone(),
            limits,
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, proxy_listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut first = TcpStream::connect(proxy_address).unwrap();
        first.set_nonblocking(true).unwrap();
        first
            .write_all(format!("CONNECT 127.0.0.1:{remote_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = [0_u8; 64];
        let mut established = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(count) = first.read(&mut response)
                && count != 0
            {
                assert_eq!(&response[..count], ProxyStatus::Established.bytes());
                established = true;
                break;
            }
        }
        assert!(established);
        let (mut remote, _) = remote_listener.accept().unwrap();
        remote.set_nonblocking(true).unwrap();
        first.write_all(b"abcdefgh").unwrap();
        let mut received = [0_u8; 8];
        let mut count = 0;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(bytes) = remote.read(&mut received[count..]) {
                count += bytes;
            }
            if engine.observations().connections().len() == 1 {
                break;
            }
        }
        assert_eq!(count, 4);
        assert_eq!(&received[..4], b"abcd");
        let mut second = TcpStream::connect(proxy_address).unwrap();
        second.set_nonblocking(true).unwrap();
        second
            .write_all(format!("CONNECT 127.0.0.1:{remote_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut limited = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(bytes) = second.read(&mut response)
                && bytes != 0
            {
                assert_eq!(&response[..bytes], ProxyStatus::TooManyRequests.bytes());
                limited = true;
                break;
            }
        }
        assert!(limited);
        let (observations, _, reports) = engine.drain().unwrap();
        assert_eq!(observations.connections().len(), 1);
        assert_eq!(observations.connections()[0].client_to_remote_bytes, 4);
        assert_eq!(
            observations.connections()[0].close_reason,
            CloseReason::ClientByteLimit
        );
        assert_eq!(observations.rejection_reason_counts()[9], 1);
        assert!(
            matches!(reports.last(), Some(ProxyReportEvent::Final { totals, .. }) if totals.client_bytes == 4)
        );
    }

    #[test]
    fn dns_special_answer_is_recorded_but_never_attempted() {
        let resolver = TcpListener::bind("127.0.0.1:0").unwrap();
        let resolver_port = resolver.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for family in 0..2 {
                let (mut stream, _) = resolver.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut query).unwrap();
                let mut response = query;
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                if family == 0 {
                    response[6..8].copy_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&30u32.to_be_bytes());
                    response.extend_from_slice(&4u16.to_be_bytes());
                    response.extend_from_slice(&[127, 0, 0, 1]);
                }
                stream
                    .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let original = super::super::tests::golden_authority();
        let policy = ResolutionPolicy::new(
            ResolverEndpoint::new(
                ResolverAddress::Ipv4([127, 0, 0, 1]),
                TcpPort::new(resolver_port).unwrap(),
            ),
            NetworkSupportPath::new("/etc/resolv.conf").unwrap(),
            4,
            16,
            512,
            2000,
            1000,
            AddressOrder::Ipv4ThenIpv6Lexicographic,
        )
        .unwrap();
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::DnsName {
                    name: EgressName::new("api.example").unwrap(),
                    scope: AddressScope::GlobalOrPrivate,
                },
                port: TcpPort::new(443).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            policy,
            original.limits(),
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut child = TcpStream::connect(address).unwrap();
        child.set_nonblocking(true).unwrap();
        child
            .write_all(b"CONNECT api.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut response = [0u8; 64];
        let mut denied = false;
        for _ in 0..400 {
            engine.step(Duration::from_millis(5)).unwrap();
            match child.read(&mut response) {
                Ok(count) if count != 0 => {
                    assert_eq!(&response[..count], ProxyStatus::BadGateway.bytes());
                    denied = true;
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("unexpected response error: {error}"),
            }
        }
        assert!(denied);
        server.join().unwrap();
        for _ in 0..4 {
            engine.step(Duration::from_millis(5)).unwrap();
        }
        let (observations, _, _) = engine.drain().unwrap();
        assert_eq!(observations.resolutions().len(), 1);
        assert_eq!(
            observations.resolutions()[0].outcome,
            DnsResolutionOutcome::NoAdmissibleAnswer
        );
        assert_eq!(observations.resolutions()[0].messages.len(), 2);
        assert_eq!(observations.connections().len(), 1);
        assert!(observations.connections()[0].attempts.is_empty());
        assert_eq!(
            observations.connections()[0].close_reason,
            CloseReason::NoAdmissibleAnswer
        );
    }

    #[test]
    fn refused_numeric_attempt_returns_502_and_records_refusal() {
        let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
        let denied_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let original = super::super::tests::golden_authority();
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::Ipv4([127, 0, 0, 1]),
                port: TcpPort::new(denied_port).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            original.resolver().clone(),
            original.limits(),
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut child = TcpStream::connect(address).unwrap();
        child.set_nonblocking(true).unwrap();
        child
            .write_all(format!("CONNECT 127.0.0.1:{denied_port} HTTP/1.1\r\n\r\n").as_bytes())
            .unwrap();
        let mut response = [0u8; 64];
        let mut denied = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            match child.read(&mut response) {
                Ok(count) if count != 0 => {
                    assert_eq!(&response[..count], ProxyStatus::BadGateway.bytes());
                    denied = true;
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("unexpected response error: {error}"),
            }
        }
        assert!(denied);
        let (observations, _, _) = engine.drain().unwrap();
        let connection = &observations.connections()[0];
        assert_eq!(connection.attempts.len(), 1);
        assert_eq!(connection.attempts[0].result, AttemptResult::Refused);
        assert_eq!(connection.close_reason, CloseReason::ConnectFailed);
    }

    #[test]
    fn provisional_client_bound_replies_429_without_unbounded_descriptors() {
        let original = super::super::tests::golden_authority();
        let mut limits = original.limits();
        limits.concurrent_connections = 1;
        let authority = EgressAuthority::new(
            original.endpoints().to_vec(),
            original.resolver().clone(),
            limits,
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let _first = TcpStream::connect(address).unwrap();
        let mut second = TcpStream::connect(address).unwrap();
        second.set_nonblocking(true).unwrap();
        let mut response = [0u8; 64];
        let mut rejected = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            match second.read(&mut response) {
                Ok(count) if count != 0 => {
                    assert_eq!(&response[..count], ProxyStatus::TooManyRequests.bytes());
                    rejected = true;
                    break;
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("unexpected response error: {error}"),
            }
        }
        assert!(rejected);
        assert!(engine.clients.iter().filter(|slot| slot.is_some()).count() <= 2);
        assert!(engine.budget.events().contains(&ProxyLimit::Concurrent));
        let (observations, _, _) = engine.drain().unwrap();
        assert_eq!(observations.rejection_total(), 1);
        assert!(observations.connections().is_empty());
    }

    #[test]
    fn exhausted_resolution_quota_returns_429_and_keeps_first_record() {
        let resolver = TcpListener::bind("127.0.0.1:0").unwrap();
        let resolver_port = resolver.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = resolver.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut query).unwrap();
                query[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                stream
                    .write_all(&u16::try_from(query.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&query).unwrap();
            }
        });
        let original = super::super::tests::golden_authority();
        let mut limits = original.limits();
        limits.resolutions = 1;
        limits.dns_messages = 2;
        let policy = ResolutionPolicy::new(
            ResolverEndpoint::new(
                ResolverAddress::Ipv4([127, 0, 0, 1]),
                TcpPort::new(resolver_port).unwrap(),
            ),
            NetworkSupportPath::new("/etc/resolv.conf").unwrap(),
            4,
            16,
            512,
            2000,
            1000,
            AddressOrder::Ipv4ThenIpv6Lexicographic,
        )
        .unwrap();
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::DnsName {
                    name: EgressName::new("api.example").unwrap(),
                    scope: AddressScope::Global,
                },
                port: TcpPort::new(443).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            policy,
            limits,
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut first = TcpStream::connect(address).unwrap();
        first.set_nonblocking(true).unwrap();
        first
            .write_all(b"CONNECT api.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut response = [0u8; 64];
        let mut first_failed = false;
        for _ in 0..400 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(count) = first.read(&mut response)
                && count != 0
            {
                assert_eq!(&response[..count], ProxyStatus::BadGateway.bytes());
                first_failed = true;
                break;
            }
        }
        assert!(first_failed);
        server.join().unwrap();
        let mut second = TcpStream::connect(address).unwrap();
        second.set_nonblocking(true).unwrap();
        second
            .write_all(b"CONNECT api.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut limited = false;
        for _ in 0..100 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(count) = second.read(&mut response)
                && count != 0
            {
                assert_eq!(&response[..count], ProxyStatus::TooManyRequests.bytes());
                limited = true;
                break;
            }
        }
        assert!(limited);
        let (observations, _, _) = engine.drain().unwrap();
        assert_eq!(observations.resolutions().len(), 1);
        assert_eq!(observations.connections().len(), 2);
        assert_eq!(observations.rejection_total(), 1);
        assert_eq!(observations.rejection_reason_counts()[7], 1);
    }

    #[test]
    fn dns_message_bound_returns_429_after_recording_both_replies() {
        let resolver = TcpListener::bind("127.0.0.1:0").unwrap();
        let resolver_port = resolver.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for query_index in 0..2 {
                let (mut stream, _) = resolver.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut length = [0u8; 2];
                stream.read_exact(&mut length).unwrap();
                let mut response = vec![0u8; usize::from(u16::from_be_bytes(length))];
                stream.read_exact(&mut response).unwrap();
                response[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&[0xc0, 0x0c]);
                response
                    .extend_from_slice(&(if query_index == 0 { 5u16 } else { 1u16 }).to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&30u32.to_be_bytes());
                let data = if query_index == 0 {
                    b"\x05alias\x07example\x00".to_vec()
                } else {
                    vec![127, 0, 0, 1]
                };
                response.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
                response.extend_from_slice(&data);
                stream
                    .write_all(&u16::try_from(response.len()).unwrap().to_be_bytes())
                    .unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        let original = super::super::tests::golden_authority();
        let mut limits = original.limits();
        limits.dns_messages = 2;
        let policy = ResolutionPolicy::new(
            ResolverEndpoint::new(
                ResolverAddress::Ipv4([127, 0, 0, 1]),
                TcpPort::new(resolver_port).unwrap(),
            ),
            NetworkSupportPath::new("/etc/resolv.conf").unwrap(),
            4,
            16,
            512,
            2000,
            1000,
            AddressOrder::Ipv4ThenIpv6Lexicographic,
        )
        .unwrap();
        let authority = EgressAuthority::new(
            vec![EgressEndpoint {
                destination: EgressDestination::DnsName {
                    name: EgressName::new("api.example").unwrap(),
                    scope: AddressScope::GlobalOrPrivate,
                },
                port: TcpPort::new(443).unwrap(),
                tls_sni: SniBinding::NotInspected,
            }],
            policy,
            limits,
            original.proxy_executable().clone(),
            original.proxy_runtime_read().to_vec(),
            original.proxy_environment().to_vec(),
            &[],
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let mut engine = EgressProxyEngine::new(authority, listener).unwrap();
        engine.mark_ready_and_serving().unwrap();
        let mut child = TcpStream::connect(address).unwrap();
        child.set_nonblocking(true).unwrap();
        child
            .write_all(b"CONNECT api.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut response = [0u8; 64];
        let mut limited = false;
        for _ in 0..400 {
            engine.step(Duration::from_millis(5)).unwrap();
            if let Ok(count) = child.read(&mut response)
                && count != 0
            {
                assert_eq!(&response[..count], ProxyStatus::TooManyRequests.bytes());
                limited = true;
                break;
            }
        }
        assert!(limited);
        server.join().unwrap();
        let (observations, _, _) = engine.drain().unwrap();
        assert_eq!(observations.resolutions().len(), 1);
        assert_eq!(observations.resolutions()[0].messages.len(), 2);
        assert_eq!(observations.rejection_reason_counts()[8], 1);
        assert_eq!(
            observations.connections()[0].close_reason,
            CloseReason::ResolutionFailed
        );
    }
}
