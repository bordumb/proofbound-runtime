//! Bounded duplex relay advanced by the proxy's shared poll loop.

use std::io::{self, Read as _, Write as _};
use std::net::TcpStream;
use std::os::fd::{AsRawFd as _, RawFd};

use super::budget::ProxyBudget;
use super::observation::CloseReason;

const RELAY_BUFFER_BYTES: usize = 8192;

#[derive(Debug, Default)]
struct PendingBytes {
    bytes: Vec<u8>,
    sent: usize,
}

impl PendingBytes {
    fn is_empty(&self) -> bool {
        self.sent == self.bytes.len()
    }

    fn replace(&mut self, bytes: &[u8]) {
        self.bytes.clear();
        self.bytes.extend_from_slice(bytes);
        self.sent = 0;
    }
}

/// A terminal step is returned as soon as one side closes or a bound trips.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayStep {
    Open,
    Closed(CloseReason),
}

/// Poll readiness supplied by the single proxy event loop.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayReady {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub hangup: bool,
}

/// One pair of nonblocking streams, each with one fixed-size pending buffer.
/// The event loop polls all pairs together and calls `advance` only on ready
/// descriptors. Byte counters increase only after successful kernel writes.
#[derive(Debug)]
pub struct RelayPair {
    client: TcpStream,
    remote: TcpStream,
    to_remote: PendingBytes,
    to_client: PendingBytes,
    client_to_remote_bytes: u64,
    remote_to_client_bytes: u64,
    last_progress_ms: u64,
}

impl RelayPair {
    pub fn new(client: TcpStream, remote: TcpStream, now_ms: u64) -> io::Result<Self> {
        client.set_nonblocking(true)?;
        remote.set_nonblocking(true)?;
        Ok(Self {
            client,
            remote,
            to_remote: PendingBytes::default(),
            to_client: PendingBytes::default(),
            client_to_remote_bytes: 0,
            remote_to_client_bytes: 0,
            last_progress_ms: now_ms,
        })
    }

    /// Buffered bytes from a CONNECT head or matched ClientHello are relayed
    /// unchanged after the remote attempt succeeds.
    pub fn seed_client_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        if bytes.len()
            > super::MAX_CONNECT_HEAD_BYTES
                + super::MAX_CLIENT_HELLO_BYTES
                + 5 * super::MAX_CLIENT_HELLO_RECORDS
            || !self.to_remote.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay seed bound",
            ));
        }
        self.to_remote.replace(bytes);
        Ok(())
    }

    #[must_use]
    pub fn interests(&self) -> [(RawFd, bool, bool); 2] {
        [
            (
                self.client.as_raw_fd(),
                self.to_remote.is_empty(),
                !self.to_client.is_empty(),
            ),
            (
                self.remote.as_raw_fd(),
                self.to_client.is_empty(),
                !self.to_remote.is_empty(),
            ),
        ]
    }

    #[must_use]
    pub const fn bytes(&self) -> (u64, u64) {
        (self.client_to_remote_bytes, self.remote_to_client_bytes)
    }

    /// Performs at most one read or write per ready direction, keeping other
    /// tunnels eligible for the next event-loop iteration.
    pub fn advance(
        &mut self,
        client_ready: RelayReady,
        remote_ready: RelayReady,
        now_ms: u64,
        budget: &mut ProxyBudget,
    ) -> io::Result<RelayStep> {
        if now_ms.saturating_sub(self.last_progress_ms)
            >= u64::from(budget.limits().connection_idle_ms)
        {
            return Ok(RelayStep::Closed(CloseReason::IdleTimeout));
        }
        if client_ready.error || remote_ready.error {
            return Ok(RelayStep::Closed(CloseReason::Reset));
        }
        if remote_ready.writable && !self.to_remote.is_empty() {
            if budget.remaining_client_bytes() == 0 {
                return Ok(RelayStep::Closed(CloseReason::ClientByteLimit));
            }
            let pending = &self.to_remote.bytes[self.to_remote.sent..];
            let cap = pending
                .len()
                .min(usize::try_from(budget.remaining_client_bytes()).unwrap_or(usize::MAX));
            match self.remote.write(&pending[..cap]) {
                Ok(0) => return Ok(RelayStep::Closed(CloseReason::RemoteClosed)),
                Ok(written) => {
                    self.to_remote.sent += written;
                    self.client_to_remote_bytes += written as u64;
                    self.last_progress_ms = now_ms;
                    let grant = budget.grant_client_bytes(written as u64);
                    debug_assert_eq!(grant.permitted, written as u64);
                    if grant.exhausted {
                        return Ok(RelayStep::Closed(CloseReason::ClientByteLimit));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(RelayStep::Closed(CloseReason::Reset));
                }
                Err(error) => return Err(error),
            }
        }
        if client_ready.writable && !self.to_client.is_empty() {
            if budget.remaining_remote_bytes() == 0 {
                return Ok(RelayStep::Closed(CloseReason::RemoteByteLimit));
            }
            let pending = &self.to_client.bytes[self.to_client.sent..];
            let cap = pending
                .len()
                .min(usize::try_from(budget.remaining_remote_bytes()).unwrap_or(usize::MAX));
            match self.client.write(&pending[..cap]) {
                Ok(0) => return Ok(RelayStep::Closed(CloseReason::ClientClosed)),
                Ok(written) => {
                    self.to_client.sent += written;
                    self.remote_to_client_bytes += written as u64;
                    self.last_progress_ms = now_ms;
                    let grant = budget.grant_remote_bytes(written as u64);
                    debug_assert_eq!(grant.permitted, written as u64);
                    if grant.exhausted {
                        return Ok(RelayStep::Closed(CloseReason::RemoteByteLimit));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(RelayStep::Closed(CloseReason::Reset));
                }
                Err(error) => return Err(error),
            }
        }
        if client_ready.readable && self.to_remote.is_empty() {
            let mut buffer = [0u8; RELAY_BUFFER_BYTES];
            match self.client.read(&mut buffer) {
                Ok(0) => return Ok(RelayStep::Closed(CloseReason::ClientClosed)),
                Ok(count) => {
                    self.to_remote.replace(&buffer[..count]);
                    self.last_progress_ms = now_ms;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(RelayStep::Closed(CloseReason::Reset));
                }
                Err(error) => return Err(error),
            }
        }
        if remote_ready.readable && self.to_client.is_empty() {
            let mut buffer = [0u8; RELAY_BUFFER_BYTES];
            match self.remote.read(&mut buffer) {
                Ok(0) => return Ok(RelayStep::Closed(CloseReason::RemoteClosed)),
                Ok(count) => {
                    self.to_client.replace(&buffer[..count]);
                    self.last_progress_ms = now_ms;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
                    return Ok(RelayStep::Closed(CloseReason::Reset));
                }
                Err(error) => return Err(error),
            }
        }
        if client_ready.hangup {
            return Ok(RelayStep::Closed(CloseReason::ClientClosed));
        }
        if remote_ready.hangup {
            return Ok(RelayStep::Closed(CloseReason::RemoteClosed));
        }
        Ok(RelayStep::Open)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::EgressLimits;
    use std::net::TcpListener;
    use std::time::Duration;

    #[test]
    fn seeded_bytes_stop_exactly_at_aggregate_client_limit() {
        let client_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let child = TcpStream::connect(client_listener.local_addr().unwrap()).unwrap();
        let (proxy_client, _) = client_listener.accept().unwrap();
        let remote_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_remote = TcpStream::connect(remote_listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = remote_listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut relay = RelayPair::new(proxy_client, proxy_remote, 0).unwrap();
        relay.seed_client_bytes(b"secret").unwrap();
        let mut budget = ProxyBudget::new(EgressLimits {
            connections: 1,
            concurrent_connections: 1,
            attempts_per_connection: 1,
            resolutions: 1,
            dns_messages: 2,
            client_to_remote_bytes: 3,
            remote_to_client_bytes: 3,
            connection_idle_ms: 1000,
        });
        let mut closed = false;
        for _ in 0..100 {
            let interests = relay.interests().map(|(descriptor, readable, writable)| {
                crate::sys::PollInterest {
                    descriptor,
                    readable,
                    writable,
                }
            });
            let readiness = crate::sys::poll_many(&interests, Duration::from_millis(10)).unwrap();
            let ready = readiness
                .into_iter()
                .map(|item| RelayReady {
                    readable: item.readable,
                    writable: item.writable,
                    error: item.error,
                    hangup: item.hangup,
                })
                .collect::<Vec<_>>();
            if relay.advance(ready[0], ready[1], 1, &mut budget).unwrap()
                == RelayStep::Closed(CloseReason::ClientByteLimit)
            {
                closed = true;
                break;
            }
        }
        assert!(closed);
        assert_eq!(relay.bytes(), (3, 0));
        let mut received = [0u8; 3];
        server.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"sec");
        assert_eq!(budget.totals().client_bytes, 3);
        drop(child);
    }
}
