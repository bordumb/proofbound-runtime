//! Numeric, nonblocking TCP connect attempts for the proxy event loop.

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd as _, OwnedFd};
use std::time::Duration;

/// Retains a socket started against one pinned numeric address.
#[derive(Debug)]
pub struct PendingTcpConnect {
    address: SocketAddr,
    descriptor: OwnedFd,
}

impl PendingTcpConnect {
    /// Starts exactly one nonblocking TCP attempt in the caller's namespace.
    pub fn start(address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            address,
            descriptor: crate::sys::connect_tcp_nonblocking(address)?,
        })
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn descriptor(&self) -> std::os::fd::RawFd {
        self.descriptor.as_raw_fd()
    }

    pub(crate) fn result(&self) -> io::Result<()> {
        crate::sys::tcp_connect_result(self.descriptor.as_raw_fd())
    }

    /// Transfers the established descriptor to a nonblocking stream.
    #[must_use]
    pub fn into_stream(self) -> TcpStream {
        TcpStream::from(self.descriptor)
    }
}

/// Polls all pending attempts together, returning one result for every ready fd.
///
/// `None` means the attempt is still pending. A ready socket is checked with
/// SO_ERROR even when readiness was reported as hangup or error.
pub fn poll_connect_attempts(
    attempts: &[PendingTcpConnect],
    timeout: Duration,
) -> io::Result<Vec<Option<io::Result<()>>>> {
    let interests = attempts
        .iter()
        .map(|attempt| crate::sys::PollInterest {
            descriptor: attempt.descriptor.as_raw_fd(),
            readable: false,
            writable: true,
        })
        .collect::<Vec<_>>();
    let ready = crate::sys::poll_many(&interests, timeout)?;
    Ok(attempts
        .iter()
        .zip(ready)
        .map(|(attempt, ready)| {
            if ready.readable || ready.writable || ready.error || ready.hangup {
                Some(crate::sys::tcp_connect_result(
                    attempt.descriptor.as_raw_fd(),
                ))
            } else {
                None
            }
        })
        .collect())
}

/// A bounded, nonblocking DNS-over-TCP exchange to the numeric resolver.
#[derive(Debug)]
pub struct DnsTcpExchange {
    stage: DnsTcpStage,
    frame: Vec<u8>,
    cursor: usize,
    maximum_response_bytes: u64,
    deadline_ms: u64,
}

#[derive(Debug)]
enum DnsTcpStage {
    Connecting(PendingTcpConnect),
    Writing(TcpStream),
    ReadingLength(TcpStream, [u8; 2]),
    ReadingMessage(TcpStream, Vec<u8>),
    Complete,
}

/// Fail-closed transport outcomes; semantic DNS checks occur separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsTransportError {
    Deadline,
    Io,
    Truncated,
    TooLarge,
    AlreadyComplete,
}

impl DnsTcpExchange {
    /// Starts a fresh TCP connection to the declared numeric resolver.
    pub fn start(
        resolver: SocketAddr,
        query: &super::dns::DnsQuery,
        maximum_response_bytes: u64,
        deadline_ms: u64,
    ) -> io::Result<Self> {
        Ok(Self {
            stage: DnsTcpStage::Connecting(PendingTcpConnect::start(resolver)?),
            frame: query.tcp_frame(),
            cursor: 0,
            maximum_response_bytes,
            deadline_ms,
        })
    }

    pub(crate) fn interest(&self) -> Option<crate::sys::PollInterest> {
        let (descriptor, readable, writable) = match &self.stage {
            DnsTcpStage::Connecting(attempt) => (attempt.descriptor.as_raw_fd(), false, true),
            DnsTcpStage::Writing(stream) => (stream.as_raw_fd(), false, true),
            DnsTcpStage::ReadingLength(stream, _) | DnsTcpStage::ReadingMessage(stream, _) => {
                (stream.as_raw_fd(), true, false)
            }
            DnsTcpStage::Complete => return None,
        };
        Some(crate::sys::PollInterest {
            descriptor,
            readable,
            writable,
        })
    }

    /// Advances at most one bounded I/O operation after descriptor readiness.
    ///
    /// A complete message is returned exactly once. EOF before the declared
    /// length is a truncated response; no partial packet reaches the decoder.
    pub(crate) fn on_ready(
        &mut self,
        now_ms: u64,
        ready: crate::sys::PollReady,
    ) -> Result<Option<Vec<u8>>, DnsTransportError> {
        if now_ms >= self.deadline_ms {
            return Err(DnsTransportError::Deadline);
        }
        if !(ready.readable || ready.writable || ready.error || ready.hangup) {
            return Ok(None);
        }
        let stage = std::mem::replace(&mut self.stage, DnsTcpStage::Complete);
        match stage {
            DnsTcpStage::Connecting(attempt) => {
                crate::sys::tcp_connect_result(attempt.descriptor.as_raw_fd())
                    .map_err(|_| DnsTransportError::Io)?;
                self.stage = DnsTcpStage::Writing(attempt.into_stream());
                Ok(None)
            }
            DnsTcpStage::Writing(mut stream) => {
                use std::io::Write as _;
                match stream.write(&self.frame[self.cursor..]) {
                    Ok(0) => Err(DnsTransportError::Truncated),
                    Ok(written) => {
                        self.cursor += written;
                        self.stage = if self.cursor == self.frame.len() {
                            self.cursor = 0;
                            DnsTcpStage::ReadingLength(stream, [0; 2])
                        } else {
                            DnsTcpStage::Writing(stream)
                        };
                        Ok(None)
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.stage = DnsTcpStage::Writing(stream);
                        Ok(None)
                    }
                    Err(_) => Err(DnsTransportError::Io),
                }
            }
            DnsTcpStage::ReadingLength(mut stream, mut length) => {
                use std::io::Read as _;
                match stream.read(&mut length[self.cursor..]) {
                    Ok(0) => Err(DnsTransportError::Truncated),
                    Ok(received) => {
                        self.cursor += received;
                        if self.cursor == 2 {
                            let size = usize::from(u16::from_be_bytes(length));
                            if size == 0 || size as u64 > self.maximum_response_bytes {
                                return Err(DnsTransportError::TooLarge);
                            }
                            self.cursor = 0;
                            self.stage = DnsTcpStage::ReadingMessage(stream, vec![0; size]);
                        } else {
                            self.stage = DnsTcpStage::ReadingLength(stream, length);
                        }
                        Ok(None)
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.stage = DnsTcpStage::ReadingLength(stream, length);
                        Ok(None)
                    }
                    Err(_) => Err(DnsTransportError::Io),
                }
            }
            DnsTcpStage::ReadingMessage(mut stream, mut message) => {
                use std::io::Read as _;
                let end = (self.cursor + 8192).min(message.len());
                match stream.read(&mut message[self.cursor..end]) {
                    Ok(0) => Err(DnsTransportError::Truncated),
                    Ok(received) => {
                        self.cursor += received;
                        if self.cursor == message.len() {
                            Ok(Some(message))
                        } else {
                            self.stage = DnsTcpStage::ReadingMessage(stream, message);
                            Ok(None)
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.stage = DnsTcpStage::ReadingMessage(stream, message);
                        Ok(None)
                    }
                    Err(_) => Err(DnsTransportError::Io),
                }
            }
            DnsTcpStage::Complete => Err(DnsTransportError::AlreadyComplete),
        }
    }
}

/// One optional progress result for each polled DNS exchange.
pub type DnsPollOutcome = Vec<Option<Result<Option<Vec<u8>>, DnsTransportError>>>;

/// Polls all active DNS exchanges together without a helper thread.
///
/// The returned vector aligns with `exchanges`; `None` means no progress for
/// that entry. A completed message appears exactly once as `Ok(Some(bytes))`.
pub fn poll_dns_exchanges(
    exchanges: &mut [DnsTcpExchange],
    origin: std::time::Instant,
    maximum_wait: Duration,
) -> io::Result<DnsPollOutcome> {
    let now_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
    let timeout = exchanges
        .iter()
        .filter_map(|exchange| exchange.interest().map(|_| exchange.deadline_ms))
        .map(|deadline| Duration::from_millis(deadline.saturating_sub(now_ms)))
        .min()
        .map_or(maximum_wait, |deadline| deadline.min(maximum_wait));
    let active = exchanges
        .iter()
        .enumerate()
        .filter_map(|(index, exchange)| exchange.interest().map(|interest| (index, interest)))
        .collect::<Vec<_>>();
    let interests = active
        .iter()
        .map(|(_, interest)| *interest)
        .collect::<Vec<_>>();
    let ready = crate::sys::poll_many(&interests, timeout)?;
    let now_ms = u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut result = (0..exchanges.len()).map(|_| None).collect::<Vec<_>>();
    for ((index, _), ready) in active.into_iter().zip(ready) {
        if now_ms >= exchanges[index].deadline_ms
            || ready.readable
            || ready.writable
            || ready.error
            || ready.hangup
        {
            result[index] = Some(exchanges[index].on_ready(now_ms, ready));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proofbound_runtime_core::ServiceName;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::time::Instant;

    #[test]
    fn local_dns_tcp_exchange_is_nonblocking_and_length_bounded() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let resolver = listener.local_addr().unwrap();
        let query = super::super::dns::DnsQuery::new(
            ServiceName::new("api.example").unwrap(),
            super::super::dns::DnsRecordType::A,
            17,
        );
        let expected = query.tcp_frame();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = vec![0; expected.len()];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(request, expected);
            let mut response = expected[2..].to_vec();
            response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
            let mut frame = Vec::new();
            frame.extend_from_slice(&u16::try_from(response.len()).unwrap().to_be_bytes());
            frame.extend_from_slice(&response);
            stream.write_all(&frame).unwrap();
            response
        });
        let origin = Instant::now();
        let mut exchanges = vec![DnsTcpExchange::start(resolver, &query, 512, 2000).unwrap()];
        for _ in 0..200 {
            let progress =
                poll_dns_exchanges(&mut exchanges, origin, Duration::from_millis(10)).unwrap();
            match &progress[0] {
                Some(Ok(Some(bytes))) => {
                    assert_eq!(*bytes, server.join().unwrap());
                    return;
                }
                Some(Err(error)) => panic!("DNS exchange failed: {error:?}"),
                _ => {}
            }
        }
        panic!("DNS exchange did not finish before its local fixture deadline");
    }
}
