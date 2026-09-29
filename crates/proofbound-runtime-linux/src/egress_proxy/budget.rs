//! Checked aggregate limits for one proxy process generation.

use std::collections::BTreeSet;

use proofbound_runtime_core::EgressLimits;

/// Names a bounded proxy resource and its stable limit event.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProxyLimit {
    Connections,
    Concurrent,
    Resolutions,
    DnsMessages,
    ClientBytes,
    RemoteBytes,
}

impl ProxyLimit {
    #[must_use]
    pub const fn event(self) -> &'static str {
        match self {
            Self::Connections => "egress-limit-connections",
            Self::Concurrent => "egress-limit-concurrent",
            Self::Resolutions => "egress-limit-resolutions",
            Self::DnsMessages => "egress-limit-dns-messages",
            Self::ClientBytes => "egress-limit-client-bytes",
            Self::RemoteBytes => "egress-limit-remote-bytes",
        }
    }
}

/// The exact number of bytes that may be relayed from one input buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteGrant {
    pub permitted: u64,
    pub exhausted: bool,
}

/// Tracks only completed resource facts; the caller owns connection records.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyBudget {
    limits: EgressLimits,
    connections: u16,
    active: u16,
    resolutions: u16,
    dns_messages: u16,
    client_bytes: u64,
    remote_bytes: u64,
    events: BTreeSet<ProxyLimit>,
}

impl ProxyBudget {
    #[must_use]
    pub const fn limits(&self) -> EgressLimits {
        self.limits
    }

    #[must_use]
    pub fn new(limits: EgressLimits) -> Self {
        Self {
            limits,
            connections: 0,
            active: 0,
            resolutions: 0,
            dns_messages: 0,
            client_bytes: 0,
            remote_bytes: 0,
            events: BTreeSet::new(),
        }
    }

    /// Counts one connection only after its declared endpoint is identified.
    /// Undeclared or malformed requests enter the separate rejection count.
    pub fn open_connection(&mut self) -> Result<u16, ProxyLimit> {
        if self.connections == self.limits.connections {
            self.events.insert(ProxyLimit::Connections);
            return Err(ProxyLimit::Connections);
        }
        if self.active == self.limits.concurrent_connections {
            self.events.insert(ProxyLimit::Concurrent);
            return Err(ProxyLimit::Concurrent);
        }
        self.connections += 1;
        self.active += 1;
        Ok(self.connections)
    }

    /// A close may occur exactly once for every accepted open.
    pub fn close_connection(&mut self) -> bool {
        let Some(active) = self.active.checked_sub(1) else {
            return false;
        };
        self.active = active;
        true
    }

    /// Reserves one proxy-owned name resolution before any query is sent.
    pub fn begin_resolution(&mut self) -> Result<u16, ProxyLimit> {
        if self.resolutions == self.limits.resolutions {
            self.events.insert(ProxyLimit::Resolutions);
            return Err(ProxyLimit::Resolutions);
        }
        self.resolutions += 1;
        Ok(self.resolutions)
    }

    /// Refuses a new query when its response could not fit the message bound.
    pub fn can_issue_dns_query(&mut self) -> Result<(), ProxyLimit> {
        if self.dns_messages == self.limits.dns_messages {
            self.events.insert(ProxyLimit::DnsMessages);
            Err(ProxyLimit::DnsMessages)
        } else {
            Ok(())
        }
    }

    /// Counts one complete DNS response before retaining its identity.
    pub fn record_dns_message(&mut self) -> Result<u16, ProxyLimit> {
        if self.dns_messages == self.limits.dns_messages {
            self.events.insert(ProxyLimit::DnsMessages);
            return Err(ProxyLimit::DnsMessages);
        }
        self.dns_messages += 1;
        Ok(self.dns_messages)
    }

    /// Caps a pending write before the kernel sees any bytes.
    #[must_use]
    pub const fn remaining_client_bytes(&self) -> u64 {
        self.limits.client_to_remote_bytes - self.client_bytes
    }

    /// Caps a pending write before the kernel sees any bytes.
    #[must_use]
    pub const fn remaining_remote_bytes(&self) -> u64 {
        self.limits.remote_to_client_bytes - self.remote_bytes
    }

    /// Grants no more than the remaining aggregate client-to-remote bytes.
    pub fn grant_client_bytes(&mut self, requested: u64) -> ByteGrant {
        grant_bytes(
            &mut self.client_bytes,
            self.limits.client_to_remote_bytes,
            requested,
            ProxyLimit::ClientBytes,
            &mut self.events,
        )
    }

    /// Grants no more than the remaining aggregate remote-to-client bytes.
    pub fn grant_remote_bytes(&mut self, requested: u64) -> ByteGrant {
        grant_bytes(
            &mut self.remote_bytes,
            self.limits.remote_to_client_bytes,
            requested,
            ProxyLimit::RemoteBytes,
            &mut self.events,
        )
    }

    #[must_use]
    pub fn events(&self) -> &BTreeSet<ProxyLimit> {
        &self.events
    }

    /// Records a bound refused before it could consume a counted resource.
    pub fn note_limit(&mut self, limit: ProxyLimit) {
        self.events.insert(limit);
    }

    #[must_use]
    pub const fn totals(&self) -> ProxyTotals {
        ProxyTotals {
            connections: self.connections,
            active: self.active,
            resolutions: self.resolutions,
            dns_messages: self.dns_messages,
            client_bytes: self.client_bytes,
            remote_bytes: self.remote_bytes,
        }
    }
}

/// Counts the proxy facts used to build and verify the final observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyTotals {
    pub connections: u16,
    pub active: u16,
    pub resolutions: u16,
    pub dns_messages: u16,
    pub client_bytes: u64,
    pub remote_bytes: u64,
}

fn grant_bytes(
    total: &mut u64,
    limit: u64,
    requested: u64,
    reason: ProxyLimit,
    events: &mut BTreeSet<ProxyLimit>,
) -> ByteGrant {
    if requested == 0 {
        return ByteGrant {
            permitted: 0,
            exhausted: *total == limit,
        };
    }
    let remaining = limit - *total;
    let permitted = requested.min(remaining);
    *total += permitted;
    let exhausted = *total == limit;
    if exhausted {
        events.insert(reason);
    }
    ByteGrant {
        permitted,
        exhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> EgressLimits {
        EgressLimits {
            connections: 2,
            concurrent_connections: 1,
            attempts_per_connection: 1,
            resolutions: 1,
            dns_messages: 2,
            client_to_remote_bytes: 5,
            remote_to_client_bytes: 7,
            connection_idle_ms: 1000,
        }
    }

    #[test]
    fn connection_and_dns_bounds_are_checked_before_increment() {
        let mut budget = ProxyBudget::new(limits());
        assert_eq!(budget.open_connection(), Ok(1));
        assert_eq!(budget.open_connection(), Err(ProxyLimit::Concurrent));
        assert!(budget.close_connection());
        assert!(!budget.close_connection());
        assert_eq!(budget.open_connection(), Ok(2));
        assert_eq!(budget.open_connection(), Err(ProxyLimit::Connections));
        assert_eq!(budget.begin_resolution(), Ok(1));
        assert_eq!(budget.begin_resolution(), Err(ProxyLimit::Resolutions));
        assert_eq!(budget.record_dns_message(), Ok(1));
        assert_eq!(budget.record_dns_message(), Ok(2));
        assert_eq!(budget.record_dns_message(), Err(ProxyLimit::DnsMessages));
        assert_eq!(budget.totals().connections, 2);
        assert_eq!(budget.totals().resolutions, 1);
        assert_eq!(budget.totals().dns_messages, 2);
    }

    #[test]
    fn byte_grants_never_cross_either_aggregate_bound() {
        let mut budget = ProxyBudget::new(limits());
        assert_eq!(
            budget.grant_client_bytes(3),
            ByteGrant {
                permitted: 3,
                exhausted: false
            }
        );
        assert_eq!(
            budget.grant_client_bytes(u64::MAX),
            ByteGrant {
                permitted: 2,
                exhausted: true
            }
        );
        assert_eq!(
            budget.grant_client_bytes(1),
            ByteGrant {
                permitted: 0,
                exhausted: true
            }
        );
        assert_eq!(
            budget.grant_remote_bytes(7),
            ByteGrant {
                permitted: 7,
                exhausted: true
            }
        );
        assert_eq!(budget.totals().client_bytes, 5);
        assert_eq!(budget.totals().remote_bytes, 7);
        assert_eq!(budget.remaining_client_bytes(), 0);
        assert_eq!(budget.remaining_remote_bytes(), 0);
        assert!(budget.events().contains(&ProxyLimit::ClientBytes));
        assert!(budget.events().contains(&ProxyLimit::RemoteBytes));
    }
}
