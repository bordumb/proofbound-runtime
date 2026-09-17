#![deny(unsafe_code)]

//! Establishes one bounded authenticated service session.

mod dns;
mod tls;

pub use dns::{
    DnsAnswer, DnsCnameObservation, DnsError, DnsMessageObservation, DnsResolution, resolve_service,
};
pub use tls::{
    AuthenticateError, AuthenticatedTlsSession, ChannelError, EndpointAttempt,
    EndpointAttemptResult, TlsError, TlsObservation, TlsVersion, TrafficObservation,
    authenticate_service, proxy_authenticated_channel,
};
