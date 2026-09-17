use core::fmt;

/// Identifies one connector-owned service-session phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSessionPhase {
    /// The connector has not started resolution.
    Created,
    /// The connector is resolving the declared service.
    Resolving,
    /// The connector is trying a recorded service endpoint.
    Connecting,
    /// The connector is authenticating the declared service.
    Authenticating,
    /// The authenticated channel is ready before child release.
    Ready,
    /// The child can exchange bounded application bytes.
    Active,
    /// The supervisor is closing the session.
    Closing,
    /// The session and connector reached clean terminal state.
    Closed,
    /// The session reached a typed failure terminal state.
    Failed,
}

/// Identifies one terminal service-session failure class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSessionFailureReason {
    /// DNS setup or resolution failed.
    Resolution,
    /// Every permitted endpoint attempt failed.
    Endpoint,
    /// TLS setup or authentication failed.
    Tls,
    /// The connector identity, protocol, or lifecycle failed.
    Connector,
    /// The private local channel failed.
    Channel,
    /// A declared service-session limit was exhausted.
    Limit,
    /// The launcher acknowledgement or release failed.
    Launcher,
    /// Terminal process, stream, or cgroup cleanup failed.
    Cleanup,
}

/// Selects one proposed service-session lifecycle event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceSessionEvent {
    /// Starts bounded service-name resolution.
    BeginResolution,
    /// Completes resolution with a bounded ordered endpoint set.
    ResolutionComplete,
    /// Completes one TCP connection to a recorded endpoint.
    EndpointConnected,
    /// Completes TLS authentication for the declared service.
    TlsAuthenticated,
    /// Releases the child after the complete boundary acknowledgement.
    ChildReleased,
    /// Starts terminal channel and connector shutdown.
    BeginClose,
    /// Completes terminal shutdown and cleanup.
    CloseComplete,
    /// Enters a typed terminal failure state.
    Fail(ServiceSessionFailureReason),
}

/// Contains the pure state of one proposed service-session lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServiceSessionLifecycle {
    phase: ServiceSessionPhase,
    failure: Option<ServiceSessionFailureReason>,
}

impl ServiceSessionLifecycle {
    /// Creates one lifecycle before resolver or connector effects begin.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            phase: ServiceSessionPhase::Created,
            failure: None,
        }
    }

    /// Returns the current closed phase.
    #[must_use]
    pub const fn phase(self) -> ServiceSessionPhase {
        self.phase
    }

    /// Returns the typed failure reason for a failed terminal state.
    #[must_use]
    pub const fn failure_reason(self) -> Option<ServiceSessionFailureReason> {
        self.failure
    }

    /// Reports whether the lifecycle is terminal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self.phase,
            ServiceSessionPhase::Closed | ServiceSessionPhase::Failed
        )
    }

    /// Applies one event without executing a resolver, connector, or child.
    pub const fn transition(
        self,
        event: ServiceSessionEvent,
    ) -> Result<Self, ServiceLifecycleError> {
        let next = match (self.phase, event) {
            (ServiceSessionPhase::Created, ServiceSessionEvent::BeginResolution) => {
                ServiceSessionPhase::Resolving
            }
            (ServiceSessionPhase::Resolving, ServiceSessionEvent::ResolutionComplete) => {
                ServiceSessionPhase::Connecting
            }
            (ServiceSessionPhase::Connecting, ServiceSessionEvent::EndpointConnected) => {
                ServiceSessionPhase::Authenticating
            }
            (ServiceSessionPhase::Authenticating, ServiceSessionEvent::TlsAuthenticated) => {
                ServiceSessionPhase::Ready
            }
            (ServiceSessionPhase::Ready, ServiceSessionEvent::ChildReleased) => {
                ServiceSessionPhase::Active
            }
            (ServiceSessionPhase::Active, ServiceSessionEvent::BeginClose) => {
                ServiceSessionPhase::Closing
            }
            (ServiceSessionPhase::Closing, ServiceSessionEvent::CloseComplete) => {
                ServiceSessionPhase::Closed
            }
            (
                ServiceSessionPhase::Created
                | ServiceSessionPhase::Resolving
                | ServiceSessionPhase::Connecting
                | ServiceSessionPhase::Authenticating
                | ServiceSessionPhase::Ready
                | ServiceSessionPhase::Active
                | ServiceSessionPhase::Closing,
                ServiceSessionEvent::Fail(reason),
            ) => {
                return Ok(Self {
                    phase: ServiceSessionPhase::Failed,
                    failure: Some(reason),
                });
            }
            _ => return Err(ServiceLifecycleError::InvalidTransition),
        };
        Ok(Self {
            phase: next,
            failure: None,
        })
    }
}

impl Default for ServiceSessionLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

/// Identifies an invalid pure service-session transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceLifecycleError {
    /// The event is not valid from the current phase.
    InvalidTransition,
}

impl ServiceLifecycleError {
    /// Returns the stable machine code for this error.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidTransition => "network.connector.lifecycle.transition.invalid",
        }
    }
}

impl fmt::Display for ServiceLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ServiceLifecycleError {}

#[cfg(test)]
mod tests {
    use super::*;

    const PHASES: [ServiceSessionPhase; 9] = [
        ServiceSessionPhase::Created,
        ServiceSessionPhase::Resolving,
        ServiceSessionPhase::Connecting,
        ServiceSessionPhase::Authenticating,
        ServiceSessionPhase::Ready,
        ServiceSessionPhase::Active,
        ServiceSessionPhase::Closing,
        ServiceSessionPhase::Closed,
        ServiceSessionPhase::Failed,
    ];

    const EVENTS: [ServiceSessionEvent; 7] = [
        ServiceSessionEvent::BeginResolution,
        ServiceSessionEvent::ResolutionComplete,
        ServiceSessionEvent::EndpointConnected,
        ServiceSessionEvent::TlsAuthenticated,
        ServiceSessionEvent::ChildReleased,
        ServiceSessionEvent::BeginClose,
        ServiceSessionEvent::CloseComplete,
    ];

    fn lifecycle(phase: ServiceSessionPhase) -> ServiceSessionLifecycle {
        ServiceSessionLifecycle {
            phase,
            failure: (phase == ServiceSessionPhase::Failed)
                .then_some(ServiceSessionFailureReason::Connector),
        }
    }

    fn expected_success(phase: ServiceSessionPhase, event: ServiceSessionEvent) -> bool {
        matches!(
            (phase, event),
            (
                ServiceSessionPhase::Created,
                ServiceSessionEvent::BeginResolution
            ) | (
                ServiceSessionPhase::Resolving,
                ServiceSessionEvent::ResolutionComplete
            ) | (
                ServiceSessionPhase::Connecting,
                ServiceSessionEvent::EndpointConnected
            ) | (
                ServiceSessionPhase::Authenticating,
                ServiceSessionEvent::TlsAuthenticated
            ) | (
                ServiceSessionPhase::Ready,
                ServiceSessionEvent::ChildReleased
            ) | (ServiceSessionPhase::Active, ServiceSessionEvent::BeginClose)
                | (
                    ServiceSessionPhase::Closing,
                    ServiceSessionEvent::CloseComplete
                )
        )
    }

    #[test]
    fn lifecycle_requires_complete_forward_release_order() {
        let mut state = ServiceSessionLifecycle::new();
        for (event, phase) in [
            (
                ServiceSessionEvent::BeginResolution,
                ServiceSessionPhase::Resolving,
            ),
            (
                ServiceSessionEvent::ResolutionComplete,
                ServiceSessionPhase::Connecting,
            ),
            (
                ServiceSessionEvent::EndpointConnected,
                ServiceSessionPhase::Authenticating,
            ),
            (
                ServiceSessionEvent::TlsAuthenticated,
                ServiceSessionPhase::Ready,
            ),
            (
                ServiceSessionEvent::ChildReleased,
                ServiceSessionPhase::Active,
            ),
            (
                ServiceSessionEvent::BeginClose,
                ServiceSessionPhase::Closing,
            ),
            (
                ServiceSessionEvent::CloseComplete,
                ServiceSessionPhase::Closed,
            ),
        ] {
            state = state
                .transition(event)
                .expect("forward transition is valid");
            assert_eq!(state.phase(), phase);
            assert_eq!(state.failure_reason(), None);
        }
        assert!(state.is_terminal());
    }

    #[test]
    fn lifecycle_rejects_every_unregistered_non_failure_transition() {
        for phase in PHASES {
            for event in EVENTS {
                assert_eq!(
                    lifecycle(phase).transition(event).is_ok(),
                    expected_success(phase, event),
                    "unexpected transition from {phase:?} with {event:?}",
                );
            }
        }
    }

    #[test]
    fn failure_is_typed_and_terminal_from_every_nonterminal_phase() {
        for phase in PHASES {
            let result = lifecycle(phase).transition(ServiceSessionEvent::Fail(
                ServiceSessionFailureReason::Cleanup,
            ));
            if matches!(
                phase,
                ServiceSessionPhase::Closed | ServiceSessionPhase::Failed
            ) {
                assert_eq!(result, Err(ServiceLifecycleError::InvalidTransition));
            } else {
                let failed = result.expect("a nonterminal phase can fail");
                assert_eq!(failed.phase(), ServiceSessionPhase::Failed);
                assert_eq!(
                    failed.failure_reason(),
                    Some(ServiceSessionFailureReason::Cleanup)
                );
                assert!(failed.is_terminal());
                assert_eq!(
                    failed.transition(ServiceSessionEvent::BeginResolution),
                    Err(ServiceLifecycleError::InvalidTransition)
                );
            }
        }
    }
}
