//! Closed proxy lifecycle enforced before each report emission.

/// The only observable proxy phases from Specification 0017 section 5.5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyPhase {
    Created,
    Ready,
    Serving,
    Draining,
    Closed,
    Failed,
}

impl ProxyPhase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Ready => "ready",
            Self::Serving => "serving",
            Self::Draining => "draining",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }
}

/// Closed failure reason; child-selected data cannot enter a report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyFailure {
    Bootstrap,
    Confinement,
    Protocol,
    Transport,
    Report,
    Deadline,
}

impl ProxyFailure {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Confinement => "confinement",
            Self::Protocol => "protocol",
            Self::Transport => "transport",
            Self::Report => "report",
            Self::Deadline => "deadline",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyPhaseError {
    InvalidTransition,
}

/// Records one exact path; a terminal state cannot be exited.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyLifecycle {
    phases: Vec<ProxyPhase>,
    failure: Option<ProxyFailure>,
}

impl Default for ProxyLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxyLifecycle {
    #[must_use]
    pub fn new() -> Self {
        Self {
            phases: vec![ProxyPhase::Created],
            failure: None,
        }
    }

    pub fn transition(&mut self, next: ProxyPhase) -> Result<(), ProxyPhaseError> {
        let valid = matches!(
            (self.current(), next),
            (ProxyPhase::Created, ProxyPhase::Ready)
                | (ProxyPhase::Ready, ProxyPhase::Serving)
                | (ProxyPhase::Serving, ProxyPhase::Draining)
                | (ProxyPhase::Draining, ProxyPhase::Closed)
        );
        if !valid {
            return Err(ProxyPhaseError::InvalidTransition);
        }
        self.phases.push(next);
        Ok(())
    }

    pub fn fail(&mut self, reason: ProxyFailure) -> Result<(), ProxyPhaseError> {
        if matches!(self.current(), ProxyPhase::Closed | ProxyPhase::Failed) {
            return Err(ProxyPhaseError::InvalidTransition);
        }
        self.failure = Some(reason);
        self.phases.push(ProxyPhase::Failed);
        Ok(())
    }

    #[must_use]
    pub fn current(&self) -> ProxyPhase {
        *self.phases.last().expect("lifecycle starts in created")
    }

    #[must_use]
    pub fn phases(&self) -> &[ProxyPhase] {
        &self.phases
    }

    #[must_use]
    pub const fn failure(&self) -> Option<ProxyFailure> {
        self.failure
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_requires_all_phases_and_never_leaves_a_terminal() {
        let mut lifecycle = ProxyLifecycle::new();
        assert_eq!(
            lifecycle.transition(ProxyPhase::Serving),
            Err(ProxyPhaseError::InvalidTransition)
        );
        for phase in [
            ProxyPhase::Ready,
            ProxyPhase::Serving,
            ProxyPhase::Draining,
            ProxyPhase::Closed,
        ] {
            lifecycle.transition(phase).unwrap();
        }
        assert_eq!(lifecycle.phases().len(), 5);
        assert_eq!(
            lifecycle.fail(ProxyFailure::Transport),
            Err(ProxyPhaseError::InvalidTransition)
        );
    }

    #[test]
    fn failure_from_any_nonterminal_phase_is_final() {
        for ready_steps in 0..4 {
            let mut lifecycle = ProxyLifecycle::new();
            for phase in [ProxyPhase::Ready, ProxyPhase::Serving, ProxyPhase::Draining]
                .into_iter()
                .take(ready_steps)
            {
                lifecycle.transition(phase).unwrap();
            }
            lifecycle.fail(ProxyFailure::Report).unwrap();
            assert_eq!(lifecycle.failure(), Some(ProxyFailure::Report));
            assert_eq!(
                lifecycle.transition(ProxyPhase::Closed),
                Err(ProxyPhaseError::InvalidTransition)
            );
        }
    }
}
