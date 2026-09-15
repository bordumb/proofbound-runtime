//! Defines the pure diagnostic observer lifecycle and bound decisions.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use crate::artifact::{DiagnosticGap, ObservationBounds};

const PTRACE_O_TRACESYSGOOD: u32 = 0x0000_0001;
const PTRACE_O_TRACEFORK: u32 = 0x0000_0002;
const PTRACE_O_TRACEVFORK: u32 = 0x0000_0004;
const PTRACE_O_TRACECLONE: u32 = 0x0000_0008;
const PTRACE_O_TRACEEXEC: u32 = 0x0000_0010;
const PTRACE_O_EXITKILL: u32 = 0x0010_0000;
const REQUIRED_TRACE_OPTIONS: u32 = PTRACE_O_TRACESYSGOOD
    | PTRACE_O_TRACEFORK
    | PTRACE_O_TRACEVFORK
    | PTRACE_O_TRACECLONE
    | PTRACE_O_TRACEEXEC
    | PTRACE_O_EXITKILL;

/// Identifies one nonzero process in the diagnostic process tree.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DiagnosticProcessId(NonZeroU32);

impl DiagnosticProcessId {
    /// Creates one process identifier.
    pub const fn new(value: u32) -> Result<Self, ObserverProtocolError> {
        match NonZeroU32::new(value) {
            Some(value) => Ok(Self(value)),
            None => Err(ObserverProtocolError::ProcessIdInvalid),
        }
    }

    /// Returns the operating-system process identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

/// Identifies how the observer learned about one child process.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ProcessCreationKind {
    /// The parent completed `clone`.
    Clone,
    /// The parent completed `fork`.
    Fork,
    /// The parent completed `vfork`.
    Vfork,
}

/// Contains the only accepted ptrace option set for diagnostic release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticTraceOptions(u32);

impl DiagnosticTraceOptions {
    /// Parses the exact required Linux ptrace option bits.
    pub const fn from_bits(bits: u32) -> Result<Self, ObserverProtocolError> {
        if bits == REQUIRED_TRACE_OPTIONS {
            Ok(Self(bits))
        } else {
            Err(ObserverProtocolError::TraceOptionsInvalid)
        }
    }

    /// Returns the required option set.
    #[must_use]
    pub const fn required() -> Self {
        Self(REQUIRED_TRACE_OPTIONS)
    }

    /// Returns the Linux ptrace option bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// Identifies the observer lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverProtocolState {
    /// The root process is known but ptrace ownership is not established.
    Prepared,
    /// Ptrace ownership of the stopped root is established.
    Attached,
    /// The launcher reported the complete production boundary.
    BoundaryReady,
    /// The exact process-tree trace options are enabled.
    OptionsEnabled,
    /// Target code can run and observation is active.
    Released,
    /// The adapter must terminate and drain the process tree.
    Draining,
    /// Observation completed without a coverage gap.
    Complete,
    /// Observation completed with one or more explicit gaps.
    Incomplete,
    /// Setup failed before target release and no artifact is eligible.
    FailedBeforeRelease,
}

/// Directs the effectful adapter after one pure transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverDirective {
    /// Continue the ordered observer protocol.
    Continue,
    /// Terminate the process tree and confirm that the tree is empty.
    TerminateAndDrain,
    /// Publish a complete diagnostic result.
    PublishComplete,
    /// Publish an incomplete diagnostic result with explicit gaps.
    PublishIncomplete,
    /// Terminate the stopped tree and publish no diagnostic artifact.
    TerminateAndPublishNothing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcessObservation {
    events: u64,
}

/// Applies the closed ordering and collection bounds for one observer run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObserverProtocol {
    state: ObserverProtocolState,
    bounds: ObservationBounds,
    root: DiagnosticProcessId,
    processes: BTreeMap<DiagnosticProcessId, ProcessObservation>,
    seen_processes: BTreeSet<DiagnosticProcessId>,
    total_events: u64,
    gaps: BTreeSet<DiagnosticGap>,
    tree_drain_confirmed: bool,
}

impl ObserverProtocol {
    /// Creates a protocol before ptrace ownership is established.
    pub fn new(
        root: DiagnosticProcessId,
        bounds: ObservationBounds,
    ) -> Result<Self, ObserverProtocolError> {
        let bounds = bounds
            .validate()
            .map_err(|_| ObserverProtocolError::BoundsInvalid)?;
        Ok(Self {
            state: ObserverProtocolState::Prepared,
            bounds,
            root,
            processes: BTreeMap::from([(root, ProcessObservation { events: 0 })]),
            seen_processes: BTreeSet::from([root]),
            total_events: 0,
            gaps: BTreeSet::new(),
            tree_drain_confirmed: false,
        })
    }

    /// Returns the current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> ObserverProtocolState {
        self.state
    }

    /// Returns the diagnostic root process.
    #[must_use]
    pub const fn root(&self) -> DiagnosticProcessId {
        self.root
    }

    /// Returns the number of retained events.
    #[must_use]
    pub const fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Returns every explicit coverage gap in canonical order.
    #[must_use]
    pub fn gaps(&self) -> impl ExactSizeIterator<Item = DiagnosticGap> + '_ {
        self.gaps.iter().copied()
    }

    /// Returns the number of active tracked processes.
    #[must_use]
    pub fn active_processes(&self) -> usize {
        self.processes.len()
    }

    /// Returns the declared lifetime process limit.
    #[must_use]
    pub const fn process_limit(&self) -> u64 {
        self.bounds.process_count
    }

    /// Returns the maximum retained bytes for one observed path.
    #[must_use]
    pub const fn path_byte_limit(&self) -> u64 {
        self.bounds.path_bytes
    }

    /// Returns the maximum retained bytes for one socket address.
    #[must_use]
    pub const fn socket_address_byte_limit(&self) -> u64 {
        self.bounds.socket_address_bytes
    }

    /// Returns the maximum bytes read for one tracee string.
    #[must_use]
    pub const fn tracee_string_byte_limit(&self) -> u64 {
        self.bounds.tracee_string_bytes
    }

    /// Reports whether one process identity is retained for terminal drain.
    #[must_use]
    pub fn tracks_process(&self, process: DiagnosticProcessId) -> bool {
        self.processes.contains_key(&process)
    }

    /// Records ptrace ownership of the initially stopped root process.
    pub fn attach_root(&mut self) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_state(ObserverProtocolState::Prepared)?;
        self.state = ObserverProtocolState::Attached;
        Ok(ObserverDirective::Continue)
    }

    /// Records the launcher's complete production-boundary acknowledgement.
    pub fn record_boundary_ready(&mut self) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_state(ObserverProtocolState::Attached)?;
        self.state = ObserverProtocolState::BoundaryReady;
        Ok(ObserverDirective::Continue)
    }

    /// Records the exact closed process-tree trace option set.
    pub fn enable_trace_options(
        &mut self,
        options: DiagnosticTraceOptions,
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_state(ObserverProtocolState::BoundaryReady)?;
        if options != DiagnosticTraceOptions::required() {
            return Err(ObserverProtocolError::TraceOptionsInvalid);
        }
        self.state = ObserverProtocolState::OptionsEnabled;
        Ok(ObserverDirective::Continue)
    }

    /// Authorizes target release only after ownership, boundary, and options.
    pub fn release_target(&mut self) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_state(ObserverProtocolState::OptionsEnabled)?;
        self.state = ObserverProtocolState::Released;
        Ok(ObserverDirective::Continue)
    }

    /// Adds one process-tree child or requires bounded termination.
    pub fn discover_child(
        &mut self,
        parent: DiagnosticProcessId,
        child: DiagnosticProcessId,
        _kind: ProcessCreationKind,
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_observing()?;
        if !self.processes.contains_key(&parent) {
            return self.stop_with_gap(DiagnosticGap::ChildLost);
        }
        if self.seen_processes.contains(&child) {
            return self.stop_with_gap(DiagnosticGap::ObserverFailed);
        }
        if self.seen_processes.len() as u64 >= self.bounds.process_count {
            return self.stop_with_gap(DiagnosticGap::ProcessLimit);
        }
        self.seen_processes.insert(child);
        self.processes
            .insert(child, ProcessObservation { events: 0 });
        if self.state == ObserverProtocolState::Draining {
            self.tree_drain_confirmed = false;
            Ok(ObserverDirective::TerminateAndDrain)
        } else {
            Ok(ObserverDirective::Continue)
        }
    }

    /// Reserves one bounded event slot for a tracked process.
    pub fn record_event(
        &mut self,
        process: DiagnosticProcessId,
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_observing()?;
        if !self.processes.contains_key(&process) {
            return self.stop_with_gap(DiagnosticGap::ChildLost);
        }
        if self.state == ObserverProtocolState::Draining {
            self.tree_drain_confirmed = false;
            return Ok(ObserverDirective::TerminateAndDrain);
        }
        let process_events = self
            .processes
            .get(&process)
            .map_or(0, |observation| observation.events);
        let per_process_exhausted = process_events >= self.bounds.event_count_per_process;
        let total_exhausted = self.total_events >= self.bounds.event_count;
        if per_process_exhausted || total_exhausted {
            if per_process_exhausted {
                self.gaps.insert(DiagnosticGap::EventPerProcessLimit);
            }
            if total_exhausted {
                self.gaps.insert(DiagnosticGap::EventLimit);
            }
            self.state = ObserverProtocolState::Draining;
            self.tree_drain_confirmed = false;
            return Ok(ObserverDirective::TerminateAndDrain);
        }
        let observation = self
            .processes
            .get_mut(&process)
            .ok_or(ObserverProtocolError::ProcessTreeChanged)?;
        observation.events += 1;
        self.total_events += 1;
        Ok(ObserverDirective::Continue)
    }

    /// Reconciles one successful exec identity transition.
    pub fn record_exec(
        &mut self,
        former: DiagnosticProcessId,
        survivor: DiagnosticProcessId,
        superseded: &[DiagnosticProcessId],
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_observing()?;
        let survivor_is_replaced = superseded.contains(&survivor);
        let identities_are_closed = self.processes.contains_key(&former)
            && !superseded.contains(&former)
            && superseded
                .iter()
                .all(|process| self.processes.contains_key(process))
            && superseded
                .iter()
                .enumerate()
                .all(|(index, process)| !superseded[..index].contains(process))
            && ((former == survivor && !survivor_is_replaced)
                || (former != survivor && survivor_is_replaced));
        if !identities_are_closed {
            return self.stop_with_gap(DiagnosticGap::ObserverFailed);
        }
        let observation = self
            .processes
            .remove(&former)
            .ok_or(ObserverProtocolError::ProcessTreeChanged)?;
        for process in superseded {
            self.processes.remove(process);
        }
        self.processes.insert(survivor, observation);
        self.seen_processes.insert(survivor);
        if self.state == ObserverProtocolState::Draining {
            self.tree_drain_confirmed = false;
            Ok(ObserverDirective::TerminateAndDrain)
        } else {
            Ok(ObserverDirective::Continue)
        }
    }

    /// Records the terminal wait result for one tracked process.
    pub fn record_process_exit(
        &mut self,
        process: DiagnosticProcessId,
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_observing()?;
        if self.processes.remove(&process).is_none() {
            return self.stop_with_gap(DiagnosticGap::ChildLost);
        }
        if self.state == ObserverProtocolState::Draining {
            Ok(ObserverDirective::TerminateAndDrain)
        } else {
            Ok(ObserverDirective::Continue)
        }
    }

    /// Records an unexpected trace stop and requires bounded termination.
    pub fn record_unexpected_stop(
        &mut self,
        process: DiagnosticProcessId,
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_observing()?;
        let gap = if self.processes.contains_key(&process) {
            DiagnosticGap::UnexpectedStop
        } else {
            DiagnosticGap::ChildLost
        };
        self.stop_with_gap(gap)
    }

    /// Records an adapter failure with pre-release publication precedence.
    pub fn record_observer_failure(&mut self) -> Result<ObserverDirective, ObserverProtocolError> {
        match self.state {
            ObserverProtocolState::Prepared
            | ObserverProtocolState::Attached
            | ObserverProtocolState::BoundaryReady
            | ObserverProtocolState::OptionsEnabled => {
                self.state = ObserverProtocolState::FailedBeforeRelease;
                Ok(ObserverDirective::TerminateAndPublishNothing)
            }
            ObserverProtocolState::Released | ObserverProtocolState::Draining => {
                self.stop_with_gap(DiagnosticGap::ObserverFailed)
            }
            ObserverProtocolState::Complete
            | ObserverProtocolState::Incomplete
            | ObserverProtocolState::FailedBeforeRelease => {
                Err(ObserverProtocolError::ProtocolTerminal)
            }
        }
    }

    /// Records that termination left no process in the diagnostic child tree.
    pub fn confirm_tree_drained(&mut self) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_state(ObserverProtocolState::Draining)?;
        if !self.processes.is_empty() {
            return Err(ObserverProtocolError::ProcessTreeNotDrained);
        }
        self.tree_drain_confirmed = true;
        Ok(ObserverDirective::Continue)
    }

    /// Completes observation only after every required drain is confirmed.
    pub fn finish(&mut self) -> Result<ObserverDirective, ObserverProtocolError> {
        self.require_observing()?;
        if !self.processes.is_empty() {
            return Err(ObserverProtocolError::ProcessTreeNotDrained);
        }
        if self.state == ObserverProtocolState::Draining && !self.tree_drain_confirmed {
            return Err(ObserverProtocolError::TreeDrainNotConfirmed);
        }
        if self.gaps.is_empty() {
            self.state = ObserverProtocolState::Complete;
            Ok(ObserverDirective::PublishComplete)
        } else {
            self.state = ObserverProtocolState::Incomplete;
            Ok(ObserverDirective::PublishIncomplete)
        }
    }

    fn require_state(&self, required: ObserverProtocolState) -> Result<(), ObserverProtocolError> {
        if matches!(
            self.state,
            ObserverProtocolState::Complete
                | ObserverProtocolState::Incomplete
                | ObserverProtocolState::FailedBeforeRelease
        ) {
            return Err(ObserverProtocolError::ProtocolTerminal);
        }
        if self.state != required {
            return Err(ObserverProtocolError::TransitionInvalid);
        }
        Ok(())
    }

    fn require_observing(&self) -> Result<(), ObserverProtocolError> {
        if matches!(
            self.state,
            ObserverProtocolState::Released | ObserverProtocolState::Draining
        ) {
            Ok(())
        } else if matches!(
            self.state,
            ObserverProtocolState::Complete
                | ObserverProtocolState::Incomplete
                | ObserverProtocolState::FailedBeforeRelease
        ) {
            Err(ObserverProtocolError::ProtocolTerminal)
        } else {
            Err(ObserverProtocolError::TransitionInvalid)
        }
    }

    fn stop_with_gap(
        &mut self,
        gap: DiagnosticGap,
    ) -> Result<ObserverDirective, ObserverProtocolError> {
        self.gaps.insert(gap);
        self.state = ObserverProtocolState::Draining;
        self.tree_drain_confirmed = false;
        Ok(ObserverDirective::TerminateAndDrain)
    }
}

/// Identifies invalid pure observer protocol input or ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserverProtocolError {
    /// The observation bounds are invalid.
    BoundsInvalid,
    /// A process identifier is zero.
    ProcessIdInvalid,
    /// The process tree changed during one pure transition.
    ProcessTreeChanged,
    /// The lifecycle transition is out of order.
    TransitionInvalid,
    /// The ptrace option set is not the exact required set.
    TraceOptionsInvalid,
    /// One or more tracked processes have no terminal wait result.
    ProcessTreeNotDrained,
    /// The adapter has not confirmed an empty child tree after termination.
    TreeDrainNotConfirmed,
    /// The protocol already reached a terminal state.
    ProtocolTerminal,
}

impl ObserverProtocolError {
    /// Returns the stable machine error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::BoundsInvalid => "diagnostic.observer.bounds-invalid",
            Self::ProcessIdInvalid => "diagnostic.observer.process-id-invalid",
            Self::ProcessTreeChanged => "diagnostic.observer.process-tree-changed",
            Self::TransitionInvalid => "diagnostic.observer.transition-invalid",
            Self::TraceOptionsInvalid => "diagnostic.observer.trace-options-invalid",
            Self::ProcessTreeNotDrained => "diagnostic.observer.process-tree-not-drained",
            Self::TreeDrainNotConfirmed => "diagnostic.observer.tree-drain-not-confirmed",
            Self::ProtocolTerminal => "diagnostic.observer.protocol-terminal",
        }
    }
}

impl fmt::Display for ObserverProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for ObserverProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn bounds() -> ObservationBounds {
        ObservationBounds {
            event_count: 8,
            event_count_per_process: 4,
            output_bytes: 1_048_576,
            path_bytes: 4096,
            process_count: 4,
            socket_address_bytes: 128,
            symlink_hops: 40,
            tracee_string_bytes: 4096,
        }
    }

    fn released() -> ObserverProtocol {
        released_with_bounds(bounds())
    }

    fn released_with_bounds(bounds: ObservationBounds) -> ObserverProtocol {
        let mut protocol =
            ObserverProtocol::new(DiagnosticProcessId::new(10).unwrap(), bounds).expect("protocol");
        protocol.attach_root().expect("attach");
        protocol.record_boundary_ready().expect("boundary");
        protocol
            .enable_trace_options(DiagnosticTraceOptions::required())
            .expect("options");
        protocol.release_target().expect("release");
        protocol
    }

    #[test]
    fn target_release_requires_boundary_and_exact_trace_options() {
        let mut protocol = ObserverProtocol::new(DiagnosticProcessId::new(10).unwrap(), bounds())
            .expect("protocol");
        assert_eq!(
            protocol.release_target(),
            Err(ObserverProtocolError::TransitionInvalid)
        );
        assert_eq!(
            protocol.record_boundary_ready(),
            Err(ObserverProtocolError::TransitionInvalid)
        );
        protocol.attach_root().expect("attach");
        assert_eq!(
            protocol.attach_root(),
            Err(ObserverProtocolError::TransitionInvalid)
        );
        assert_eq!(
            protocol.release_target(),
            Err(ObserverProtocolError::TransitionInvalid)
        );
        assert_eq!(
            protocol.enable_trace_options(DiagnosticTraceOptions::required()),
            Err(ObserverProtocolError::TransitionInvalid)
        );
        protocol.record_boundary_ready().expect("boundary");
        assert_eq!(
            DiagnosticTraceOptions::from_bits(DiagnosticTraceOptions::required().bits() | 0x20),
            Err(ObserverProtocolError::TraceOptionsInvalid)
        );
        protocol
            .enable_trace_options(DiagnosticTraceOptions::required())
            .expect("options");
        assert_eq!(protocol.release_target(), Ok(ObserverDirective::Continue));
    }

    #[test]
    fn complete_tree_requires_every_terminal_wait_result() {
        let root = DiagnosticProcessId::new(10).unwrap();
        let child = DiagnosticProcessId::new(11).unwrap();
        let mut protocol = released();
        protocol
            .discover_child(root, child, ProcessCreationKind::Clone)
            .expect("child");
        protocol.record_event(root).expect("root event");
        protocol.record_event(child).expect("child event");
        protocol.record_process_exit(root).expect("root exit");
        assert_eq!(
            protocol.finish(),
            Err(ObserverProtocolError::ProcessTreeNotDrained)
        );
        protocol.record_process_exit(child).expect("child exit");
        assert_eq!(protocol.finish(), Ok(ObserverDirective::PublishComplete));
        assert_eq!(protocol.state(), ObserverProtocolState::Complete);
        assert_eq!(protocol.total_events(), 2);
        assert_eq!(protocol.active_processes(), 0);
        assert_eq!(protocol.gaps().collect::<Vec<_>>(), vec![]);
    }

    #[test]
    fn collection_bounds_require_termination_and_explicit_gaps() {
        let root = DiagnosticProcessId::new(10).unwrap();
        let child = DiagnosticProcessId::new(11).unwrap();
        let mut limited = bounds();
        limited.event_count = 1;
        limited.process_count = 1;
        limited.event_count_per_process = 1;
        let mut protocol = ObserverProtocol::new(root, limited).expect("protocol");
        protocol.attach_root().unwrap();
        protocol.record_boundary_ready().unwrap();
        protocol
            .enable_trace_options(DiagnosticTraceOptions::required())
            .unwrap();
        protocol.release_target().unwrap();
        protocol.record_event(root).expect("first event");
        assert_eq!(
            protocol.record_event(root),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.discover_child(root, child, ProcessCreationKind::Fork),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.gaps().collect::<Vec<_>>(),
            vec![
                DiagnosticGap::EventLimit,
                DiagnosticGap::EventPerProcessLimit,
                DiagnosticGap::ProcessLimit,
            ]
        );
        assert_eq!(
            protocol.record_process_exit(root),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.finish(),
            Err(ObserverProtocolError::TreeDrainNotConfirmed)
        );
        assert_eq!(
            protocol.confirm_tree_drained(),
            Ok(ObserverDirective::Continue)
        );
        assert_eq!(protocol.finish(), Ok(ObserverDirective::PublishIncomplete));
    }

    #[test]
    fn natural_exact_capacity_completion_adds_no_gap() {
        let root = DiagnosticProcessId::new(10).unwrap();
        for (event_count, event_count_per_process, process_count) in
            [(1, 2, 2), (2, 1, 2), (2, 2, 1)]
        {
            let mut exact = bounds();
            exact.event_count = event_count;
            exact.event_count_per_process = event_count_per_process;
            exact.process_count = process_count;
            let mut protocol = released_with_bounds(exact);
            assert_eq!(protocol.record_event(root), Ok(ObserverDirective::Continue));
            assert_eq!(
                protocol.record_process_exit(root),
                Ok(ObserverDirective::Continue)
            );
            assert_eq!(protocol.finish(), Ok(ObserverDirective::PublishComplete));
            assert_eq!(protocol.gaps().collect::<Vec<_>>(), vec![]);
        }
    }

    #[test]
    fn each_collection_bound_has_one_exact_gap() {
        let root = DiagnosticProcessId::new(10).unwrap();

        let mut total_bounds = bounds();
        total_bounds.event_count = 1;
        let mut total = released_with_bounds(total_bounds);
        total.record_event(root).expect("retained event");
        total.record_event(root).expect("total overflow");
        assert_eq!(
            total.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::EventLimit]
        );

        let mut per_process_bounds = bounds();
        per_process_bounds.event_count_per_process = 1;
        let mut per_process = released_with_bounds(per_process_bounds);
        per_process.record_event(root).expect("retained event");
        per_process
            .record_event(root)
            .expect("per-process overflow");
        assert_eq!(
            per_process.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::EventPerProcessLimit]
        );

        let mut process_bounds = bounds();
        process_bounds.process_count = 1;
        let mut process = released_with_bounds(process_bounds);
        process
            .discover_child(
                root,
                DiagnosticProcessId::new(11).unwrap(),
                ProcessCreationKind::Clone,
            )
            .expect("process overflow");
        assert_eq!(
            process.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::ProcessLimit]
        );
    }

    #[test]
    fn drain_tracks_children_until_the_process_bound() {
        let root = DiagnosticProcessId::new(10).unwrap();
        let child = DiagnosticProcessId::new(11).unwrap();
        let mut limited = bounds();
        limited.event_count = 1;
        limited.process_count = 2;
        let mut protocol = ObserverProtocol::new(root, limited).expect("protocol");
        protocol.attach_root().unwrap();
        protocol.record_boundary_ready().unwrap();
        protocol
            .enable_trace_options(DiagnosticTraceOptions::required())
            .unwrap();
        protocol.release_target().unwrap();
        protocol.record_event(root).expect("retained event");
        assert_eq!(
            protocol.record_event(root),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.discover_child(root, child, ProcessCreationKind::Clone),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(protocol.active_processes(), 2);
        assert_eq!(
            protocol.record_process_exit(root),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.finish(),
            Err(ObserverProtocolError::ProcessTreeNotDrained)
        );
        assert_eq!(
            protocol.record_process_exit(child),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        protocol.confirm_tree_drained().expect("tree drained");
        assert_eq!(protocol.finish(), Ok(ObserverDirective::PublishIncomplete));
    }

    #[test]
    fn exec_identity_replacement_is_atomic_and_closed() {
        let root = DiagnosticProcessId::new(10).expect("root");
        let former = DiagnosticProcessId::new(11).expect("former");
        let sibling = DiagnosticProcessId::new(12).expect("sibling");
        let mut protocol = released();
        protocol
            .discover_child(root, former, ProcessCreationKind::Clone)
            .expect("former child");
        protocol
            .discover_child(root, sibling, ProcessCreationKind::Clone)
            .expect("sibling child");
        protocol.record_event(former).expect("former event");

        assert_eq!(
            protocol.record_exec(former, root, &[root, sibling]),
            Ok(ObserverDirective::Continue)
        );
        assert!(protocol.tracks_process(root));
        assert!(!protocol.tracks_process(former));
        assert!(!protocol.tracks_process(sibling));
        assert_eq!(protocol.active_processes(), 1);
        assert_eq!(protocol.record_event(root), Ok(ObserverDirective::Continue));

        let mut invalid = released();
        assert_eq!(
            invalid.record_exec(root, former, &[]),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(invalid.state(), ObserverProtocolState::Draining);
        assert_eq!(
            invalid.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::ObserverFailed]
        );
        assert!(invalid.tracks_process(root));
        assert!(!invalid.tracks_process(former));
    }

    #[test]
    fn later_observation_invalidates_a_tree_drain_confirmation() {
        let root = DiagnosticProcessId::new(10).unwrap();
        let overflow_child = DiagnosticProcessId::new(11).unwrap();
        let mut limited = bounds();
        limited.process_count = 1;
        let mut protocol = released_with_bounds(limited);
        protocol
            .discover_child(root, overflow_child, ProcessCreationKind::Fork)
            .expect("process overflow");
        protocol.record_process_exit(root).expect("root exit");
        protocol.confirm_tree_drained().expect("tree drained");
        assert_eq!(
            protocol.record_unexpected_stop(overflow_child),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.finish(),
            Err(ObserverProtocolError::TreeDrainNotConfirmed)
        );
        protocol.confirm_tree_drained().expect("tree drained again");
        assert_eq!(protocol.finish(), Ok(ObserverDirective::PublishIncomplete));
    }

    #[test]
    fn total_process_and_event_bounds_do_not_reset_during_drain() {
        let root = DiagnosticProcessId::new(10).unwrap();
        let first_child = DiagnosticProcessId::new(11).unwrap();
        let later_child = DiagnosticProcessId::new(12).unwrap();
        let mut limited = bounds();
        limited.event_count = 2;
        limited.event_count_per_process = 4;
        limited.process_count = 2;
        let mut protocol = ObserverProtocol::new(root, limited).expect("protocol");
        protocol.attach_root().unwrap();
        protocol.record_boundary_ready().unwrap();
        protocol
            .enable_trace_options(DiagnosticTraceOptions::required())
            .unwrap();
        protocol.release_target().unwrap();
        protocol
            .discover_child(root, first_child, ProcessCreationKind::Clone)
            .expect("first child");
        protocol.record_event(root).expect("root event");
        protocol.record_event(first_child).expect("child event");
        assert_eq!(
            protocol.record_event(root),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(protocol.total_events(), 2);
        protocol
            .record_process_exit(first_child)
            .expect("first child exit");
        assert_eq!(
            protocol.discover_child(root, later_child, ProcessCreationKind::Fork),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(protocol.active_processes(), 1);
        assert_eq!(
            protocol.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::EventLimit, DiagnosticGap::ProcessLimit]
        );
    }

    #[test]
    fn failures_keep_pre_release_and_post_release_publication_distinct() {
        let mut setup = ObserverProtocol::new(DiagnosticProcessId::new(10).unwrap(), bounds())
            .expect("protocol");
        assert_eq!(
            setup.record_observer_failure(),
            Ok(ObserverDirective::TerminateAndPublishNothing)
        );
        assert_eq!(setup.state(), ObserverProtocolState::FailedBeforeRelease);

        let mut known_stop = released();
        assert_eq!(
            known_stop.record_unexpected_stop(DiagnosticProcessId::new(10).unwrap()),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            known_stop.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::UnexpectedStop]
        );

        let mut live = released();
        assert_eq!(
            live.record_unexpected_stop(DiagnosticProcessId::new(99).unwrap()),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            live.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::ChildLost]
        );
        assert_eq!(
            live.record_observer_failure(),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            live.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::ChildLost, DiagnosticGap::ObserverFailed]
        );
    }

    #[test]
    fn invalid_inputs_duplicates_and_terminal_reuse_fail_closed() {
        let mut invalid_bounds = bounds();
        invalid_bounds.process_count = 0;
        assert_eq!(
            ObserverProtocol::new(DiagnosticProcessId::new(10).unwrap(), invalid_bounds),
            Err(ObserverProtocolError::BoundsInvalid)
        );
        assert_eq!(
            DiagnosticProcessId::new(0),
            Err(ObserverProtocolError::ProcessIdInvalid)
        );
        assert_eq!(
            DiagnosticTraceOptions::from_bits(0),
            Err(ObserverProtocolError::TraceOptionsInvalid)
        );
        assert_eq!(
            DiagnosticTraceOptions::from_bits(DiagnosticTraceOptions::required().bits() | 0x20),
            Err(ObserverProtocolError::TraceOptionsInvalid)
        );

        let root = DiagnosticProcessId::new(10).unwrap();
        let child = DiagnosticProcessId::new(11).unwrap();
        let mut protocol = released();
        protocol
            .discover_child(root, child, ProcessCreationKind::Fork)
            .expect("child");
        assert_eq!(
            protocol.discover_child(root, child, ProcessCreationKind::Vfork),
            Ok(ObserverDirective::TerminateAndDrain)
        );
        assert_eq!(
            protocol.gaps().collect::<Vec<_>>(),
            vec![DiagnosticGap::ObserverFailed]
        );
        assert_eq!(
            protocol.confirm_tree_drained(),
            Err(ObserverProtocolError::ProcessTreeNotDrained)
        );
        protocol.record_process_exit(child).expect("child exit");
        protocol.record_process_exit(root).expect("root exit");
        assert_eq!(
            protocol.finish(),
            Err(ObserverProtocolError::TreeDrainNotConfirmed)
        );
        protocol.confirm_tree_drained().expect("tree drained");
        assert_eq!(protocol.finish(), Ok(ObserverDirective::PublishIncomplete));
        assert_eq!(
            protocol.record_event(root),
            Err(ObserverProtocolError::ProtocolTerminal)
        );
    }
}
