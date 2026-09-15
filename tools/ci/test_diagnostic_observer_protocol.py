import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OBSERVER = ROOT / "crates/proofbound-runtime-diagnose/src/observer.rs"
PRODUCTION_MANIFESTS = [
    ROOT / "crates/proofbound-runtime-cli/Cargo.toml",
    ROOT / "crates/proofbound-runtime-linux/Cargo.toml",
]


class DiagnosticObserverProtocolContractTests(unittest.TestCase):
    def setUp(self):
        self.source = OBSERVER.read_text()

    def test_release_order_and_terminal_states_are_closed(self):
        self.assertIn(
            "self.require_state(ObserverProtocolState::OptionsEnabled)?;",
            self.source,
        )
        for state in [
            "Prepared",
            "Attached",
            "BoundaryReady",
            "OptionsEnabled",
            "Released",
            "Draining",
            "Complete",
            "Incomplete",
            "FailedBeforeRelease",
        ]:
            self.assertIn(state, self.source)
        self.assertIn("ProcessTreeNotDrained", self.source)

    def test_trace_options_and_bound_gaps_are_explicit(self):
        for option in [
            "PTRACE_O_TRACESYSGOOD",
            "PTRACE_O_TRACEFORK",
            "PTRACE_O_TRACEVFORK",
            "PTRACE_O_TRACECLONE",
            "PTRACE_O_TRACEEXEC",
            "PTRACE_O_EXITKILL",
        ]:
            self.assertIn(option, self.source)
        for gap in [
            "DiagnosticGap::ChildLost",
            "DiagnosticGap::EventLimit",
            "DiagnosticGap::EventPerProcessLimit",
            "DiagnosticGap::ObserverFailed",
            "DiagnosticGap::ProcessLimit",
            "DiagnosticGap::UnexpectedStop",
        ]:
            self.assertIn(gap, self.source)
        for guard in [
            "seen_processes",
            "self.state == ObserverProtocolState::Draining",
            "ObserverDirective::TerminateAndPublishNothing",
            "ObserverDirective::TerminateAndDrain",
            "ProcessTreeChanged",
            "TreeDrainNotConfirmed",
            "confirm_tree_drained",
            "per_process_exhausted",
            "total_exhausted",
        ]:
            self.assertIn(guard, self.source)

    def test_pure_protocol_is_absent_from_production_dependencies(self):
        self.assertNotIn("unsafe", self.source)
        for forbidden in [
            "std::fs",
            "std::net",
            "std::process",
            "libc::",
        ]:
            self.assertNotIn(forbidden, self.source)
        for path in PRODUCTION_MANIFESTS:
            self.assertNotIn("proofbound-runtime-diagnose", path.read_text(), path)


if __name__ == "__main__":
    unittest.main()
