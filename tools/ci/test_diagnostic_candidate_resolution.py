import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
MAPPING = ROOT / "crates/proofbound-runtime-diagnose-linux/src/mapping.rs"
COMMAND = ROOT / "crates/proofbound-runtime-diagnose-cli/src/main.rs"


def assert_candidate_resolution_contract(trace, mapping, command):
    observer = trace.split("fn observe_failed_candidate", 1)[1].split("\n    fn ", 1)[0]
    assert observer.count("resolve_candidate_once") >= 2
    for marker in [
        "self.processes.len() != 1",
        "before.path != after.path",
        "before.symlink_hops != after.symlink_hops",
        "before.identity != after.identity",
        "TraceCandidateObservation::IdentityDrift",
    ]:
        assert marker in observer
    walker = trace.split("fn walk_candidate_path", 1)[1].split("\n}", 1)[0]
    for marker in [
        "Component::ParentDir",
        "current != root",
        "symlink_hops > symlink_hop_limit",
        "!current.starts_with(root)",
    ]:
        assert marker in walker
    candidate = mapping.split("fn map_candidate_parts", 1)[1].split("\n}", 1)[0]
    assert "ObservationResolution::StableCandidate" in candidate
    assert "ObservationResolution::KernelSelected" not in candidate
    assert "before != after" in candidate
    assert "DiagnosticGap::IdentityDrift" in command
    assert "DiagnosticGap::SymlinkLimit" in command
    assert "DiagnosticCompletion::Incomplete" in command
    connection = """let candidate =
                            self.observe_failed_candidate(process, &invocation, is_error);"""
    assert connection in trace
    exit_branch = trace.split(
        "crate::sys::TraceSyscallStop::Exit { result, is_error } =>", 1
    )[1].split("crate::sys::TraceSyscallStop::Seccomp", 1)[0]
    candidate_position = exit_branch.index(connection)
    event_position = exit_branch.index("ActiveTraceEvent::SyscallCompleted")
    assert candidate_position < event_position
    assert "resume_before_deadline" not in exit_branch[candidate_position:event_position]


class DiagnosticCandidateResolutionContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.mapping = MAPPING.read_text()
        self.command = COMMAND.read_text()

    def test_candidate_walk_is_root_confined_and_symlink_bounded(self):
        assert_candidate_resolution_contract(self.trace, self.mapping, self.command)
        self.assertIn("walk_candidate_path", self.trace)
        self.assertIn("CandidateResolutionError::SymlinkLimit", self.trace)
        self.assertIn("symlink_hop_limit", self.trace)
        self.assertIn("Component::ParentDir", self.trace)
        self.assertIn("current != root", self.trace)
        self.assertIn("candidate_walk_is_root_confined_and_symlink_bounded", self.trace)

    def test_candidate_requires_two_matching_stopped_observations(self):
        body = self.trace.split("fn observe_failed_candidate", 1)[1].split("\n    fn ", 1)[0]
        self.assertGreaterEqual(body.count("resolve_candidate_once"), 2)
        self.assertIn("before.path != after.path", body)
        self.assertIn("before.identity != after.identity", body)
        self.assertIn("TraceCandidateObservation::IdentityDrift", body)
        self.assertIn("self.processes.len() != 1", body)

    def test_mapping_keeps_candidates_advisory(self):
        self.assertIn("ObservationResolution::StableCandidate", self.mapping)
        self.assertIn("TraceCandidateObservation::IdentityDrift", self.mapping)
        self.assertIn("TraceCandidateObservation::SymlinkLimit", self.mapping)
        self.assertIn("ObservationResolution::Unresolved", self.mapping)
        self.assertNotIn("ObservationResolution::KernelSelected, candidate", self.mapping)

    def test_command_preserves_typed_candidate_gaps(self):
        self.assertIn("DiagnosticGap::IdentityDrift", self.command)
        self.assertIn("DiagnosticGap::SymlinkLimit", self.command)
        self.assertIn("DiagnosticCompletion::Incomplete", self.command)

    def test_mutations_remove_required_guards(self):
        mutations = [
            (
                self.trace.replace("before.identity != after.identity", "false", 1),
                self.mapping,
                self.command,
            ),
            (
                self.trace.replace("current != root", "true", 1),
                self.mapping,
                self.command,
            ),
            (
                self.trace,
                self.mapping.replace(
                    "ObservationResolution::StableCandidate",
                    "ObservationResolution::KernelSelected",
                ),
                self.command,
            ),
            (
                self.trace.replace(
                    """let candidate =
                            self.observe_failed_candidate(process, &invocation, is_error);""",
                    "let candidate = None;",
                    1,
                ),
                self.mapping,
                self.command,
            ),
            (
                self.trace.replace(
                    """let candidate =
                            self.observe_failed_candidate(process, &invocation, is_error);""",
                    """let candidate =
                            self.observe_failed_candidate(process, &invocation, is_error);
                        self.resume_before_deadline(process)?;""",
                    1,
                ),
                self.mapping,
                self.command,
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=hash("".join(mutation))):
                with self.assertRaises(AssertionError):
                    assert_candidate_resolution_contract(*mutation)


if __name__ == "__main__":
    unittest.main()
