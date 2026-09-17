import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
MAPPING = ROOT / "crates/proofbound-runtime-diagnose-linux/src/mapping.rs"
COMMAND = ROOT / "crates/proofbound-runtime-diagnose-cli/src/main.rs"


class DiagnosticCandidateResolutionContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.mapping = MAPPING.read_text()
        self.command = COMMAND.read_text()

    def test_candidate_walk_is_root_confined_and_symlink_bounded(self):
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
            self.trace.replace("before.identity != after.identity", "false", 1),
            self.trace.replace("current != root", "true", 1),
            self.mapping.replace("ObservationResolution::StableCandidate", "ObservationResolution::KernelSelected", 1),
        ]
        self.assertNotIn("before.identity != after.identity", mutations[0])
        self.assertNotIn("current != root", mutations[1])
        self.assertNotEqual(mutations[2], self.mapping)


if __name__ == "__main__":
    unittest.main()
