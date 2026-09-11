import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
CI_SCRIPT = REPOSITORY_ROOT / "tools" / "ci" / "ci.sh"
LEGACY_NATIVE_WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "linux-enforcement.yml"
)


class RequiredWorkflowTests(unittest.TestCase):
    def test_required_workflow_has_one_fail_closed_aggregate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("name: Current assurance gate"), 1)
        self.assertRegex(workflow, r"(?m)^  preflight:\n")
        self.assertRegex(workflow, r"(?m)^  rust:\n")
        self.assertRegex(workflow, r"(?m)^  formal:\n")
        self.assertRegex(workflow, r"(?m)^  native:\n")
        self.assertRegex(workflow, r"(?m)^  required:\n")
        self.assertGreaterEqual(workflow.count("needs: preflight"), 3)
        self.assertIn(
            "needs:\n      - preflight\n      - rust\n      - formal\n      - native", workflow
        )
        self.assertIn("if: ${{ always() }}", workflow)
        for result in ("preflight", "rust", "formal", "native"):
            self.assertIn(f'needs.{result}.result == \'success\'', workflow)

    def test_native_matrix_is_part_of_the_partition(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("name: Native boundary (${{ matrix.architecture }})", workflow)
        self.assertIn("architecture: x86_64", workflow)
        self.assertIn("architecture: aarch64", workflow)
        self.assertIn("bash tools/ci/native-linux.sh", workflow)
        self.assertFalse(LEGACY_NATIVE_WORKFLOW.exists())

    def test_each_lane_selects_one_shared_gate_partition(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        script = CI_SCRIPT.read_text(encoding="utf-8")

        for stage in ("preflight", "rust", "formal"):
            self.assertEqual(workflow.count(f"bash tools/ci/ci.sh {stage}"), 1)
            self.assertRegex(script, rf'(?m)^if selected "{stage}"; then$')
        self.assertIn('stage="${1:-all}"', script)
        self.assertIn('all|preflight|rust|formal', script)

    def test_triggers_and_cancellation_remain_closed(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("    branches:\n      - main\n", workflow)
        self.assertIn('      - "v*"\n', workflow)
        self.assertIn(
            "group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
            workflow,
        )
        self.assertIn(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", workflow
        )
        self.assertIsNone(re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", workflow))


if __name__ == "__main__":
    unittest.main()
