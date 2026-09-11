import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
MANUAL_EXPERIMENT_WORKFLOWS = (
    WORKFLOW_ROOT / "network-authority-experiment.yml",
    WORKFLOW_ROOT / "performance-baseline.yml",
)
CI_SCRIPT = REPOSITORY_ROOT / "tools" / "ci" / "ci.sh"
LEGACY_NATIVE_WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "linux-enforcement.yml"
)
CHECKOUT_ACTION = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    " # v7.0.1"
)
UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    " # v7.0.1"
)
DOWNLOAD_ARTIFACT_ACTION = (
    "actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3"
    " # v8.0.0"
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

    def test_preflight_runs_independent_performance_verifier_falsifiers(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "timed_unit performance-verifier-tests python3 -m unittest "
            "experiments.performance.test_discover_runtime_libraries "
            "experiments.performance.test_verify_pure "
            "experiments.performance.test_verify_native",
            script,
        )

    def test_preflight_validates_closed_performance_result_schema(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "timed_unit performance-schema-tests python3 -m unittest "
            "experiments.performance.test_pure_result_schema "
            "experiments.performance.test_native_result_schema",
            script,
        )

    def test_preflight_validates_performance_workflow(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "timed_unit performance-workflow-tests python3 -m unittest "
            "tools.ci.test_performance_workflow",
            script,
        )

    def test_each_lane_uploads_timing_outside_assurance_evidence(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("actions/upload-artifact@"), 4)
        self.assertEqual(workflow.count("if: ${{ always() }}"), 5)
        self.assertEqual(workflow.count("proofbound-runtime-ci-timing-"), 4)
        self.assertNotIn(".proofbound", "\n".join(
            line for line in workflow.splitlines() if "timing" in line.lower()
        ))

    def test_each_lane_checks_out_and_confirms_the_exact_pr_head(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        exact_sha = "${{ github.event.pull_request.head.sha || github.sha }}"

        self.assertIn(f"PBR_EXACT_SHA: {exact_sha}", workflow)
        self.assertEqual(workflow.count(f"uses: {CHECKOUT_ACTION}"), 4)
        self.assertEqual(workflow.count("ref: ${{ env.PBR_EXACT_SHA }}"), 4)
        self.assertEqual(
            workflow.count(
                'run: test "$(git rev-parse HEAD)" = "$PBR_EXACT_SHA"'
            ),
            4,
        )
        self.assertEqual(workflow.count("-${{ env.PBR_EXACT_SHA }}"), 4)
        self.assertNotIn('= "$GITHUB_SHA"', workflow)

    def test_first_party_actions_are_exact_node24_releases(self) -> None:
        uses_pattern = re.compile(
            r"(?m)^\s*uses:\s+"
            r"(actions/(?:checkout|upload-artifact|download-artifact)@[^\n]+)$"
        )
        observed: list[tuple[str, str]] = []
        for workflow_path in sorted(WORKFLOW_ROOT.glob("*.yml")):
            for action in uses_pattern.findall(
                workflow_path.read_text(encoding="utf-8")
            ):
                observed.append((workflow_path.name, action))

        self.assertTrue(observed)
        allowed = {CHECKOUT_ACTION, UPLOAD_ARTIFACT_ACTION, DOWNLOAD_ARTIFACT_ACTION}
        self.assertEqual(
            [(name, action) for name, action in observed if action not in allowed],
            [],
        )

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

    def test_completed_experiment_workflows_are_manual_only(self) -> None:
        for workflow_path in MANUAL_EXPERIMENT_WORKFLOWS:
            with self.subTest(workflow=workflow_path.name):
                workflow = workflow_path.read_text(encoding="utf-8")
                self.assertIn("  workflow_dispatch:\n", workflow)
                self.assertIn("    inputs:\n      revision:\n", workflow)
                self.assertNotIn("  pull_request:\n", workflow)
                self.assertNotIn("github.event.pull_request", workflow)

    def test_network_experiment_requires_an_exact_revision(self) -> None:
        workflow = MANUAL_EXPERIMENT_WORKFLOWS[0].read_text(encoding="utf-8")

        self.assertIn("EXPERIMENT_SHA: ${{ inputs.revision }}", workflow)
        self.assertEqual(
            workflow.count('[[ "$EXPERIMENT_SHA" =~ ^[0-9a-f]{40}$ ]]'),
            workflow.count("Confirm the exact experiment head"),
        )


if __name__ == "__main__":
    unittest.main()
