from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github/workflows/performance-baseline.yml"


class PerformanceWorkflowTests(unittest.TestCase):
    def test_workflow_is_exact_revision_manual_matrix(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("revision:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertIn("runner: ubuntu-24.04\n", workflow)
        self.assertIn("runner: ubuntu-24.04-arm\n", workflow)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            workflow,
        )
        self.assertIn('[[ "$PBR_PERFORMANCE_REVISION" =~ ^[0-9a-f]{40}$ ]]', workflow)
        self.assertIn(
            'test "$(git rev-parse HEAD)" = "$PBR_PERFORMANCE_REVISION"', workflow
        )

    def test_workflow_runs_and_independently_verifies_all_pure_subjects(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "cargo build --release --locked -p proofbound-runtime-bench --bin pbr-bench",
            workflow,
        )
        self.assertIn(
            'target/release/pbr-bench pure --source-commit "$PBR_PERFORMANCE_REVISION"',
            workflow,
        )
        self.assertIn("experiments/performance/verify_pure.py", workflow)
        self.assertIn('--expected-architecture "${{ matrix.architecture }}"', workflow)
        self.assertIn("--plan-fixture tests/conformance/plan/positive/minimal-v1.toml", workflow)
        self.assertIn(
            "--receipt-fixture experiments/performance/fixtures/reusable-receipt-v1.json",
            workflow,
        )
        self.assertIn(
            "--composition-fixture crates/proofbound-runtime-bench/src/composition_fixture.rs",
            workflow,
        )
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            workflow,
        )

    def test_workflow_retains_producer_and_verifier_failures(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        for retained in (
            "producer.stderr",
            "producer.exit",
            "verifier.stderr",
            "verifier.exit",
        ):
            self.assertIn(retained, workflow)
        self.assertIn("if: ${{ always() }}", workflow)


if __name__ == "__main__":
    unittest.main()
