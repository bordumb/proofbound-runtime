import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFY_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
CACHE_ACTION = "nix-community/cache-nix-action@7df957e333c1e5da7721f60227dbba6d06080569"
AENEAS_REVISION = "3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0"


class ExactToolCacheTests(unittest.TestCase):
    def test_proof_jobs_share_a_closed_immutable_cache_identity(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count(CACHE_ACTION), 2)
        self.assertIn(f"AENEAS_SOURCE_REVISION: {AENEAS_REVISION}", workflow)
        cache_identity = (
            "primary-key: formal-nix-v1-${{ runner.os }}-${{ runner.arch }}-"
            "${{ env.AENEAS_SOURCE_REVISION }}-"
            "${{ hashFiles('proofbound/toolchains/translation.lock') }}"
        )
        self.assertEqual(workflow.count(cache_identity), 2)
        self.assertNotRegex(workflow, r"restore-prefix(?:es|-keys)")

    def test_cache_precedes_each_build_and_tool_identity_verification(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")

        formal_start = workflow.index("\n  formal:\n")
        evidence_start = workflow.index("\n  fresh-evidence:\n")
        native_start = workflow.index("\n  native:\n")
        jobs = (
            (workflow[formal_start:evidence_start], "Run formal model and refinement gates"),
            (workflow[evidence_start:native_start], "Run fresh evidence gate"),
        )
        for job, gate_name in jobs:
            with self.subTest(gate=gate_name):
                cache_position = job.index(CACHE_ACTION)
                build_position = job.index("Install pinned Charon and Aeneas tools")
                verify_position = job.index("Verify pinned translation tools")
                gate_position = job.index(gate_name)
                self.assertLess(cache_position, build_position)
                self.assertLess(build_position, verify_position)
                self.assertLess(verify_position, gate_position)
        manifests = (REPOSITORY_ROOT / "tools" / "ci" / "manifests.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('check --root "$check_root" --fresh --json', manifests)

    def test_cache_paths_exclude_assurance_build_and_release_outputs(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")
        release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(CACHE_ACTION, workflow)
        cache_step = workflow[workflow.index(CACHE_ACTION):]
        cache_step = cache_step[: cache_step.index("\n\n      - name:")]

        for forbidden in (".proofbound", "target", ".lake", "dist"):
            self.assertNotIn(forbidden, cache_step)
        self.assertNotIn("cache-nix-action", release)

    def test_cache_is_confined_to_the_proof_jobs(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")
        formal_start = workflow.index("\n  formal:\n")
        native_start = workflow.index("\n  native:\n")
        proof_jobs = workflow[formal_start:native_start]

        self.assertEqual(proof_jobs.count(CACHE_ACTION), 2)
        self.assertIsNone(re.search(r"cache-nix-action", workflow[:formal_start]))
        self.assertIsNone(re.search(r"cache-nix-action", workflow[native_start:]))


if __name__ == "__main__":
    unittest.main()
