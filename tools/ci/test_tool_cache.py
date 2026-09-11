import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VERIFY_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"
CACHE_ACTION = "nix-community/cache-nix-action@7df957e333c1e5da7721f60227dbba6d06080569"
AENEAS_REVISION = "3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0"


class ExactToolCacheTests(unittest.TestCase):
    def test_formal_cache_identity_is_closed_and_immutable(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count(CACHE_ACTION), 1)
        self.assertIn(f"AENEAS_SOURCE_REVISION: {AENEAS_REVISION}", workflow)
        self.assertIn(
            "primary-key: formal-nix-v1-${{ runner.os }}-${{ runner.arch }}-"
            "${{ env.AENEAS_SOURCE_REVISION }}-"
            "${{ hashFiles('proofbound/toolchains/translation.lock') }}",
            workflow,
        )
        self.assertNotRegex(workflow, r"restore-prefix(?:es|-keys)")

    def test_cache_precedes_build_and_identity_tool_identity_verification(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(CACHE_ACTION, workflow)
        cache_position = workflow.index(CACHE_ACTION)
        build_position = workflow.index("Install pinned Charon and Aeneas tools")
        verify_position = workflow.index("Verify pinned translation tools")
        evidence_position = workflow.index("Run formal and fresh evidence gates")
        self.assertLess(cache_position, build_position)
        self.assertLess(build_position, verify_position)
        self.assertLess(verify_position, evidence_position)
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

    def test_cache_is_confined_to_the_formal_job(self) -> None:
        workflow = VERIFY_WORKFLOW.read_text(encoding="utf-8")
        formal_start = workflow.index("\n  formal:\n")
        native_start = workflow.index("\n  native:\n")
        formal_job = workflow[formal_start:native_start]

        self.assertIn(CACHE_ACTION, formal_job)
        self.assertIsNone(re.search(r"cache-nix-action", workflow[:formal_start]))
        self.assertIsNone(re.search(r"cache-nix-action", workflow[native_start:]))


if __name__ == "__main__":
    unittest.main()
