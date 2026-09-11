import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class ResourceExpansionContractTests(unittest.TestCase):
    def test_cpu_decision_is_closed_without_claiming_a_total_time_limit(self) -> None:
        decision = (
            REPOSITORY_ROOT / "docs/adr/0006-cpu-bandwidth-boundary.md"
        ).read_text(encoding="utf-8")

        self.assertIn("**Status:** accepted", decision)
        self.assertIn("`cpu.max`", decision)
        self.assertIn("fixed 100,000 microsecond period", decision)
        self.assertIn("not a total CPU-time budget", decision)
        self.assertIn("Version 3", decision)
        for case in (
            "single busy loop",
            "multi-process busy loop",
            "wall-time interaction",
            "counter read race",
        ):
            self.assertIn(case, decision)

    def test_output_capacity_decision_rejects_post_run_enforcement(self) -> None:
        decision = (
            REPOSITORY_ROOT / "docs/adr/0007-output-capacity-boundary.md"
        ).read_text(encoding="utf-8")

        self.assertIn("**Status:** accepted", decision)
        self.assertIn("XFS project quota", decision)
        self.assertIn("allocated blocks and inodes", decision)
        self.assertIn("privileged host storage manager", decision)
        self.assertIn("post-run inventory is observation, not enforcement", decision)
        for boundary in (
            "sparse files",
            "deleted-open files",
            "memory-mapped writes",
            "nested mounts",
        ):
            self.assertIn(boundary, decision)


if __name__ == "__main__":
    unittest.main()
