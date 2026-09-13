import tempfile
import unittest
from pathlib import Path

from tools.ci.documentation import assurance_summary_errors


class AssuranceSummaryTests(unittest.TestCase):
    def test_missing_claim_row_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "claims").mkdir()
            (root / "docs").mkdir()
            (root / "claims/PBR-TEST-001.toml").write_text("id = 'PBR-TEST-001'\n")
            (root / "docs/assurance-plan.md").write_text("| Claim | Result |\n")
            self.assertEqual(
                assurance_summary_errors(root),
                ["docs/assurance-plan.md: assurance summary omits claim PBR-TEST-001"],
            )

    def test_exact_claim_inventory_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "claims").mkdir()
            (root / "docs").mkdir()
            (root / "claims/PBR-TEST-001.toml").write_text("id = 'PBR-TEST-001'\n")
            (root / "docs/assurance-plan.md").write_text(
                "| `PBR-TEST-001` | tested | exact |\n"
            )
            self.assertEqual(assurance_summary_errors(root), [])


if __name__ == "__main__":
    unittest.main()
