import json
import re
import subprocess
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LEAN_TOOLCHAIN = "leanprover/lean4:v4.33.0"
MATHLIB_INPUT = "v4.33.0"


class LeanToolchainIdentityTests(unittest.TestCase):
    def test_root_vendor_and_translation_lock_select_one_lean(self) -> None:
        for relative in ("lean-toolchain", "formal/vendor/aeneas/lean-toolchain"):
            with self.subTest(path=relative):
                self.assertEqual(
                    (REPOSITORY_ROOT / relative).read_text(encoding="utf-8").strip(),
                    LEAN_TOOLCHAIN,
                )

        lock = (
            REPOSITORY_ROOT / "proofbound/toolchains/translation.lock"
        ).read_text(encoding="utf-8")
        matches = re.findall(
            r'^lean_toolchain = "([^"]+)"$', lock, flags=re.MULTILINE
        )
        self.assertEqual(matches, [LEAN_TOOLCHAIN])

    def test_root_and_vendor_manifests_select_the_same_mathlib_release(self) -> None:
        for relative in ("lake-manifest.json", "formal/vendor/aeneas/lake-manifest.json"):
            with self.subTest(path=relative):
                manifest = json.loads(
                    (REPOSITORY_ROOT / relative).read_text(encoding="utf-8")
                )
                mathlib = [
                    package
                    for package in manifest["packages"]
                    if package.get("name") == "mathlib"
                ]
                self.assertEqual(len(mathlib), 1)
                self.assertEqual(mathlib[0]["inputRev"], MATHLIB_INPUT)

    def test_tracked_tree_has_no_lean_431_reference(self) -> None:
        old_version = "4." + "31"
        result = subprocess.run(
            ["git", "grep", "-n", "-E", f"v?{old_version}(\\.0)?"],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
