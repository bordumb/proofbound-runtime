import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class AcceptancePolicyCompilerTests(unittest.TestCase):
    def test_reviewable_source_reproduces_the_golden_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.cbor"
            process = subprocess.run(
                [
                    sys.executable,
                    "tools/acceptance/compile_policy.py",
                    "--source", "examples/acceptance-policy/golden-policy.json",
                    "--output", str(output),
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            expected = bytes.fromhex(
                (ROOT / "schemas/vectors/v2/acceptance-policy.cbor.hex").read_text().strip()
            )
            self.assertEqual(output.read_bytes(), expected)
            result = json.loads(process.stdout)
            self.assertEqual(result["schema"], "proofbound-runtime-policy-compile-result/1")
            self.assertTrue(result["policy_identity"].startswith("sha256:"))

    def test_unknown_fields_and_replacement_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = json.loads(
                (ROOT / "examples/acceptance-policy/golden-policy.json").read_text()
            )
            source["unexpected"] = True
            bad = root / "bad.json"
            bad.write_text(json.dumps(source))
            output = root / "policy.cbor"
            process = subprocess.run(
                [sys.executable, "tools/acceptance/compile_policy.py", "--source", str(bad), "--output", str(output)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(process.returncode, 0)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
