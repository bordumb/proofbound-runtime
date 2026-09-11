import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACTION = ROOT / ".github/actions/proofbound-runtime/action.yml"
RUNNER = ROOT / ".github/actions/proofbound-runtime/run.py"


class AcceptanceActionTests(unittest.TestCase):
    def test_action_pins_inputs_runs_the_full_chain_and_retains_outputs(self) -> None:
        action = ACTION.read_text(encoding="utf-8")
        for name in (
            "runtime-archive",
            "runtime-archive-sha256",
            "acceptor",
            "acceptor-sha256",
            "policy",
            "policy-identity",
            "plan",
            "cgroup-root",
            "proofbound-release",
            "proofbound-verifier",
            "proofbound-observation-inputs",
        ):
            self.assertIn(f"  {name}:\n", action)
        self.assertNotIn("latest", action.lower())
        self.assertIn("pbr run", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("pbr-verify", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("pbr-compose", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("pbr-accept", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("if: always()", action)
        self.assertIn(
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            action,
        )

    def test_runner_rejects_substituted_bytes_and_existing_output(self) -> None:
        spec = importlib.util.spec_from_file_location("acceptance_action", RUNNER)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            artifact.write_bytes(b"exact")
            with self.assertRaises(module.ActionError):
                module.require_digest(artifact, "0" * 64, "artifact")
            output = root / "output"
            output.mkdir()
            with self.assertRaises(module.ActionError):
                module.require_absent(output)


if __name__ == "__main__":
    unittest.main()
