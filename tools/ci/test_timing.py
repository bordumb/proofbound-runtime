import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TIMING_TOOL = REPOSITORY_ROOT / "tools" / "ci" / "timing.py"


class TimingMetadataTests(unittest.TestCase):
    def run_timed(
        self, output: Path, *, stage: str, kind: str, name: str, command: list[str]
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "GITHUB_SHA": "0123456789abcdef0123456789abcdef01234567",
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_JOB": "formal",
                "RUNNER_ARCH": "ARM64",
            }
        )
        return subprocess.run(
            [
                sys.executable,
                str(TIMING_TOOL),
                "run",
                "--output",
                str(output),
                "--stage",
                stage,
                "--kind",
                kind,
                "--name",
                name,
                "--",
                *command,
            ],
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_successful_command_appends_exact_build_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timing.jsonl"
            result = self.run_timed(
                output,
                stage="formal",
                kind="unit",
                name="lean-build",
                command=[sys.executable, "-c", "print('timed-output')"],
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "timed-output\n")
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["schema"], "proofbound-runtime-ci-timing/1")
            self.assertEqual(record["stage"], "formal")
            self.assertEqual(record["kind"], "unit")
            self.assertEqual(record["name"], "lean-build")
            self.assertEqual(record["outcome"], "success")
            self.assertEqual(record["exit_code"], 0)
            self.assertGreaterEqual(record["duration_ms"], 0)
            self.assertEqual(
                record["revision"], "0123456789abcdef0123456789abcdef01234567"
            )
            self.assertEqual(record["run_id"], "12345")
            self.assertEqual(record["run_attempt"], "2")
            self.assertEqual(record["job"], "formal")
            self.assertEqual(record["runner_arch"], "ARM64")

    def test_failure_is_recorded_and_preserves_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timing.jsonl"
            result = self.run_timed(
                output,
                stage="rust",
                kind="stage",
                name="rust",
                command=[sys.executable, "-c", "raise SystemExit(7)"],
            )

            self.assertEqual(result.returncode, 7)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["outcome"], "failure")
            self.assertEqual(record["exit_code"], 7)
            self.assertEqual(record["kind"], "stage")

    def test_multiple_records_are_valid_json_lines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timing.jsonl"
            for name in ("first", "second"):
                result = self.run_timed(
                    output,
                    stage="preflight",
                    kind="unit",
                    name=name,
                    command=[sys.executable, "-c", "pass"],
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            records = [
                json.loads(line)
                for line in output.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual([record["name"] for record in records], ["first", "second"])

    def test_closed_identifiers_and_missing_commands_fail_without_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "timing.jsonl"
            invalid_name = self.run_timed(
                output,
                stage="formal",
                kind="unit",
                name="not allowed",
                command=[sys.executable, "-c", "pass"],
            )
            missing_command = self.run_timed(
                output,
                stage="formal",
                kind="unit",
                name="valid",
                command=[],
            )

            self.assertEqual(invalid_name.returncode, 2)
            self.assertEqual(missing_command.returncode, 2)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
