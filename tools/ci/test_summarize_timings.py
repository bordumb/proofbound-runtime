import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SUMMARY_TOOL = REPOSITORY_ROOT / "tools/ci/summarize_timings.py"


def record(
    *,
    duration_ms: int,
    kind: str,
    name: str,
    stage: str,
    exit_code: int = 0,
    job: str = "formal",
    runner_arch: str = "X64",
    run_id: str = "100",
) -> dict[str, object]:
    return {
        "duration_ms": duration_ms,
        "exit_code": exit_code,
        "job": job,
        "kind": kind,
        "name": name,
        "outcome": "success" if exit_code == 0 else "failure",
        "revision": "0123456789abcdef0123456789abcdef01234567",
        "run_attempt": "1",
        "run_id": run_id,
        "runner_arch": runner_arch,
        "schema": "proofbound-runtime-ci-timing/1",
        "stage": stage,
    }


class TimingSummaryTests(unittest.TestCase):
    def run_summary(self, *inputs: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SUMMARY_TOOL), *(str(path) for path in inputs)],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_summary_is_sorted_and_uses_successful_nearest_rank_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = [
                record(duration_ms=300, kind="stage", name="formal", stage="formal", run_id="3"),
                record(duration_ms=100, kind="stage", name="formal", stage="formal", run_id="1"),
                record(duration_ms=200, kind="stage", name="formal", stage="formal", run_id="2"),
                record(
                    duration_ms=400,
                    kind="stage",
                    name="formal",
                    stage="formal",
                    exit_code=7,
                    run_id="4",
                ),
                record(
                    duration_ms=25,
                    kind="unit",
                    name="rust-format",
                    stage="rust",
                    job="rust",
                    run_id="1",
                ),
            ]
            artifact = root / "timing.jsonl"
            artifact.write_text(
                "".join(json.dumps(item) + "\n" for item in records),
                encoding="utf-8",
            )

            result = self.run_summary(root)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout,
                "kind\tstage\tname\tsamples\tsuccesses\tfailures\tmedian_ms\tp95_ms\n"
                "stage\tformal\tformal\t4\t3\t1\t200\t300\n"
                "unit\trust\trust-format\t1\t1\t0\t25\t25\n",
            )

    def test_invalid_or_duplicate_records_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "unknown-field": {**record(duration_ms=1, kind="stage", name="formal", stage="formal"), "extra": True},
                "wrong-outcome": {**record(duration_ms=1, kind="stage", name="formal", stage="formal"), "outcome": "failure"},
                "bad-revision": {**record(duration_ms=1, kind="stage", name="formal", stage="formal"), "revision": "main"},
            }
            for name, value in cases.items():
                with self.subTest(name=name):
                    artifact = root / f"{name}.jsonl"
                    artifact.write_text(json.dumps(value) + "\n", encoding="utf-8")
                    result = self.run_summary(artifact)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("timing summary error:", result.stderr)

            duplicate = root / "duplicate.jsonl"
            value = record(duration_ms=1, kind="stage", name="formal", stage="formal")
            duplicate.write_text(
                json.dumps(value) + "\n" + json.dumps(value) + "\n",
                encoding="utf-8",
            )
            result = self.run_summary(duplicate)
            self.assertEqual(result.returncode, 2)
            self.assertIn("duplicate timing record", result.stderr)

    def test_same_native_stage_on_two_runner_architectures_is_not_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            records = [
                record(
                    duration_ms=17_035,
                    kind="stage",
                    name="native-boundary",
                    stage="native",
                    job="native",
                    runner_arch="X64",
                ),
                record(
                    duration_ms=17_648,
                    kind="stage",
                    name="native-boundary",
                    stage="native",
                    job="native",
                    runner_arch="ARM64",
                ),
            ]
            artifact = root / "timing.jsonl"
            artifact.write_text(
                "".join(json.dumps(item) + "\n" for item in records),
                encoding="utf-8",
            )

            result = self.run_summary(artifact)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("stage\tnative\tnative-boundary\t2\t2\t0", result.stdout)


if __name__ == "__main__":
    unittest.main()
