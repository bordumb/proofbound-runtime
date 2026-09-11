from pathlib import Path
import os
import sys
import tempfile
import unittest


SDK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = SDK_ROOT.parents[1]
sys.path.insert(0, str(SDK_ROOT))

from proofbound_runtime import SdkError, build_plan, parse_run_result, run


def golden_plan() -> dict:
    return {
        "id": "golden-v2",
        "executable": "bin/hello",
        "arguments": [],
        "working_directory": ".",
        "read": [],
        "runtime_read": [],
        "write": ["out"],
        "execute": ["bin/hello"],
        "environment": [],
        "processes": 2,
        "wall_time_ms": 1_000,
        "stdout_bytes": 1_024,
        "stderr_bytes": 1_024,
        "memory_bytes": 65_536,
        "swap_bytes": 0,
    }


RESULT = b'{"schema":"proofbound-runtime-run-result/2","outcome":{"kind":"exited","code":0},"receipt":"receipt.cbor","commitment":"hex:0909090909090909090909090909090909090909090909090909090909090909","execution_id":"hex:00000000000040008000000000000000"}'


class PythonSdkTests(unittest.TestCase):
    def test_plan_matches_the_frozen_v2_golden(self) -> None:
        expected = bytes.fromhex(
            (REPOSITORY_ROOT / "schemas/vectors/v2/execution-plan.cbor.hex").read_text()
        )
        self.assertEqual(build_plan(**golden_plan()), expected)

    def test_invalid_plan_inputs_fail_before_encoding(self) -> None:
        duplicate = golden_plan()
        duplicate["environment"] = ["PATH", "PATH"]
        with self.assertRaisesRegex(SdkError, "sdk.plan.duplicate"):
            build_plan(**duplicate)
        unquantized = golden_plan()
        unquantized["memory_bytes"] += 1
        with self.assertRaisesRegex(SdkError, "sdk.plan.limit-not-quantized"):
            build_plan(**unquantized)

    def test_result_projection_is_closed(self) -> None:
        result = parse_run_result(RESULT)
        self.assertEqual(result.receipt, "receipt.cbor")
        self.assertEqual(result.outcome_kind, "exited")
        with self.assertRaisesRegex(SdkError, "sdk.result.unknown-field"):
            parse_run_result(RESULT[:-1] + b',"verified":true}')

    def test_run_uses_exact_arguments_without_shell_or_ambient_environment(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "pbr"
            plan = root / "plan;touch-injection"
            receipt = root / "receipt.cbor"
            cgroup = root / "cgroup"
            script = """#!/bin/sh
test "$#" -eq 7 || exit 91
test "$1" = run || exit 92
test "$2" = --plan || exit 93
test "$3" = 'PLAN_PATH' || exit 94
test "$4" = --receipt || exit 95
test "$5" = 'RECEIPT_PATH' || exit 96
test "$6" = --cgroup-root || exit 97
test "$7" = 'CGROUP_PATH' || exit 98
test "$EXACT" = yes || exit 99
test -z "$PROOFBOUND_SDK_LEAK" || exit 100
printf '%s\n' 'RESULT_VALUE'
"""
            script = (
                script.replace("PLAN_PATH", str(plan))
                .replace("RECEIPT_PATH", str(receipt))
                .replace("CGROUP_PATH", str(cgroup))
                .replace("RESULT_VALUE", RESULT.decode())
            )
            fake.write_text(script)
            fake.chmod(0o755)
            old = os.environ.get("PROOFBOUND_SDK_LEAK")
            os.environ["PROOFBOUND_SDK_LEAK"] = "ambient"
            try:
                result = run(
                    pbr=fake,
                    plan=plan,
                    receipt=receipt,
                    cgroup_root=cgroup,
                    environment={"EXACT": "yes"},
                )
            finally:
                if old is None:
                    del os.environ["PROOFBOUND_SDK_LEAK"]
                else:
                    os.environ["PROOFBOUND_SDK_LEAK"] = old
            self.assertEqual(result.outcome_detail, 0)
            self.assertFalse((root / "touch-injection").exists())

    def test_run_kills_oversized_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "pbr"
            fake.write_text("#!/bin/sh\nprintf '%0100d' 0\n")
            fake.chmod(0o755)
            with self.assertRaisesRegex(SdkError, "sdk.process.output-bound"):
                run(
                    pbr=fake,
                    plan=root / "plan",
                    receipt=root / "receipt",
                    cgroup_root=root / "cgroup",
                    environment={},
                    max_output_bytes=16,
                )


if __name__ == "__main__":
    unittest.main()
