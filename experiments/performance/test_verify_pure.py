from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from experiments.performance.verify_pure import VerificationFailure, main, verify_result


SOURCE = "a" * 40
SUBJECTS = (
    "plan-parse-v1",
    "authority-normalization-v1",
    "policy-compilation-v1",
    "receipt-construction-v1",
    "receipt-canonical-encoding-v1",
    "receipt-independent-verification-v1",
    "release-execution-composition-v1",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_result(
    executable: bytes, plan_fixture: bytes, receipt_fixture: bytes
) -> dict[str, object]:
    samples = list(range(1_000))
    measurement = {
        "batch_count": 1,
        "summary": {
            "samples_ns": samples,
            "count": 1_000,
            "minimum_ns": 0,
            "median_ns": 499,
            "p95_ns": 949,
            "maximum_ns": 999,
        },
    }
    return {
        "schema": "proofbound-runtime-performance-result/1",
        "kind": "pure",
        "complete": True,
        "source": {"commit": SOURCE, "tree_state": "clean"},
        "benchmark_executable_sha256": digest(executable),
        "toolchain": {
            "release": "1.93.0",
            "target": "x86_64-unknown-linux-gnu",
        },
        "build_profile": "release",
        "architecture": "x86_64",
        "protocol": {
            "warmup_count": 100,
            "sample_count": 1_000,
            "target_sample_ns": 10_000_000,
        },
        "subjects": [
            {
                "subject": subject,
                "fixture_sha256": digest(
                    plan_fixture if subject.startswith(("plan-", "authority-", "policy-"))
                    else receipt_fixture
                ),
                "measurement": copy.deepcopy(measurement),
            }
            for subject in SUBJECTS
        ],
    }


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class PureBenchmarkVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.executable = root / "pbr-bench"
        self.plan_fixture = root / "minimal-v1.toml"
        self.receipt_fixture = root / "reusable-receipt-v1.json"
        self.executable.write_bytes(b"exact benchmark executable")
        self.plan_fixture.write_bytes(b"exact plan fixture")
        self.receipt_fixture.write_bytes(b"exact receipt fixture")
        self.value = fixture_result(
            self.executable.read_bytes(),
            self.plan_fixture.read_bytes(),
            self.receipt_fixture.read_bytes(),
        )

    def verify(self, value: object | None = None) -> dict[str, object]:
        return verify_result(
            encode(self.value if value is None else value),
            SOURCE,
            self.executable,
            self.plan_fixture,
            self.receipt_fixture,
        )

    def test_valid_result_is_rederived_from_raw_bytes(self) -> None:
        raw = encode(self.value)
        report = verify_result(
            raw,
            SOURCE,
            self.executable,
            self.plan_fixture,
            self.receipt_fixture,
        )
        self.assertEqual(report["schema"], "proofbound-runtime-performance-verification/1")
        self.assertTrue(report["valid"])
        self.assertEqual(report["result_sha256"], digest(raw))
        self.assertEqual(report["source_commit"], SOURCE)
        self.assertEqual(report["subjects"], list(SUBJECTS))

    def test_unknown_duplicate_and_incomplete_shapes_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.value)
        unknown["unexpected"] = True
        missing = copy.deepcopy(self.value)
        missing["subjects"] = missing["subjects"][:-1]
        cases = (
            (encode(unknown), "benchmark.verify.schema-invalid"),
            (encode(missing), "benchmark.verify.subject-domain-mismatch"),
            (b'{"schema":1,"schema":2}', "benchmark.verify.json-invalid"),
        )
        for raw, code in cases:
            with self.subTest(code=code), self.assertRaises(VerificationFailure) as caught:
                verify_result(
                    raw,
                    SOURCE,
                    self.executable,
                    self.plan_fixture,
                    self.receipt_fixture,
                )
            self.assertEqual(caught.exception.code, code)

    def test_external_identity_substitutions_fail_closed(self) -> None:
        cases = []
        source = copy.deepcopy(self.value)
        source["source"]["commit"] = "b" * 40
        cases.append((source, "benchmark.verify.source-mismatch"))
        executable = copy.deepcopy(self.value)
        executable["benchmark_executable_sha256"] = "b" * 64
        cases.append((executable, "benchmark.verify.executable-mismatch"))
        fixture = copy.deepcopy(self.value)
        fixture["subjects"][0]["fixture_sha256"] = "b" * 64
        cases.append((fixture, "benchmark.verify.fixture-mismatch"))
        for value, code in cases:
            with self.subTest(code=code), self.assertRaises(VerificationFailure) as caught:
                self.verify(value)
            self.assertEqual(caught.exception.code, code)

    def test_sample_and_summary_forgery_fail_closed(self) -> None:
        unsorted = copy.deepcopy(self.value)
        unsorted["subjects"][0]["measurement"]["summary"]["samples_ns"][:2] = [1, 0]
        statistic = copy.deepcopy(self.value)
        statistic["subjects"][0]["measurement"]["summary"]["p95_ns"] = 950
        count = copy.deepcopy(self.value)
        count["protocol"]["sample_count"] = 999
        for value in (unsorted, statistic, count):
            with self.assertRaises(VerificationFailure) as caught:
                self.verify(value)
            self.assertEqual(
                caught.exception.code, "benchmark.verify.statistics-mismatch"
            )

    def test_standalone_command_emits_a_separate_verification_report(self) -> None:
        result = Path(self.temporary.name) / "RESULT.json"
        result.write_bytes(encode(self.value))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exit_code = main(
                [
                    "--result",
                    str(result),
                    "--expected-source",
                    SOURCE,
                    "--benchmark-executable",
                    str(self.executable),
                    "--plan-fixture",
                    str(self.plan_fixture),
                    "--receipt-fixture",
                    str(self.receipt_fixture),
                ]
            )
        self.assertEqual(exit_code, 0)
        report = json.loads(output.getvalue())
        self.assertTrue(report["valid"])
        self.assertEqual(report["result_sha256"], digest(result.read_bytes()))


if __name__ == "__main__":
    unittest.main()
