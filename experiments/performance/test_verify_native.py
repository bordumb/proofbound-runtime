from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.performance.verify_native import VerificationFailure, verify_result


SOURCE = "a" * 40
PHASES = (
    "plan-validation-and-normalization-v1",
    "host-and-path-preflight-v1",
    "executable-closure-inventory-v1",
    "cgroup-creation-and-readback-v1",
    "launcher-request-and-identity-revalidation-v1",
    "stopped-launcher-creation-v1",
    "boundary-installation-v1",
    "child-execution-v1",
    "process-tree-cleanup-v1",
    "stream-collection-v1",
    "output-inventory-v1",
    "receipt-construction-and-publication-v1",
    "run-result-projection-v1",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def summary(samples: list[int]) -> dict[str, object]:
    ordered = sorted(samples)
    count = len(ordered)
    middle = count // 2
    median = (
        ordered[middle]
        if count % 2
        else ordered[middle - 1] + (ordered[middle] - ordered[middle - 1]) // 2
    )
    return {
        "samples_ns": ordered,
        "count": count,
        "minimum_ns": ordered[0],
        "median_ns": median,
        "p95_ns": ordered[count - count // 20 - 1],
        "maximum_ns": ordered[-1],
    }


def encode(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


class NativeBenchmarkVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.executable = self.write("pbr-bench", b"benchmark")
        self.pbr = self.write("pbr", b"runtime")
        self.launcher = self.write("pbr-native-launcher", b"launcher")
        self.plan = self.write("plan.toml", b"exact plan")
        self.workload = self.write("hello-static", b"exact workload")
        self.expected_output = self.write(
            "expected-output.txt", b"hello from a bounded execution\n"
        )
        self.verifier = self.root / "pbr-verify"
        self.verifier.write_text(
            "#!/usr/bin/env python3\n"
            "import hashlib,json,sys\n"
            "raw=open(sys.argv[-1],'rb').read()\n"
            "expected='sha256:'+hashlib.sha256(raw).hexdigest()\n"
            "assert sys.argv[1:3] == ['--expected-commitment', expected]\n"
            "print(json.dumps({'eligibility':{'reasons':[],'status':'reusable'},"
            "'receipt_commitment':expected,'valid':True},separators=(',',':')))\n"
        )
        self.verifier.chmod(0o755)
        self.value = self.fixture_result()

    def write(self, name: str, data: bytes) -> Path:
        path = self.root / name
        path.write_bytes(data)
        return path

    def fixture_result(self) -> dict[str, object]:
        runs = []
        phase_columns = [[] for _ in PHASES]
        totals = []
        for index in range(100):
            run_root = self.root / "runs" / f"{index:03d}"
            run_root.mkdir(parents=True)
            receipt = (json.dumps({"receipt": index}) + "\n").encode()
            receipt_digest = digest(receipt)
            output = self.expected_output.read_bytes()
            result = encode(
                {
                    "commitment": f"sha256:{receipt_digest}",
                    "execution_id": f"execution-{index:03d}",
                    "outcome": {"code": 0, "kind": "exited"},
                    "receipt": str(run_root / "receipt.json"),
                    "schema": "proofbound-runtime-run-result/1",
                }
            )
            (run_root / "receipt.json").write_bytes(receipt)
            (run_root / "run-result.json").write_bytes(result)
            (run_root / "hello.txt").write_bytes(output)
            phase_samples = [index + phase + 1 for phase in range(len(PHASES))]
            total = sum(phase_samples)
            totals.append(total)
            for column, sample in zip(phase_columns, phase_samples, strict=True):
                column.append(sample)
            runs.append(
                {
                    "index": index,
                    "total_ns": total,
                    "phase_samples_ns": phase_samples,
                    "receipt_sha256": receipt_digest,
                    "run_result_sha256": digest(result),
                    "output_sha256": digest(output),
                }
            )
        return {
            "schema": "proofbound-runtime-performance-result/1",
            "kind": "native",
            "complete": True,
            "source": {"commit": SOURCE, "tree_state": "clean"},
            "benchmark_executable_sha256": digest(self.executable.read_bytes()),
            "toolchain": {
                "release": "1.94.0",
                "target": "x86_64-unknown-linux-gnu",
            },
            "build_profile": "release",
            "architecture": "x86_64",
            "protocol": {"warmup_count": 10, "sample_count": 100},
            "host": {
                "runner_image": "ubuntu-24.04",
                "cpu_model": "fixture cpu",
                "cpu_count": 4,
                "memory_bytes": 8 * 1024 * 1024 * 1024,
                "kernel_release": "6.17.0-fixture",
                "cgroup_version": 2,
                "enabled_controllers": ["pids"],
                "maximum_resident_set_bytes": 4 * 1024 * 1024,
            },
            "runtime": {
                "pbr_sha256": digest(self.pbr.read_bytes()),
                "launcher_sha256": digest(self.launcher.read_bytes()),
                "verifier_sha256": digest(self.verifier.read_bytes()),
            },
            "workload": {
                "id": "hello-static-v1",
                "plan_sha256": digest(self.plan.read_bytes()),
                "executable_sha256": digest(self.workload.read_bytes()),
                "expected_output_sha256": digest(self.expected_output.read_bytes()),
            },
            "measurements": {
                "runs": runs,
                "total": summary(totals),
                "phases": [
                    {"phase": phase, "summary": summary(samples)}
                    for phase, samples in zip(PHASES, phase_columns, strict=True)
                ],
            },
        }

    def verify(self, value: object | None = None) -> dict[str, object]:
        return verify_result(
            encode(self.value if value is None else value),
            SOURCE,
            "x86_64",
            self.executable,
            self.pbr,
            self.launcher,
            self.verifier,
            self.plan,
            self.workload,
            self.expected_output,
            self.root / "runs",
        )

    def test_valid_result_rederives_every_run_and_summary(self) -> None:
        report = self.verify()
        self.assertTrue(report["valid"])
        self.assertEqual(
            report["schema"], "proofbound-runtime-performance-verification/1"
        )
        self.assertEqual(report["source_commit"], SOURCE)
        self.assertEqual(report["workload"], "hello-static-v1")
        self.assertEqual(report["sample_count"], 100)

    def test_unknown_duplicate_and_incomplete_shapes_fail_closed(self) -> None:
        unknown = copy.deepcopy(self.value)
        unknown["unexpected"] = True
        incomplete = copy.deepcopy(self.value)
        incomplete["measurements"]["runs"].pop()
        cases = (
            (encode(unknown), "benchmark.verify.schema-invalid"),
            (encode(incomplete), "benchmark.verify.statistics-mismatch"),
            (b'{"schema":1,"schema":2}', "benchmark.verify.json-invalid"),
        )
        for raw, code in cases:
            with self.subTest(code=code), self.assertRaises(VerificationFailure) as caught:
                verify_result(
                    raw,
                    SOURCE,
                    "x86_64",
                    self.executable,
                    self.pbr,
                    self.launcher,
                    self.verifier,
                    self.plan,
                    self.workload,
                    self.expected_output,
                    self.root / "runs",
                )
            self.assertEqual(caught.exception.code, code)

    def test_identity_and_retained_file_substitutions_fail_closed(self) -> None:
        cases = []
        runtime = copy.deepcopy(self.value)
        runtime["runtime"]["pbr_sha256"] = "b" * 64
        cases.append((runtime, "benchmark.verify.runtime-mismatch"))
        workload = copy.deepcopy(self.value)
        workload["workload"]["plan_sha256"] = "b" * 64
        cases.append((workload, "benchmark.verify.workload-mismatch"))
        receipt = copy.deepcopy(self.value)
        receipt["measurements"]["runs"][0]["receipt_sha256"] = "b" * 64
        cases.append((receipt, "benchmark.verify.run-artifact-mismatch"))
        projection = self.root / "runs/000/run-result.json"
        projection_value = json.loads(projection.read_bytes())
        del projection_value["receipt"]
        projection.write_bytes(encode(projection_value))
        projection_missing_receipt = copy.deepcopy(self.value)
        projection_missing_receipt["measurements"]["runs"][0]["run_result_sha256"] = digest(
            projection.read_bytes()
        )
        cases.append(
            (projection_missing_receipt, "benchmark.verify.run-artifact-mismatch")
        )
        for value, code in cases:
            with self.subTest(code=code), self.assertRaises(VerificationFailure) as caught:
                self.verify(value)
            self.assertEqual(caught.exception.code, code)

    def test_phase_correlation_and_summaries_cannot_be_forged(self) -> None:
        correlation = copy.deepcopy(self.value)
        correlation["measurements"]["runs"][0]["total_ns"] += 1
        summary_forgery = copy.deepcopy(self.value)
        summary_forgery["measurements"]["phases"][0]["summary"]["p95_ns"] += 1
        phase_order = copy.deepcopy(self.value)
        phase_order["measurements"]["phases"].reverse()
        for value in (correlation, summary_forgery, phase_order):
            with self.assertRaises(VerificationFailure) as caught:
                self.verify(value)
            self.assertEqual(caught.exception.code, "benchmark.verify.statistics-mismatch")


if __name__ == "__main__":
    unittest.main()
