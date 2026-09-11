"""Independently verifies raw version 1 native benchmark results."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import NoReturn


MAX_RESULT_BYTES = 32 * 1024 * 1024
MAX_UINT64 = 2**64 - 1
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
TOP_LEVEL_KEYS = {
    "schema",
    "kind",
    "complete",
    "source",
    "benchmark_executable_sha256",
    "toolchain",
    "build_profile",
    "architecture",
    "protocol",
    "host",
    "runtime",
    "workload",
    "measurements",
}
RUN_KEYS = {
    "index",
    "total_ns",
    "phase_samples_ns",
    "receipt_sha256",
    "run_result_sha256",
    "output_sha256",
}


class VerificationFailure(Exception):
    """One closed independent-verification failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def fail(code: str) -> NoReturn:
    raise VerificationFailure(code)


def digest_path(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            fail("benchmark.verify.json-invalid")
        output[key] = value
    return output


def decode(raw: bytes) -> dict[str, object]:
    if not raw or len(raw) > MAX_RESULT_BYTES:
        fail("benchmark.verify.json-invalid")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=strict_object,
            parse_constant=lambda _value: fail("benchmark.verify.json-invalid"),
        )
    except VerificationFailure:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("benchmark.verify.json-invalid")
    if type(value) is not dict:
        fail("benchmark.verify.schema-invalid")
    return value


def require_object(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        fail("benchmark.verify.schema-invalid")
    return value


def require_uint(value: object) -> int:
    if type(value) is not int or value < 0 or value > MAX_UINT64:
        fail("benchmark.verify.schema-invalid")
    return value


def require_nonempty_text(value: object) -> str:
    if type(value) is not str or not value or len(value) > 512:
        fail("benchmark.verify.schema-invalid")
    return value


def is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def verify_summary(value: object, expected_samples: list[int]) -> None:
    summary = require_object(
        value,
        {
            "samples_ns",
            "count",
            "minimum_ns",
            "median_ns",
            "p95_ns",
            "maximum_ns",
        },
    )
    samples_value = summary["samples_ns"]
    if type(samples_value) is not list:
        fail("benchmark.verify.schema-invalid")
    samples = [require_uint(sample) for sample in samples_value]
    expected = sorted(expected_samples)
    count = len(expected)
    if count == 0 or samples != expected or require_uint(summary["count"]) != count:
        fail("benchmark.verify.statistics-mismatch")
    middle = count // 2
    median = (
        expected[middle]
        if count % 2
        else expected[middle - 1] + (expected[middle] - expected[middle - 1]) // 2
    )
    statistics = {
        "minimum_ns": expected[0],
        "median_ns": median,
        "p95_ns": expected[count - count // 20 - 1],
        "maximum_ns": expected[-1],
    }
    if any(require_uint(summary[name]) != expected_value for name, expected_value in statistics.items()):
        fail("benchmark.verify.statistics-mismatch")


def require_digest(value: object, path: Path, code: str) -> None:
    if not is_lower_hex(value, 64):
        fail("benchmark.verify.schema-invalid")
    try:
        observed = digest_path(path)
    except OSError:
        fail(code)
    if value != observed:
        fail(code)


def verify_receipt(
    verifier: Path, receipt: Path, commitment: str
) -> None:
    try:
        completed = subprocess.run(
            [str(verifier), "--expected-commitment", commitment, str(receipt)],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail("benchmark.verify.receipt-invalid")
    if completed.returncode != 0 or completed.stderr:
        fail("benchmark.verify.receipt-invalid")
    report = require_object(
        decode(completed.stdout),
        {"eligibility", "receipt_commitment", "valid"},
    )
    eligibility = require_object(report["eligibility"], {"reasons", "status"})
    if (
        report["valid"] is not True
        or report["receipt_commitment"] != commitment
        or eligibility != {"reasons": [], "status": "reusable"}
    ):
        fail("benchmark.verify.receipt-invalid")


def verify_result(
    raw: bytes,
    expected_source: str,
    expected_architecture: str,
    benchmark_executable: Path,
    pbr: Path,
    launcher: Path,
    verifier: Path,
    plan: Path,
    workload_executable: Path,
    expected_output: Path,
    runs_root: Path,
) -> dict[str, object]:
    """Verifies one raw result and all separately retained run artifacts."""

    value = require_object(decode(raw), TOP_LEVEL_KEYS)
    if (
        value["schema"] != "proofbound-runtime-performance-result/1"
        or value["kind"] != "native"
        or value["complete"] is not True
        or value["build_profile"] != "release"
    ):
        fail("benchmark.verify.schema-invalid")

    source = require_object(value["source"], {"commit", "tree_state"})
    if (
        not is_lower_hex(source["commit"], 40)
        or not is_lower_hex(expected_source, 40)
        or source["commit"] != expected_source
        or source["tree_state"] != "clean"
    ):
        fail("benchmark.verify.source-mismatch")
    require_digest(
        value["benchmark_executable_sha256"],
        benchmark_executable,
        "benchmark.verify.executable-mismatch",
    )

    toolchain = require_object(value["toolchain"], {"release", "target"})
    require_nonempty_text(toolchain["release"])
    target = require_nonempty_text(toolchain["target"])
    architecture = require_nonempty_text(value["architecture"])
    prefix = {"x86_64": "x86_64-", "aarch64": "aarch64-"}.get(expected_architecture)
    if architecture != expected_architecture or prefix is None:
        fail("benchmark.verify.architecture-mismatch")
    if not target.startswith(prefix):
        fail("benchmark.verify.schema-invalid")

    protocol = require_object(value["protocol"], {"warmup_count", "sample_count"})
    if (require_uint(protocol["warmup_count"]), require_uint(protocol["sample_count"])) != (
        10,
        100,
    ):
        fail("benchmark.verify.statistics-mismatch")

    host = require_object(
        value["host"],
        {
            "runner_image",
            "cpu_model",
            "cpu_count",
            "memory_bytes",
            "kernel_release",
            "cgroup_version",
            "enabled_controllers",
            "maximum_resident_set_bytes",
        },
    )
    for name in ("runner_image", "cpu_model", "kernel_release"):
        require_nonempty_text(host[name])
    if (
        require_uint(host["cpu_count"]) == 0
        or require_uint(host["memory_bytes"]) == 0
        or require_uint(host["cgroup_version"]) != 2
    ):
        fail("benchmark.verify.schema-invalid")
    controllers_value = host["enabled_controllers"]
    if type(controllers_value) is not list:
        fail("benchmark.verify.schema-invalid")
    controllers = [require_nonempty_text(item) for item in controllers_value]
    if controllers != sorted(set(controllers)) or "pids" not in controllers:
        fail("benchmark.verify.schema-invalid")
    maximum_rss = host["maximum_resident_set_bytes"]
    if maximum_rss is not None:
        require_uint(maximum_rss)

    runtime = require_object(
        value["runtime"], {"pbr_sha256", "launcher_sha256", "verifier_sha256"}
    )
    for field, path in (
        ("pbr_sha256", pbr),
        ("launcher_sha256", launcher),
        ("verifier_sha256", verifier),
    ):
        require_digest(runtime[field], path, "benchmark.verify.runtime-mismatch")

    workload = require_object(
        value["workload"],
        {"id", "plan_sha256", "executable_sha256", "expected_output_sha256"},
    )
    if workload["id"] != "hello-static-v1":
        fail("benchmark.verify.workload-mismatch")
    for field, path in (
        ("plan_sha256", plan),
        ("executable_sha256", workload_executable),
        ("expected_output_sha256", expected_output),
    ):
        require_digest(workload[field], path, "benchmark.verify.workload-mismatch")
    expected_output_bytes = expected_output.read_bytes()

    measurements = require_object(value["measurements"], {"runs", "total", "phases"})
    runs_value = measurements["runs"]
    if type(runs_value) is not list or len(runs_value) != 100:
        fail("benchmark.verify.statistics-mismatch")
    totals: list[int] = []
    phase_columns: list[list[int]] = [[] for _ in PHASES]
    for expected_index, run_value in enumerate(runs_value):
        run = require_object(run_value, RUN_KEYS)
        if require_uint(run["index"]) != expected_index:
            fail("benchmark.verify.statistics-mismatch")
        phase_samples_value = run["phase_samples_ns"]
        if type(phase_samples_value) is not list or len(phase_samples_value) != len(PHASES):
            fail("benchmark.verify.statistics-mismatch")
        phase_samples = [require_uint(sample) for sample in phase_samples_value]
        total = require_uint(run["total_ns"])
        if sum(phase_samples) != total or total > MAX_UINT64:
            fail("benchmark.verify.statistics-mismatch")
        totals.append(total)
        for column, sample in zip(phase_columns, phase_samples):
            column.append(sample)

        run_root = runs_root / f"{expected_index:03d}"
        receipt = run_root / "receipt.json"
        run_result = run_root / "run-result.json"
        output = run_root / "hello.txt"
        for field, path in (
            ("receipt_sha256", receipt),
            ("run_result_sha256", run_result),
            ("output_sha256", output),
        ):
            require_digest(run[field], path, "benchmark.verify.run-artifact-mismatch")
        try:
            if output.read_bytes() != expected_output_bytes:
                fail("benchmark.verify.run-artifact-mismatch")
            projection = decode(run_result.read_bytes())
        except OSError:
            fail("benchmark.verify.run-artifact-mismatch")
        if set(projection) != {
            "schema",
            "commitment",
            "execution_id",
            "outcome",
            "receipt",
        }:
            fail("benchmark.verify.run-artifact-mismatch")
        commitment = f"sha256:{run['receipt_sha256']}"
        receipt_projection = require_nonempty_text(projection["receipt"])
        if (
            projection["schema"] != "proofbound-runtime-run-result/1"
            or projection["commitment"] != commitment
            or not require_nonempty_text(projection["execution_id"])
            or projection["outcome"] != {"kind": "exited", "code": 0}
            or Path(receipt_projection).parts[-3:]
            != ("runs", f"{expected_index:03d}", "receipt.json")
        ):
            fail("benchmark.verify.run-artifact-mismatch")
        verify_receipt(verifier, receipt, commitment)

    verify_summary(measurements["total"], totals)
    phases_value = measurements["phases"]
    if type(phases_value) is not list or len(phases_value) != len(PHASES):
        fail("benchmark.verify.statistics-mismatch")
    for expected_phase, samples, phase_value in zip(PHASES, phase_columns, phases_value):
        phase = require_object(phase_value, {"phase", "summary"})
        if phase["phase"] != expected_phase:
            fail("benchmark.verify.statistics-mismatch")
        verify_summary(phase["summary"], samples)

    return {
        "schema": "proofbound-runtime-performance-verification/1",
        "valid": True,
        "result_sha256": hashlib.sha256(raw).hexdigest(),
        "source_commit": expected_source,
        "workload": "hello-static-v1",
        "sample_count": 100,
    }


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Independently verify a native Runtime benchmark result."
    )
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--expected-source", required=True)
    parser.add_argument("--expected-architecture", required=True)
    parser.add_argument("--benchmark-executable", type=Path, required=True)
    parser.add_argument("--pbr", type=Path, required=True)
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--verifier", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--workload-executable", type=Path, required=True)
    parser.add_argument("--expected-output", type=Path, required=True)
    parser.add_argument("--runs-root", type=Path, required=True)
    options = parser.parse_args(arguments)
    try:
        raw = options.result.read_bytes()
        report = verify_result(
            raw,
            options.expected_source,
            options.expected_architecture,
            options.benchmark_executable,
            options.pbr,
            options.launcher,
            options.verifier,
            options.plan,
            options.workload_executable,
            options.expected_output,
            options.runs_root,
        )
    except OSError:
        print("benchmark.verify.result-read-failed", file=sys.stderr)
        return 1
    except VerificationFailure as error:
        print(error.code, file=sys.stderr)
        return 1
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
