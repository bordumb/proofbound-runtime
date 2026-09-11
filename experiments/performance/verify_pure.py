"""Independently verifies raw version 1 pure benchmark results."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import NoReturn


MAX_RESULT_BYTES = 16 * 1024 * 1024
SUBJECTS = (
    "plan-parse-v1",
    "authority-normalization-v1",
    "policy-compilation-v1",
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
    "subjects",
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


def is_lower_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def require_nonempty_text(value: object) -> str:
    if type(value) is not str or not value:
        fail("benchmark.verify.schema-invalid")
    return value


def require_uint(value: object) -> int:
    if type(value) is not int or value < 0 or value > (2**64 - 1):
        fail("benchmark.verify.schema-invalid")
    return value


def verify_summary(value: object, sample_count: int) -> None:
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
    count = require_uint(summary["count"])
    if (
        count != sample_count
        or len(samples) != sample_count
        or sample_count == 0
        or samples != sorted(samples)
    ):
        fail("benchmark.verify.statistics-mismatch")
    middle = sample_count // 2
    median = (
        samples[middle]
        if sample_count % 2 == 1
        else samples[middle - 1] + (samples[middle] - samples[middle - 1]) // 2
    )
    p95 = samples[sample_count - sample_count // 20 - 1]
    expected = {
        "minimum_ns": samples[0],
        "median_ns": median,
        "p95_ns": p95,
        "maximum_ns": samples[-1],
    }
    if any(require_uint(summary[name]) != expected[name] for name in expected):
        fail("benchmark.verify.statistics-mismatch")


def verify_result(
    raw: bytes,
    expected_source: str,
    benchmark_executable: Path,
    fixture: Path,
) -> dict[str, object]:
    """Verifies a raw result against separately supplied exact identities."""

    value = require_object(decode(raw), TOP_LEVEL_KEYS)
    if (
        value["schema"] != "proofbound-runtime-performance-result/1"
        or value["kind"] != "pure"
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

    executable_identity = value["benchmark_executable_sha256"]
    if not is_lower_hex(executable_identity, 64):
        fail("benchmark.verify.schema-invalid")
    try:
        observed_executable = digest_path(benchmark_executable)
    except OSError:
        fail("benchmark.verify.executable-mismatch")
    if executable_identity != observed_executable:
        fail("benchmark.verify.executable-mismatch")

    toolchain = require_object(value["toolchain"], {"release", "target"})
    require_nonempty_text(toolchain["release"])
    target = require_nonempty_text(toolchain["target"])
    architecture = require_nonempty_text(value["architecture"])
    expected_prefix = {"x86_64": "x86_64-", "aarch64": "aarch64-"}.get(
        architecture
    )
    if expected_prefix is None or not target.startswith(expected_prefix):
        fail("benchmark.verify.schema-invalid")

    protocol = require_object(
        value["protocol"], {"warmup_count", "sample_count", "target_sample_ns"}
    )
    warmup_count = require_uint(protocol["warmup_count"])
    sample_count = require_uint(protocol["sample_count"])
    target_sample_ns = require_uint(protocol["target_sample_ns"])
    if (warmup_count, sample_count, target_sample_ns) != (100, 1_000, 10_000_000):
        fail("benchmark.verify.statistics-mismatch")

    subjects_value = value["subjects"]
    if type(subjects_value) is not list or [
        subject.get("subject") if type(subject) is dict else None
        for subject in subjects_value
    ] != list(SUBJECTS):
        fail("benchmark.verify.subject-domain-mismatch")
    try:
        fixture_identity = digest_path(fixture)
    except OSError:
        fail("benchmark.verify.fixture-mismatch")
    for subject_value in subjects_value:
        subject = require_object(
            subject_value, {"subject", "fixture_sha256", "measurement"}
        )
        if (
            not is_lower_hex(subject["fixture_sha256"], 64)
            or subject["fixture_sha256"] != fixture_identity
        ):
            fail("benchmark.verify.fixture-mismatch")
        measurement = require_object(
            subject["measurement"], {"batch_count", "summary"}
        )
        if require_uint(measurement["batch_count"]) == 0:
            fail("benchmark.verify.statistics-mismatch")
        verify_summary(measurement["summary"], sample_count)

    return {
        "schema": "proofbound-runtime-performance-verification/1",
        "valid": True,
        "result_sha256": hashlib.sha256(raw).hexdigest(),
        "source_commit": expected_source,
        "subjects": list(SUBJECTS),
    }
