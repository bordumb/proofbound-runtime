#!/usr/bin/env python3
"""Raw lifecycle evidence primitives for experiment 0001H."""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
from pathlib import Path

from experiments.network_authority.record_common import RecordError, regular_bytes, write_new


class LifecycleEvidenceError(Exception):
    """A lifecycle observation was incomplete or ambiguous."""


def sha256(path: Path) -> str:
    return hashlib.sha256(regular_bytes(path)).hexdigest()


def executable_digest() -> str:
    return sha256(Path(sys.executable).resolve(strict=True))


def start_mediator() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "PYTHONHASHSEED": "0"},
    )


def stop_mediator(process: subprocess.Popen[bytes]) -> dict[str, object]:
    process.send_signal(signal.SIGKILL)
    status = process.wait(timeout=2)
    if status != -signal.SIGKILL:
        raise LifecycleEvidenceError("mediator did not retain the injected signal")
    return {"pid": process.pid, "signal": signal.SIGKILL, "status": "signaled"}


def crash_evidence(phase: str) -> dict[str, object]:
    if phase not in {"before-release", "during-exchange"}:
        raise LifecycleEvidenceError("crash phase is unknown")
    digest = executable_digest()
    process = start_mediator()
    identity = {"executable_sha256": digest, "pid": process.pid}
    try:
        stopped = stop_mediator(process)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
    return {
        "event": f"mediator-crashed-{phase}",
        "identity": identity,
        "schema": "proofbound-runtime-mediator-crash-evidence/1",
        "termination": stopped,
    }


def restart_evidence() -> dict[str, object]:
    digest = executable_digest()
    first = start_mediator()
    first_identity = {"executable_sha256": digest, "pid": first.pid}
    try:
        stop_mediator(first)
    finally:
        if first.poll() is None:
            first.kill()
            first.wait(timeout=2)
    second = start_mediator()
    try:
        second_identity = {"executable_sha256": digest, "pid": second.pid}
        if first_identity == second_identity:
            raise LifecycleEvidenceError("mediator restart did not change identity")
        return {
            "event": "mediator-identity-mismatch",
            "first": first_identity,
            "schema": "proofbound-runtime-mediator-restart-evidence/1",
            "second": second_identity,
        }
    finally:
        stop_mediator(second)


def substitution_evidence(subject: Path, replacement: bytes) -> dict[str, object]:
    before = sha256(subject)
    subject.write_bytes(replacement)
    after = sha256(subject)
    if before == after:
        raise LifecycleEvidenceError("substitution did not change identity")
    return {
        "after_sha256": after,
        "before_sha256": before,
        "event": "subject-digest-mismatch",
        "mutation_count": 1,
        "schema": "proofbound-runtime-substitution-evidence/1",
    }


def cleanup_evidence() -> dict[str, object]:
    process = start_mediator()
    stopped = stop_mediator(process)
    if process.poll() is None:
        raise LifecycleEvidenceError("cleanup retained a live process")
    return {
        "event": "failure-retained",
        "injected": "teardown-failure",
        "schema": "proofbound-runtime-cleanup-evidence/1",
        "survivor_count": 0,
        "termination": stopped,
    }


def no_replace_evidence(path: Path) -> dict[str, object]:
    sentinel = b"existing-result\n"
    write_new(path, sentinel)
    before = sha256(path)
    rejected = False
    try:
        write_new(path, b"replacement\n")
    except (FileExistsError, RecordError):
        rejected = True
    after = sha256(path)
    if not rejected or before != after or regular_bytes(path) != sentinel:
        raise LifecycleEvidenceError("existing result was not preserved")
    return {
        "event": "replacement-rejected",
        "preserved_sha256": after,
        "schema": "proofbound-runtime-publication-evidence/1",
    }
