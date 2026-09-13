#!/usr/bin/env python3
"""Raw lifecycle evidence primitives for experiment 0001H."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
import stat

from experiments.network_authority.record_common import RecordError, regular_bytes, write_new


class LifecycleEvidenceError(Exception):
    """A lifecycle observation was incomplete or ambiguous."""


def sha256(path: Path) -> str:
    return hashlib.sha256(regular_bytes(path)).hexdigest()


def executable_digest() -> str:
    path = Path(sys.executable).resolve(strict=True)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 128 * 1024 * 1024:
        raise LifecycleEvidenceError("mediator executable is not bounded and regular")
    value = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


@dataclass
class Mediator:
    process: subprocess.Popen[bytes]
    channel: socket.socket
    channel_peer: str
    generation: int
    root: Path


def start_mediator(generation: int = 1) -> Mediator:
    if type(generation) is not int or generation <= 0:
        raise LifecycleEvidenceError("mediator generation is invalid")
    root = Path(tempfile.mkdtemp(prefix="proofbound-mediator-"))
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    process: subprocess.Popen[bytes] | None = None
    try:
        listener.bind(str(root / "channel.sock"))
        listener.listen(1)
        listener.settimeout(2)
        program = (
            "import os,socket,sys,time;"
            "root=sys.argv[1];"
            "peer=f'{root}/peer-{os.getpid()}';"
            "channel=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);"
            "channel.bind(peer);channel.connect(root+'/channel.sock');"
            "channel.sendall(b'ready\\n');time.sleep(30)"
        )
        process = subprocess.Popen(
            [sys.executable, "-c", program, str(root)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"},
        )
        channel, _address = listener.accept()
        channel.settimeout(2)
        peer = channel.getpeername()
        if peer != str(root / f"peer-{process.pid}") or channel.recv(6) != b"ready\n":
            raise LifecycleEvidenceError("mediator channel peer is invalid")
        if sys.platform.startswith("linux"):
            raw = channel.getsockopt(socket.SOL_SOCKET, 17, 12)
            if len(raw) != 12 or struct.unpack("=3i", raw)[0] != process.pid:
                raise LifecycleEvidenceError("mediator kernel peer identity changed")
        return Mediator(process, channel, peer, generation, root)
    except BaseException:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        shutil.rmtree(root, ignore_errors=True)
        raise
    finally:
        listener.close()


def mediator_identity(mediator: Mediator) -> dict[str, object]:
    return {
        "channel_peer": mediator.channel_peer,
        "executable_sha256": executable_digest(),
        "generation": mediator.generation,
        "pid": mediator.process.pid,
    }


def stop_mediator(mediator: Mediator) -> dict[str, object]:
    process = mediator.process
    process.send_signal(signal.SIGKILL)
    status = process.wait(timeout=2)
    if status != -signal.SIGKILL:
        raise LifecycleEvidenceError("mediator did not retain the injected signal")
    mediator.channel.close()
    shutil.rmtree(mediator.root)
    return {"pid": process.pid, "signal": signal.SIGKILL, "status": "signaled"}


def crash_evidence(phase: str) -> dict[str, object]:
    if phase not in {"before-release", "during-exchange"}:
        raise LifecycleEvidenceError("crash phase is unknown")
    mediator = start_mediator(1)
    try:
        identity = mediator_identity(mediator)
        stopped = stop_mediator(mediator)
    finally:
        if mediator.process.poll() is None:
            stop_mediator(mediator)
    return {
        "event": f"mediator-crashed-{phase}",
        "identity": identity,
        "schema": "proofbound-runtime-mediator-crash-evidence/1",
        "termination": stopped,
    }


def restart_evidence() -> dict[str, object]:
    first = start_mediator(1)
    try:
        first_identity = mediator_identity(first)
        stop_mediator(first)
    finally:
        if first.process.poll() is None:
            stop_mediator(first)
    second = start_mediator(2)
    try:
        second_identity = mediator_identity(second)
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
    mediator = start_mediator(1)
    try:
        identity = mediator_identity(mediator)
        stopped = stop_mediator(mediator)
        if mediator.process.poll() is None:
            raise LifecycleEvidenceError("cleanup retained a live process")
    finally:
        if mediator.process.poll() is None:
            stop_mediator(mediator)
    return {
        "event": "failure-retained",
        "injected": "teardown-failure",
        "mediator_identity": identity,
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
