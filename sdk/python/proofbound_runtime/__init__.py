"""Plan construction and control-result decoding for Proofbound Runtime 0.2."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
from typing import Any, Mapping, Sequence


__version__ = "0.2.0"
_PLAN_ID = re.compile(r"^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$")
_LOWER_HEX = re.compile(r"^[0-9a-f]+$")
_QUANTUM = 65_536
_MAX_RESOURCE = 1_099_511_627_776
_MAX_U64 = (1 << 64) - 1
_MAX_U32 = (1 << 32) - 1
_RESULT_KEYS = {"commitment", "execution_id", "outcome", "receipt", "schema"}


class SdkError(ValueError):
    """A stable SDK validation or invocation failure."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class RunResult:
    """Strictly decoded control-channel result projection."""

    receipt: str
    execution_id: bytes
    commitment: bytes
    outcome_kind: str
    outcome_detail: int | None


def build_plan(
    *,
    id: str,
    executable: str,
    arguments: Sequence[str],
    working_directory: str,
    read: Sequence[str],
    runtime_read: Sequence[str],
    write: Sequence[str],
    execute: Sequence[str],
    environment: Sequence[str],
    processes: int,
    wall_time_ms: int,
    stdout_bytes: int,
    stderr_bytes: int,
    memory_bytes: int,
    swap_bytes: int,
) -> bytes:
    """Return one strictly validated deterministic-CBOR v2 plan."""
    if not isinstance(id, str) or _PLAN_ID.fullmatch(id) is None:
        raise SdkError("sdk.plan.id-invalid")
    strings = {
        "arguments": arguments,
        "read": read,
        "runtime_read": runtime_read,
        "write": write,
        "execute": execute,
        "environment": environment,
    }
    for name, values in strings.items():
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise SdkError("sdk.plan.field-invalid", name)
        if any(not isinstance(value, str) or "\0" in value for value in values):
            raise SdkError("sdk.plan.field-invalid", name)
        if name != "arguments" and len(set(values)) != len(values):
            raise SdkError("sdk.plan.duplicate", name)
    for name, value in (
        ("executable", executable),
        ("working_directory", working_directory),
    ):
        if not isinstance(value, str) or not value or "\0" in value:
            raise SdkError("sdk.plan.field-invalid", name)
    if any(not value or "=" in value for value in environment):
        raise SdkError("sdk.plan.field-invalid", "environment")
    if len(write) != 1 or len(execute) != 1 or execute[0] != executable:
        raise SdkError("sdk.plan.shape-invalid")
    if any(not Path(value).is_absolute() for value in runtime_read):
        raise SdkError("sdk.plan.runtime-read-not-absolute")
    for name, value, minimum, maximum in (
        ("processes", processes, 1, _MAX_U32),
        ("wall_time_ms", wall_time_ms, 1, _MAX_U64),
        ("stdout_bytes", stdout_bytes, 0, _MAX_U64),
        ("stderr_bytes", stderr_bytes, 0, _MAX_U64),
        ("memory_bytes", memory_bytes, _QUANTUM, _MAX_RESOURCE),
        ("swap_bytes", swap_bytes, 0, _MAX_RESOURCE),
    ):
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not minimum <= value <= maximum
        ):
            raise SdkError("sdk.plan.limit-invalid", name)
    if memory_bytes % _QUANTUM or swap_bytes % _QUANTUM:
        raise SdkError("sdk.plan.limit-not-quantized")
    plan = {
        "id": id,
        "schema": "proofbound-runtime-plan/2",
        "limits": {
            "processes": processes,
            "swap_bytes": swap_bytes,
            "stderr_bytes": stderr_bytes,
            "stdout_bytes": stdout_bytes,
            "memory_bytes": memory_bytes,
            "wall_time_ms": wall_time_ms,
        },
        "command": {
            "arguments": list(arguments),
            "executable": executable,
            "working_directory": working_directory,
        },
        "authority": {
            "read": list(read),
            "write": list(write),
            "execute": list(execute),
            "network": "deny",
            "environment": list(environment),
            "runtime_read": list(runtime_read),
        },
    }
    return _encode(plan)


def parse_run_result(value: bytes | str) -> RunResult:
    """Strictly decode the JSON control projection printed by pbr run."""
    try:
        decoded = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as error:
        raise SdkError("sdk.result.malformed-json") from error
    if not isinstance(decoded, dict) or set(decoded) != _RESULT_KEYS:
        raise SdkError("sdk.result.unknown-field")
    if decoded["schema"] != "proofbound-runtime-run-result/2":
        raise SdkError("sdk.result.schema-unsupported")
    receipt = decoded["receipt"]
    if not isinstance(receipt, str) or not receipt:
        raise SdkError("sdk.result.field-invalid", "receipt")
    commitment = _decode_hex(decoded["commitment"], 32)
    execution_id = _decode_hex(decoded["execution_id"], 16)
    if execution_id[6] >> 4 != 4 or execution_id[8] >> 6 != 2:
        raise SdkError("sdk.result.field-invalid", "execution_id")
    kind, detail = _decode_outcome(decoded["outcome"])
    return RunResult(receipt, execution_id, commitment, kind, detail)


def run(
    *,
    pbr: Path,
    plan: Path,
    receipt: Path,
    cgroup_root: Path,
    environment: Mapping[str, str],
    max_output_bytes: int = 1_048_576,
) -> RunResult:
    """Invoke exactly one separate pbr run process without a shell."""
    paths = (pbr, plan, receipt, cgroup_root)
    if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
        raise SdkError("sdk.process.path-not-absolute")
    if (
        isinstance(max_output_bytes, bool)
        or not isinstance(max_output_bytes, int)
        or not 1 <= max_output_bytes <= 16_777_216
    ):
        raise SdkError("sdk.process.bound-invalid")
    child_environment = dict(environment)
    if any(
        not isinstance(name, str)
        or not name
        or "=" in name
        or "\0" in name
        or not isinstance(value, str)
        or "\0" in value
        for name, value in child_environment.items()
    ):
        raise SdkError("sdk.process.environment-invalid")
    arguments = [
        str(pbr),
        "run",
        "--plan",
        str(plan),
        "--receipt",
        str(receipt),
        "--cgroup-root",
        str(cgroup_root),
    ]
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment,
            shell=False,
            close_fds=True,
        )
    except OSError as error:
        raise SdkError("sdk.process.start-failed") from error
    stdout, stderr = _bounded_communicate(process, max_output_bytes)
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").rstrip("\n")
        raise SdkError("sdk.process.failed", f"exit={process.returncode} stderr={detail}")
    if not stdout.endswith(b"\n") or b"\n" in stdout[:-1]:
        raise SdkError("sdk.result.not-one-line")
    return parse_run_result(stdout[:-1])


def _bounded_communicate(
    process: subprocess.Popen[bytes], limit: int
) -> tuple[bytes, bytes]:
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, 0)
    selector.register(process.stderr, selectors.EVENT_READ, 1)
    buffers = [bytearray(), bytearray()]
    try:
        while selector.get_map():
            for key, _events in selector.select():
                chunk = os.read(key.fd, min(65_536, limit + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = buffers[key.data]
                target.extend(chunk)
                if len(target) > limit:
                    process.kill()
                    process.wait()
                    raise SdkError("sdk.process.output-bound")
        process.wait()
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return bytes(buffers[0]), bytes(buffers[1])


def _decode_outcome(value: Any) -> tuple[str, int | None]:
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        raise SdkError("sdk.result.field-invalid", "outcome")
    kind = value["kind"]
    if kind == "exited":
        if set(value) != {"kind", "code"} or not _bounded_int(value["code"], 0, 255):
            raise SdkError("sdk.result.field-invalid", "outcome")
        return kind, value["code"]
    if kind == "signaled":
        if set(value) != {"kind", "signal"} or not _bounded_int(
            value["signal"], 1, 255
        ):
            raise SdkError("sdk.result.field-invalid", "outcome")
        return kind, value["signal"]
    if kind in {"timed-out", "denied", "launcher-failed", "incomplete"}:
        if set(value) != {"kind"}:
            raise SdkError("sdk.result.unknown-field")
        return kind, None
    raise SdkError("sdk.result.field-invalid", "outcome")


def _bounded_int(value: Any, minimum: int, maximum: int) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int)
        and minimum <= value <= maximum
    )


def _decode_hex(value: Any, size: int) -> bytes:
    if (
        not isinstance(value, str)
        or not value.startswith("hex:")
        or len(value) != 4 + size * 2
        or _LOWER_HEX.fullmatch(value[4:]) is None
    ):
        raise SdkError("sdk.result.field-invalid")
    return bytes.fromhex(value[4:])


def _encode_argument(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for additional, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if value < 1 << (width * 8):
            return bytes([(major << 5) | additional]) + value.to_bytes(width, "big")
    raise SdkError("sdk.plan.cbor-bound")


def _encode(value: Any) -> bytes:
    if isinstance(value, str):
        payload = value.encode("utf-8")
        return _encode_argument(3, len(payload)) + payload
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return _encode_argument(0, value)
    if isinstance(value, list):
        return _encode_argument(4, len(value)) + b"".join(
            _encode(item) for item in value
        )
    if isinstance(value, dict):
        entries = sorted((_encode(key), _encode(item)) for key, item in value.items())
        return _encode_argument(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise SdkError("sdk.plan.field-invalid")


__all__ = ["RunResult", "SdkError", "build_plan", "parse_run_result", "run"]
