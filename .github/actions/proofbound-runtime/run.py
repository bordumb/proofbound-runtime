#!/usr/bin/env python3
"""Run the exact first-party Proofbound Runtime acceptance chain."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path


MEMBERS = (
    "RELEASE-MANIFEST.json",
    "pbr",
    "pbr-native-launcher",
    "pbr-verify",
    "pbr-compose",
)
BINARIES = MEMBERS[1:]
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
POLICY_DOMAIN = b"proofbound-runtime-acceptance-policy/1\0"


class ActionError(Exception):
    """One fail-closed action error."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_hex_digest(value: str, label: str) -> str:
    normalized = value.removeprefix("sha256:")
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ActionError(f"{label} digest is invalid")
    return normalized


def require_regular(path: Path, label: str, limit: int = MAX_MEMBER_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ActionError(f"{label} is not one regular file")
    if path.stat().st_size > limit:
        raise ActionError(f"{label} exceeds {limit} bytes")
    return path.read_bytes()


def require_digest(path: Path, expected: str, label: str) -> bytes:
    limit = MAX_ARCHIVE_BYTES if label == "runtime archive" else MAX_MEMBER_BYTES
    data = require_regular(path, label, limit)
    expected = require_hex_digest(expected, label)
    actual = sha256(data)
    if actual != expected:
        raise ActionError(
            f"{label} digest mismatch: expected sha256:{expected}, actual sha256:{actual}"
        )
    return data


def require_absent(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise ActionError(f"output already exists: {path}")
    if not path.parent.is_dir():
        raise ActionError(f"output parent is not a directory: {path.parent}")


def extract_runtime(archive: Path, destination: Path) -> None:
    require_absent(destination)
    destination.mkdir(mode=0o755)
    try:
        with tarfile.open(archive, mode="r:gz") as source:
            members = source.getmembers()
            if [member.name for member in members] != list(MEMBERS):
                raise ActionError("runtime archive has an unexpected member inventory")
            for member in members:
                if not member.isfile() or member.size > MAX_MEMBER_BYTES:
                    raise ActionError(f"runtime member is invalid: {member.name}")
                opened = source.extractfile(member)
                if opened is None:
                    raise ActionError(f"runtime member cannot be read: {member.name}")
                data = opened.read(MAX_MEMBER_BYTES + 1)
                if len(data) != member.size:
                    raise ActionError(f"runtime member size mismatch: {member.name}")
                output = destination / member.name
                output.write_bytes(data)
                output.chmod(0o755 if member.name in BINARIES else 0o644)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    validate_manifest(destination)


def validate_manifest(directory: Path) -> None:
    try:
        manifest = json.loads((directory / "RELEASE-MANIFEST.json").read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActionError("runtime manifest is invalid") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "architecture",
        "artifacts",
        "schema",
        "target",
        "toolchain",
        "version",
    }:
        raise ActionError("runtime manifest is not closed")
    if manifest["schema"] != "proofbound-runtime-release-manifest/1":
        raise ActionError("runtime manifest schema is unsupported")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(BINARIES):
        raise ActionError("runtime manifest artifact inventory is invalid")
    for name, artifact in zip(BINARIES, artifacts, strict=True):
        if not isinstance(artifact, dict) or set(artifact) != {
            "name",
            "sha256",
            "size",
        }:
            raise ActionError("runtime manifest artifact is not closed")
        data = require_regular(directory / name, name)
        expected = {"name": name, "sha256": sha256(data), "size": len(data)}
        if artifact != expected:
            raise ActionError(f"runtime artifact identity mismatch: {name}")


def run_command(arguments: list[str], output: Path) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(arguments, check=False, capture_output=True, env={})
    if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
        raise ActionError(f"command output exceeds bound: {arguments[0]}")
    output.write_bytes(result.stdout)
    if result.returncode != 0:
        raise ActionError(
            f"command failed ({result.returncode}): {arguments[0]}: "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}"
        )
    if result.stderr:
        raise ActionError(f"command wrote unexpected stderr: {arguments[0]}")
    return result


def parse_run_result(path: Path) -> tuple[str, str]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActionError("run result is invalid JSON") from error
    if value.get("schema") != "proofbound-runtime-run-result/2":
        raise ActionError("run result schema is unsupported")
    commitment = value.get("commitment")
    execution_id = value.get("execution_id")
    if not isinstance(commitment, str) or not isinstance(execution_id, str):
        raise ActionError("run result omits control identities")
    if commitment.startswith("hex:"):
        commitment = "sha256:" + commitment.removeprefix("hex:")
    require_hex_digest(commitment, "execution commitment")
    return commitment, execution_id


def policy_identity(policy: bytes) -> str:
    return "sha256:" + sha256(POLICY_DOMAIN + policy)


def write_github_outputs(output: Path, decision: dict[str, object]) -> None:
    destination_path = os.environ.get("GITHUB_OUTPUT")
    if not destination_path:
        return
    decision_id = decision.get("decision_id")
    status = decision.get("status")
    reasons = decision.get("reasons")
    if not isinstance(decision_id, str) or status not in {"accepted", "rejected"}:
        raise ActionError("accept result omits decision outputs")
    if not isinstance(reasons, list) or not all(isinstance(item, str) for item in reasons):
        raise ActionError("accept result reasons are invalid")
    with Path(destination_path).open("a", encoding="utf-8") as destination:
        destination.write(f"decision-id={decision_id}\n")
        destination.write(f"status={status}\n")
        destination.write(f"reasons={json.dumps(reasons, separators=(',', ':'))}\n")
        destination.write(f"result-root={output}\n")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--runtime-archive", required=True, type=Path)
    result.add_argument("--runtime-archive-sha256", required=True)
    result.add_argument("--acceptor", required=True, type=Path)
    result.add_argument("--acceptor-sha256", required=True)
    result.add_argument("--policy", required=True, type=Path)
    result.add_argument("--policy-identity", required=True)
    result.add_argument("--plan", required=True, type=Path)
    result.add_argument("--cgroup-root", required=True, type=Path)
    result.add_argument("--proofbound-release", required=True, type=Path)
    result.add_argument("--proofbound-verifier", required=True, type=Path)
    result.add_argument("--proofbound-observation-inputs", required=True, type=Path)
    result.add_argument("--output", required=True, type=Path)
    return result


def run(args: argparse.Namespace) -> int:
    require_digest(args.runtime_archive, args.runtime_archive_sha256, "runtime archive")
    acceptor = require_digest(args.acceptor, args.acceptor_sha256, "acceptor")
    policy = require_regular(args.policy, "acceptance policy")
    if policy_identity(policy) != args.policy_identity:
        raise ActionError("acceptance policy identity mismatch")
    require_regular(args.plan, "execution plan")
    require_regular(args.proofbound_verifier, "Proofbound verifier")
    require_regular(args.proofbound_observation_inputs, "Proofbound observation inputs")
    if args.proofbound_release.is_symlink() or not args.proofbound_release.is_dir():
        raise ActionError("Proofbound release is not one directory")
    if args.cgroup_root.is_symlink() or not args.cgroup_root.is_dir():
        raise ActionError("cgroup root is not one directory")
    require_absent(args.output)
    args.output.mkdir(mode=0o755)
    runtime = args.output / "runtime"
    extract_runtime(args.runtime_archive, runtime)
    local_acceptor = args.output / "pbr-accept"
    local_acceptor.write_bytes(acceptor)
    local_acceptor.chmod(0o755)

    # pbr run: exact plan to exact raw receipt and control-channel result.
    run_command(
        [str(runtime / "pbr"), "plan", "check", "--plan", str(args.plan)],
        args.output / "plan-check.json",
    )
    receipt = args.output / "execution-receipt.cbor"
    run_result = args.output / "run-result.json"
    run_command(
        [
            str(runtime / "pbr"),
            "run",
            "--plan",
            str(args.plan),
            "--receipt",
            str(receipt),
            "--cgroup-root",
            str(args.cgroup_root),
        ],
        run_result,
    )
    commitment, execution_id = parse_run_result(run_result)

    # pbr-verify: explicit independent verification before composition.
    run_command(
        [
            str(runtime / "pbr-verify"),
            "--expected-commitment",
            commitment,
            str(receipt),
        ],
        args.output / "execution-verification.json",
    )

    # pbr-compose: exact independently verified execution and release.
    composed = args.output / "composed-receipt.cbor"
    run_command(
        [
            str(runtime / "pbr-compose"),
            "--release",
            str(args.proofbound_release),
            "--proofbound-verifier",
            str(args.proofbound_verifier),
            "--proofbound-observation-inputs",
            str(args.proofbound_observation_inputs),
            "--runtime-bundle",
            str(runtime),
            "--execution-receipt",
            str(receipt),
            "--execution-commitment",
            commitment,
            "--expected-execution-id",
            execution_id,
            "--output",
            str(composed),
        ],
        args.output / "composition-result.json",
    )

    # pbr-accept: both verifiers are re-run over raw inputs before policy.
    decision = args.output / "acceptance-decision.cbor"
    accept_result = args.output / "accept-result.json"
    result = subprocess.run(
        [
            str(local_acceptor),
            "--policy",
            str(args.policy),
            "--expected-policy-identity",
            args.policy_identity,
            "--release",
            str(args.proofbound_release),
            "--proofbound-verifier",
            str(args.proofbound_verifier),
            "--proofbound-observation-inputs",
            str(args.proofbound_observation_inputs),
            "--runtime-bundle",
            str(runtime),
            "--execution-receipt",
            str(receipt),
            "--execution-commitment",
            commitment,
            "--expected-execution-id",
            execution_id,
            "--output",
            str(decision),
        ],
        check=False,
        capture_output=True,
        env={},
    )
    if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
        raise ActionError("pbr-accept output exceeds bound")
    accept_result.write_bytes(result.stdout)
    if result.returncode not in {0, 7} or result.stderr:
        raise ActionError("pbr-accept did not produce a canonical decision")
    try:
        summary = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActionError("pbr-accept result is invalid JSON") from error
    run_command(
        [str(local_acceptor), "inspect", str(decision)],
        args.output / "acceptance-decision.projection.json",
    )
    write_github_outputs(args.output, summary)
    return result.returncode


def main() -> int:
    try:
        return run(parser().parse_args())
    except (ActionError, OSError, tarfile.TarError) as error:
        print(f"proofbound-runtime action: {error}", file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
