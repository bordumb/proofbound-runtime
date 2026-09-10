#!/usr/bin/env python3
"""Independent verifier for experiment 0001H bypass/lifecycle results."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

try:
    import tomllib as toml
except ModuleNotFoundError:
    import tomli as toml  # type: ignore[no-redef]


MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_FILES = 4096
COMMIT = re.compile(r"[0-9a-f]{40}")
MECHANISMS = (
    "landlock-port", "cgroup-endpoint", "explicit-broker",
    "preconnected-channel",
)
ACTIONS = {
    "pathname-unix-socket": ("open-pathname-unix-stream", "socket-bypass"),
    "abstract-unix-socket": ("open-abstract-unix-stream", "socket-bypass"),
    "inherited-connected-internet-socket": ("inherit-connected-inet-stream", "socket-bypass"),
    "io-uring-socket-create-connect": ("submit-io-uring-socket-connect", "socket-bypass"),
    "io-uring-descriptor-send": ("submit-io-uring-descriptor-send", "socket-bypass"),
    "raw-and-packet-sockets": ("open-raw-and-packet-sockets", "socket-bypass"),
    "fork-exec-at-process-limit": ("fork-exec-at-limit", "lifecycle"),
    "concurrent-install-and-connect": ("race-install-with-connect", "lifecycle"),
    "mediator-crash-before-release": ("crash-mediator-before-release", "lifecycle"),
    "mediator-crash-during-exchange": ("crash-mediator-during-exchange", "lifecycle"),
    "mediator-restart-substitution": ("restart-substitute-mediator", "lifecycle"),
    "policy-program-map-rule-substitution": ("substitute-native-policy", "lifecycle"),
    "resolver-and-trust-root-substitution": ("substitute-resolver-trust-root", "lifecycle"),
    "certificate-and-channel-substitution": ("substitute-certificate-channel", "lifecycle"),
    "executable-and-staged-client-substitution": ("substitute-executable-client", "lifecycle"),
    "connection-reuse-beyond-count": ("reuse-beyond-one-connection", "lifecycle"),
    "cleanup-and-namespace-teardown-failure": ("inject-cleanup-failure", "lifecycle"),
    "existing-result-replacement": ("replace-existing-result", "publication"),
}
RAW_FIELDS = {
    "case", "cleanup", "connection_count", "events", "mechanism",
    "plan_rejection", "prelaunch_rejection", "publication_preserved",
    "schema", "survivor_count", "syscall_attempts",
}
SUBJECT_NAMES = {
    "certificate", "channel", "client", "executable", "native-policy",
    "resolver", "trust-root",
}


class VerificationError(Exception):
    """A bypass/lifecycle result is incomplete, inconsistent, or replaceable."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("JSON contains a duplicate name")
        result[key] = value
    return result


def regular_bytes(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
        raise VerificationError(f"result input is not bounded and regular: {path.name}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev, metadata.st_ino, metadata.st_size,
        ):
            raise VerificationError("result input identity changed")
        data = os.read(descriptor, MAX_FILE_BYTES + 1)
        if len(data) != metadata.st_size or len(data) > MAX_FILE_BYTES:
            raise VerificationError("result input size changed")
        return data
    finally:
        os.close(descriptor)


def document(path: Path) -> dict[str, object]:
    try:
        value = json.loads(regular_bytes(path), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as error:
        raise VerificationError(f"JSON input is invalid: {path.name}") from error
    if not isinstance(value, dict):
        raise VerificationError("JSON input is not an object")
    return value


def result_files(root: Path) -> dict[str, bytes]:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise VerificationError("result root is invalid")
    result: dict[str, bytes] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"result contains a symlink: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                result[relative] = regular_bytes(path)
            else:
                raise VerificationError(f"result contains a special file: {relative}")
            if len(result) > MAX_FILES:
                raise VerificationError("result file inventory exceeds its bound")
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(
        character in "0123456789abcdef" for character in value
    )


def expected_cells(matrix_bytes: bytes, mechanism: str) -> list[tuple[str, str, str]]:
    try:
        matrix = toml.loads(matrix_bytes.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise VerificationError("decision matrix is invalid") from error
    if not isinstance(matrix, dict) or matrix.get("schema") != "proofbound-runtime-network-decision-matrix/1":
        raise VerificationError("decision matrix schema is invalid")
    cases = matrix.get("cases")
    if not isinstance(cases, list):
        raise VerificationError("decision case inventory is invalid")
    result = []
    for case in cases:
        if not isinstance(case, dict) or case.get("slice") != "bypass-lifecycle":
            continue
        identifier = case.get("id")
        expectations = case.get("expectations")
        if (
            identifier not in ACTIONS
            or case.get("fixture") != ACTIONS[identifier][1]
            or case.get("maximum_seconds") != 10
            or not isinstance(expectations, list)
        ):
            raise VerificationError("bypass case identity is invalid")
        matches = [
            item for item in expectations
            if isinstance(item, str) and item.startswith(mechanism + "=")
        ]
        if len(matches) != 1 or matches[0].count("@") != 1:
            raise VerificationError("bypass expectation is not unique")
        outcome, stage = matches[0].split("=", 1)[1].split("@")
        result.append((str(identifier), outcome, stage))
    if tuple(item[0] for item in result) != tuple(ACTIONS):
        raise VerificationError("bypass case order or coverage changed")
    return result


def expected_parameters(case: str) -> dict[str, object]:
    if case == "pathname-unix-socket":
        return {"address": "cases/undeclared.sock", "family": "AF_UNIX"}
    if case == "abstract-unix-socket":
        return {"address_hex": "0070726f6f66626f756e642d756e6465636c61726564", "family": "AF_UNIX"}
    if case == "inherited-connected-internet-socket":
        return {"descriptor_inventory": "exact", "peer": "127.0.0.2:443"}
    if case.startswith("io-uring-"):
        return {"entries": 2, "opcode_set": ["socket", "connect", "send"]}
    if case == "raw-and-packet-sockets":
        return {"families": ["AF_INET", "AF_PACKET"], "types": ["SOCK_RAW", "SOCK_DGRAM"]}
    if case == "fork-exec-at-process-limit":
        return {"maximum_processes": 1, "operations": ["fork", "exec"]}
    if case == "concurrent-install-and-connect":
        return {"child_state": "stopped", "release_after": "boundary-acknowledged"}
    if case.startswith("mediator-"):
        return {"generation": 1, "identity": ["pid", "executable-sha256", "channel-peer"]}
    substitutions = {
        "policy-program-map-rule-substitution": "native-policy",
        "resolver-and-trust-root-substitution": "resolver",
        "certificate-and-channel-substitution": "certificate",
        "executable-and-staged-client-substitution": "executable",
    }
    if case in substitutions:
        return {"mutated_subject": substitutions[case], "mutation_count": 1, "phase": "after-plan-before-release"}
    if case == "connection-reuse-beyond-count":
        return {"registered_connections": 1, "attempted_connections": 2}
    if case == "cleanup-and-namespace-teardown-failure":
        return {"injected_failure": "teardown", "survivor_count": 0}
    return {"publication": "no-replace", "sentinel": "existing-result"}


def expected_identities(files: dict[str, bytes], case: str, mechanism: str) -> dict[str, str]:
    def evidence(name: str) -> str:
        value = files.get("evidence/" + name)
        if value is None:
            raise VerificationError(f"planned evidence subject is absent: {name}")
        return sha256(value)

    if case == "inherited-connected-internet-socket" or case.startswith("mediator-") or "substitution" in case or case in {"cleanup-and-namespace-teardown-failure", "existing-result-replacement"}:
        return {name: evidence(f"artifacts/subjects/{name}") for name in sorted(SUBJECT_NAMES)}
    if case == "connection-reuse-beyond-count":
        result = {
            "broker-child": evidence("artifacts/broker-child-control"),
            "client": evidence("artifacts/staged/experiments/network_authority/connection_reuse_client.py"),
            "preconnected-child": evidence("artifacts/preconnected-child-control"),
            "routing-child": evidence("artifacts/routing-child-control"),
        }
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            control = "routing-landlock-control" if mechanism == "landlock-port" else "routing-endpoint-control"
            result["fixture"] = evidence("artifacts/staged/experiments/network_authority/connection_reuse_fixture.py")
            result["mechanism-control"] = evidence(f"artifacts/{control}")
        return result
    child = {
        "landlock-port": "routing-child-control",
        "cgroup-endpoint": "routing-child-control",
        "explicit-broker": "broker-child-control",
        "preconnected-channel": "preconnected-child-control",
    }[mechanism]
    result = {
        "child-control": evidence(f"artifacts/{child}"),
        "client": evidence("artifacts/staged/experiments/network_authority/bypass_syscall_probe.py"),
        "process-limit-control": evidence("artifacts/process-limit-control"),
    }
    if mechanism in {"landlock-port", "cgroup-endpoint"}:
        control = "routing-landlock-control" if mechanism == "landlock-port" else "routing-endpoint-control"
        result["mechanism-control"] = evidence(f"artifacts/{control}")
    if case == "concurrent-install-and-connect":
        result["stopped-release-control"] = evidence("artifacts/stopped-release-control")
    return result


def _attempts(raw: dict[str, object], names: tuple[str, ...], numbers: tuple[int, ...]) -> None:
    attempts = raw["syscall_attempts"]
    if not isinstance(attempts, list) or attempts != [
        {"errno": number, "result": "error", "syscall": name}
        for name, number in zip(names, numbers)
    ]:
        raise VerificationError("syscall evidence changed")


def derive(raw: object, case: str, mechanism: str) -> tuple[str, str]:
    if not isinstance(raw, dict) or set(raw) != RAW_FIELDS:
        raise VerificationError("raw bypass cell schema is not closed")
    if (
        raw["schema"] != "proofbound-runtime-bypass-raw-cell/1"
        or raw["case"] != case or raw["mechanism"] != mechanism
        or raw["cleanup"] is not True
        or type(raw["connection_count"]) is not int
        or type(raw["survivor_count"]) is not int
        or type(raw["publication_preserved"]) is not bool
        or not isinstance(raw["events"], list)
    ):
        raise VerificationError("raw bypass identity is invalid")
    if case in {"pathname-unix-socket", "abstract-unix-socket"}:
        suffix = "-abstract" if case.startswith("abstract") else ""
        _attempts(raw, (f"socket(AF_UNIX,SOCK_STREAM){suffix}",), (errno.EPERM,))
        return "denied", "child-boundary"
    if case.startswith("io-uring-"):
        _attempts(raw, ("io_uring_setup",), (errno.EPERM,))
        return "denied", "child-boundary"
    if case == "raw-and-packet-sockets":
        _attempts(raw, ("socket(AF_INET,SOCK_RAW)", "socket(AF_PACKET,SOCK_DGRAM)"), (errno.EPERM, errno.EPERM))
        return "denied", "child-boundary"
    if case == "inherited-connected-internet-socket":
        if raw["prelaunch_rejection"] != "foreign-descriptor-present" or raw["syscall_attempts"]:
            raise VerificationError("inherited descriptor rejection changed")
        return "denied", "prelaunch"
    if case == "fork-exec-at-process-limit":
        _attempts(raw, ("fork",), (errno.EAGAIN,))
        return "denied", "child-boundary"
    if case == "concurrent-install-and-connect":
        if raw["events"] != ["child-stopped", "boundary-acknowledged", "child-released", "connect-denied"]:
            raise VerificationError("install race sequence changed")
        number = errno.EACCES if mechanism == "landlock-port" else errno.EPERM
        _attempts(raw, ("connect-after-acknowledgement",), (number,))
        return "denied", "child-boundary"
    if case.startswith("mediator-"):
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            if raw["plan_rejection"] != "mechanism-has-no-mediator" or raw["events"]:
                raise VerificationError("non-mediator plan rejection changed")
            return "denied", "plan"
        event, stage = {
            "mediator-crash-before-release": ("mediator-crashed-before-release", "prelaunch"),
            "mediator-crash-during-exchange": ("mediator-crashed-during-exchange", "lifecycle"),
            "mediator-restart-substitution": ("mediator-identity-mismatch", "lifecycle"),
        }[case]
        if raw["events"] != [event]:
            raise VerificationError("mediator lifecycle evidence changed")
        return "denied", stage
    if "substitution" in case:
        rejection = {
            "policy-program-map-rule-substitution": "native-policy-digest-mismatch",
            "resolver-and-trust-root-substitution": "resolver-trust-root-digest-mismatch",
            "certificate-and-channel-substitution": "certificate-channel-identity-mismatch",
            "executable-and-staged-client-substitution": "executable-client-digest-mismatch",
        }[case]
        if raw["prelaunch_rejection"] != rejection:
            raise VerificationError("substitution rejection changed")
        return "denied", "prelaunch"
    if case == "connection-reuse-beyond-count":
        if mechanism in {"landlock-port", "cgroup-endpoint"}:
            if raw["connection_count"] != 2 or raw["events"] != ["registered-exchange", "excess-exchange"]:
                raise VerificationError("routing reuse exposure changed")
            return "exposes-limitation", "routing"
        event = "operation-rejected" if mechanism == "explicit-broker" else "channel-closed-after-registered-exchange"
        stage = "application-protocol" if mechanism == "explicit-broker" else "lifecycle"
        if raw["connection_count"] != 1 or raw["events"] != ["registered-exchange", event]:
            raise VerificationError("mediated reuse denial changed")
        return "denied", stage
    if case == "cleanup-and-namespace-teardown-failure":
        if raw["events"] != ["teardown-failure-injected", "failure-retained"] or raw["survivor_count"] != 0:
            raise VerificationError("cleanup failure evidence changed")
        return "denied", "cleanup"
    if case == "existing-result-replacement":
        if raw["events"] != ["replacement-rejected"] or raw["publication_preserved"] is not True:
            raise VerificationError("publication preservation changed")
        return "denied", "cleanup"
    raise VerificationError("raw case has no independent derivation")


def _verify_manifest(manifest: dict[str, object], files: dict[str, bytes], prefix: str, schema: str) -> None:
    if set(manifest) != {"files", "schema"} or manifest["schema"] != schema or not isinstance(manifest["files"], list):
        raise VerificationError("file manifest schema is invalid")
    expected: dict[str, tuple[int, str]] = {}
    for entry in manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {"mode", "name", "sha256", "size"}:
            raise VerificationError("file manifest entry is invalid")
        name = entry["name"]
        if not isinstance(name, str) or name in expected or not digest(entry["sha256"]) or type(entry["size"]) is not int:
            raise VerificationError("file manifest identity is invalid")
        expected[name] = (entry["size"], entry["sha256"])
    actual = {name.removeprefix(prefix): data for name, data in files.items() if name.startswith(prefix)}
    if set(actual) != set(expected):
        raise VerificationError("file manifest inventory changed")
    for name, data in actual.items():
        if expected[name] != (len(data), sha256(data)):
            raise VerificationError("file manifest digest changed")


def verify(root: Path) -> dict[str, object]:
    files = result_files(root)
    result = document(root / "RESULT.json")
    fields = {"case_count", "complete", "conclusion", "decision_matrix_sha256", "inputs", "matched_case_count", "mechanism", "schema", "source_commit"}
    if set(result) != fields or result["schema"] != "proofbound-runtime-bypass-result/1":
        raise VerificationError("result schema is not closed")
    mechanism = result["mechanism"]
    if mechanism not in MECHANISMS or not COMMIT.fullmatch(str(result["source_commit"])):
        raise VerificationError("result identity is invalid")
    if not isinstance(result["inputs"], list):
        raise VerificationError("result input inventory is invalid")
    declared: dict[str, tuple[int, str]] = {}
    for item in result["inputs"]:
        if not isinstance(item, dict) or set(item) != {"name", "sha256", "size"}:
            raise VerificationError("result input entry is invalid")
        name = item["name"]
        if not isinstance(name, str) or name in declared or not digest(item["sha256"]) or type(item["size"]) is not int:
            raise VerificationError("result input identity is invalid")
        declared[name] = (item["size"], item["sha256"])
    actual = {name: data for name, data in files.items() if name != "RESULT.json"}
    if set(actual) != set(declared):
        raise VerificationError("result input inventory changed")
    for name, data in actual.items():
        if declared[name] != (len(data), sha256(data)):
            raise VerificationError("result input digest changed")
    matrix_bytes = actual.get("decision-matrix.toml")
    if matrix_bytes is None or sha256(matrix_bytes) != result["decision_matrix_sha256"]:
        raise VerificationError("decision matrix identity changed")
    expected = expected_cells(matrix_bytes, str(mechanism))
    matched = 0
    for case, outcome, stage in expected:
        cell = document(root / f"cells/{case}/CELL.json")
        if set(cell) != {"case", "expectation", "failure", "matched", "mechanism", "observed", "raw", "schema"} or cell["schema"] != "proofbound-runtime-bypass-cell/1" or cell["case"] != case or cell["mechanism"] != mechanism:
            raise VerificationError("cell identity changed")
        plan = document(root / f"evidence/cases/{case}/case-plan.json")
        if (
            set(plan) != {"action", "case", "decision_matrix_sha256", "expectation", "mechanism", "parameters", "schema", "source_commit", "subject_identities"}
            or plan["action"] != ACTIONS[case][0]
            or plan["case"] != case
            or plan["decision_matrix_sha256"] != result["decision_matrix_sha256"]
            or plan["expectation"] != {"outcome": outcome, "stage": stage}
            or plan["mechanism"] != mechanism
            or plan["parameters"] != expected_parameters(case)
            or plan["schema"] != "proofbound-runtime-bypass-case-plan/1"
            or plan["source_commit"] != result["source_commit"]
            or plan["subject_identities"] != expected_identities(files, case, str(mechanism))
        ):
            raise VerificationError("prelaunch bypass plan changed")
        evidence_raw = document(root / f"evidence/cases/{case}/raw-cell.json")
        if cell["failure"] is not None or cell["raw"] != evidence_raw:
            raise VerificationError("cell does not retain exact raw evidence")
        derived = derive(cell["raw"], case, str(mechanism))
        if cell["expectation"] != {"outcome": outcome, "stage": stage} or cell["observed"] != {"outcome": derived[0], "stage": derived[1]} or derived != (outcome, stage) or cell["matched"] is not True:
            raise VerificationError("cell result does not independently match")
        matched += 1
    _verify_manifest(document(root / "evidence-manifest.json"), files, "evidence/", "proofbound-runtime-bypass-evidence-manifest/1")
    source = document(root / "source-manifest.json")
    if set(source) != {"decision_matrix_sha256", "files", "schema", "source_commit"} or source["schema"] != "proofbound-runtime-bypass-source-manifest/1" or source["source_commit"] != result["source_commit"] or source["decision_matrix_sha256"] != result["decision_matrix_sha256"] or not isinstance(source["files"], list):
        raise VerificationError("source manifest identity changed")
    source_names = set()
    for entry in source["files"]:
        if not isinstance(entry, dict) or set(entry) != {"mode", "name", "path", "sha256", "size"}:
            raise VerificationError("source manifest entry is invalid")
        name = entry["name"]
        if not isinstance(name, str) or name in source_names:
            raise VerificationError("source manifest name is invalid")
        source_names.add(name)
        data = files.get(f"source/{name}")
        if data is None or entry["size"] != len(data) or entry["sha256"] != sha256(data):
            raise VerificationError("source manifest digest changed")
    if {name.removeprefix("source/") for name in files if name.startswith("source/")} != source_names:
        raise VerificationError("source file inventory changed")
    tool = document(root / "tool-manifest.json")
    if set(tool) != {"architecture", "compiler", "kernel_release", "python", "schema"} or tool["architecture"] not in {"x86_64", "aarch64"} or tool["schema"] != "proofbound-runtime-bypass-tool-manifest/1" or any(not isinstance(tool[name], str) or not tool[name] for name in ("compiler", "kernel_release", "python")):
        raise VerificationError("tool manifest identity changed")
    if result["case_count"] != 18 or result["matched_case_count"] != matched or result["complete"] is not True or result["conclusion"] != "bypass-lifecycle-slice-matched":
        raise VerificationError("result conclusion is not complete")
    return {"complete": True, "matched_case_count": matched, "mechanism": mechanism, "schema": "proofbound-runtime-bypass-verification/1", "source_commit": result["source_commit"]}


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("result", type=Path)
    return result


def main() -> int:
    try:
        print(json.dumps(verify(parser().parse_args().result), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, VerificationError, ValueError) as error:
        print(f"bypass lifecycle verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
