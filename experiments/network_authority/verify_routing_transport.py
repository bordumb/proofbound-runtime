#!/usr/bin/env python3
"""Independent verifier for experiment 0001F routing results."""

from __future__ import annotations

import argparse
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


MAX_FILE_BYTES = 1024 * 1024
MAX_FILES = 1024
MECHANISMS = (
    "landlock-port",
    "cgroup-endpoint",
    "explicit-broker",
    "preconnected-channel",
)
ACTIONS = {
    "exact-service-ipv4": "tls-request-ipv4",
    "exact-service-ipv6": "tls-request-ipv6",
    "undeclared-service-ipv4-443": "raw-undeclared-ipv4",
    "undeclared-service-ipv6-443": "raw-undeclared-ipv6",
    "literal-allowed-address": "raw-literal-allowed",
    "literal-undeclared-address": "raw-literal-undeclared",
    "allowed-endpoint-wrong-certificate": "tls-wrong-certificate",
    "alternate-endpoint-allowed-certificate": "raw-alternate-allowed-certificate",
    "direct-tcp-other-port": "direct-tcp-other-port",
    "direct-udp-dns-shaped": "direct-udp-dns-shaped",
    "direct-udp-quic-shaped": "direct-udp-quic-shaped",
    "tcp-bind-listen": "tcp-bind-listen",
    "udp-bind": "udp-bind",
    "ipv4-mapped-ipv6": "raw-ipv4-mapped-ipv6",
    "non-scoped-ipv6-scope-id": "reject-non-scoped-ipv6-scope-id",
    "alternate-address-text": "reject-alternate-address-text",
}
RAW_FIELDS = {
    "case",
    "cleanup",
    "client",
    "client_exit",
    "client_started",
    "fixture_complete",
    "fixture_contact",
    "mechanism",
    "mediator",
    "plan_rejection",
    "schema",
}
COMMIT = re.compile(r"[0-9a-f]{40}")


class VerificationError(Exception):
    """A routing result is incomplete, inconsistent, or replaceable."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON names."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError("JSON contains a duplicate name")
        result[key] = value
    return result


def regular_bytes(path: Path) -> bytes:
    """Read one bounded regular file without following a symlink."""

    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_FILE_BYTES:
        raise VerificationError(f"result input is not bounded and regular: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise VerificationError("result input identity changed")
        data = os.read(descriptor, MAX_FILE_BYTES + 1)
        if len(data) != metadata.st_size or len(data) > MAX_FILE_BYTES:
            raise VerificationError("result input size changed")
        return data
    finally:
        os.close(descriptor)


def document(path: Path) -> dict[str, object]:
    """Decode one unique JSON object."""

    try:
        value = json.loads(regular_bytes(path), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as error:
        raise VerificationError(f"JSON input is invalid: {path.name}") from error
    if not isinstance(value, dict):
        raise VerificationError("JSON input is not an object")
    return value


def result_files(root: Path) -> dict[str, bytes]:
    """Inventory every bounded result file without following links."""

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
    """Return one lowercase SHA-256 digest."""

    return hashlib.sha256(data).hexdigest()


def expected_cells(matrix_bytes: bytes, mechanism: str) -> list[tuple[str, str, str]]:
    """Independently project the ordered routing expectations from TOML."""

    try:
        matrix = toml.loads(matrix_bytes.decode("utf-8"))
    except (UnicodeDecodeError, toml.TOMLDecodeError) as error:
        raise VerificationError("decision matrix is invalid") from error
    if not isinstance(matrix, dict) or matrix.get("schema") != "proofbound-runtime-network-decision-matrix/1":
        raise VerificationError("decision matrix schema is invalid")
    raw_cases = matrix.get("cases")
    if not isinstance(raw_cases, list):
        raise VerificationError("decision case inventory is invalid")
    result = []
    for case in raw_cases:
        if not isinstance(case, dict) or case.get("slice") != "routing-transport":
            continue
        identifier = case.get("id")
        if identifier not in ACTIONS or not isinstance(case.get("expectations"), list):
            raise VerificationError("routing case identity is invalid")
        matches = [
            item
            for item in case["expectations"]
            if isinstance(item, str) and item.startswith(mechanism + "=")
        ]
        if len(matches) != 1:
            raise VerificationError("routing expectation is not unique")
        remainder = matches[0].split("=", 1)[1]
        if remainder.count("@") != 1:
            raise VerificationError("routing expectation grammar is invalid")
        outcome, stage = remainder.split("@")
        result.append((identifier, outcome, stage))
    if tuple(item[0] for item in result) != tuple(ACTIONS):
        raise VerificationError("routing case order or coverage changed")
    return result


def digest(value: object) -> bool:
    """Recognize one lowercase SHA-256 value."""

    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def validate_client(client: object, case: str) -> dict[str, object]:
    """Independently validate the closed child observation grammar."""

    if not isinstance(client, dict):
        raise VerificationError("client observation is absent")
    common = {"action", "case", "errno", "event", "phase", "schema"}
    extra = {
        "operation-error": set(),
        "certificate-rejected": {"verify_code"} - {"errno"},
        "exact-response": {"response_sha256", "tls_version"},
        "mediated-response": {"response_sha256"},
        "mediator-rejected": {"code"},
        "routing-connected": set(),
        "socket-sentinel": {"response_sha256"},
        "datagram-sentinel": {"request_sha256", "response_sha256"},
        "bind-succeeded": set(),
    }
    event = client.get("event")
    if not isinstance(event, str) or event not in extra:
        raise VerificationError("client event is unknown")
    expected_fields = common | extra[event]
    if event == "certificate-rejected":
        expected_fields = {"action", "case", "event", "phase", "schema", "verify_code"}
    if set(client) != expected_fields:
        raise VerificationError("client observation schema is not closed")
    if (
        client["schema"] != "proofbound-runtime-routing-client-observation/1"
        or client["case"] != case
        or client["action"] != ACTIONS[case]
        or not isinstance(client["phase"], str)
    ):
        raise VerificationError("client identity is invalid")
    if event == "operation-error":
        if type(client["errno"]) is not int or not 1 <= client["errno"] <= 4095:
            raise VerificationError("client errno is invalid")
    elif event != "certificate-rejected" and client["errno"] is not None:
        raise VerificationError("successful client event contains an errno")
    phases = {
        "certificate-rejected": "tls",
        "exact-response": "application-protocol",
        "mediated-response": "application-protocol",
        "mediator-rejected": "application-protocol",
        "routing-connected": "connect",
        "socket-sentinel": "application-protocol",
        "datagram-sentinel": "application-protocol",
    }
    if event in phases and client["phase"] != phases[event]:
        raise VerificationError("client event phase is inconsistent")
    if event == "bind-succeeded" and client["phase"] not in {"bind", "listen"}:
        raise VerificationError("bind success phase is invalid")
    if event == "certificate-rejected" and (
        type(client["verify_code"]) is not int or client["verify_code"] <= 0
    ):
        raise VerificationError("certificate rejection code is invalid")
    if event == "mediator-rejected" and client["code"] not in {
        "certificate-rejected",
        "connector-endpoint-mismatch",
        "target-field-rejected",
    }:
        raise VerificationError("mediator rejection code is invalid")
    for field in ("request_sha256", "response_sha256"):
        if field in client and not digest(client[field]):
            raise VerificationError("client transcript digest is invalid")
    if event == "exact-response" and client["tls_version"] != "TLSv1.3":
        raise VerificationError("direct client TLS identity is invalid")
    return client


def derive(raw: object, case: str, mechanism: str) -> tuple[str, str]:
    """Independently derive one valid raw-cell outcome."""

    if not isinstance(raw, dict) or set(raw) != RAW_FIELDS:
        raise VerificationError("raw cell schema is not closed")
    if (
        raw["schema"] != "proofbound-runtime-routing-raw-cell/1"
        or raw["case"] != case
        or raw["mechanism"] != mechanism
        or raw["cleanup"] is not True
        or type(raw["client_started"]) is not bool
        or type(raw["fixture_contact"]) is not bool
        or type(raw["fixture_complete"]) is not bool
    ):
        raise VerificationError("raw cell identity is invalid")
    started = raw["client_started"]
    client = raw["client"]
    if started:
        if raw["client_exit"] != 0 or not isinstance(client, dict):
            raise VerificationError("started client evidence is incomplete")
        client = validate_client(client, case)
    elif raw["client_exit"] is not None or client is not None:
        raise VerificationError("unstarted client has evidence")

    rejection = raw["plan_rejection"]
    mediator = raw["mediator"]
    if rejection is not None:
        if (
            not isinstance(rejection, str)
            or rejection
            not in {
                "address-text-not-canonical",
                "scope-id-not-allowed",
                "interface-cannot-represent-address",
            }
            or started
            or mediator is not None
            or raw["fixture_contact"]
            or raw["fixture_complete"]
        ):
            raise VerificationError("plan rejection evidence is inconsistent")
        return "denied", "plan"

    if mediator is not None:
        if not isinstance(mediator, dict) or set(mediator) != {
            "detail",
            "event",
            "schema",
            "stage",
        }:
            raise VerificationError("mediator schema is not closed")
        event = mediator["event"]
        stage = mediator["stage"]
        detail = mediator["detail"]
        if (
            mediator["schema"]
            != "proofbound-runtime-routing-mediator-observation/1"
            or not isinstance(event, str)
            or not isinstance(stage, str)
            or not isinstance(detail, str)
        ):
            raise VerificationError("mediator schema identity is invalid")
        if event == "exact-response":
            if (
                stage != "application-protocol"
                or detail != "authenticated-exact-response"
                or not started
                or client.get("event") != "mediated-response"
                or not raw["fixture_contact"]
                or not raw["fixture_complete"]
            ):
                raise VerificationError("mediator success is incomplete")
            return "allowed", "application-protocol"
        pairs = {
            ("prelaunch", "certificate-rejected"),
            ("tls", "certificate-rejected"),
            ("prelaunch", "connector-endpoint-mismatch"),
            ("routing", "connector-endpoint-mismatch"),
            ("application-protocol", "target-field-rejected"),
        }
        if event != "rejected" or (stage, detail) not in pairs or raw["fixture_complete"]:
            raise VerificationError("mediator rejection is invalid")
        if stage == "prelaunch":
            if started:
                raise VerificationError("prelaunch rejection started a client")
        elif (
            not started
            or client.get("event") != "mediator-rejected"
            or client.get("code") != detail
        ):
            raise VerificationError("postlaunch rejection evidence disagrees")
        if stage in {"routing", "tls"} and not raw["fixture_contact"]:
            raise VerificationError("post-connect rejection lacks contact")
        return "denied", stage

    if not started:
        raise VerificationError("direct cell has no client")
    event = client.get("event")
    phase = client.get("phase")
    if event == "operation-error":
        if phase in {"socket", "bind", "listen", "datagram"}:
            stage = "child-boundary"
            errnos = {1}
        elif phase == "connect":
            stage = "routing"
            errnos = {1, 13}
        else:
            raise VerificationError("operation error phase is invalid")
        if client.get("errno") not in errnos or raw["fixture_contact"] or raw["fixture_complete"]:
            raise VerificationError("operation denial evidence is inconsistent")
        return "denied", stage
    if event == "certificate-rejected":
        if phase != "tls" or not raw["fixture_contact"] or raw["fixture_complete"]:
            raise VerificationError("certificate denial evidence is inconsistent")
        return "denied", "tls"
    if event == "exact-response":
        if (
            phase != "application-protocol"
            or client.get("tls_version") != "TLSv1.3"
            or not raw["fixture_contact"]
            or not raw["fixture_complete"]
        ):
            raise VerificationError("direct success evidence is inconsistent")
        return "allowed", "application-protocol"
    if event == "routing-connected":
        if phase != "connect" or not raw["fixture_contact"] or raw["fixture_complete"]:
            raise VerificationError("routing exposure evidence is inconsistent")
        return "exposes-limitation", "routing"
    if event in {"socket-sentinel", "datagram-sentinel", "bind-succeeded"}:
        if event != "bind-succeeded" and not raw["fixture_complete"]:
            raise VerificationError("bypass exposure lacks fixture completion")
        return "exposes-limitation", (
            "routing" if event == "socket-sentinel" else "child-boundary"
        )
    raise VerificationError("raw client event cannot be derived")


def verify(root: Path) -> dict[str, object]:
    """Verify result inventory, hashes, manifests, and independent cell derivation."""

    files = result_files(root)
    result = document(root / "RESULT.json")
    expected_result_fields = {
        "case_count",
        "complete",
        "conclusion",
        "decision_matrix_sha256",
        "inputs",
        "matched_case_count",
        "mechanism",
        "schema",
        "source_commit",
    }
    if set(result) != expected_result_fields or result["schema"] != "proofbound-runtime-routing-result/1":
        raise VerificationError("result schema is not closed")
    mechanism = result["mechanism"]
    if mechanism not in MECHANISMS:
        raise VerificationError("result mechanism is invalid")
    inputs = result["inputs"]
    if not isinstance(inputs, list):
        raise VerificationError("result inputs are invalid")
    actual_inputs = {name: data for name, data in files.items() if name != "RESULT.json"}
    expected_names = []
    for entry in inputs:
        if not isinstance(entry, dict) or set(entry) != {"name", "sha256", "size"}:
            raise VerificationError("result input entry is invalid")
        name = entry["name"]
        if not isinstance(name, str) or name not in actual_inputs:
            raise VerificationError("result input name is invalid")
        data = actual_inputs[name]
        if entry["sha256"] != sha256(data) or entry["size"] != len(data):
            raise VerificationError("result input identity does not match")
        expected_names.append(name)
    if expected_names != sorted(actual_inputs) or len(set(expected_names)) != len(expected_names):
        raise VerificationError("result input inventory is not exact")

    evidence_manifest = document(root / "evidence-manifest.json")
    if set(evidence_manifest) != {"files", "schema"} or evidence_manifest["schema"] != "proofbound-runtime-routing-evidence-manifest/1":
        raise VerificationError("evidence manifest schema is invalid")
    observed_evidence = []
    for name, data in sorted(actual_inputs.items()):
        if not name.startswith("evidence/"):
            continue
        metadata = (root / name).lstat()
        observed_evidence.append(
            {
                "mode": format(stat.S_IMODE(metadata.st_mode), "04o"),
                "name": name.removeprefix("evidence/"),
                "sha256": sha256(data),
                "size": len(data),
            }
        )
    if evidence_manifest["files"] != observed_evidence:
        raise VerificationError("evidence manifest does not derive")

    source_manifest = document(root / "source-manifest.json")
    if set(source_manifest) != {
        "decision_matrix_sha256",
        "files",
        "schema",
        "source_commit",
    } or source_manifest["schema"] != "proofbound-runtime-routing-source-manifest/1":
        raise VerificationError("source manifest schema is invalid")
    if (
        not isinstance(source_manifest["files"], list)
        or not COMMIT.fullmatch(str(source_manifest["source_commit"]))
        or source_manifest["source_commit"] != result["source_commit"]
    ):
        raise VerificationError("source manifest identity is invalid")
    source_names = []
    for entry in source_manifest["files"]:
        if not isinstance(entry, dict) or set(entry) != {
            "mode",
            "name",
            "path",
            "sha256",
            "size",
        }:
            raise VerificationError("source manifest entry is invalid")
        name = entry["name"]
        published_name = f"source/{name}"
        if not isinstance(name, str) or published_name not in actual_inputs:
            raise VerificationError("source manifest file is absent")
        data = actual_inputs[published_name]
        mode = format(stat.S_IMODE((root / published_name).lstat().st_mode), "04o")
        if (
            entry["mode"] != mode
            or entry["sha256"] != sha256(data)
            or entry["size"] != len(data)
            or not isinstance(entry["path"], str)
            or entry["path"].startswith("/")
            or ".." in Path(entry["path"]).parts
        ):
            raise VerificationError("source manifest entry does not derive")
        source_names.append(published_name)
    if sorted(source_names) != sorted(name for name in actual_inputs if name.startswith("source/")):
        raise VerificationError("source manifest inventory is not exact")

    tool_manifest = document(root / "tool-manifest.json")
    if set(tool_manifest) != {
        "architecture",
        "compiler",
        "kernel_release",
        "openssl",
        "python",
        "schema",
    } or tool_manifest["schema"] != "proofbound-runtime-routing-tool-manifest/1":
        raise VerificationError("tool manifest schema is invalid")
    if tool_manifest["architecture"] not in {"x86_64", "aarch64"} or any(
        not isinstance(tool_manifest[field], str) or not tool_manifest[field]
        for field in ("compiler", "kernel_release", "openssl", "python")
    ):
        raise VerificationError("tool manifest values are invalid")

    matrix_bytes = actual_inputs.get("decision-matrix.toml")
    if matrix_bytes is None or result["decision_matrix_sha256"] != sha256(matrix_bytes):
        raise VerificationError("decision matrix identity does not match")
    if source_manifest["decision_matrix_sha256"] != sha256(matrix_bytes):
        raise VerificationError("source manifest matrix identity does not match")
    expectations = expected_cells(matrix_bytes, mechanism)
    matched = 0
    for case, expected_outcome, expected_stage in expectations:
        plan = document(root / f"evidence/cases/{case}/case-plan.json")
        expected_plan = {
            "action": ACTIONS[case],
            "case": case,
            "decision_matrix_sha256": sha256(matrix_bytes),
            "expectation": {"outcome": expected_outcome, "stage": expected_stage},
            "mechanism": mechanism,
            "schema": "proofbound-runtime-routing-case-plan/1",
        }
        if plan != expected_plan:
            raise VerificationError("prelaunch case plan does not match the matrix")
        cell = document(root / f"cells/{case}/CELL.json")
        if set(cell) != {
            "case",
            "expectation",
            "failure",
            "matched",
            "mechanism",
            "observed",
            "raw",
            "schema",
        }:
            raise VerificationError("cell schema is not closed")
        expected = {"outcome": expected_outcome, "stage": expected_stage}
        if (
            cell["schema"] != "proofbound-runtime-routing-cell/1"
            or cell["case"] != case
            or cell["mechanism"] != mechanism
            or cell["expectation"] != expected
        ):
            raise VerificationError("cell identity or expectation changed")
        try:
            observed_outcome, observed_stage = derive(cell["raw"], case, mechanism)
            observed = {"outcome": observed_outcome, "stage": observed_stage}
            agrees = observed == expected
            if cell["failure"] is not None:
                raise VerificationError("derived cell contains a failure label")
        except VerificationError:
            observed = {"outcome": "harness-failure", "stage": None}
            agrees = False
            if cell["failure"] is None:
                raise
        if cell["observed"] != observed or cell["matched"] is not agrees:
            raise VerificationError("producer and independent cell derivation disagree")
        matched += int(agrees)
    complete = matched == 16
    conclusion = (
        "routing-transport-slice-matched"
        if complete
        else "routing-transport-slice-mismatch"
    )
    if (
        result["case_count"] != 16
        or result["matched_case_count"] != matched
        or result["complete"] is not complete
        or result["conclusion"] != conclusion
    ):
        raise VerificationError("result conclusion does not derive")
    return {
        "complete": complete,
        "matched_case_count": matched,
        "mechanism": mechanism,
        "schema": "proofbound-runtime-routing-verification/1",
        "source_commit": result["source_commit"],
    }


def parser() -> argparse.ArgumentParser:
    """Build the independent verifier interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("result", type=Path)
    return result


def main() -> int:
    """Verify one result and emit a canonical summary."""

    try:
        summary = verify(parser().parse_args().result)
        sys.stdout.buffer.write(
            json.dumps(summary, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        )
        return 0
    except (OSError, VerificationError, ValueError) as error:
        print(f"routing transport verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
