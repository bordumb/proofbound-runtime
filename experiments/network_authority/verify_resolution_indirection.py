#!/usr/bin/env python3
"""Independent verifier for experiment 0001G resolution results."""

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
MAX_FILES = 4096
COMMIT = re.compile(r"[0-9a-f]{40}")
MECHANISMS = (
    "landlock-port",
    "cgroup-endpoint",
    "explicit-broker",
    "preconnected-channel",
)
ACTIONS = {
    "stable-a-and-aaaa": "resolve-stable-dual-stack",
    "ttl-rebind-to-undeclared": "resolve-after-ttl",
    "cname-to-declared-service": "resolve-declared-alias",
    "cname-to-undeclared-service": "resolve-undeclared-alias",
    "cname-loop-or-depth": "reject-loop-and-depth",
    "resolver-timeout": "reject-resolver-timeout",
    "resolver-truncated-tcp-fallback": "resolve-truncated-with-tcp",
    "resolver-malformed-response": "reject-malformed-response",
    "resolver-dnssec-flag-confusion": "reject-unrequested-dnssec",
    "redirect-undeclared-host": "follow-redirect-host",
    "redirect-cleartext": "follow-redirect-cleartext",
    "redirect-other-port": "follow-redirect-port",
    "http-connect-target-confusion": "send-http-connect",
    "socks-target-confusion": "send-socks5-connect",
    "ambient-http-proxy": "consume-http-proxy",
    "ambient-https-proxy": "consume-https-proxy",
    "ambient-all-proxy": "consume-all-proxy",
    "resolver-configuration-substitution": "consume-substituted-resolver",
}
RAW_FIELDS = {
    "case",
    "cleanup",
    "client_exit",
    "client_started",
    "dns_query_count",
    "mechanism",
    "network_events",
    "plan_rejection",
    "prelaunch_rejection",
    "proxy_complete_count",
    "proxy_contact_count",
    "resolver_events",
    "schema",
    "service_complete_count",
    "service_contact_count",
}


class VerificationError(Exception):
    """A resolution result is incomplete, inconsistent, or replaceable."""


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
    return isinstance(value, str) and len(value) == 64 and all(character in "0123456789abcdef" for character in value)


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
        if not isinstance(case, dict) or case.get("slice") != "resolution-indirection":
            continue
        identifier = case.get("id")
        expectations = case.get("expectations")
        if identifier not in ACTIONS or not isinstance(expectations, list):
            raise VerificationError("resolution case identity is invalid")
        matches = [
            item
            for item in expectations
            if isinstance(item, str) and item.startswith(mechanism + "=")
        ]
        if len(matches) != 1 or matches[0].count("@") != 1:
            raise VerificationError("resolution expectation is not unique")
        outcome, stage = matches[0].split("=", 1)[1].split("@")
        result.append((identifier, outcome, stage))
    if tuple(item[0] for item in result) != tuple(ACTIONS):
        raise VerificationError("resolution case order or coverage changed")
    return result


def _fact(
    value: object,
) -> tuple[str, str | None, str | None, str | None, tuple[str, ...]]:
    fields = {"address", "event", "reason", "schema", "terminal_name", "transports"}
    if not isinstance(value, dict) or set(value) != fields or value["schema"] != "proofbound-runtime-resolution-fact/1":
        raise VerificationError("resolver fact schema is invalid")
    transports = value["transports"]
    if transports not in [["udp"], ["udp", "tcp"]]:
        raise VerificationError("resolver transport inventory is invalid")
    event = value["event"]
    if event == "resolved":
        if (
            value["reason"] is not None
            or value["address"] not in {"127.0.0.1", "127.0.0.2", "fd00::1", "fd00::2"}
            or value["terminal_name"] not in {"allowed.test", "denied.test"}
        ):
            raise VerificationError("resolved terminal identity is invalid")
    elif event == "rejected":
        if not isinstance(value["reason"], str) or value["address"] is not None or value["terminal_name"] is not None:
            raise VerificationError("resolver rejection identity is invalid")
    else:
        raise VerificationError("resolver fact event is invalid")
    return (
        str(event),
        value["address"],
        value["terminal_name"],
        value["reason"],
        tuple(transports),
    )


def _counts(raw: dict[str, object], expected: tuple[int, int, int, int]) -> None:
    actual = (
        raw["service_contact_count"],
        raw["service_complete_count"],
        raw["proxy_contact_count"],
        raw["proxy_complete_count"],
    )
    if actual != expected:
        raise VerificationError("fixture counts do not match the exchange")


def derive(raw: object, case: str, mechanism: str) -> tuple[str, str]:
    """Independently derive one raw-cell outcome."""

    if not isinstance(raw, dict) or set(raw) != RAW_FIELDS:
        raise VerificationError("raw cell schema is not closed")
    if (
        raw["schema"] != "proofbound-runtime-resolution-raw-cell/1"
        or raw["case"] != case
        or raw["mechanism"] != mechanism
        or raw["cleanup"] is not True
        or type(raw["client_started"]) is not bool
    ):
        raise VerificationError("raw cell identity is invalid")
    for name in (
        "dns_query_count",
        "service_contact_count",
        "service_complete_count",
        "proxy_contact_count",
        "proxy_complete_count",
    ):
        if type(raw[name]) is not int or not 0 <= raw[name] <= 4:
            raise VerificationError("raw fixture count is invalid")
    if raw["client_started"]:
        if raw["client_exit"] != 0:
            raise VerificationError("started client result is incomplete")
    elif raw["client_exit"] is not None:
        raise VerificationError("unstarted client has an exit result")
    resolver_values = raw["resolver_events"]
    network = raw["network_events"]
    if not isinstance(resolver_values, list) or not isinstance(network, list):
        raise VerificationError("raw event inventories are invalid")
    resolvers = [_fact(value) for value in resolver_values]
    if raw["dns_query_count"] != sum(len(value[4]) for value in resolvers):
        raise VerificationError("DNS query count changed")
    plan = raw["plan_rejection"]
    prelaunch = raw["prelaunch_rejection"]
    if plan is not None:
        if plan != "ambient-environment-present" or prelaunch is not None or raw["client_started"] or resolvers or network:
            raise VerificationError("plan rejection evidence is inconsistent")
        _counts(raw, (0, 0, 0, 0))
        return "denied", "plan"
    if prelaunch is not None:
        if prelaunch != "resolver-config-digest-mismatch" or raw["client_started"] or resolvers or network:
            raise VerificationError("prelaunch rejection evidence is inconsistent")
        _counts(raw, (0, 0, 0, 0))
        return "denied", "prelaunch"
    allowed4 = ("resolved", "127.0.0.1", "allowed.test", None, ("udp",))
    allowed6 = ("resolved", "fd00::1", "allowed.test", None, ("udp",))
    rebound = ("resolved", "127.0.0.2", "allowed.test", None, ("udp",))
    denied = ("resolved", "127.0.0.2", "denied.test", None, ("udp",))
    if case == "stable-a-and-aaaa":
        if resolvers != [allowed4, allowed6] or network != ["declared-response"]:
            raise VerificationError("stable resolution evidence changed")
        _counts(raw, (2, 2, 0, 0))
        return "allowed", "application-protocol"
    if case == "cname-to-declared-service":
        if resolvers != [allowed4] or network != ["declared-response"]:
            raise VerificationError("declared alias evidence changed")
        _counts(raw, (1, 1, 0, 0))
        return "allowed", "application-protocol"
    if case == "resolver-truncated-tcp-fallback":
        if resolvers != [("resolved", "127.0.0.1", "allowed.test", None, ("udp", "tcp"))] or network != ["declared-response"]:
            raise VerificationError("TCP fallback evidence changed")
        _counts(raw, (1, 1, 0, 0))
        return "allowed", "application-protocol"
    rejection_reasons = {
        "cname-loop-or-depth": ["cname-loop-or-depth", "cname-loop-or-depth"],
        "resolver-timeout": ["timeout"],
        "resolver-malformed-response": ["malformed"],
        "resolver-dnssec-flag-confusion": ["dnssec-flags"],
    }
    if case in rejection_reasons:
        if [value[3] for value in resolvers] != rejection_reasons[case] or any(value[0] != "rejected" for value in resolvers) or network or raw["client_started"]:
            raise VerificationError("resolver rejection evidence changed")
        _counts(raw, (0, 0, 0, 0))
        return "denied", "resolver"
    if case == "ttl-rebind-to-undeclared":
        if mechanism in {"explicit-broker", "preconnected-channel"}:
            if resolvers != [allowed4, ("rejected", None, None, "terminal-address", ("udp",))] or network != ["declared-response"]:
                raise VerificationError("policy refresh evidence changed")
            _counts(raw, (1, 1, 0, 0))
            return "denied", "resolver"
        if resolvers != [allowed4, rebound]:
            raise VerificationError("transparent refresh evidence changed")
        if mechanism == "landlock-port":
            if network != ["declared-response", "undeclared-contact"]:
                raise VerificationError("Landlock refresh exposure changed")
            _counts(raw, (2, 1, 0, 0))
            return "exposes-limitation", "resolver"
        if network != ["declared-response", "routing-denied"]:
            raise VerificationError("endpoint refresh denial changed")
        _counts(raw, (1, 1, 0, 0))
        return "denied", "routing"
    if case == "cname-to-undeclared-service":
        if mechanism in {"explicit-broker", "preconnected-channel"}:
            if resolvers != [("rejected", None, None, "terminal-service", ("udp",))] or network or raw["client_started"]:
                raise VerificationError("policy alias rejection changed")
            _counts(raw, (0, 0, 0, 0))
            return "denied", "resolver"
        if resolvers != [denied]:
            raise VerificationError("transparent alias evidence changed")
        if mechanism == "landlock-port":
            if network != ["undeclared-contact"]:
                raise VerificationError("Landlock alias exposure changed")
            _counts(raw, (1, 0, 0, 0))
            return "exposes-limitation", "resolver"
        if network != ["routing-denied"]:
            raise VerificationError("endpoint alias denial changed")
        _counts(raw, (0, 0, 0, 0))
        return "denied", "routing"
    if case == "resolver-configuration-substitution":
        if mechanism != "landlock-port" or resolvers != [rebound] or network != ["undeclared-contact"]:
            raise VerificationError("resolver substitution exposure changed")
        _counts(raw, (1, 0, 0, 0))
        return "exposes-limitation", "resolver"
    if case.startswith("redirect-"):
        event = {
            "redirect-undeclared-host": "redirect-host",
            "redirect-cleartext": "redirect-cleartext",
            "redirect-other-port": "redirect-port",
        }[case]
        if mechanism == "explicit-broker":
            if network != ["operation-rejected"]:
                raise VerificationError("broker redirect rejection changed")
            _counts(raw, (1, 1, 0, 0))
            return "denied", "application-protocol"
        if mechanism == "preconnected-channel":
            if network != [event, "child-boundary-denied"]:
                raise VerificationError("channel redirect denial changed")
            _counts(raw, (1, 1, 0, 0))
            return "denied", "child-boundary"
        if case == "redirect-undeclared-host" and mechanism == "landlock-port":
            if network != [event, "undeclared-contact"]:
                raise VerificationError("redirect exposure changed")
            _counts(raw, (2, 1, 0, 0))
            return "exposes-limitation", "routing"
        if network != [event, "routing-denied"]:
            raise VerificationError("redirect routing denial changed")
        _counts(raw, (1, 1, 0, 0))
        return "denied", "routing"
    if case in {"http-connect-target-confusion", "socks-target-confusion"}:
        if mechanism == "explicit-broker":
            if network != ["operation-rejected"]:
                raise VerificationError("broker proxy rejection changed")
            _counts(raw, (0, 0, 0, 0))
            return "denied", "application-protocol"
        if network != ["proxy-target-reached"]:
            raise VerificationError("proxy target exposure changed")
        _counts(raw, (0, 0, 1, 1))
        return "exposes-limitation", "application-protocol"
    if case.startswith("ambient-"):
        if mechanism == "landlock-port":
            if network != ["ambient-proxy-contact"]:
                raise VerificationError("ambient proxy exposure changed")
            _counts(raw, (0, 0, 1, 1))
            return "exposes-limitation", "routing"
        if mechanism == "cgroup-endpoint" and network == ["routing-denied"]:
            _counts(raw, (0, 0, 0, 0))
            return "denied", "routing"
        raise VerificationError("ambient proxy lacks its plan or routing denial")
    raise VerificationError("raw case has no independent derivation")


def _verify_manifest(
    manifest: dict[str, object],
    files: dict[str, bytes],
    prefix: str,
    schema: str,
) -> None:
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
    """Verify inventories, digests, plans, manifests, and every cell."""

    files = result_files(root)
    result = document(root / "RESULT.json")
    fields = {
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
    if set(result) != fields or result["schema"] != "proofbound-runtime-resolution-result/1":
        raise VerificationError("result schema is not closed")
    mechanism = result["mechanism"]
    if mechanism not in MECHANISMS or not COMMIT.fullmatch(str(result["source_commit"])):
        raise VerificationError("result mechanism or source commit is invalid")
    inputs = result["inputs"]
    if not isinstance(inputs, list):
        raise VerificationError("result input inventory is invalid")
    declared: dict[str, tuple[int, str]] = {}
    for item in inputs:
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
    expected = expected_cells(matrix_bytes, mechanism)
    registered = actual.get("evidence/artifacts/registered-resolver.json")
    substitute = actual.get("evidence/artifacts/substitute-resolver.json")
    if registered is None or substitute is None or registered == substitute:
        raise VerificationError("resolver configuration identities are invalid")
    registered_digest = sha256(registered)
    substitute_digest = sha256(substitute)
    matched = 0
    for case, outcome, stage in expected:
        cell = document(root / f"cells/{case}/CELL.json")
        if set(cell) != {"case", "expectation", "failure", "matched", "mechanism", "observed", "raw", "schema"}:
            raise VerificationError("cell schema is not closed")
        if cell["case"] != case or cell["mechanism"] != mechanism or cell["schema"] != "proofbound-runtime-resolution-cell/1":
            raise VerificationError("cell identity changed")
        plan = document(root / f"evidence/cases/{case}/case-plan.json")
        if (
            set(plan) != {
                "action", "case", "decision_matrix_sha256", "expectation", "mechanism",
                "parameters", "registered_environment", "registered_resolver_sha256",
                "schema", "substitute_resolver_sha256",
            }
            or plan["action"] != ACTIONS[case]
            or plan["case"] != case
            or plan["decision_matrix_sha256"] != result["decision_matrix_sha256"]
            or plan["expectation"] != {"outcome": outcome, "stage": stage}
            or plan["mechanism"] != mechanism
            or not isinstance(plan["parameters"], dict)
            or plan["registered_environment"] != {}
            or plan["registered_resolver_sha256"] != registered_digest
            or plan["substitute_resolver_sha256"] != substitute_digest
            or plan["schema"] != "proofbound-runtime-resolution-case-plan/1"
        ):
            raise VerificationError("prelaunch case plan changed")
        if cell["failure"] is not None or cell["raw"] is None:
            raise VerificationError("cell retains a harness failure")
        derived = derive(cell["raw"], case, mechanism)
        if (
            cell["expectation"] != {"outcome": outcome, "stage": stage}
            or cell["observed"] != {"outcome": derived[0], "stage": derived[1]}
            or derived != (outcome, stage)
            or cell["matched"] is not True
        ):
            raise VerificationError("cell result does not independently match")
        matched += 1
    evidence_manifest = document(root / "evidence-manifest.json")
    _verify_manifest(
        evidence_manifest,
        files,
        "evidence/",
        "proofbound-runtime-resolution-evidence-manifest/1",
    )
    source_manifest = document(root / "source-manifest.json")
    if (
        set(source_manifest) != {"decision_matrix_sha256", "files", "schema", "source_commit"}
        or source_manifest["schema"] != "proofbound-runtime-resolution-source-manifest/1"
        or source_manifest["source_commit"] != result["source_commit"]
        or source_manifest["decision_matrix_sha256"] != result["decision_matrix_sha256"]
        or not isinstance(source_manifest["files"], list)
    ):
        raise VerificationError("source manifest identity changed")
    source_names = set()
    for entry in source_manifest["files"]:
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
    if (
        set(tool) != {"architecture", "compiler", "kernel_release", "openssl", "python", "schema"}
        or tool["architecture"] not in {"x86_64", "aarch64"}
        or tool["schema"] != "proofbound-runtime-resolution-tool-manifest/1"
        or any(not isinstance(tool[name], str) or not tool[name] for name in ("compiler", "kernel_release", "openssl", "python"))
    ):
        raise VerificationError("tool manifest identity changed")
    if (
        result["case_count"] != 18
        or result["matched_case_count"] != matched
        or result["complete"] is not True
        or result["conclusion"] != "resolution-indirection-slice-matched"
    ):
        raise VerificationError("result conclusion is not complete")
    return {
        "complete": True,
        "matched_case_count": matched,
        "mechanism": mechanism,
        "schema": "proofbound-runtime-resolution-verification/1",
        "source_commit": result["source_commit"],
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("result", type=Path)
    return result


def main() -> int:
    try:
        print(json.dumps(verify(parser().parse_args().result), sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, VerificationError, ValueError) as error:
        print(f"resolution indirection verification failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
