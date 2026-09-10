#!/usr/bin/env python3
"""Run one non-syscall experiment 0001H lifecycle case."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import socket
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.bypass_cell import raw_cell
from experiments.network_authority.bypass_lifecycle_case import case_plan, load_bypass_matrix
from experiments.network_authority.bypass_lifecycle_evidence import (
    cleanup_evidence, crash_evidence, no_replace_evidence, restart_evidence,
    substitution_evidence,
)
from experiments.network_authority.record_common import canonical_json, regular_bytes, write_new


SUBJECTS = (
    "certificate", "channel", "client", "executable", "native-policy",
    "resolver", "trust-root",
)


class BypassOrchestrationError(Exception):
    """One bypass lifecycle case could not produce complete raw evidence."""


def identities(root: Path) -> dict[str, str]:
    if not root.is_absolute() or not root.is_dir() or root.is_symlink():
        raise BypassOrchestrationError("subject root is invalid")
    result = {}
    for name in SUBJECTS:
        data = regular_bytes(root / name)
        result[name] = hashlib.sha256(data).hexdigest()
    return result


def _substitution_name(case_id: str) -> tuple[str, str]:
    return {
        "policy-program-map-rule-substitution": ("native-policy", "native-policy-digest-mismatch"),
        "resolver-and-trust-root-substitution": ("resolver", "resolver-trust-root-digest-mismatch"),
        "certificate-and-channel-substitution": ("certificate", "certificate-channel-identity-mismatch"),
        "executable-and-staged-client-substitution": ("executable", "executable-client-digest-mismatch"),
    }[case_id]


def run(arguments: argparse.Namespace) -> dict[str, object]:
    if os.geteuid() != 0:
        raise BypassOrchestrationError("bypass lifecycle orchestration requires root")
    matrix = load_bypass_matrix(arguments.matrix)
    matches = [case for case in matrix.cases if case.identifier == arguments.case]
    if len(matches) != 1:
        raise BypassOrchestrationError("bypass lifecycle case is not unique")
    case = matches[0]
    subject_identities = identities(arguments.subject_root)
    arguments.case_root.mkdir(mode=0o755)
    write_new(
        arguments.case_root / "case-plan.json",
        canonical_json(case_plan(case, arguments.mechanism, matrix.source_sha256, arguments.source_commit, subject_identities)),
    )

    identifier = case.identifier
    evidence: dict[str, object] | None = None
    if identifier == "inherited-connected-internet-socket":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.2", 0))
            listener.listen(1)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as inherited:
                inherited.connect(listener.getsockname())
                peer, _address = listener.accept()
                with peer:
                    os.fstat(inherited.fileno())
                    evidence = {
                        "event": "foreign-descriptor-present",
                        "family": "AF_INET",
                        "local": list(inherited.getsockname()),
                        "peer": list(inherited.getpeername()),
                        "schema": "proofbound-runtime-inherited-socket-evidence/1",
                        "type": "SOCK_STREAM",
                    }
        raw = raw_cell(case, arguments.mechanism, prelaunch_rejection="foreign-descriptor-present")
    elif identifier.startswith("mediator-"):
        if arguments.mechanism in {"landlock-port", "cgroup-endpoint"}:
            raw = raw_cell(case, arguments.mechanism, plan_rejection="mechanism-has-no-mediator")
        elif identifier == "mediator-crash-before-release":
            evidence = crash_evidence("before-release")
            raw = raw_cell(case, arguments.mechanism, events=[str(evidence["event"])])
        elif identifier == "mediator-crash-during-exchange":
            evidence = crash_evidence("during-exchange")
            raw = raw_cell(case, arguments.mechanism, events=[str(evidence["event"])])
        else:
            evidence = restart_evidence()
            raw = raw_cell(case, arguments.mechanism, events=[str(evidence["event"])])
    elif "substitution" in identifier:
        name, rejection = _substitution_name(identifier)
        target = arguments.case_root / "mutated-subject"
        shutil.copyfile(arguments.subject_root / name, target)
        evidence = substitution_evidence(target, b"proofbound-substitute-subject\n")
        raw = raw_cell(case, arguments.mechanism, prelaunch_rejection=rejection)
    elif identifier == "cleanup-and-namespace-teardown-failure":
        evidence = cleanup_evidence()
        raw = raw_cell(case, arguments.mechanism, events=["teardown-failure-injected", str(evidence["event"])])
    elif identifier == "existing-result-replacement":
        evidence = no_replace_evidence(arguments.case_root / "existing-result")
        raw = raw_cell(case, arguments.mechanism, events=[str(evidence["event"])], publication_preserved=True)
    else:
        raise BypassOrchestrationError("case requires the native syscall or reuse orchestrator")
    if evidence is not None:
        write_new(arguments.case_root / "lifecycle-evidence.json", canonical_json(evidence))
    write_new(arguments.raw_output, canonical_json(raw))
    return raw


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", required=True)
    result.add_argument("--mechanism", required=True)
    result.add_argument("--source-commit", required=True)
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--matrix", type=Path, required=True)
    result.add_argument("--case-root", type=Path, required=True)
    result.add_argument("--raw-output", type=Path, required=True)
    result.add_argument("--subject-root", type=Path, required=True)
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        if (
            not arguments.repository_root.is_absolute() or not arguments.matrix.is_absolute()
            or not arguments.case_root.is_absolute() or not arguments.raw_output.is_absolute()
            or arguments.raw_output.parent != arguments.case_root
        ):
            raise BypassOrchestrationError("bypass lifecycle paths are invalid")
        run(arguments)
        return 0
    except (BypassOrchestrationError, OSError, ValueError) as error:
        print(f"bypass lifecycle case failed: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
