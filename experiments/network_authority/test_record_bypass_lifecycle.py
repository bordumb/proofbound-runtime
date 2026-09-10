"""Mutation and publication tests for the experiment 0001H recorder."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.bypass_lifecycle_case import case_plan, load_bypass_matrix
from experiments.network_authority.record_bypass_lifecycle import (
    REQUIRED_ARTIFACTS, STAGED_FILES, SUBJECT_NAMES, expected_identities, record,
)
from experiments.network_authority.record_common import RecordError, canonical_json
from experiments.network_authority.test_bypass_cell import observed


ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_bypass_matrix(ROOT / "experiments/network_authority/decision-matrix.toml")


class BypassRecorderTests(unittest.TestCase):
    def evidence(self, root: Path, mechanism: str = "landlock-port") -> Path:
        evidence = root / "evidence"; artifacts = evidence / "artifacts"; cases = evidence / "cases"
        artifacts.mkdir(parents=True); cases.mkdir()
        for name in REQUIRED_ARTIFACTS[mechanism] - {"staged", "subjects"}:
            path = artifacts / name; path.write_bytes((name + "\n").encode()); path.chmod(0o755)
        subjects = artifacts / "subjects"; subjects.mkdir()
        for name in SUBJECT_NAMES:
            (subjects / name).write_bytes((name + "\n").encode())
        staged = artifacts / "staged/experiments/network_authority"; staged.mkdir(parents=True)
        (staged.parent / "__init__.py").write_bytes(b"")
        for name in STAGED_FILES:
            (staged / name).write_bytes((name + "\n").encode())
        inventory = {}
        for path in artifacts.rglob("*"):
            if path.is_file():
                inventory[path.relative_to(evidence).as_posix()] = (path.read_bytes(), path.stat().st_mode)
        for case in MATRIX.cases:
            case_root = cases / case.identifier; case_root.mkdir()
            identities = expected_identities(inventory, case.identifier, mechanism)
            plan = case_plan(case, mechanism, MATRIX.source_sha256, "a" * 40, identities)
            (case_root / "case-plan.json").write_bytes(canonical_json(plan))
            raw = observed(case, mechanism)
            (case_root / "raw-cell.json").write_bytes(canonical_json(raw))
            for name, data in (("runner.exit", b"0\n"), ("runner.stdout", b""), ("runner.stderr", b"")):
                (case_root / name).write_bytes(data)
            syscall_cases = {
                "pathname-unix-socket", "abstract-unix-socket",
                "io-uring-socket-create-connect", "io-uring-descriptor-send",
                "raw-and-packet-sockets", "fork-exec-at-process-limit",
                "concurrent-install-and-connect",
            }
            if case.identifier in syscall_cases:
                child = case_root / "child-output"; child.mkdir()
                (child / "started.txt").write_bytes(b"started\n")
                (child / "observation.json").write_bytes(canonical_json({"action": case.identifier, "attempts": raw["syscall_attempts"], "schema": "proofbound-runtime-bypass-syscall-observation/1"}))
                (case_root / "child.stdout").write_bytes(b"")
                (case_root / "child.stderr").write_bytes(b"")
                if case.identifier == "concurrent-install-and-connect":
                    sequence = case_root / "release-sequence"; sequence.mkdir()
                    (sequence / "child-stopped.txt").write_bytes(b"child-stopped\n")
                    (sequence / "boundary-acknowledged.txt").write_bytes(b"boundary-acknowledged\n")
            elif case.identifier == "inherited-connected-internet-socket":
                (case_root / "lifecycle-evidence.json").write_bytes(canonical_json({"event": "foreign-descriptor-present", "family": "AF_INET", "local": ["127.0.0.1", 30000], "peer": ["127.0.0.2", 443], "schema": "proofbound-runtime-inherited-socket-evidence/1", "type": "SOCK_STREAM"}))
            elif case.identifier.startswith("mediator-"):
                pass
            elif "substitution" in case.identifier:
                mutated = b"proofbound-substitute-subject\n"
                (case_root / "mutated-subject").write_bytes(mutated)
                subject = plan["parameters"]["mutated_subject"]
                (case_root / "lifecycle-evidence.json").write_bytes(canonical_json({"after_sha256": hashlib.sha256(mutated).hexdigest(), "before_sha256": identities[subject], "event": "subject-digest-mismatch", "mutation_count": 1, "schema": "proofbound-runtime-substitution-evidence/1"}))
            elif case.identifier == "connection-reuse-beyond-count":
                child = case_root / "child-output"; child.mkdir()
                (child / "started.txt").write_bytes(b"started\n")
                (child / "observation.json").write_bytes(canonical_json({"action": "direct", "events": raw["events"], "schema": "proofbound-runtime-connection-reuse-client/1", "transcript_sha256": hashlib.sha256("\n".join(raw["events"]).encode()).hexdigest()}))
                (case_root / "child.stdout").write_bytes(b"")
                (case_root / "child.stderr").write_bytes(b"")
                (case_root / "fixture-ready.json").write_bytes(canonical_json({"address": "127.0.0.1", "port": 443, "schema": "proofbound-runtime-connection-reuse-ready/1"}))
                (case_root / "fixture-observation.json").write_bytes(canonical_json({"connection_count": 2, "probe_sha256": hashlib.sha256(b"proofbound-reuse-probe\n").hexdigest(), "schema": "proofbound-runtime-connection-reuse-observation/1", "sentinel_sha256": hashlib.sha256(b"proofbound-reuse-sentinel\n").hexdigest()}))
            elif case.identifier == "cleanup-and-namespace-teardown-failure":
                identity_value = {"channel_peer": "/tmp/proofbound-mediator-test/peer-10", "executable_sha256": "b" * 64, "generation": 1, "pid": 10}
                (case_root / "lifecycle-evidence.json").write_bytes(canonical_json({"event": "failure-retained", "injected": "teardown-failure", "mediator_identity": identity_value, "schema": "proofbound-runtime-cleanup-evidence/1", "survivor_count": 0, "termination": {"pid": 10, "signal": 9, "status": "signaled"}}))
            elif case.identifier == "existing-result-replacement":
                sentinel = b"existing-result\n"
                (case_root / "existing-result").write_bytes(sentinel)
                (case_root / "lifecycle-evidence.json").write_bytes(canonical_json({"event": "replacement-rejected", "preserved_sha256": hashlib.sha256(sentinel).hexdigest(), "schema": "proofbound-runtime-publication-evidence/1"}))
        return evidence

    def arguments(self, root: Path, evidence: Path, mechanism: str = "landlock-port") -> argparse.Namespace:
        return argparse.Namespace(output=str(root / "result"), source_root=str(ROOT), evidence_root=str(evidence), source_commit="a" * 40, mechanism=mechanism, architecture="x86_64", kernel_release="test-kernel", compiler="test-cc", python="test-python")

    def test_complete_record_publishes_eighteen_matched_cells(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); result = record(self.arguments(root, self.evidence(root)))
            summary = json.loads((result / "RESULT.json").read_bytes())
            self.assertTrue(summary["complete"]); self.assertEqual(summary["matched_case_count"], 18)

    def test_raw_mutation_is_retained_as_harness_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); evidence = self.evidence(root)
            path = evidence / "cases/pathname-unix-socket/raw-cell.json"; raw = json.loads(path.read_bytes()); raw["cleanup"] = False; path.write_bytes(canonical_json(raw))
            result = record(self.arguments(root, evidence)); summary = json.loads((result / "RESULT.json").read_bytes())
            self.assertFalse(summary["complete"]); self.assertEqual(summary["matched_case_count"], 17)

    def test_symlink_and_existing_output_fail_before_replacement(self) -> None:
        for mutation in ("symlink", "existing"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary); evidence = self.evidence(root); arguments = self.arguments(root, evidence)
                if mutation == "symlink":
                    path = evidence / "cases/pathname-unix-socket/child.stdout"; path.unlink(); os.symlink("raw-cell.json", path)
                else:
                    (root / "result").mkdir(); (root / "result/sentinel").write_bytes(b"keep\n")
                with self.assertRaises(RecordError):
                    record(arguments)


if __name__ == "__main__":
    unittest.main()
