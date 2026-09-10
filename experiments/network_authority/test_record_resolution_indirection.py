"""Mutation and publication tests for the experiment 0001G recorder."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_common import RecordError, canonical_json
from experiments.network_authority.record_resolution_indirection import record
from experiments.network_authority.resolution_indirection_case import case_plan, load_resolution_matrix
from experiments.network_authority.test_resolution_cell import ResolutionCellTests


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_resolution_matrix(REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml")


class ResolutionRecorderTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        evidence = root / "evidence"
        artifacts = evidence / "artifacts"
        cases = evidence / "cases"
        artifacts.mkdir(parents=True)
        cases.mkdir()
        for name in (
            "allowed-certificate.pem",
            "registered-resolver.json",
            "substitute-resolver.json",
            "routing-child-control",
            "routing-landlock-control",
        ):
            path = artifacts / name
            path.write_bytes((name + "\n").encode())
            if name.endswith("-control"):
                path.chmod(0o755)
        staged = artifacts / "staged/experiments/network_authority"
        staged.mkdir(parents=True)
        (staged.parent / "__init__.py").write_bytes(b"")
        for name in (
            "__init__.py",
            "decision_http_fixture.py",
            "decision_proxy_fixture.py",
            "explicit_broker.py",
            "record_common.py",
            "resolution_indirection_client.py",
            "resolution_network_client.py",
            "scripted_dns.py",
        ):
            (staged / name).write_bytes((name + "\n").encode())
        registered_digest = __import__("hashlib").sha256(
            (artifacts / "registered-resolver.json").read_bytes()
        ).hexdigest()
        substitute_digest = __import__("hashlib").sha256(
            (artifacts / "substitute-resolver.json").read_bytes()
        ).hexdigest()
        helper = ResolutionCellTests()
        for case in MATRIX.cases:
            case_root = cases / case.identifier
            case_root.mkdir()
            (case_root / "case-plan.json").write_bytes(
                canonical_json(
                    case_plan(
                        case,
                        "landlock-port",
                        MATRIX.source_sha256,
                        registered_digest,
                        substitute_digest,
                    )
                )
            )
            (case_root / "raw-cell.json").write_bytes(
                canonical_json(helper.observed_raw(case, "landlock-port"))
            )
            (case_root / "trace.txt").write_bytes(b"bounded trace\n")
        return evidence

    def arguments(self, root: Path, evidence: Path, output: str) -> argparse.Namespace:
        return argparse.Namespace(
            output=str(root / output),
            source_root=str(REPOSITORY_ROOT),
            evidence_root=str(evidence),
            source_commit="a" * 40,
            mechanism="landlock-port",
            architecture="x86_64",
            kernel_release="test-kernel",
            compiler="test-cc",
            openssl="test-openssl",
            python="test-python",
        )

    def test_complete_result_publishes_all_eighteen_cells_and_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = record(self.arguments(root, self.fixture(root), "result"))
            result = json.loads((output / "RESULT.json").read_bytes())
            self.assertTrue(result["complete"])
            self.assertEqual(result["matched_case_count"], 18)
            self.assertEqual(result["conclusion"], "resolution-indirection-slice-matched")
            self.assertEqual(len(list((output / "cells").glob("*/CELL.json"))), 18)

    def test_mismatch_and_malformed_raw_are_retained_fail_closed(self) -> None:
        for mutation in ("mismatch", "malformed"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = self.fixture(root)
                path = evidence / "cases/stable-a-and-aaaa/raw-cell.json"
                if mutation == "malformed":
                    path.write_bytes(b'{"schema":"one","schema":"two"}\n')
                else:
                    raw = json.loads(path.read_bytes())
                    raw["network_events"] = ["routing-denied"]
                    path.write_bytes(canonical_json(raw))
                output = record(self.arguments(root, evidence, "result"))
                result = json.loads((output / "RESULT.json").read_bytes())
                cell = json.loads((output / "cells/stable-a-and-aaaa/CELL.json").read_bytes())
                self.assertFalse(result["complete"])
                self.assertFalse(cell["matched"])
                self.assertEqual(cell["observed"]["outcome"], "harness-failure")

    def test_symlink_and_unknown_case_fail_before_publication(self) -> None:
        for mutation in ("symlink", "unknown"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = self.fixture(root)
                if mutation == "symlink":
                    path = evidence / "cases/stable-a-and-aaaa/trace.txt"
                    path.unlink()
                    os.symlink("raw-cell.json", path)
                else:
                    (evidence / "cases/unknown").mkdir()
                with self.assertRaises(RecordError):
                    record(self.arguments(root, evidence, "result"))
                self.assertFalse((root / "result").exists())

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = self.fixture(root)
            output = root / "result"
            output.mkdir()
            (output / "foreign").write_bytes(b"keep\n")
            with self.assertRaises(RecordError):
                record(self.arguments(root, evidence, "result"))
            self.assertEqual((output / "foreign").read_bytes(), b"keep\n")


if __name__ == "__main__":
    unittest.main()
