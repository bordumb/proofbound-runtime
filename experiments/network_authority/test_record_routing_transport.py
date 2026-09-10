"""Mutation and publication tests for the experiment 0001F recorder."""

from __future__ import annotations

import argparse
import errno
import json
import os
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_common import RecordError, canonical_json
from experiments.network_authority.record_routing_transport import record
from experiments.network_authority.routing_cell import CLIENT_SCHEMA, raw_cell
from experiments.network_authority.routing_transport_case import (
    RoutingCase,
    load_routing_matrix,
    plan_rejection,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = load_routing_matrix(
    REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"
)


def client(case: RoutingCase, event: str, phase: str, error: int | None = None):
    result = {
        "action": case.action,
        "case": case.identifier,
        "errno": error,
        "event": event,
        "phase": phase,
        "schema": CLIENT_SCHEMA,
    }
    if event == "exact-response":
        result.update(response_sha256="a" * 64, tls_version="TLSv1.3")
    if event == "certificate-rejected":
        result.pop("errno")
        result["verify_code"] = 18
    return result


def landlock_raw(case: RoutingCase):
    identifier = case.identifier
    rejection = plan_rejection(identifier)
    if rejection is not None:
        return raw_cell(case, "landlock-port", plan_rejection=rejection)
    if identifier.startswith("exact-service-"):
        return raw_cell(
            case,
            "landlock-port",
            client=client(case, "exact-response", "application-protocol"),
            client_started=True,
            fixture_contact=True,
            fixture_complete=True,
        )
    if identifier == "allowed-endpoint-wrong-certificate":
        return raw_cell(
            case,
            "landlock-port",
            client=client(case, "certificate-rejected", "tls"),
            client_started=True,
            fixture_contact=True,
        )
    if identifier == "direct-tcp-other-port":
        return raw_cell(
            case,
            "landlock-port",
            client=client(case, "operation-error", "connect", errno.EACCES),
            client_started=True,
        )
    if identifier in {
        "direct-udp-dns-shaped",
        "direct-udp-quic-shaped",
        "tcp-bind-listen",
        "udp-bind",
    }:
        phase = "bind" if identifier == "tcp-bind-listen" else "socket"
        return raw_cell(
            case,
            "landlock-port",
            client=client(case, "operation-error", phase, errno.EPERM),
            client_started=True,
        )
    return raw_cell(
        case,
        "landlock-port",
        client=client(case, "routing-connected", "connect"),
        client_started=True,
        fixture_contact=True,
    )


class RoutingRecorderTests(unittest.TestCase):
    def fixture(self, root: Path):
        evidence = root / "evidence"
        artifacts = evidence / "artifacts"
        cases = evidence / "cases"
        artifacts.mkdir(parents=True)
        cases.mkdir()
        for name in (
            "allowed-certificate.pem",
            "denied-certificate.pem",
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
            "decision_socket_fixture.py",
            "record_common.py",
            "routing_transport_case.py",
            "routing_transport_client.py",
        ):
            (staged / name).write_bytes((name + "\n").encode())
        for case in MATRIX.cases:
            case_root = cases / case.identifier
            case_root.mkdir()
            (case_root / "raw-cell.json").write_bytes(canonical_json(landlock_raw(case)))
            (case_root / "child.stdout").write_bytes(b"")
            (case_root / "child.stderr").write_bytes(b"")
        return evidence

    def arguments(self, root: Path, evidence: Path, output: str):
        return argparse.Namespace(
            output=str(root / output),
            source_root=str(REPOSITORY_ROOT),
            evidence_root=str(evidence),
            source_commit="a" * 40,
            mechanism="landlock-port",
            architecture="x86_64",
            kernel_release="6.11.0-test",
            compiler="cc test",
            openssl="OpenSSL test",
            python="Python test",
        )

    def test_exact_sixteen_case_result_is_complete_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = self.fixture(root)
            first = record(self.arguments(root, evidence, "first"))
            second = record(self.arguments(root, evidence, "second"))
            first_result = (first / "RESULT.json").read_bytes()
            self.assertEqual(first_result, (second / "RESULT.json").read_bytes())
            result = json.loads(first_result)
            self.assertTrue(result["complete"])
            self.assertEqual(result["case_count"], 16)
            self.assertEqual(result["matched_case_count"], 16)
            self.assertEqual(result["conclusion"], "routing-transport-slice-matched")
            self.assertEqual(len(list((first / "cells").glob("*/CELL.json"))), 16)

    def test_valid_but_mismatched_cell_is_retained_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = self.fixture(root)
            case = next(case for case in MATRIX.cases if case.identifier == "literal-allowed-address")
            path = evidence / f"cases/{case.identifier}/raw-cell.json"
            path.write_bytes(
                canonical_json(
                    raw_cell(
                        case,
                        "landlock-port",
                        client=client(case, "operation-error", "connect", errno.EACCES),
                        client_started=True,
                    )
                )
            )
            output = record(self.arguments(root, evidence, "mismatch"))
            result = json.loads((output / "RESULT.json").read_bytes())
            cell = json.loads((output / f"cells/{case.identifier}/CELL.json").read_bytes())
            self.assertFalse(result["complete"])
            self.assertEqual(result["matched_case_count"], 15)
            self.assertFalse(cell["matched"])
            self.assertEqual(cell["observed"], {"outcome": "denied", "stage": "routing"})

    def test_malformed_or_unclean_raw_becomes_harness_failure(self) -> None:
        for mutation in ("malformed", "unclean"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = self.fixture(root)
                case = MATRIX.cases[0]
                path = evidence / f"cases/{case.identifier}/raw-cell.json"
                if mutation == "malformed":
                    path.write_bytes(b'{"schema":"duplicate","schema":"duplicate"}\n')
                else:
                    raw = landlock_raw(case)
                    raw["cleanup"] = False
                    path.write_bytes(canonical_json(raw))
                output = record(self.arguments(root, evidence, mutation))
                cell = json.loads((output / f"cells/{case.identifier}/CELL.json").read_bytes())
                self.assertEqual(cell["observed"]["outcome"], "harness-failure")
                self.assertFalse(json.loads((output / "RESULT.json").read_bytes())["complete"])

    def test_unknown_case_directory_and_symlink_fail_before_publication(self) -> None:
        for mutation in ("unknown", "symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                evidence = self.fixture(root)
                if mutation == "unknown":
                    (evidence / "cases/unknown").mkdir()
                else:
                    target = evidence / "cases/exact-service-ipv4/child.stdout"
                    target.unlink()
                    os.symlink("child.stderr", target)
                with self.assertRaises(RecordError):
                    record(self.arguments(root, evidence, "result"))
                self.assertFalse((root / "result").exists())

    def test_existing_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = self.fixture(root)
            output = root / "result"
            output.mkdir()
            (output / "foreign").write_text("keep\n", encoding="utf-8")
            with self.assertRaises(RecordError):
                record(self.arguments(root, evidence, "result"))
            self.assertEqual((output / "foreign").read_text(encoding="utf-8"), "keep\n")


if __name__ == "__main__":
    unittest.main()
