"""Publication and mutation tests for experiment 0001I measurements."""

from __future__ import annotations

import argparse
import json
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.measurement_domain import load_measurement_domain
from experiments.network_authority.measurement_observation import summarize_samples
from experiments.network_authority.record_common import RecordError, canonical_json, sha256
from experiments.network_authority.record_network_measurement import record
from experiments.network_authority.record_network_measurement_failure import (
    record_failure,
)
from experiments.network_authority.routing_cell import CLIENT_SCHEMA, raw_cell
from experiments.network_authority.routing_transport_case import load_routing_matrix
from experiments.network_authority.run_network_measurement import tree_summary
from experiments.network_authority.verify_network_measurement import (
    VerificationError,
    verify,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOMAIN_PATH = REPOSITORY_ROOT / "experiments/network_authority/measurement-domain.toml"
MATRIX_PATH = REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"
SOURCE_COMMIT = "a" * 40
REQUEST_SHA256 = "74d2d0d91b73d482d44bc44c9efce9fb374bd424634b224f8f5ad7955307c804"
RESPONSE_SHA256 = "171b2e654c262c92a4325908047e52e6dc22b739fb8339a0f8c0f5321d1140ee"


class NetworkMeasurementPublicationTests(unittest.TestCase):
    def fixture(self, root: Path) -> Path:
        evidence = root / "evidence"
        artifacts = evidence / "artifacts"
        observation = evidence / "observation"
        reference = observation / "reference-setup-state"
        requests = observation / "requests"
        artifacts.mkdir(parents=True)
        reference.mkdir(parents=True)
        requests.mkdir()

        for name in (
            "certificate", "routing-child-control", "routing-landlock-control",
            "trust-root",
        ):
            path = artifacts / name
            path.write_bytes((name + "\n").encode())
            if name.endswith("-control"):
                path.chmod(0o755)
        (reference / "boundary-observations.txt").write_bytes(b"no_new_privs=1\n")
        (reference / "ruleset-configuration.txt").write_bytes(
            b"handled_access_net=connect_tcp\nallowed_port=443\n"
        )
        state = tree_summary(reference)

        matrix = load_routing_matrix(MATRIX_PATH)
        exact = next(case for case in matrix.cases if case.identifier == "exact-service-ipv4")
        request_observations = []
        fixture = {
            "event": "exact-response",
            "peer_ip": "127.0.0.1",
            "request_sha256": REQUEST_SHA256,
            "response_sha256": RESPONSE_SHA256,
            "schema": "proofbound-runtime-decision-http-observation/1",
            "sni": "allowed.test",
            "tls_version": "TLSv1.3",
        }
        client = {
            "action": exact.action,
            "case": exact.identifier,
            "errno": None,
            "event": "exact-response",
            "phase": "application-protocol",
            "response_sha256": RESPONSE_SHA256,
            "schema": CLIENT_SCHEMA,
            "tls_version": "TLSv1.3",
        }
        for index in range(100):
            request_root = requests / f"{index:03d}"
            request_root.mkdir()
            raw_path = request_root / "raw-cell.json"
            raw_path.write_bytes(canonical_json(raw_cell(
                exact,
                "landlock-port",
                client=client,
                client_started=True,
                fixture_contact=True,
                fixture_complete=True,
            )))
            (request_root / "fixture-observation.json").write_bytes(
                canonical_json(fixture)
            )
            request_observations.append({
                "duration_ns": index + 101,
                "iteration": index,
                "raw_cell_sha256": sha256(raw_path.read_bytes()),
            })

        domain = load_measurement_domain(DOMAIN_PATH)
        setup = [
            {
                "cleanup": True,
                "duration_ns": index + 1,
                "exit": 0,
                "iteration": index,
                "state": state,
            }
            for index in range(100)
        ]
        raw = {
            "decision_matrix_sha256": matrix.source_sha256,
            "lifecycle": {
                "bit_order": "least-significant-bit-first",
                "bits_hex": "ff" * 125,
                "first_failure": None,
                "iteration_count": 1000,
                "passed_count": 1000,
            },
            "measurement_domain_sha256": domain.source_sha256,
            "mechanism": "landlock-port",
            "mediator_resources": {
                "maximum_process_count": None,
                "maximum_resident_set_bytes": None,
            },
            "platform": {
                "architecture": "x86_64",
                "bpf_features": [],
                "cgroup_v2_controllers": ["cpu", "memory"],
                "effective_capabilities": "0000000000000000",
                "kernel_release": "6.11.0-test",
                "landlock_abi": 4,
                "monotonic_clock": "CLOCK_MONOTONIC_RAW",
                "namespace_operations": ["mount", "network"],
                "python": "3.13.0",
                "schema": "proofbound-runtime-network-measurement-platform/1",
                "tls_implementation": "OpenSSL test",
            },
            "request_observations": request_observations,
            "request_summary": summarize_samples(range(101, 201), 100),
            "residual_authority": list(
                domain.profile("landlock-port").expected_residual_authority
            ),
            "schema": "proofbound-runtime-network-raw-measurement/1",
            "setup_observations": setup,
            "setup_summary": summarize_samples(range(1, 101), 100),
            "source_commit": SOURCE_COMMIT,
        }
        (observation / "RAW.json").write_bytes(canonical_json(raw))
        (observation / "namespace-cleanup.json").write_bytes(canonical_json({
            "mount_namespace_handle_absent": True,
            "namespace_process_pid": 1234,
            "namespace_process_reaped": True,
            "network_namespace_handle_absent": True,
            "schema": "proofbound-runtime-network-measurement-namespace-cleanup/1",
        }))
        return evidence

    def arguments(self, root: Path, evidence: Path) -> argparse.Namespace:
        return argparse.Namespace(
            output=str(root / "result"),
            source_root=str(REPOSITORY_ROOT),
            evidence_root=str(evidence),
            source_commit=SOURCE_COMMIT,
            mechanism="landlock-port",
            architecture="x86_64",
            kernel_release="6.11.0-test",
            compiler="cc test",
            python="Python 3.13.0",
        )

    def failure_arguments(self, root: Path) -> argparse.Namespace:
        stdout = root / "inner.stdout"
        stderr = root / "inner.stderr"
        stdout.write_bytes(b"partial native setup\n")
        stderr.write_bytes(b"required mechanism unavailable\n")
        return argparse.Namespace(
            output=str(root / "incomplete"),
            source_root=str(REPOSITORY_ROOT),
            stdout=str(stdout),
            stderr=str(stderr),
            source_commit=SOURCE_COMMIT,
            mechanism="cgroup-endpoint",
            architecture="aarch64",
            kernel_release="6.11.0-test",
            compiler="cc test",
            python="Python 3.13.0",
            exit_status=3,
        )

    @staticmethod
    def rebind_raw(result_root: Path, raw: dict[str, object]) -> None:
        raw_path = result_root / "evidence/observation/RAW.json"
        raw_path.write_bytes(canonical_json(raw))
        evidence_manifest_path = result_root / "evidence-manifest.json"
        evidence_manifest = json.loads(evidence_manifest_path.read_bytes())
        for item in evidence_manifest["files"]:
            if item["name"] == "observation/RAW.json":
                item["sha256"] = sha256(raw_path.read_bytes())
                item["size"] = raw_path.stat().st_size
        evidence_manifest_path.write_bytes(canonical_json(evidence_manifest))
        result_path = result_root / "RESULT.json"
        result = json.loads(result_path.read_bytes())
        result["raw_measurement_sha256"] = sha256(raw_path.read_bytes())
        changed = {
            "evidence/observation/RAW.json": raw_path,
            "evidence-manifest.json": evidence_manifest_path,
        }
        for item in result["inputs"]:
            if item["name"] in changed:
                path = changed[item["name"]]
                item["sha256"] = sha256(path.read_bytes())
                item["size"] = path.stat().st_size
        result_path.write_bytes(canonical_json(result))

    def test_result_round_trips_through_independent_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = record(self.arguments(root, self.fixture(root)))
            verified = verify(result)
            self.assertTrue(verified["complete"])
            self.assertEqual(verified["conclusion"], "network-measurement-complete")
            self.assertEqual(verified["setup_summary"]["count"], 100)
            self.assertEqual(verified["request_summary"]["count"], 100)
            with self.assertRaises(RecordError):
                record(self.arguments(root, root / "evidence"))

    def test_producer_rejects_malformed_setup_state_member(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = self.fixture(root)
            raw_path = evidence / "observation/RAW.json"
            raw = json.loads(raw_path.read_bytes())
            raw["setup_observations"][7]["state"]["files"][0]["size_bytes"] = True
            raw_path.write_bytes(canonical_json(raw))
            with self.assertRaises(RecordError):
                record(self.arguments(root, evidence))

    def test_verifier_rejects_rehashed_semantic_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = record(self.arguments(root, self.fixture(root)))
            raw_path = result / "evidence/observation/RAW.json"
            raw = json.loads(raw_path.read_bytes())
            raw["setup_observations"][7]["state"]["files"][0]["size_bytes"] = True
            raw["setup_observations"][7]["state"]["total_bytes"] += 1
            self.rebind_raw(result, raw)
            with self.assertRaises(VerificationError):
                verify(result)

    def test_incomplete_native_result_is_retained_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = record_failure(self.failure_arguments(root))
            verified = verify(result)
            self.assertIs(verified["complete"], False)
            self.assertEqual(verified["conclusion"], "network-measurement-incomplete")
            self.assertEqual(verified["exit_status"], 3)
            with self.assertRaises(RecordError):
                record_failure(self.failure_arguments(root))

    def test_incomplete_result_rejects_diagnostic_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = record_failure(self.failure_arguments(root))
            (result / "diagnostic/stderr.txt").write_bytes(b"substituted\n")
            with self.assertRaises(VerificationError):
                verify(result)


if __name__ == "__main__":
    unittest.main()
