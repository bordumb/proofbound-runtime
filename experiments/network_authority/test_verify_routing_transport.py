"""Mutation tests for the independent experiment 0001F verifier."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_routing_transport import record
from experiments.network_authority.test_record_routing_transport import RoutingRecorderTests
from experiments.network_authority.verify_routing_transport import (
    VerificationError,
    verify,
)


class RoutingVerifierTests(unittest.TestCase):
    def result(self, root: Path) -> Path:
        helper = RoutingRecorderTests()
        evidence = helper.fixture(root)
        return record(helper.arguments(root, evidence, "result"))

    def test_complete_result_verifies_independently(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            summary = verify(self.result(Path(temporary)))
            self.assertTrue(summary["complete"])
            self.assertEqual(summary["matched_case_count"], 16)
            self.assertEqual(summary["mechanism"], "landlock-port")

    def test_input_byte_mutation_and_extra_file_are_rejected(self) -> None:
        for mutation in ("byte", "extra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                result = self.result(Path(temporary))
                if mutation == "byte":
                    path = result / "evidence/artifacts/allowed-certificate.pem"
                    path.write_bytes(path.read_bytes() + b"mutated\n")
                else:
                    (result / "extra").write_bytes(b"not registered\n")
                with self.assertRaises(VerificationError):
                    verify(result)

    def test_semantic_cell_mutation_fails_after_hash_is_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_root = self.result(Path(temporary))
            path = result_root / "cells/exact-service-ipv4/CELL.json"
            cell = json.loads(path.read_bytes())
            cell["observed"] = {"outcome": "denied", "stage": "routing"}
            data = json.dumps(cell, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            path.write_bytes(data)
            result_path = result_root / "RESULT.json"
            result = json.loads(result_path.read_bytes())
            name = "cells/exact-service-ipv4/CELL.json"
            entry = next(item for item in result["inputs"] if item["name"] == name)
            entry["sha256"] = hashlib.sha256(data).hexdigest()
            entry["size"] = len(data)
            result_path.write_bytes(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
            )
            with self.assertRaises(VerificationError):
                verify(result_root)

    def test_duplicate_json_name_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result_root = self.result(Path(temporary))
            path = result_root / "tool-manifest.json"
            path.write_bytes(b'{"schema":"first","schema":"second"}\n')
            with self.assertRaises(VerificationError):
                verify(result_root)


if __name__ == "__main__":
    unittest.main()
