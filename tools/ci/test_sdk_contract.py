#!/usr/bin/env python3
"""Freeze the cross-language SDK boundary before implementation."""

from pathlib import Path
import json
import unittest


ROOT = Path(__file__).resolve().parents[2]


class SdkContractTests(unittest.TestCase):
    def test_spec_keeps_execution_and_verification_out_of_process(self) -> None:
        spec = (ROOT / "docs/specs/0012_plan_sdks.md").read_text()
        for required in (
            "deterministic-CBOR",
            "separate child process",
            "never receipt-verification input",
            "places no shell",
            "does not retry",
            "registry authenticity",
        ):
            self.assertIn(required, spec)

    def test_three_packages_and_result_schema_exist(self) -> None:
        for path in (
            "crates/proofbound-runtime-sdk/Cargo.toml",
            "crates/proofbound-runtime-sdk/src/lib.rs",
            "sdk/python/pyproject.toml",
            "sdk/python/proofbound_runtime/__init__.py",
            "sdk/typescript/package.json",
            "sdk/typescript/src/index.ts",
            "schemas/run-result-v2.schema.json",
        ):
            self.assertTrue((ROOT / path).is_file(), path)

    def test_package_versions_and_names_are_closed(self) -> None:
        python = (ROOT / "sdk/python/pyproject.toml").read_text()
        typescript = json.loads((ROOT / "sdk/typescript/package.json").read_text())
        self.assertIn('name = "proofbound-runtime-sdk"', python)
        self.assertIn('version = "0.2.0"', python)
        self.assertEqual(typescript["name"], "@proofbound/runtime-sdk")
        self.assertEqual(typescript["version"], "0.2.0")


if __name__ == "__main__":
    unittest.main()
