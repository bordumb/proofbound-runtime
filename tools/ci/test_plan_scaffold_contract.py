#!/usr/bin/env python3
"""Freeze the review and non-policy boundary for RT-3.3."""

from pathlib import Path
import json
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PlanScaffoldContractTests(unittest.TestCase):
    def test_spec_freezes_non_policy_output_and_human_choices(self) -> None:
        spec = (ROOT / "docs/specs/0011_plan_scaffold.md").read_text()
        for required in (
            "proofbound-runtime-plan-scaffold/1",
            "safe_policy: false",
            "never executes the target",
            "write roots",
            "environment variable names",
            "memory, and swap limits",
            "network mode",
            "search-path-conflict",
        ):
            self.assertIn(required, spec)

    def test_implementation_and_attack_registration_exist(self) -> None:
        required = (
            "crates/proofbound-runtime-cli/src/scaffold.rs",
            "tests/attacks/scaffold/v1.toml",
            "proofbound/evidence/plan-scaffold-attacks.toml",
            "claims/PBR-SCAFFOLD-013.toml",
        )
        for path in required:
            self.assertTrue((ROOT / path).is_file(), path)

    def test_cli_exposes_only_the_closed_scaffold_shape(self) -> None:
        main = (ROOT / "crates/proofbound-runtime-cli/src/main.rs").read_text()
        self.assertIn('subcommand == "scaffold"', main)
        self.assertIn('OsStr::new("--executable")', main)
        self.assertIn('OsStr::new("--host-profile")', main)

    def test_json_projection_schema_is_closed_and_cannot_be_a_policy(self) -> None:
        schema = json.loads((ROOT / "schemas/plan-scaffold-v1.schema.json").read_text())
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["safe_policy"], {"const": False})
        self.assertEqual(
            schema["properties"]["schema"],
            {"const": "proofbound-runtime-plan-scaffold/1"},
        )
        for definition in schema["$defs"].values():
            if definition.get("type") == "object":
                self.assertFalse(definition["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
