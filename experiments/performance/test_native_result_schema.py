from __future__ import annotations

import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "experiments/performance/native-result-v1.schema.json"
PHASES = [
    "plan-validation-and-normalization-v1",
    "host-and-path-preflight-v1",
    "executable-closure-inventory-v1",
    "cgroup-creation-and-readback-v1",
    "launcher-request-and-identity-revalidation-v1",
    "stopped-launcher-creation-v1",
    "boundary-installation-v1",
    "child-execution-v1",
    "process-tree-cleanup-v1",
    "stream-collection-v1",
    "output-inventory-v1",
    "receipt-construction-and-publication-v1",
    "run-result-projection-v1",
]


class NativeResultSchemaTests(unittest.TestCase):
    def test_schema_closes_every_object_and_exact_native_domains(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(set(schema["required"]), set(schema["properties"]))
        for definition in schema["$defs"].values():
            if definition.get("type") == "object":
                self.assertFalse(definition["additionalProperties"])
                self.assertEqual(
                    set(definition["required"]), set(definition["properties"])
                )

        protocol = schema["properties"]["protocol"]
        self.assertEqual(protocol["properties"]["warmup_count"]["const"], 10)
        self.assertEqual(protocol["properties"]["sample_count"]["const"], 100)
        runs = schema["properties"]["measurements"]["properties"]["runs"]
        self.assertEqual((runs["minItems"], runs["maxItems"]), (100, 100))
        phase_samples = schema["$defs"]["run"]["properties"]["phase_samples_ns"]
        self.assertEqual(
            (phase_samples["minItems"], phase_samples["maxItems"]),
            (len(PHASES), len(PHASES)),
        )
        phases = schema["properties"]["measurements"]["properties"]["phases"]
        self.assertFalse(phases["items"])
        self.assertEqual(
            [
                item["allOf"][1]["properties"]["phase"]["const"]
                for item in phases["prefixItems"]
            ],
            PHASES,
        )
        self.assertEqual(
            schema["properties"]["workload"]["properties"]["id"]["enum"],
            ["hello-static-v1", "hello-dynamic-v1"],
        )


if __name__ == "__main__":
    unittest.main()
