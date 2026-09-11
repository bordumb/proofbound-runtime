from __future__ import annotations

import json
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "experiments/performance/pure-result-v1.schema.json"
SUBJECTS = [
    "plan-parse-v1",
    "authority-normalization-v1",
    "policy-compilation-v1",
]


class PureResultSchemaTests(unittest.TestCase):
    def test_schema_closes_every_object_and_exact_subject_order(self) -> None:
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

        subjects = schema["properties"]["subjects"]
        self.assertEqual(subjects["minItems"], 3)
        self.assertEqual(subjects["maxItems"], 3)
        self.assertFalse(subjects["items"])
        self.assertEqual(
            [
                item["allOf"][1]["properties"]["subject"]["const"]
                for item in subjects["prefixItems"]
            ],
            SUBJECTS,
        )


if __name__ == "__main__":
    unittest.main()
