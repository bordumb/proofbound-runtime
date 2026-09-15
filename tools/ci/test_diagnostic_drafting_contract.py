import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DIAGNOSTIC_SCHEMA = ROOT / "schemas/diagnostic-receipt-v1.schema.json"
DRAFT_SCHEMA = ROOT / "schemas/plan-draft-v1.schema.json"
ACCEPTANCE_SCHEMA = ROOT / "schemas/acceptance-decision-v2.cddl"
DIAGNOSTIC_VECTOR = ROOT / "schemas/vectors/diagnostic/diagnostic-receipt.json"
DRAFT_VECTOR = ROOT / "schemas/vectors/diagnostic/plan-draft.json"


def _resolve_reference(root, reference):
    prefix = "#/$defs/"
    if not reference.startswith(prefix):
        raise AssertionError(f"unsupported schema reference: {reference}")
    return root["$defs"][reference.removeprefix(prefix)]


def _matches(instance, schema, root):
    try:
        _validate(instance, schema, root)
    except AssertionError:
        return False
    return True


def _canonical_json_bytes(value):
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("JSON contains an unpaired surrogate") from error


def _validate(instance, schema, root):
    if "$ref" in schema:
        _validate(instance, _resolve_reference(root, schema["$ref"]), root)
    for member in schema.get("allOf", []):
        _validate(instance, member, root)
    if "oneOf" in schema:
        assert sum(_matches(instance, member, root) for member in schema["oneOf"]) == 1
    if "if" in schema and _matches(instance, schema["if"], root):
        _validate(instance, schema.get("then", {}), root)

    if "const" in schema:
        assert instance == schema["const"]
    if "enum" in schema:
        assert instance in schema["enum"]

    expected_type = schema.get("type")
    if expected_type is not None:
        expected_types = (
            expected_type if isinstance(expected_type, list) else [expected_type]
        )
        checks = {
            "array": lambda value: isinstance(value, list),
            "boolean": lambda value: isinstance(value, bool),
            "integer": lambda value: isinstance(value, int)
            and not isinstance(value, bool),
            "null": lambda value: value is None,
            "object": lambda value: isinstance(value, dict),
            "string": lambda value: isinstance(value, str),
        }
        assert any(checks[name](instance) for name in expected_types)

    if isinstance(instance, dict):
        required = set(schema.get("required", []))
        assert required <= set(instance)
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            assert set(instance) <= set(properties)
        for name, value in instance.items():
            if name in properties:
                _validate(value, properties[name], root)

    if isinstance(instance, list):
        if "minItems" in schema:
            assert len(instance) >= schema["minItems"]
        if "maxItems" in schema:
            assert len(instance) <= schema["maxItems"]
        if schema.get("uniqueItems"):
            canonical = [json.dumps(value, sort_keys=True) for value in instance]
            assert len(canonical) == len(set(canonical))
        if "items" in schema:
            for value in instance:
                _validate(value, schema["items"], root)
        if "contains" in schema:
            matches = sum(
                _matches(value, schema["contains"], root) for value in instance
            )
            assert matches >= schema.get("minContains", 1)
            if "maxContains" in schema:
                assert matches <= schema["maxContains"]

    if isinstance(instance, str):
        try:
            instance.encode("utf-8")
        except UnicodeEncodeError as error:
            raise AssertionError("string is not valid Unicode scalar text") from error
        if "minLength" in schema:
            assert len(instance) >= schema["minLength"]
        if "maxLength" in schema:
            assert len(instance) <= schema["maxLength"]
        if "pattern" in schema:
            assert re.search(schema["pattern"], instance) is not None

    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema:
            assert instance >= schema["minimum"]
        if "maximum" in schema:
            assert instance <= schema["maximum"]


def _assert_wire_objects_are_closed(schema):
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    for definition in schema["$defs"].values():
        if definition.get("type") == "object":
            assert definition["additionalProperties"] is False
    for property_schema in schema["properties"].values():
        if property_schema.get("type") == "object":
            assert property_schema["additionalProperties"] is False


class DiagnosticDraftingContractTests(unittest.TestCase):
    def test_vectors_are_duplicate_free_canonical_json_with_closed_non_claim_flags(
        self,
    ):
        for path in [DIAGNOSTIC_VECTOR, DRAFT_VECTOR]:
            raw = path.read_bytes().removesuffix(b"\n")
            value = json.loads(raw, object_pairs_hook=self._closed_object)
            canonical = _canonical_json_bytes(value)
            self.assertEqual(raw, canonical, path)
            self.assertFalse(value["safe_policy"])

        with self.assertRaises(ValueError):
            _canonical_json_bytes({"argument": "\ud800"})

        receipt = json.loads(DIAGNOSTIC_VECTOR.read_bytes())
        self.assertEqual(receipt["execution_profile"], "diagnostic")
        self.assertFalse(receipt["reusable"])
        self.assertIn(receipt["completion"], {"complete", "incomplete"})
        self.assertEqual(receipt["mechanism"], "linux-ptrace-syscall-v1")
        self.assertEqual(receipt["arguments"], ["--fixture", "π"])
        self.assertEqual(receipt["events"][0]["operands"]["kind"], "path")
        self.assertEqual(receipt["events"][0]["operands"]["symlink_hops"], 0)
        self.assertEqual(
            receipt["events"][0]["object_before"], receipt["events"][0]["object_after"]
        )
        self.assertEqual(receipt["events"][1]["operands"]["address"]["family"], "inet")

        draft = json.loads(DRAFT_VECTOR.read_bytes())
        self.assertEqual(draft["arguments"], receipt["arguments"])
        self.assertEqual(draft["environment_names"], receipt["environment_names"])
        self.assertEqual(draft["inputs"], [])
        self.assertIsNone(draft["static_scaffold"])
        self.assertIsNone(draft["capsec"])
        self.assertEqual(draft["differences"], [])
        self.assertEqual(
            draft["candidates"],
            [
                {
                    "kind": "read",
                    "path": "/workspace/config",
                    "provenance": ["diagnostic-runtime-observation"],
                }
            ],
        )
        self.assertEqual(
            {item["code"] for item in draft["open_items"]},
            {
                "capsec-missing",
                "choose-environment",
                "choose-limits",
                "choose-network-mode",
                "choose-write-roots",
                "diagnostic-gap",
                "network-attempt",
                "observation-unresolved",
            },
        )

    def test_schemas_are_closed_and_fix_every_security_discriminant(self):
        diagnostic = json.loads(DIAGNOSTIC_SCHEMA.read_bytes())
        draft = json.loads(DRAFT_SCHEMA.read_bytes())
        for schema in [diagnostic, draft]:
            _assert_wire_objects_are_closed(schema)
            self.assertEqual(schema["properties"]["safe_policy"], {"const": False})

        self.assertEqual(
            diagnostic["properties"]["schema"]["const"],
            "proofbound-runtime-diagnostic-receipt/1",
        )
        self.assertEqual(
            diagnostic["properties"]["execution_profile"]["const"], "diagnostic"
        )
        self.assertEqual(diagnostic["properties"]["reusable"], {"const": False})
        self.assertEqual(
            diagnostic["properties"]["mechanism"]["const"],
            "linux-ptrace-syscall-v1",
        )
        expected_roles = {
            "launcher": "launcher-binary",
            "observer": "diagnostic-observer",
            "runtime": "runtime-binary",
            "seed_plan": "execution-plan",
            "target": "runtime-executable",
        }
        for field, role in expected_roles.items():
            self.assertEqual(
                diagnostic["properties"][field]["allOf"][1]["properties"]["role"][
                    "const"
                ],
                role,
            )
        self.assertEqual(len(diagnostic["$defs"]["event"]["oneOf"]), 2)
        self.assertEqual(len(diagnostic["$defs"]["event"]["allOf"]), 7)
        self.assertIn(
            "symlink_hops", diagnostic["$defs"]["pathOperands"]["required"]
        )
        self.assertEqual(len(diagnostic["allOf"]), 2)
        self.assertEqual(
            draft["properties"]["schema"]["const"],
            "proofbound-runtime-plan-draft/1",
        )
        self.assertEqual(
            set(draft["$defs"]["provenance"]["enum"]),
            {
                "capsec-source-observation",
                "diagnostic-runtime-observation",
                "human-authored",
                "platform-required-closure",
                "static-executable-closure",
            },
        )
        self.assertTrue(
            {
                "arguments",
                "capsec",
                "differences",
                "environment_names",
                "inputs",
                "static_scaffold",
            }
            <= set(draft["required"])
        )
        mandatory = {
            item["$ref"] for item in draft["properties"]["open_items"]["allOf"]
        }
        self.assertEqual(
            mandatory,
            {
                "#/$defs/chooseEnvironment",
                "#/$defs/chooseLimits",
                "#/$defs/chooseNetwork",
                "#/$defs/chooseWriteRoots",
            },
        )
        self.assertEqual(draft["properties"]["gaps"]["items"], {"$ref": "#/$defs/gap"})

    def test_canonical_vectors_validate_against_the_complete_closed_schemas(self):
        diagnostic_schema = json.loads(DIAGNOSTIC_SCHEMA.read_bytes())
        draft_schema = json.loads(DRAFT_SCHEMA.read_bytes())
        diagnostic = json.loads(DIAGNOSTIC_VECTOR.read_bytes())
        draft = json.loads(DRAFT_VECTOR.read_bytes())
        _validate(diagnostic, diagnostic_schema, diagnostic_schema)
        _validate(draft, draft_schema, draft_schema)

        redacted_path = json.loads(json.dumps(diagnostic))
        redacted_path["events"][0]["resolution"] = "redacted"
        redacted_path["events"][0]["object_before"] = None
        redacted_path["events"][0]["object_after"] = None
        redacted_path["events"][0]["resolved_path"] = None
        self.assertFalse(_matches(redacted_path, diagnostic_schema, diagnostic_schema))
        redacted_path["events"][0]["operands"]["path"] = None
        _validate(redacted_path, diagnostic_schema, diagnostic_schema)

        redacted_socket = json.loads(json.dumps(diagnostic))
        redacted_socket["events"][1]["resolution"] = "redacted"
        self.assertFalse(_matches(redacted_socket, diagnostic_schema, diagnostic_schema))
        redacted_socket["events"][1]["operands"]["address"] = None
        _validate(redacted_socket, diagnostic_schema, diagnostic_schema)

        incomplete_stable_path = json.loads(json.dumps(diagnostic))
        incomplete_stable_path["events"][0]["operands"]["path"] = None
        self.assertFalse(
            _matches(incomplete_stable_path, diagnostic_schema, diagnostic_schema)
        )
        incomplete_stable_path = json.loads(json.dumps(diagnostic))
        incomplete_stable_path["events"][0]["operands"]["symlink_hops"] = None
        self.assertFalse(
            _matches(incomplete_stable_path, diagnostic_schema, diagnostic_schema)
        )

        for missing_field in ["path", "symlink_hops"]:
            incomplete_kernel_path = json.loads(json.dumps(diagnostic))
            incomplete_kernel_path["events"][0]["error"] = None
            incomplete_kernel_path["events"][0]["result"] = 3
            incomplete_kernel_path["events"][0]["resolution"] = "kernel-selected"
            incomplete_kernel_path["events"][0]["object_before"] = None
            incomplete_kernel_path["events"][0]["operands"][missing_field] = None
            self.assertFalse(
                _matches(incomplete_kernel_path, diagnostic_schema, diagnostic_schema)
            )

        capsec_candidate = json.loads(json.dumps(draft))
        capsec_candidate["candidates"] = [
            {
                "kind": "read",
                "path": "/workspace/config",
                "provenance": ["capsec-source-observation"],
            }
        ]
        self.assertFalse(_matches(capsec_candidate, draft_schema, draft_schema))
        identity = {"sha256": "sha256:" + "1" * 64, "size_bytes": 1}
        capsec_candidate["capsec"] = {
            "analyzer": identity,
            "report": identity,
            "schema_identity": "capsec-report/1",
            "source": identity,
            "usability": "usable",
        }
        _validate(capsec_candidate, draft_schema, draft_schema)

    def test_production_entry_points_have_no_diagnostic_observer_dependency(self):
        cli_manifest = (ROOT / "crates/proofbound-runtime-cli/Cargo.toml").read_text()
        linux_manifest = (
            ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
        ).read_text()
        launcher = (
            ROOT / "crates/proofbound-runtime-linux/src/bin/pbr-native-launcher.rs"
        ).read_text()
        for text in [cli_manifest, linux_manifest, launcher]:
            self.assertNotIn("proofbound-runtime-diagnose", text)
            self.assertNotIn("linux-ptrace-syscall-v1", text)

    def test_each_production_consumer_has_the_required_non_reuse_reason(self):
        verifier = (ROOT / "crates/proofbound-runtime-verify/src/error.rs").read_text()
        composer = (ROOT / "crates/proofbound-runtime-compose/src/main.rs").read_text()
        acceptor = (ROOT / "crates/proofbound-runtime-accept/src/main.rs").read_text()
        acceptance = (ROOT / "crates/proofbound-runtime-accept/src/lib.rs").read_text()
        acceptance_schema = ACCEPTANCE_SCHEMA.read_text()
        self.assertIn("profile.diagnostic.not-reusable", verifier)
        self.assertIn("profile.diagnostic.not-reusable", composer)
        self.assertIn("profile.diagnostic.not-reusable", acceptor)
        self.assertIn("diagnostic-profile-not-reusable", acceptance)
        self.assertIn('"proofbound-runtime-acceptance-decision/2"', acceptance_schema)
        self.assertIn('"diagnostic-profile-not-reusable"', acceptance_schema)
        self.assertNotIn("proofbound-runtime-acceptance-decision/1", acceptance)
        self.assertNotIn("proofbound-runtime-acceptance-decision/1", acceptance_schema)

    @staticmethod
    def _closed_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"duplicate JSON member: {key}")
            value[key] = item
        return value


if __name__ == "__main__":
    unittest.main()
