import copy
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.ci.deterministic_cbor import decode_strict
from tools.ci.encode_plan_v2 import encode
from tools.ci.service_receipt_contract import ContractError, FAILURE_PHASES, validate_receipt


ROOT = Path(__file__).resolve().parents[2]
VECTOR_ROOT = ROOT / "schemas/vectors/v2"


def payload(name: str) -> bytes:
    return bytes.fromhex((VECTOR_ROOT / f"{name}.cbor.hex").read_text(encoding="ascii").strip())


def vector(name: str) -> dict:
    return decode_strict(payload(name))


def digest(name: str) -> bytes:
    return hashlib.sha256(payload(name)).digest()


class ServiceReceiptContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.success = vector("service-session-receipt-success")
        self.failure = vector("service-session-receipt-failure")
        self.bindings = {
            "expected_execution_id": bytes(range(16)),
            "expected_plan_sha256": bytes([0x81]) * 32,
            "expected_policy_sha256": bytes([0x71]) * 32,
            "expected_service_name": "api.anthropic.com",
            "expected_service_port": 443,
            "expected_tcb_identities": {
                "connector-executable": bytes([0x21]) * 32,
                "dns-resolver": bytes([0x31]) * 32,
                "host-hardware-firmware": bytes([0x41]) * 32,
                "linux-kernel": bytes([0x51]) * 32,
                "tls-implementation": bytes([0x61]) * 32,
                "tls-trust-roots": bytes([0x52]) * 32,
            },
            "install_request_sha256": digest("service-launcher-install"),
            "installed_sha256": digest("service-launcher-installed"),
            "release_sha256": digest("service-launcher-release"),
        }

    def validate(self, value: dict) -> None:
        validate_receipt(value, **self.bindings)

    def test_canonical_vectors_validate_and_match_projections(self) -> None:
        for name in ("service-session-receipt-success", "service-session-receipt-failure"):
            value = vector(name)
            self.assertEqual(encode(value), payload(name))
            self.validate(value)

    def test_generator_reproduces_both_vectors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in ("service-launcher-install", "service-launcher-installed", "service-launcher-release"):
                for suffix in ("cbor.hex", "projection.json"):
                    (directory / f"{name}.{suffix}").write_bytes((VECTOR_ROOT / f"{name}.{suffix}").read_bytes())
            subprocess.run(
                [sys.executable, str(ROOT / "tools/ci/generate_service_receipt_v1_vectors.py"), "--directory", str(directory)],
                cwd=ROOT,
                check=True,
            )
            for name in ("service-session-receipt-success", "service-session-receipt-failure"):
                for suffix in ("cbor.hex", "projection.json"):
                    self.assertEqual((directory / f"{name}.{suffix}").read_bytes(), (VECTOR_ROOT / f"{name}.{suffix}").read_bytes())

    def test_success_mutations_are_rejected_causally(self) -> None:
        cases = []

        def add(name, mutate):
            value = copy.deepcopy(self.success)
            mutate(value)
            cases.append((name, value))

        add("unknown-field", lambda value: value.update({"credential_value": "canary-secret"}))
        add("execution-substitution", lambda value: value.__setitem__("execution_id", bytes(16)))
        add("plan-substitution", lambda value: value.__setitem__("plan_sha256", bytes(32)))
        add("policy-substitution", lambda value: value.__setitem__("policy_sha256", bytes(32)))
        add("install-substitution", lambda value: value.__setitem__("install_request_sha256", bytes(32)))
        add("installed-substitution", lambda value: value["result"].__setitem__("installed_sha256", bytes(32)))
        add("release-substitution", lambda value: value["result"].__setitem__("release_sha256", bytes(32)))
        add("observation-digest-substitution", lambda value: value["result"].__setitem__("observation_sha256", bytes(32)))
        add("service-substitution", lambda value: value["service"].__setitem__("name", "other.example"))
        add("reusable-reason", lambda value: value["eligibility"]["reasons"].append("network.unknown"))
        add("nonzero-exit", lambda value: value["result"]["child_outcome"].__setitem__("code", 1))
        add("assumption-omission", lambda value: value["assumptions"].pop())
        add("assumption-order", lambda value: value["assumptions"].reverse())
        add("tcb-omission", lambda value: value["trusted_computing_base"].pop())
        add("tcb-substitution", lambda value: value["trusted_computing_base"][0].__setitem__("role", "ambient-proxy"))
        add("tcb-identity-substitution", lambda value: value["trusted_computing_base"][0].__setitem__("identity_sha256", bytes(32)))
        add("tcb-secret", lambda value: value["trusted_computing_base"][0].__setitem__("identity_sha256", "canary-secret"))

        def mutate_nested(value, mutate):
            nested = decode_strict(value["result"]["observation_cbor"])
            mutate(nested)
            encoded = encode(nested)
            value["result"]["observation_cbor"] = encoded
            value["result"]["observation_sha256"] = hashlib.sha256(encoded).digest()

        add("nested-service-substitution", lambda value: mutate_nested(value, lambda nested: nested["service"].__setitem__("name", "other.example")))
        add("nested-connector-tcb-substitution", lambda value: mutate_nested(value, lambda nested: nested["connector"]["executable"].__setitem__("sha256", bytes(32))))
        add("nested-resolver-tcb-substitution", lambda value: mutate_nested(value, lambda nested: nested["dns"]["configuration"].__setitem__("sha256", bytes(32))))
        add("nested-trust-root-tcb-substitution", lambda value: mutate_nested(value, lambda nested: nested["tls"]["trust_root_set"].__setitem__("sha256", bytes(32))))
        add("nested-secret", lambda value: mutate_nested(value, lambda nested: nested.update({"credential_value": "canary-secret"})))

        for name, value in cases:
            with self.subTest(name=name), self.assertRaises(ContractError):
                self.validate(value)

    def test_failure_mutations_are_rejected_causally(self) -> None:
        cases = []

        def add(name, mutate):
            value = copy.deepcopy(self.failure)
            mutate(value)
            cases.append((name, value))

        add("reusable-failure", lambda value: value["eligibility"].update({"status": "reusable", "reasons": []}))
        add("reason-loss", lambda value: value["eligibility"]["reasons"].clear())
        add("reason-substitution", lambda value: value["result"].__setitem__("reason", "resolver-failed"))
        add("phase-substitution", lambda value: value["result"].__setitem__("phase", "active"))
        add("execution-substitution", lambda value: value.__setitem__("execution_id", bytes(16)))
        add("plan-substitution", lambda value: value.__setitem__("plan_sha256", bytes(32)))
        add("policy-substitution", lambda value: value.__setitem__("policy_sha256", bytes(32)))
        add("service-substitution", lambda value: value["service"].__setitem__("name", "other.example"))
        add("early-installed-boundary", lambda value: value["result"].update({"boundary_state": "installed", "installed_sha256": self.bindings["installed_sha256"]}))
        add("uninstalled-identity", lambda value: value["result"].__setitem__("installed_sha256", bytes(32)))
        add("pre-release-identity", lambda value: value["result"].__setitem__("release_sha256", self.bindings["release_sha256"]))
        add("success-observation-on-failure", lambda value: value["result"].__setitem__("observation_sha256", bytes(32)))
        add("pre-release-child", lambda value: value["result"]["cleanup"].__setitem__("child", "reaped"))
        add("connector-loss", lambda value: value["result"]["cleanup"].__setitem__("connector", "not-started"))
        add("unreported-cleanup-failure", lambda value: value["result"]["cleanup"].__setitem__("channel", "cleanup-failed"))
        add("false-cleanup-reason", lambda value: value["result"].update({"phase": "closing", "reason": "cleanup-failed"}))

        def post_release_substitution(value):
            value["result"].update(
                {
                    "phase": "active",
                    "reason": "channel-lost",
                    "boundary_state": "installed",
                    "installed_sha256": self.bindings["installed_sha256"],
                    "release_sha256": bytes(32),
                }
            )
            value["result"]["cleanup"]["child"] = "reaped"

        add("post-release-substitution", post_release_substitution)

        for name, value in cases:
            with self.subTest(name=name), self.assertRaises(ContractError):
                self.validate(value)

    def test_failure_reason_phase_matrix_is_closed(self) -> None:
        phases = {phase for allowed in FAILURE_PHASES.values() for phase in allowed}
        for reason, allowed in FAILURE_PHASES.items():
            for phase in phases:
                value = copy.deepcopy(self.failure)
                value["result"].update(
                    {
                        "phase": phase,
                        "reason": reason,
                        "boundary_state": "not-installed",
                        "installed_sha256": None,
                        "release_sha256": None,
                    }
                )
                value["eligibility"]["reasons"] = [f"network.{reason}"]
                cleanup = value["result"]["cleanup"]
                cleanup["child"] = "not-started"
                cleanup["connector"] = "not-started" if phase == "created" else "reaped"
                cleanup["channel"] = "closed"
                if reason == "cleanup-failed":
                    cleanup["channel"] = "cleanup-failed"
                if phase in {"active", "closing"}:
                    value["result"].update(
                        {
                            "boundary_state": "installed",
                            "installed_sha256": self.bindings["installed_sha256"],
                            "release_sha256": self.bindings["release_sha256"],
                        }
                    )
                    cleanup["child"] = "reaped"
                if phase in allowed:
                    with self.subTest(reason=reason, phase=phase, expected="accepted"):
                        self.validate(value)
                else:
                    with self.subTest(reason=reason, phase=phase, expected="rejected"), self.assertRaises(ContractError):
                        self.validate(value)

    def test_ready_failure_may_bind_an_installed_unreleased_boundary(self) -> None:
        value = copy.deepcopy(self.failure)
        value["result"].update(
            {
                "phase": "ready",
                "reason": "launcher-install-failed",
                "boundary_state": "installed",
                "installed_sha256": self.bindings["installed_sha256"],
                "release_sha256": None,
            }
        )
        value["eligibility"]["reasons"] = ["network.launcher-install-failed"]
        self.validate(value)

    def test_schema_is_closed_and_content_free(self) -> None:
        schema = (ROOT / "schemas/service-session-receipt-v1.cddl").read_text(encoding="utf-8")
        self.assertIn('"observation_cbor": bstr .size (1..1048576)', schema)
        self.assertIn('"status": "reusable" / "non-reusable"', schema)
        self.assertIn('"observation_sha256": null', schema)
        self.assertIn('"release_sha256": bstr .size 32 / null', schema)
        for forbidden in ("credential_value", "application_request", "application_response", "ambient-network"):
            self.assertNotIn(forbidden, schema)
            self.assertNotIn(forbidden.encode(), payload("service-session-receipt-success"))
            self.assertNotIn(forbidden.encode(), payload("service-session-receipt-failure"))


if __name__ == "__main__":
    unittest.main()
