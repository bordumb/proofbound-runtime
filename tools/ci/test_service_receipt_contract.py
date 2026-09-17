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
        launcher = vector("service-launcher-install")
        observation = vector("service-session-observation")
        self.bindings = {
            "expected_execution_id": bytes(range(16)),
            "expected_plan_sha256": bytes([0x81]) * 32,
            "expected_policy_sha256": bytes([0x71]) * 32,
            "expected_service_name": "api.anthropic.com",
            "expected_service_port": 443,
            "expected_tcb_identities": {
                "connector-executable": launcher["service"]["connector"]["executable"]["sha256"],
                "connector-runtime-closure": launcher["service"]["connector"]["runtime_closure_sha256"],
                "tls-implementation": observation["tls"]["implementation_sha256"],
                "tls-trust-roots": observation["tls"]["trust_root_set"]["sha256"],
            },
            "install_request_cbor": payload("service-launcher-install"),
            "installed_cbor": payload("service-launcher-installed"),
            "release_cbor": payload("service-launcher-release"),
        }
        self.install_request_sha256 = digest("service-launcher-install")
        self.installed_sha256 = digest("service-launcher-installed")
        self.release_sha256 = digest("service-launcher-release")

    def validate(self, value: dict) -> None:
        bindings = dict(self.bindings)
        if value["result"]["kind"] == "failed":
            if value["result"]["boundary_state"] == "not-installed":
                bindings["installed_cbor"] = None
            if value["result"]["release_sha256"] is None:
                bindings["release_cbor"] = None
        validate_receipt(value, **bindings)

    def refreshed_success(
        self,
        receipt: dict,
        install: dict,
        installed: dict,
        release: dict,
    ) -> dict:
        installed["service"] = copy.deepcopy(install["service"])
        install_bytes = encode(install)
        install_sha256 = hashlib.sha256(install_bytes).digest()
        installed["install_request_sha256"] = install_sha256
        release["install_request_sha256"] = install_sha256
        release["service_binding_sha256"] = hashlib.sha256(encode(install["service"])).digest()
        receipt["install_request_sha256"] = install_sha256
        receipt["result"]["installed_sha256"] = hashlib.sha256(encode(installed)).digest()
        receipt["result"]["release_sha256"] = hashlib.sha256(encode(release)).digest()
        return {
            **self.bindings,
            "install_request_cbor": install_bytes,
            "installed_cbor": encode(installed),
            "release_cbor": encode(release),
        }

    @staticmethod
    def replace_observation(receipt: dict, observation: dict) -> None:
        observation_bytes = encode(observation)
        receipt["result"]["observation_cbor"] = observation_bytes
        receipt["result"]["observation_sha256"] = hashlib.sha256(observation_bytes).digest()

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

    def test_coherent_launcher_session_substitution_is_rejected(self) -> None:
        install = vector("service-launcher-install")
        installed = vector("service-launcher-installed")
        release = vector("service-launcher-release")
        substituted_execution = bytes([0x91]) * 16
        for message in (install, installed, release):
            message["execution_id"] = substituted_execution
        install_bytes = encode(install)
        install_sha256 = hashlib.sha256(install_bytes).digest()
        installed["install_request_sha256"] = install_sha256
        release["install_request_sha256"] = install_sha256
        substituted = dict(self.bindings)
        substituted.update(
            {
                "install_request_cbor": install_bytes,
                "installed_cbor": encode(installed),
                "release_cbor": encode(release),
            }
        )
        with self.assertRaises(ContractError):
            validate_receipt(self.success, **substituted)

    def test_credentialed_launcher_transcript_is_accepted_and_bound(self) -> None:
        receipt = copy.deepcopy(self.success)
        install = vector("service-launcher-install")
        installed = vector("service-launcher-installed")
        release = vector("service-launcher-release")
        descriptor = {
            "id": "anthropic-test",
            "service": "api.anthropic.com",
            "environment": "API_KEY",
        }
        install["service"]["credential_source"] = descriptor
        install_bytes = encode(install)
        install_sha256 = hashlib.sha256(install_bytes).digest()
        service_sha256 = hashlib.sha256(encode(install["service"])).digest()
        installed["install_request_sha256"] = install_sha256
        installed["service"] = copy.deepcopy(install["service"])
        release["install_request_sha256"] = install_sha256
        release["service_binding_sha256"] = service_sha256
        release["credential_state"] = {
            "state": "released",
            "source_id": descriptor["id"],
            "environment": descriptor["environment"],
        }
        observation = decode_strict(receipt["result"]["observation_cbor"])
        observation["credential_source"] = descriptor
        observation_bytes = encode(observation)
        receipt["install_request_sha256"] = install_sha256
        receipt["result"]["installed_sha256"] = hashlib.sha256(encode(installed)).digest()
        receipt["result"]["release_sha256"] = hashlib.sha256(encode(release)).digest()
        receipt["result"]["observation_cbor"] = observation_bytes
        receipt["result"]["observation_sha256"] = hashlib.sha256(observation_bytes).digest()
        bindings = dict(self.bindings)
        bindings.update(
            {
                "install_request_cbor": install_bytes,
                "installed_cbor": encode(installed),
                "release_cbor": encode(release),
            }
        )
        validate_receipt(receipt, **bindings)

        missing = dict(bindings)
        changed_release = copy.deepcopy(release)
        changed_release["credential_state"]["source_id"] = "other-source"
        missing["release_cbor"] = encode(changed_release)
        with self.assertRaises(ContractError):
            validate_receipt(receipt, **missing)

    def test_failure_requires_exact_observed_launcher_prefix(self) -> None:
        early = copy.deepcopy(self.failure)
        self.validate(early)
        with self.assertRaises(ContractError):
            validate_receipt(early, **self.bindings)

        installed = copy.deepcopy(self.failure)
        installed["result"].update(
            {
                "phase": "ready",
                "reason": "launcher-release-failed",
                "boundary_state": "installed",
                "installed_sha256": self.installed_sha256,
                "release_sha256": None,
            }
        )
        installed["eligibility"]["reasons"] = ["network.launcher-release-failed"]
        self.validate(installed)
        premature = dict(self.bindings)
        premature["release_cbor"] = self.bindings["release_cbor"]
        with self.assertRaises(ContractError):
            validate_receipt(installed, **premature)

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
        add("nested-connector-closure-substitution", lambda value: mutate_nested(value, lambda nested: nested["connector"].__setitem__("runtime_closure_sha256", bytes(32))))
        add("nested-resolver-tcb-substitution", lambda value: mutate_nested(value, lambda nested: nested["dns"]["configuration"].__setitem__("sha256", bytes(32))))
        add("nested-tls-implementation-substitution", lambda value: mutate_nested(value, lambda nested: nested["tls"].__setitem__("implementation_sha256", bytes(32))))
        add("nested-trust-root-tcb-substitution", lambda value: mutate_nested(value, lambda nested: nested["tls"]["trust_root_set"].__setitem__("sha256", bytes(32))))
        add("nested-secret", lambda value: mutate_nested(value, lambda nested: nested.update({"credential_value": "canary-secret"})))

        for name, value in cases:
            with self.subTest(name=name), self.assertRaises(ContractError):
                self.validate(value)

    def test_launcher_to_observation_cross_bindings_are_causal(self) -> None:
        cases = {
            "connector generation": lambda service: service["connector"].__setitem__("process_generation", 2),
            "selected endpoint": lambda service: service.__setitem__(
                "selected_endpoint",
                {"family": "ipv6", "address": bytes.fromhex("20010db8000000000000000000000010"), "port": 443},
            ),
            "limits": lambda service: service["limits"].__setitem__("session_time_ms", 30_001),
            "channel descriptor": lambda service: service["channel"].__setitem__("child_descriptor", 6),
            "channel endpoint": lambda service: service["channel"].__setitem__("child_endpoint_id", bytes([0x62]) * 16),
        }
        for name, mutate in cases.items():
            receipt = copy.deepcopy(self.success)
            install = vector("service-launcher-install")
            installed = vector("service-launcher-installed")
            release = vector("service-launcher-release")
            mutate(install["service"])
            bindings = self.refreshed_success(receipt, install, installed, release)
            with self.subTest(name=name), self.assertRaisesRegex(ContractError, "inconsistent with the launcher"):
                validate_receipt(receipt, **bindings)

        receipt = copy.deepcopy(self.success)
        install = vector("service-launcher-install")
        installed = vector("service-launcher-installed")
        release = vector("service-launcher-release")
        descriptor = {"id": "anthropic-test", "service": "api.anthropic.com", "environment": "API_KEY"}
        install["service"]["credential_source"] = descriptor
        release["credential_state"] = {
            "state": "released",
            "source_id": descriptor["id"],
            "environment": descriptor["environment"],
        }
        bindings = self.refreshed_success(receipt, install, installed, release)
        with self.assertRaisesRegex(ContractError, "credential source is inconsistent with the launcher"):
            validate_receipt(receipt, **bindings)

    def test_observation_to_tcb_cross_bindings_are_causal(self) -> None:
        def executable(observation, service):
            identity = bytes([0x24]) * 32
            observation["connector"]["executable"]["sha256"] = identity
            service["connector"]["executable"]["sha256"] = identity

        def closure(observation, service):
            observation["connector"]["runtime_closure"][0]["sha256"] = bytes([0x25]) * 32
            identity = hashlib.sha256(encode(observation["connector"]["runtime_closure"])).digest()
            observation["connector"]["runtime_closure_sha256"] = identity
            service["connector"]["runtime_closure_sha256"] = identity

        def tls_implementation(observation, service):
            observation["tls"]["implementation_sha256"] = bytes([0x54]) * 32
            service["tls_observation_sha256"] = hashlib.sha256(encode(observation["tls"])).digest()

        def trust_roots(observation, service):
            observation["tls"]["trust_root_set"]["sha256"] = bytes([0x55]) * 32
            service["tls_observation_sha256"] = hashlib.sha256(encode(observation["tls"])).digest()

        cases = {
            "connector executable": executable,
            "connector closure": closure,
            "TLS implementation": tls_implementation,
            "TLS trust roots": trust_roots,
        }
        for name, mutate in cases.items():
            receipt = copy.deepcopy(self.success)
            observation = decode_strict(receipt["result"]["observation_cbor"])
            install = vector("service-launcher-install")
            installed = vector("service-launcher-installed")
            release = vector("service-launcher-release")
            mutate(observation, install["service"])
            self.replace_observation(receipt, observation)
            bindings = self.refreshed_success(receipt, install, installed, release)
            with self.subTest(name=name), self.assertRaisesRegex(ContractError, "trusted computing base identity is inconsistent"):
                validate_receipt(receipt, **bindings)

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
        add("clock-substitution", lambda value: value["result"].__setitem__("clock", "wall-clock"))
        add("execution-substitution", lambda value: value.__setitem__("execution_id", bytes(16)))
        add("plan-substitution", lambda value: value.__setitem__("plan_sha256", bytes(32)))
        add("policy-substitution", lambda value: value.__setitem__("policy_sha256", bytes(32)))
        add("service-substitution", lambda value: value["service"].__setitem__("name", "other.example"))
        add("early-installed-boundary", lambda value: value["result"].update({"boundary_state": "installed", "installed_sha256": self.installed_sha256}))
        add("uninstalled-identity", lambda value: value["result"].__setitem__("installed_sha256", bytes(32)))
        add("pre-release-identity", lambda value: value["result"].__setitem__("release_sha256", self.release_sha256))
        add("success-observation-on-failure", lambda value: value["result"].__setitem__("observation_sha256", bytes(32)))
        add("pre-release-child", lambda value: value["result"]["cleanup"].__setitem__("child", "reaped"))
        add("connector-loss", lambda value: value["result"]["cleanup"].__setitem__("connector", "not-started"))
        add("unreported-cleanup-failure", lambda value: value["result"]["cleanup"].__setitem__("channel", "cleanup-failed"))
        add("false-cleanup-reason", lambda value: value["result"].__setitem__("reason", "cleanup-failed"))

        def post_release_substitution(value):
            value["result"].update(
                {
                    "phase": "active",
                    "reason": "channel-lost",
                    "boundary_state": "installed",
                    "installed_sha256": self.installed_sha256,
                    "release_sha256": bytes(32),
                }
            )
            value["result"]["cleanup"]["child"] = "reaped"

        add("post-release-substitution", post_release_substitution)

        def post_release_child_not_started(value):
            value["result"].update(
                {
                    "phase": "active",
                    "reason": "channel-lost",
                    "boundary_state": "installed",
                    "installed_sha256": self.installed_sha256,
                    "release_sha256": self.release_sha256,
                }
            )
            value["eligibility"]["reasons"] = ["network.channel-lost"]

        add("post-release-child-not-started", post_release_child_not_started)

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
                if reason == "launcher-release-failed":
                    value["result"].update(
                        {
                            "boundary_state": "installed",
                            "installed_sha256": self.installed_sha256,
                        }
                    )
                if phase in {"active", "closing"}:
                    value["result"].update(
                        {
                            "boundary_state": "installed",
                            "installed_sha256": self.installed_sha256,
                            "release_sha256": self.release_sha256,
                        }
                    )
                    cleanup["child"] = "reaped"
                if phase in allowed:
                    with self.subTest(reason=reason, phase=phase, expected="accepted"):
                        self.validate(value)
                else:
                    with self.subTest(reason=reason, phase=phase, expected="rejected"), self.assertRaises(ContractError):
                        self.validate(value)

    def test_ready_release_failure_binds_an_installed_unreleased_boundary(self) -> None:
        value = copy.deepcopy(self.failure)
        value["result"].update(
            {
                "phase": "ready",
                "reason": "launcher-release-failed",
                "boundary_state": "installed",
                "installed_sha256": self.installed_sha256,
                "release_sha256": None,
            }
        )
        value["eligibility"]["reasons"] = ["network.launcher-release-failed"]
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
