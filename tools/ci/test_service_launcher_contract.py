import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.ci.deterministic_cbor import decode_strict, json_projection
from tools.ci.encode_plan_v2 import encode
from tools.ci.service_launcher_contract import (
    ContractError,
    validate_retained_transcript,
    validate_transcript,
)


ROOT = Path(__file__).resolve().parents[2]
VECTOR_ROOT = ROOT / "schemas/vectors/v2"


def vector(name: str) -> dict:
    return decode_strict(bytes.fromhex((VECTOR_ROOT / f"service-launcher-{name}.cbor.hex").read_text(encoding="ascii")))


def refresh_bindings(request: dict, installed: dict, release: dict, credential: dict | None = None) -> None:
    installed["service"] = copy.deepcopy(request["service"])
    service_identity = hashlib.sha256(encode(request["service"])).digest()
    install_identity = hashlib.sha256(encode(request)).digest()
    installed["install_request_sha256"] = install_identity
    release["install_request_sha256"] = install_identity
    release["service_binding_sha256"] = service_identity
    if credential is not None:
        credential["install_request_sha256"] = install_identity
        credential["service_binding_sha256"] = service_identity


class ServiceLauncherContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = vector("install")
        self.installed = vector("installed")
        self.release = vector("release")

    def test_canonical_handshake_is_complete_and_valid(self) -> None:
        validate_transcript([self.request, self.installed, self.release])
        for name, value in (("install", self.request), ("installed", self.installed), ("release", self.release)):
            expected = json.loads((VECTOR_ROOT / f"service-launcher-{name}.projection.json").read_text(encoding="utf-8"))
            self.assertEqual(json_projection(value), expected)

    def test_retained_prefix_accepts_only_observed_forward_progress(self) -> None:
        validate_retained_transcript([self.request])
        validate_retained_transcript([self.request, self.installed])
        validate_retained_transcript([self.request, self.installed, self.release])
        with self.assertRaises(ContractError):
            validate_retained_transcript([self.request, self.release])

    def test_generator_reproduces_all_vectors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            subprocess.run(
                [sys.executable, str(ROOT / "tools/ci/generate_service_launcher_v1_vectors.py"), "--directory", str(output)],
                cwd=ROOT,
                check=True,
            )
            for name in ("install", "installed", "release"):
                for suffix in ("cbor.hex", "projection.json"):
                    self.assertEqual(
                        (output / f"service-launcher-{name}.{suffix}").read_bytes(),
                        (VECTOR_ROOT / f"service-launcher-{name}.{suffix}").read_bytes(),
                    )

    def test_registered_binding_mutations_are_rejected(self) -> None:
        cases = []

        def add(name, mutate):
            request = copy.deepcopy(self.request)
            installed = copy.deepcopy(self.installed)
            release = copy.deepcopy(self.release)
            mutate(request, installed, release)
            cases.append((name, request, installed, release))

        def overlap_descriptor(request, installed, release):
            request["service"]["channel"]["child_descriptor"] = request["executable_fd"]
            refresh_bindings(request, installed, release)

        def move_descriptor_into_close_range(request, installed, release):
            request["close_file_descriptors_from"] = 9
            refresh_bindings(request, installed, release)

        add("unknown-request-field", lambda request, _installed, _release: request.update({"network": "ambient"}))
        add("execution-substitution", lambda _request, installed, _release: installed.__setitem__("execution_id", bytes(16)))
        add("policy-substitution", lambda _request, _installed, release: release.__setitem__("policy_sha256", bytes(32)))
        add("cgroup-substitution", lambda _request, installed, _release: installed["cgroup"].__setitem__("inode", 74))
        add("connector-generation-substitution", lambda _request, installed, _release: installed["service"]["connector"].__setitem__("process_generation", 2))
        add("connector-closure-substitution", lambda _request, installed, _release: installed["service"]["connector"].__setitem__("runtime_closure_sha256", bytes(32)))
        add("dns-observation-substitution", lambda _request, installed, _release: installed["service"].__setitem__("dns_observation_sha256", bytes(32)))
        add("tls-observation-substitution", lambda _request, installed, _release: installed["service"].__setitem__("tls_observation_sha256", bytes(32)))
        add("selected-endpoint-substitution", lambda _request, installed, _release: installed["service"]["selected_endpoint"].__setitem__("address", bytes([203, 0, 113, 9])))
        add("service-substitution", lambda _request, installed, _release: installed["service"]["service"].__setitem__("name", "example.com"))
        add("channel-endpoint-alias", lambda request, _installed, _release: request["service"]["channel"].__setitem__("child_endpoint_id", request["service"]["channel"]["connector_endpoint_id"]))
        add("descriptor-overlap", overlap_descriptor)
        add("descriptor-in-close-range", move_descriptor_into_close_range)
        add("executable-rule-omission", lambda request, _installed, _release: request["filesystem"].pop(0))
        add("filesystem-order-substitution", lambda request, _installed, _release: request["filesystem"].reverse())
        add("limit-substitution", lambda _request, installed, _release: installed["service"]["limits"].__setitem__("session_time_ms", 30_001))
        add("argument-nul", lambda request, _installed, _release: request["arguments"].__setitem__(0, "bin/client\0substitute"))
        add("filter-substitution", lambda request, _installed, _release: request.__setitem__("seccomp_program", bytes([0x82]) * 64))
        add("binding-digest-substitution", lambda _request, _installed, release: release.__setitem__("service_binding_sha256", bytes(32)))
        add("retained-secret", lambda request, _installed, _release: request["service"].update({"credential_value": "canary"}))

        for name, request, installed, release in cases:
            with self.subTest(name=name):
                with self.assertRaises(ContractError):
                    validate_transcript([request, installed, release])

    def test_release_identity_is_canonical_service_binding_digest(self) -> None:
        self.assertEqual(
            self.release["service_binding_sha256"],
            hashlib.sha256(encode(self.request["service"])).digest(),
        )

    def test_declared_credential_is_released_only_after_installed_ack(self) -> None:
        request = copy.deepcopy(self.request)
        installed = copy.deepcopy(self.installed)
        release = copy.deepcopy(self.release)
        descriptor = {
            "id": "anthropic-test",
            "service": "api.anthropic.com",
            "environment": "API_KEY",
        }
        request["service"]["credential_source"] = descriptor
        binding_identity = hashlib.sha256(encode(request["service"])).digest()
        release["credential_state"] = {
            "state": "released",
            "source_id": descriptor["id"],
            "environment": descriptor["environment"],
        }
        transient = {
            "schema": "proofbound-runtime-service-launcher-credential-release/1",
            "execution_id": request["execution_id"],
            "policy_sha256": request["policy_sha256"],
            "cgroup": copy.deepcopy(request["cgroup"]),
            "install_request_sha256": hashlib.sha256(encode(request)).digest(),
            "service_binding_sha256": binding_identity,
            "source_id": descriptor["id"],
            "environment": descriptor["environment"],
            "value": bytes(range(1, 33)),
        }
        refresh_bindings(request, installed, release, transient)
        validate_transcript([request, installed, transient, release])

        early = copy.deepcopy(request)
        early_installed = copy.deepcopy(installed)
        early_release = copy.deepcopy(release)
        early_transient = copy.deepcopy(transient)
        early["environment"][descriptor["environment"]] = "x"
        refresh_bindings(early, early_installed, early_release, early_transient)
        with self.assertRaises(ContractError):
            validate_transcript([early, early_installed, early_transient, early_release])

        substituted = copy.deepcopy(transient)
        substituted["source_id"] = "other-source"
        with self.assertRaises(ContractError):
            validate_transcript([request, installed, substituted, release])

        order_mutations = {
            "credential-before-installed": [request, transient, installed, release],
            "release-before-credential": [request, installed, release, transient],
            "installed-duplicated": [request, installed, installed, transient, release],
            "installed-skipped": [request, transient, release],
        }
        for name, transcript in order_mutations.items():
            with self.subTest(name=name):
                with self.assertRaises(ContractError):
                    validate_transcript(transcript)

    def test_complete_install_request_and_whole_frame_are_bound(self) -> None:
        installed = copy.deepcopy(self.installed)
        release = copy.deepcopy(self.release)
        request = copy.deepcopy(self.request)
        request["arguments"].append("")
        with self.assertRaises(ContractError):
            validate_transcript([request, installed, release])

        oversized = copy.deepcopy(self.request)
        oversized["seccomp_program"] = bytes(1_048_576)
        with self.assertRaises(ContractError):
            validate_transcript([oversized, self.installed, self.release])

        oversized_text = copy.deepcopy(self.request)
        oversized_text["arguments"].append("x" * 1_048_576)
        with self.assertRaises(ContractError):
            validate_transcript([oversized_text, self.installed, self.release])

    def test_empty_argument_and_non_shell_environment_name_match_current_domain(self) -> None:
        request = copy.deepcopy(self.request)
        installed = copy.deepcopy(self.installed)
        release = copy.deepcopy(self.release)
        request["arguments"].append("")
        request["environment"]["X-NAME"] = ""
        refresh_bindings(request, installed, release)
        validate_transcript([request, installed, release])


if __name__ == "__main__":
    unittest.main()
