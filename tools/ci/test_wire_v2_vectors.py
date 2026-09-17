import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.ci.deterministic_cbor import CborError, decode_strict, json_projection


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas"
VECTOR_ROOT = SCHEMA_ROOT / "vectors/v2"
WIRE_OBJECTS = {
    "execution-plan": ("proofbound-runtime-plan/2", 2),
    "compiled-policy": ("proofbound-runtime-linux-policy/2", 2),
    "run-result": ("proofbound-runtime-run-result/2", 2),
    "execution-receipt": ("proofbound-runtime-execution-receipt/2", 2),
    "composed-receipt": ("proofbound-runtime-composed-receipt/2", 2),
    "acceptance-policy": ("proofbound-runtime-acceptance-policy/1", 1),
    "acceptance-decision": ("proofbound-runtime-acceptance-decision/2", 2),
    "release-provenance": ("proofbound-runtime-release-provenance/2", 2),
}
ADDITIONAL_VECTORS = {
    "execution-plan-service-session": "proofbound-runtime-plan/2",
    "compiled-policy-service-session": "proofbound-runtime-linux-policy/2",
}


class WireV2GoldenVectorTests(unittest.TestCase):
    def test_vectors_are_strict_deterministic_cbor_with_expected_projection(
        self,
    ) -> None:
        vectors = {
            name: identity for name, (identity, _version) in WIRE_OBJECTS.items()
        }
        vectors.update(ADDITIONAL_VECTORS)
        for name, identity in vectors.items():
            with self.subTest(name=name):
                encoded = bytes.fromhex(
                    (VECTOR_ROOT / f"{name}.cbor.hex").read_text(encoding="ascii")
                )
                decoded = decode_strict(encoded)
                self.assertEqual(decoded["schema"], identity)
                expected = json.loads(
                    (VECTOR_ROOT / f"{name}.projection.json").read_text(
                        encoding="utf-8"
                    )
                )
                self.assertEqual(json_projection(decoded), expected)

    def test_decoder_rejects_every_forbidden_encoding_class(self) -> None:
        attacks = {
            "non-shortest integer": bytes.fromhex("1817"),
            "indefinite array": bytes.fromhex("9fff"),
            "integer map key": bytes.fromhex("a10000"),
            "out-of-order keys": bytes.fromhex("a2616200616100"),
            "duplicate key": bytes.fromhex("a2616100616101"),
            "trailing item": bytes.fromhex("0000"),
            "tag": bytes.fromhex("c000"),
            "floating point": bytes.fromhex("f90000"),
        }
        for name, encoded in attacks.items():
            with self.subTest(name=name):
                with self.assertRaises(CborError):
                    decode_strict(encoded)

    def test_cddl_roots_and_text_key_policy_are_explicit(self) -> None:
        for name, (_identity, version) in WIRE_OBJECTS.items():
            with self.subTest(name=name):
                cddl = (SCHEMA_ROOT / f"{name}-v{version}.cddl").read_text(
                    encoding="utf-8"
                )
                self.assertIn(f"{name}-v{version} = {{", cddl)
                self.assertNotRegex(cddl, r"(?m)^\s*[0-9]+\s*:")

    def test_maintained_plan_encoder_reproduces_the_golden_vector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.cbor"
            subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "tools/ci/encode_plan_v2.py"),
                    "--output",
                    str(output),
                    "--id",
                    "golden-v2",
                    "--executable",
                    "bin/hello",
                    "--working-directory",
                    ".",
                    "--write",
                    "out",
                    "--execute",
                    "bin/hello",
                    "--processes",
                    "2",
                    "--wall-time-ms",
                    "1000",
                    "--stdout-bytes",
                    "1024",
                    "--stderr-bytes",
                    "1024",
                    "--memory-bytes",
                    "65536",
                    "--swap-bytes",
                    "0",
                ],
                check=True,
            )
            expected = bytes.fromhex(
                (VECTOR_ROOT / "execution-plan.cbor.hex").read_text(encoding="ascii")
            )
            self.assertEqual(output.read_bytes(), expected)

    def test_maintained_plan_encoder_reproduces_the_service_session_vector(
        self,
    ) -> None:
        network = {
            "mode": "authenticated-service-session",
            "service": {"name": "api.anthropic.com", "port": 443},
            "resolver": {
                "address": {"family": "ipv4", "bytes": [1, 1, 1, 1]},
                "port": 53,
                "configuration": "/etc/proofbound/resolver.conf",
                "maximum_cname_depth": 8,
                "maximum_answer_count": 16,
                "maximum_response_bytes": 65_536,
                "resolution_deadline_ms": 5_000,
                "attempt_deadline_ms": 1_000,
                "address_order": "ipv4-then-ipv6-lexicographic",
            },
            "tls": {
                "trust_root_set": "/etc/ssl/certs/ca-certificates.crt",
                "minimum_version": "tls-1.3",
                "service_name_verification": "dns-san-exact",
                "revocation": "not-checked-recorded-assumption",
                "session_resumption": "deny",
                "early_data": "deny",
            },
            "limits": {
                "setup_time_ms": 10_000,
                "session_time_ms": 30_000,
                "child_to_service_bytes": 1_048_576,
                "service_to_child_bytes": 1_048_576,
                "dns_messages": 4,
                "endpoint_attempts": 4,
                "tls_handshake_bytes": 262_144,
            },
            "connector_executable": "/usr/libexec/proofbound-connector",
            "connector_runtime_read": ["/usr/lib"],
            "local_channel": {
                "protocol": "unix-stream-v1",
                "child_descriptor": 9,
            },
            "credential_source": {
                "id": "anthropic-test",
                "service": "api.anthropic.com",
                "environment": "API_KEY",
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "plan.cbor"
            subprocess.run(
                [
                    sys.executable,
                    str(REPOSITORY_ROOT / "tools/ci/encode_plan_v2.py"),
                    "--output",
                    str(output),
                    "--id",
                    "golden-v2",
                    "--executable",
                    "bin/hello",
                    "--working-directory",
                    ".",
                    "--write",
                    "out",
                    "--execute",
                    "bin/hello",
                    "--environment",
                    "API_KEY",
                    "--network-json",
                    json.dumps(network, separators=(",", ":")),
                    "--processes",
                    "2",
                    "--wall-time-ms",
                    "1000",
                    "--stdout-bytes",
                    "1024",
                    "--stderr-bytes",
                    "1024",
                    "--memory-bytes",
                    "65536",
                    "--swap-bytes",
                    "0",
                ],
                check=True,
            )
            expected = bytes.fromhex(
                (VECTOR_ROOT / "execution-plan-service-session.cbor.hex").read_text(
                    encoding="ascii"
                )
            )
            self.assertEqual(output.read_bytes(), expected)

    def test_service_policy_generator_reproduces_the_golden_vector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "policy.hex"
            projection = Path(directory) / "policy.json"
            subprocess.run(
                [
                    sys.executable,
                    str(
                        REPOSITORY_ROOT
                        / "tools/ci/generate_service_policy_v2_vector.py"
                    ),
                    "--plan",
                    str(VECTOR_ROOT / "execution-plan-service-session.cbor.hex"),
                    "--output",
                    str(output),
                    "--projection",
                    str(projection),
                ],
                cwd=REPOSITORY_ROOT,
                check=True,
            )
            self.assertEqual(
                output.read_bytes(),
                (VECTOR_ROOT / "compiled-policy-service-session.cbor.hex").read_bytes(),
            )
            self.assertEqual(
                projection.read_bytes(),
                (
                    VECTOR_ROOT / "compiled-policy-service-session.projection.json"
                ).read_bytes(),
            )
            decoded = decode_strict(bytes.fromhex(output.read_text(encoding="ascii")))
            self.assertEqual(decoded["network"], "deny-network-v1")
            self.assertEqual(decoded["child_network"], "channel-only-v1")
            self.assertEqual(
                decoded["service_session"]["mode"],
                "authenticated-service-session-v1",
            )


if __name__ == "__main__":
    unittest.main()
