import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MAPPING = ROOT / "crates/proofbound-runtime-diagnose-linux/src/mapping.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
ARTIFACT = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"
LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
CLAIM = ROOT / "claims/PBR-OBSERVER-026.toml"
UNIT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-event-mapping.toml"
CONTRACT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-event-mapping-contract.toml"


def implementation(source: str, signature: str) -> str:
    start = source.find(signature)
    if start == -1:
        raise AssertionError(f"missing implementation: {signature}")
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
    raise AssertionError(f"unterminated implementation: {signature}")


def assert_mapping_contract(mapping: str, trace: str, artifact: str) -> None:
    map_event = implementation(mapping, "pub fn map(")
    map_parts = implementation(mapping, "fn map_parts(")
    map_operands = implementation(mapping, "fn map_operands(")
    map_outcome = implementation(mapping, "fn map_outcome(")
    map_architecture = implementation(mapping, "const fn map_architecture(")
    map_class = implementation(mapping, "const fn map_class(")
    socket_family = implementation(mapping, "fn socket_address_family(")

    for event_form in [
        "ActiveTraceEvent::SyscallCompleted",
        "ActiveTraceEvent::ProcessCreated",
        "ActiveTraceEvent::ImageReplaced",
        "ActiveTraceEvent::ProcessExited",
        "ActiveTraceEvent::UnexpectedStop",
    ]:
        if event_form not in map_event:
            raise AssertionError(f"missing closed trace event form: {event_form}")
    for required in [
        "invocation.architecture()",
        "invocation.class()",
        "invocation.operands()",
        "checked_add(1)",
        "Execve | TraceSyscallClass::Execveat",
    ]:
        if required not in mapping:
            raise AssertionError(f"missing event mapping term: {required}")
    if "ObservationResolution::Unresolved" not in map_parts:
        raise AssertionError("mapped trace events must not invent object resolution")
    for forbidden in [
        "ObservationResolution::KernelSelected",
        "ObservationResolution::StableCandidate",
        "unsafe",
        "from_utf8_lossy",
        "payload.clone()",
    ]:
        if forbidden in mapping:
            raise AssertionError(f"forbidden mapping term: {forbidden}")
    if "String::from_utf8(path.clone())" not in map_operands:
        raise AssertionError("path conversion must reject invalid UTF-8")
    if "bytes.clone()" not in map_operands or "payload_bytes: *payload_bytes" not in map_operands:
        raise AssertionError("socket mapping must retain address and length without payload bytes")
    for required in ["checked_neg()", "MAX_LINUX_ERRNO", "u64::try_from(result)"]:
        if required not in map_outcome:
            raise AssertionError(f"missing outcome validation: {required}")
    if mapping.count("const MAX_LINUX_ERRNO: u32 = 4095;") != 1:
        raise AssertionError("Linux error range is not closed")
    for constant in [
        "const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;",
        "const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;",
    ]:
        if mapping.count(constant) != 1 or trace.count(constant) != 1:
            raise AssertionError(f"architecture identity mismatch: {constant}")
    for source, target in [
        ("Bind", "Bind"),
        ("Clone", "Clone"),
        ("Connect", "Connect"),
        ("Creat", "Creat"),
        ("Execve", "Execve"),
        ("Execveat", "Execveat"),
        ("Fork", "Fork"),
        ("Newfstatat", "Newfstatat"),
        ("Open", "Open"),
        ("Openat", "Openat"),
        ("Openat2", "Openat2"),
        ("Readlink", "Readlink"),
        ("Readlinkat", "Readlinkat"),
        ("Sendto", "Sendto"),
        ("Socket", "Socket"),
        ("Statx", "Statx"),
        ("Vfork", "Vfork"),
    ]:
        term = f"TraceSyscallClass::{source} => DiagnosticEventClass::{target}"
        if map_class.count(term) != 1:
            raise AssertionError(f"missing exact class mapping: {term}")
    for family in ["Unix", "Inet", "Inet6", "Netlink", "Other"]:
        if f"SocketAddressFamily::{family}" not in socket_family:
            raise AssertionError(f"missing socket family mapping: {family}")
    if "pub enum DiagnosticEvent" not in artifact:
        raise AssertionError("closed artifact event type is absent")
    if "pub enum ActiveTraceEvent" not in trace:
        raise AssertionError("closed trace event type is absent")


EXPECTED_BODIES = {
    "map": "adf5d35f39347534fc2901469a569dd13e5086735111e8af7f74996e108b8055",
    "map-architecture": "ba1f1c66f0198f7609d47576f86b6b6ddc764eb26a5220249db9de184dcf0fd0",
    "map-class": "e150fb281d68b0250f2c6fff2d5900da2055ee47276dd72e890d01d16307a35b",
    "map-operands": "e3210d830927931fcde6ba91e39bc14d32b0c14530d4a479ed4e2745049dad4f",
    "map-outcome": "645dda6c1e900ad8c4235e13ec0cde9b22dd8f164210cf9f46bd0915554a26eb",
    "map-parts": "5d517272ea0c187fa28d48d26a03d089367833b5c07253d1a3af5d10a83cf8ec",
    "socket-family": "bffe838f3e4eb69b1a34aa55f705f5da8719e1b527d19411093be8de6c074e9d",
}
EXPECTED_FILES = {
    "claim": "e3a324ce603ca6440d21d569c1fb805d24de20f1191a25758278c818f4cc0f4c",
    "contract-evidence": "d8baa4d7b672b2b570fbf09b42de432c853f7659557a9387c84a1e4d09a04ae7",
    "lib": "0d660b53e0ebf49bf0a817d9a7dcf7e88bdd7eeb0a522c646bb0de6d5ae723ce",
    "manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "mapping": "ea3c2765a503708ad4a695224027099db1b9e1cb3ca2a2b3f80e4fcd0c9e87c4",
    "unit-evidence": "1a046691b447830c74dcf77cb9b41d10e09a6b8e2e400744727ca05abb04c5e4",
}


class DiagnosticEventMappingContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mapping = MAPPING.read_text()
        self.trace = TRACE.read_text()
        self.artifact = ARTIFACT.read_text()

    def test_mapping_contract(self) -> None:
        assert_mapping_contract(self.mapping, self.trace, self.artifact)

    def test_mapping_mutations_are_rejected(self) -> None:
        mutations = [
            self.mapping.replace(
                "ObservationResolution::Unresolved",
                "ObservationResolution::KernelSelected",
                1,
            ),
            self.mapping.replace("checked_add(1)", "wrapping_add(1)", 1),
            self.mapping.replace("String::from_utf8(path.clone())", "String::from_utf8_lossy(path)", 1),
            self.mapping.replace("MAX_LINUX_ERRNO", "65_535", 1),
            self.mapping.replace(
                "TraceSyscallClass::Bind => DiagnosticEventClass::Bind,", "", 1
            ),
            self.mapping.replace("bytes.clone()", "Vec::new()", 1),
            self.mapping.replace(
                "TraceSyscallClass::Execve | TraceSyscallClass::Execveat",
                "TraceSyscallClass::Execve",
                1,
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=hashlib.sha256(mutation.encode()).hexdigest()[:12]):
                with self.assertRaises(AssertionError):
                    assert_mapping_contract(mutation, self.trace, self.artifact)

    def test_exact_load_bearing_source(self) -> None:
        bodies = {
            "map": implementation(self.mapping, "pub fn map("),
            "map-architecture": implementation(self.mapping, "const fn map_architecture("),
            "map-class": implementation(self.mapping, "const fn map_class("),
            "map-operands": implementation(self.mapping, "fn map_operands("),
            "map-outcome": implementation(self.mapping, "fn map_outcome("),
            "map-parts": implementation(self.mapping, "fn map_parts("),
            "socket-family": implementation(self.mapping, "fn socket_address_family("),
        }
        actual_bodies = {
            name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()
        }
        self.assertEqual(actual_bodies, EXPECTED_BODIES)

        files = {
            "claim": CLAIM,
            "contract-evidence": CONTRACT_EVIDENCE,
            "lib": LIB,
            "manifest": MANIFEST,
            "mapping": MAPPING,
            "unit-evidence": UNIT_EVIDENCE,
        }
        actual_files = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in files.items()
        }
        self.assertEqual(actual_files, EXPECTED_FILES)

    def test_public_export_and_dependency_are_explicit(self) -> None:
        lib = LIB.read_text()
        manifest = MANIFEST.read_text()
        self.assertEqual(lib.count("mod mapping;"), 1)
        self.assertEqual(
            lib.count("pub use mapping::{DiagnosticEventMapError, DiagnosticEventMapper};"),
            1,
        )
        self.assertEqual(manifest.count("proofbound-runtime-core.workspace = true"), 1)
        self.assertNotRegex(manifest, re.compile(r"(?m)^default\s*=.*diagnostic"))


if __name__ == "__main__":
    unittest.main()
