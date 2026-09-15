import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
DECODE_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-DECODE-AX-017.toml"
MAP_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-MAP-CHECK-AX-019.toml"
MAPPING = ROOT / "crates/proofbound-runtime-diagnose-linux/src/mapping.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
ARTIFACT = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"
LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
CORE_MANIFEST = ROOT / "crates/proofbound-runtime-core/Cargo.toml"
CORE_DIAGNOSTIC = ROOT / "crates/proofbound-runtime-core/src/diagnostic.rs"
CORE_LIB = ROOT / "crates/proofbound-runtime-core/src/lib.rs"
CORE_RECEIPT = ROOT / "crates/proofbound-runtime-core/src/receipt.rs"
DIAGNOSE_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose/Cargo.toml"
DIAGNOSE_LIB = ROOT / "crates/proofbound-runtime-diagnose/src/lib.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
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
    if (
        "bytes.clone()" not in map_operands
        or "payload_bytes: *payload_bytes" not in map_operands
    ):
        raise AssertionError(
            "socket mapping must retain address and length without payload bytes"
        )
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
        ("AUDIT_ARCH_X86_64", "Architecture::X86_64"),
        ("AUDIT_ARCH_AARCH64", "Architecture::Aarch64"),
    ]:
        term = f"{source} => Ok({target})"
        if map_architecture.count(term) != 1:
            raise AssertionError(f"missing exact architecture mapping: {term}")
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
    "artifact": "ad7cce45d286623dcfd55c21189cb7d58e29f1943960d0a061d6f85c2640baa3",
    "claim": "ad703e8f87b620838974f7a1f8530b2ca1d37b18a22423b7d2820a2a702a0205",
    "contract-evidence": "84852872175ba02a3c936e52f4513f2ff04a0229b4b83f57b90870f5a0d26097",
    "core-diagnostic": "e0a3f1e3204c5dc5b3b152e6432737e90bf5af93f5024a4e6f1d1c25a4f42918",
    "core-lib": "2039d8c789844cddaaabbf432a0a6ef465f77300577f3b57922d7bcbcc930450",
    "core-manifest": "0d22823a1d4f397fb58693c7d9fe7498969ce242b5da0f372d8cc8f55f960b9b",
    "core-receipt": "fc27edf189014a49af8af380902fe90b12cbbd71a2b49301064b589c8a4c4024",
    "decode-assumption": "0a71deec98c2cb281170fe85d911eb6dba5947161e8130554b5b922f47457847",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "lib": "967270aa9c886b9ead6c80fbeae2c44fce868aa36fbb0c5d6071c77c2fa6ca16",
    "linux-lib": "a1d7d31fb602afd59aab41aa4153fa2a6fcc0923518118bf956e5939f29c97a8",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "lock": "376572c5d111f5ea72e38667b5813a7c051e9fa128d5af355468e5294889a0c6",
    "map-assumption": "e787e8a57b35b174462b2a960a7a91be63e2f2d83da569ecdb1beb26d94b28bd",
    "manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "mapping": "ea3c2765a503708ad4a695224027099db1b9e1cb3ca2a2b3f80e4fcd0c9e87c4",
    "root-manifest": "1ea75287f62129c6b15038b0c45df42e616fc4c92e59e61bc03358746fd5d7d6",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "f490dd4398cff760aef70d1f305f4f98a26663b282cf45a86fab78f185b3df27",
    "unit-evidence": "c1628a6afa1a191c17c71debd3a8e4f224e31e406f6c280b5ccb1e03371bfa92",
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
            self.mapping.replace(
                "String::from_utf8(path.clone())", "String::from_utf8_lossy(path)", 1
            ),
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
            with self.subTest(
                mutation=hashlib.sha256(mutation.encode()).hexdigest()[:12]
            ):
                with self.assertRaises(AssertionError):
                    assert_mapping_contract(mutation, self.trace, self.artifact)

    def test_exact_load_bearing_source(self) -> None:
        bodies = {
            "map": implementation(self.mapping, "pub fn map("),
            "map-architecture": implementation(
                self.mapping, "const fn map_architecture("
            ),
            "map-class": implementation(self.mapping, "const fn map_class("),
            "map-operands": implementation(self.mapping, "fn map_operands("),
            "map-outcome": implementation(self.mapping, "fn map_outcome("),
            "map-parts": implementation(self.mapping, "fn map_parts("),
            "socket-family": implementation(self.mapping, "fn socket_address_family("),
        }
        actual_bodies = {
            name: hashlib.sha256(body.encode()).hexdigest()
            for name, body in bodies.items()
        }
        self.assertEqual(actual_bodies, EXPECTED_BODIES)

        files = {
            "artifact": ARTIFACT,
            "claim": CLAIM,
            "contract-evidence": CONTRACT_EVIDENCE,
            "core-diagnostic": CORE_DIAGNOSTIC,
            "core-lib": CORE_LIB,
            "core-manifest": CORE_MANIFEST,
            "core-receipt": CORE_RECEIPT,
            "decode-assumption": DECODE_ASSUMPTION,
            "diagnose-lib": DIAGNOSE_LIB,
            "diagnose-manifest": DIAGNOSE_MANIFEST,
            "lib": LIB,
            "linux-lib": LINUX_LIB,
            "linux-manifest": LINUX_MANIFEST,
            "lock": LOCK,
            "map-assumption": MAP_ASSUMPTION,
            "manifest": MANIFEST,
            "mapping": MAPPING,
            "root-manifest": ROOT_MANIFEST,
            "toolchain": TOOLCHAIN,
            "trace": TRACE,
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
            lib.count(
                "pub use mapping::{DiagnosticEventMapError, DiagnosticEventMapper};"
            ),
            1,
        )
        self.assertEqual(manifest.count("proofbound-runtime-core.workspace = true"), 1)
        self.assertNotRegex(manifest, re.compile(r"(?m)^default\s*=.*diagnostic"))


if __name__ == "__main__":
    unittest.main()
