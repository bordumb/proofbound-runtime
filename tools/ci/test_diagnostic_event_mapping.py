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
    map_resolution = implementation(mapping, "fn map_object_resolution(")
    map_selected = implementation(mapping, "fn map_selected_object(")
    map_selected_parts = implementation(mapping, "fn map_selected_parts(")
    map_candidate = implementation(mapping, "fn map_candidate_object(")
    map_candidate_parts = implementation(mapping, "fn map_candidate_parts(")
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
    for required in [
        "selected_object.as_ref()",
        "candidate.as_ref()",
        "map_object_resolution(selected_object, candidate)",
    ]:
        if required not in mapping:
            raise AssertionError(f"missing selected-object mapping term: {required}")
    for required in [
        "ObservationResolution::Unresolved",
        "ObservationResolution::KernelSelected",
        "String::from_utf8(path.to_vec())",
        "!is_normalized_absolute_path(&path)",
        'path.ends_with(" (deleted)")',
        "ObservedObjectIdentity::new(",
    ]:
        if required not in map_selected_parts:
            raise AssertionError(f"missing conservative resolution term: {required}")
    for required in [
        "String::from_utf8(path.to_vec())",
        "!is_normalized_absolute_path(&path)",
        'path.ends_with(" (deleted)")',
        "before != after",
        "ObservationResolution::StableCandidate",
    ]:
        if required not in map_candidate_parts:
            raise AssertionError(f"missing conservative candidate term: {required}")
    for required in [
        "TraceCandidateObservation::Stable",
        "TraceCandidateObservation::IdentityDrift",
        "TraceCandidateObservation::SymlinkLimit",
        "ObservationResolution::Unresolved",
    ]:
        if required not in map_resolution:
            raise AssertionError(f"missing candidate-resolution term: {required}")
    for required in [
        "ObservationResolution::StableCandidate",
        "candidate.object_before()",
        "candidate.object_after()",
        "candidate.symlink_hops()",
    ]:
        if required not in mapping:
            raise AssertionError(f"missing candidate mapping term: {required}")
    if "map_candidate_parts(" not in map_candidate:
        raise AssertionError("candidate mapping must use the conservative parts mapper")
    for forbidden in ["unsafe", "from_utf8_lossy", "payload.clone()"]:
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
    "map": "9292cc83fd66379a9aef0aa0b7dc16c307749dc4b1194f14ec9dcc08e3335661",
    "map-architecture": "ba1f1c66f0198f7609d47576f86b6b6ddc764eb26a5220249db9de184dcf0fd0",
    "map-class": "e150fb281d68b0250f2c6fff2d5900da2055ee47276dd72e890d01d16307a35b",
    "map-operands": "fefb34a5dc82081c8068ddb3aeece12c65342c745a689ff11f8428b2438ab4bd",
    "map-outcome": "645dda6c1e900ad8c4235e13ec0cde9b22dd8f164210cf9f46bd0915554a26eb",
    "map-parts": "a67d40aa0b66342ef7978c342f303dcfa593c89956845f5c74cae117eea08205",
    "map-object-resolution": "7fa99b1fc4a1e3ce52cc788020305c2513814a0e7a8c22a0d47901758717fb5c",
    "map-candidate-object": "e14fdd1d36d7af318d886f742c769df2bc5ffb530448cf9a5980c48006243f61",
    "map-candidate-parts": "a54d5f175dda6ecc269a62c73a1fc96b3a4c4e29069153b10dd48f4c97fa8948",
    "map-selected-object": "4ed6700c2c0e7dda1b86344c8559201147109b09d374412d28490ff5fcf29a11",
    "map-selected-parts": "5c34446ad2bce89317af19098521ce48ea49e11b9cb0b3f0326f3260b9552352",
    "normalized-path": "8dd9fc40ce325d6210ab52dc5129403c99541f94b38ef3f85226bad548723ebd",
    "socket-family": "bffe838f3e4eb69b1a34aa55f705f5da8719e1b527d19411093be8de6c074e9d",
}
EXPECTED_FILES = {
    "artifact": "bb353a2c06312a034bfba7ed687430e102284f05495fee58df3ee88acc056bee",
    "claim": "b98715b1db470d5a5f1651b90a67c77f33a1e93ca3a002ec096f6d3f6b36bb1e",
    "contract-evidence": "84852872175ba02a3c936e52f4513f2ff04a0229b4b83f57b90870f5a0d26097",
    "core-diagnostic": "e0a3f1e3204c5dc5b3b152e6432737e90bf5af93f5024a4e6f1d1c25a4f42918",
    "core-lib": "2039d8c789844cddaaabbf432a0a6ef465f77300577f3b57922d7bcbcc930450",
    "core-manifest": "0d22823a1d4f397fb58693c7d9fe7498969ce242b5da0f372d8cc8f55f960b9b",
    "core-receipt": "fc27edf189014a49af8af380902fe90b12cbbd71a2b49301064b589c8a4c4024",
    "decode-assumption": "0a71deec98c2cb281170fe85d911eb6dba5947161e8130554b5b922f47457847",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "lib": "8859f99339377b7034d43dd9d4fd20713824b5ad2708cd52d76412272a3858e2",
    "linux-lib": "10dddcf330422289b7ab1f5ac5ee9574ce63ea9c29ac86fa1ba1f1909eff6c2a",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "lock": "5fb7c8b16c4b865630a8e7e80f16919d443c3c276970959cd80ab26581229640",
    "map-assumption": "e787e8a57b35b174462b2a960a7a91be63e2f2d83da569ecdb1beb26d94b28bd",
    "manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "mapping": "1375b3cbcc94a9f1b845eb4ef7f77101696e272e586b09502f2f20f360092551",
    "root-manifest": "8cd67ea78720c5637340140ac6ea94a9d76ddeaf4fb0df40881c4e8dab371466",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "0090c6b187659bde2431775f3c89008d837c324f9242bdb3cb0793c22072f197",
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
                "!is_normalized_absolute_path(&path)",
                "false",
                1,
            ),
            self.mapping.replace(' || path.ends_with(" (deleted)")', "", 1),
            self.mapping.replace(
                "ObservationResolution::KernelSelected",
                "ObservationResolution::StableCandidate",
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
            "map-object-resolution": implementation(
                self.mapping, "fn map_object_resolution("
            ),
            "map-candidate-object": implementation(
                self.mapping, "fn map_candidate_object("
            ),
            "map-candidate-parts": implementation(
                self.mapping, "fn map_candidate_parts("
            ),
            "map-selected-object": implementation(
                self.mapping, "fn map_selected_object("
            ),
            "map-selected-parts": implementation(
                self.mapping, "fn map_selected_parts("
            ),
            "normalized-path": implementation(
                self.mapping, "fn is_normalized_absolute_path("
            ),
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
