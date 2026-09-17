import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
LOCK = ROOT / "Cargo.lock"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
ADAPTER = ROOT / "crates/proofbound-runtime-diagnose-linux/src/adapter.rs"
OBSERVER = ROOT / "crates/proofbound-runtime-diagnose/src/observer.rs"
ARTIFACT = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
DIAGNOSE_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose/Cargo.toml"
DIAGNOSE_LIB = ROOT / "crates/proofbound-runtime-diagnose/src/lib.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
DIAGNOSE_LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
DIAGNOSE_LINUX_LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
CLAIM = ROOT / "claims/PBR-OBSERVER-025.toml"
DECODER_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-syscall-decoder-contract.toml"
ADAPTER_EVIDENCE = (
    ROOT / "proofbound/evidence/diagnostic-observer-adapter-contract.toml"
)
ADAPTER_COMPILE_EVIDENCE = (
    ROOT / "proofbound/evidence/diagnostic-syscall-decoder-adapter.toml"
)


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


def body_sha256(source: str, signature: str) -> str:
    return hashlib.sha256(implementation(source, signature).encode()).hexdigest()


EXPECTED_LOAD_BEARING_BODIES = {
    "adapter-release": "183231f22a22fa4e71f9c7cea064811e5dec2f10b409c3a26b9ce5f1b0124066",
    "adapter-next-event": "98e8b121729094ec65ba7fedb38da6c11e3dc6c3666e9c529cfc2d01a1647825",
    "aarch64-table": "45fe041bd934a083c660e316a30c289c5d2ce3d1b3dcf1d2ce430cd30b0b9c11",
    "capture": "e03c8d8f690304b9865ea829f026da17babea4c3175f8aff81b0a8c472a1dd48",
    "capture-path-limit-accessor": "e21f1d9a95771bd5e2a3c7d36ed6bfe6879d2d2c9ab17433a40cf5e15e94ce5a",
    "capture-socket-limit-accessor": "6d26b9a042b9d673d7d97730366d4930038c522e7cc625b8aab3292015421dc6",
    "capture-string-limit-accessor": "163cf7392109e73f6f014975fadce6ade1ba70c8e62b11163bb7f0bc0170da68",
    "capture-symlink-limit-accessor": "328d8e75f0e0aff13b043e0fa3a0ffcf3d1d2b88c67c281d03d672423b8daeef",
    "entry-order": "3696e132089f0f39cb9d644b76f88de8856893857cb19f2cc978a689dba04a22",
    "exact-read": "4e4099b351e973ff312431159f64eac771b748820e5ec2d06daaaf6816efa452",
    "i32-argument": "48640c1efe3c88ce6281053cbc2385160faa326f92713f81c2874fe6210a243c",
    "little-endian-reader": "8669e2dac5832ba4dd7eb1708f3992af050868ab67fd791661c005957203cadd",
    "limits": "9d66b90c935331d4d530c9b8be79318f18c2439be6e7ee61e96dbf41801b26fb",
    "observation-bounds-validate": "2d67ca521bfc51fc0c9bd674d8f2e0ffcb4abdd272136c487fd161bb9cc3bc17",
    "observer-protocol-new": "dd85162d9b12bbbe1f0a17b5a08a8ecb083f5b3ace9e2cde59805d9e3dbeb685",
    "path-limit": "a1f57b2d41134fd23d07262bec9cb74cc859e9386675809369068105b04e7623",
    "prepare-observer": "87249591d00f744461a37375f91c44dc1171520b284a61173c05d465cfac0b11",
    "prepared-observer-spawn": "c38122828f9b03054a7ac29ab4b5d2a3f26bf6e6d6261315da1be5273fdcbf56",
    "raw-syscall-info-layout": "f8cdd24d2d33c79a783ddda369d93ede67a96849b1fcef460487b2cf08b75399",
    "raw-read": "0330210e9d4092a932240580c2f161a42374ac625cc28c89510f7a13ca44b5be",
    "router": "5d7181dc73c1a5f99ee30e5787fdf27dede851ba882fd989a451ea91b9a03b66",
    "socket-address-read": "8622490a7207ba8b4e29f75c66994d39f411b15b102986b4077c9be1acb52fb6",
    "socket-limit": "5abf245a10ffd0ce08305686d98acb204459c3a1a853a6dc854a578a26de6e65",
    "string-limit": "a839a837690914354efd25be3073c3ad8c1e21491d274004f54cb4464317eb3a",
    "symlink-limit": "285ed72730f288991502539ef54872d3baa8755b4ca718462387db107c0ad1f7",
    "supported-families": "928ac43d5c23a7e3bcbd24edf3d895597a55aa7a855ca4e2fdb8cfea4fa94f88",
    "syscall-info-fetch": "0b5e52f129fc45db01bd022959e42237ae68f7c44aff9f0b483a278546bb8084",
    "syscall-info-parser": "796f463adb9db22ebf211f25ff7d0097f86ab49f9d240a62319161dc3f91af5e",
    "tracee-string-read": "54fec5ee2c46ba8bd614c0da4e769b311ca6ff65637e7685be6e086369f7189c",
    "resume-before-deadline": "bff9c1e06b805663e587a4dd5a5313bb7e04a6aceeb68aa017e4c09a4953f502",
    "trace-next-event": "d338650ed48b9e795519e78b67f2b23052c42f5d09de1c2fe76f019688d98efb",
    "trace-ready-release": "4ca785fc73104cd6bfa3f6941ad4ae3f748d62d1b48cf77c4424b7f1881e3df7",
    "uapi-i64-reader": "62197020cc4c5b8faac0c4f44c81291f12e7986681a3e7c08080ef7be4e0f938",
    "uapi-u64-reader": "aa2b02fd921a14e0fb178214da9ea0183bddde4b7d5d3b2305cffe9abe5ca63e",
    "wait-observation-router": "a185c9d1ffac7131bc194c6e1d6a70eb7bce5bb2235d16bce0538808f2d51050",
    "u32-argument": "9a611e944f835a154c65dc1745c111c20a12d97323954af68e80fee6e74d391e",
    "x86-64-table": "64ecbc45be34c91cbbd7e12bbfb1bab005186d0b4cbbd47554a8fd2a9af16dcc",
}


EXPECTED_CLOSURE_FILES = {
    "adapter-compile-evidence": "1d9a1de8e312278a92a62a142e0e5da1662bc7529f2eff8029578386a61d7847",
    "adapter-evidence": "bf94a7ab9b7975a533620f92db4a09a73bbf13b1ff17cf2eec4c2fa2f386b56e",
    "claim": "e64e5c04d488cc353e78eb33ff4f96507d6bc4606616f97ab516c9e92b67ec92",
    "decoder-evidence": "5a0bc0b9ee07ecdd1a67e287f938355cab905b808da75e3b39578a0cb003fa91",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-linux-lib": "8859f99339377b7034d43dd9d4fd20713824b5ad2708cd52d76412272a3858e2",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "diagnose-linux-manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "linux-lib": "10dddcf330422289b7ab1f5ac5ee9574ce63ea9c29ac86fa1ba1f1909eff6c2a",
    "lock": "5fb7c8b16c4b865630a8e7e80f16919d443c3c276970959cd80ab26581229640",
    "root-manifest": "8cd67ea78720c5637340140ac6ea94a9d76ddeaf4fb0df40881c4e8dab371466",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
}


EXPECTED_LOAD_BEARING_CONSTANTS = {
    "audit-aarch64": "const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;",
    "audit-x86-64": "const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;",
    "path-maximum": "const MAX_TRACE_PATH_BYTES: u32 = 1_048_576;",
    "ptrace-get-syscall-info": "const PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e;",
    "socket-address-maximum": "const MAX_TRACE_SOCKET_ADDRESS_BYTES: u32 = 4096;",
}


def assert_load_bearing_constants(trace: str, sys: str) -> None:
    sources = {
        "audit-aarch64": trace,
        "audit-x86-64": trace,
        "path-maximum": trace,
        "ptrace-get-syscall-info": sys,
        "socket-address-maximum": trace,
    }
    for name, expected in EXPECTED_LOAD_BEARING_CONSTANTS.items():
        if sources[name].count(expected) != 1:
            raise AssertionError(f"load-bearing decoder constant mismatch: {name}")


def assert_load_bearing_bodies(
    trace: str, sys: str, adapter: str, observer: str, artifact: str
) -> None:
    actual = {
        "adapter-release": body_sha256(adapter, "pub fn release(self)"),
        "adapter-next-event": body_sha256(adapter, "pub fn next_event(mut self)"),
        "aarch64-table": body_sha256(trace, "fn decode_aarch64_syscall"),
        "capture": body_sha256(trace, "fn capture_syscall_invocation"),
        "capture-path-limit-accessor": body_sha256(trace, "const fn path_bytes(self)"),
        "capture-socket-limit-accessor": body_sha256(
            trace, "const fn socket_address_bytes(self)"
        ),
        "capture-string-limit-accessor": body_sha256(
            trace, "const fn tracee_string_bytes(self)"
        ),
        "capture-symlink-limit-accessor": body_sha256(
            trace, "const fn symlink_hops(self)"
        ),
        "entry-order": body_sha256(trace, "fn handle_syscall_stop"),
        "exact-read": body_sha256(trace, "fn read_exact_tracee_memory"),
        "i32-argument": body_sha256(trace, "fn trace_i32_argument"),
        "little-endian-reader": body_sha256(trace, "fn read_little_endian_u64"),
        "limits": body_sha256(trace, "pub const fn new(\n        path_bytes"),
        "observation-bounds-validate": body_sha256(artifact, "pub fn validate"),
        "observer-protocol-new": body_sha256(observer, "pub fn new(\n        root"),
        "path-limit": body_sha256(observer, "pub const fn path_byte_limit"),
        "prepare-observer": body_sha256(adapter, "pub fn prepare_observer"),
        "prepared-observer-spawn": body_sha256(adapter, "pub fn spawn(self)"),
        "raw-syscall-info-layout": body_sha256(
            sys,
            '#[cfg(feature = "diagnostic-observer")]\n#[repr(C)]\nstruct RawSyscallInfo',
        ),
        "raw-read": body_sha256(sys, "pub(crate) fn trace_read_process_memory"),
        "resume-before-deadline": body_sha256(trace, "fn resume_before_deadline("),
        "router": body_sha256(trace, "fn decode_trace_syscall"),
        "socket-address-read": body_sha256(trace, "fn capture_socket_address"),
        "socket-limit": body_sha256(observer, "pub const fn socket_address_byte_limit"),
        "string-limit": body_sha256(observer, "pub const fn tracee_string_byte_limit"),
        "symlink-limit": body_sha256(observer, "pub const fn symlink_hop_limit"),
        "supported-families": body_sha256(trace, "fn decode_supported_syscall"),
        "syscall-info-fetch": body_sha256(sys, "pub(crate) fn trace_syscall_stop"),
        "syscall-info-parser": body_sha256(sys, "fn decode_trace_syscall_stop"),
        "tracee-string-read": body_sha256(trace, "fn read_tracee_string"),
        "trace-next-event": body_sha256(trace, "pub fn next_event(&mut self)"),
        "trace-ready-release": body_sha256(
            trace, "pub fn release(\n        mut self,\n        process_limit"
        ),
        "uapi-i64-reader": body_sha256(sys, "fn trace_read_i64"),
        "uapi-u64-reader": body_sha256(sys, "fn trace_read_u64"),
        "wait-observation-router": body_sha256(trace, "fn handle_wait_observation"),
        "u32-argument": body_sha256(trace, "fn trace_u32_argument"),
        "x86-64-table": body_sha256(trace, "fn decode_x86_64_syscall"),
    }
    if actual != EXPECTED_LOAD_BEARING_BODIES:
        raise AssertionError(f"load-bearing decoder body mismatch: {actual!r}")


def assert_source_closure() -> None:
    actual = {
        "adapter-compile-evidence": hashlib.sha256(
            ADAPTER_COMPILE_EVIDENCE.read_bytes()
        ).hexdigest(),
        "adapter-evidence": hashlib.sha256(ADAPTER_EVIDENCE.read_bytes()).hexdigest(),
        "claim": hashlib.sha256(CLAIM.read_bytes()).hexdigest(),
        "decoder-evidence": hashlib.sha256(DECODER_EVIDENCE.read_bytes()).hexdigest(),
        "diagnose-lib": hashlib.sha256(DIAGNOSE_LIB.read_bytes()).hexdigest(),
        "diagnose-linux-lib": hashlib.sha256(
            DIAGNOSE_LINUX_LIB.read_bytes()
        ).hexdigest(),
        "diagnose-manifest": hashlib.sha256(DIAGNOSE_MANIFEST.read_bytes()).hexdigest(),
        "diagnose-linux-manifest": hashlib.sha256(
            DIAGNOSE_LINUX_MANIFEST.read_bytes()
        ).hexdigest(),
        "linux-manifest": hashlib.sha256(LINUX_MANIFEST.read_bytes()).hexdigest(),
        "linux-lib": hashlib.sha256(LINUX_LIB.read_bytes()).hexdigest(),
        "lock": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
        "root-manifest": hashlib.sha256(ROOT_MANIFEST.read_bytes()).hexdigest(),
        "toolchain": hashlib.sha256(TOOLCHAIN.read_bytes()).hexdigest(),
    }
    if actual != EXPECTED_CLOSURE_FILES:
        raise AssertionError(f"decoder source-closure mismatch: {actual!r}")


def assert_decoder_contract(
    trace: str, sys: str, adapter: str, observer: str, artifact: str
) -> None:
    entry = implementation(trace, "fn handle_syscall_stop")
    capture = implementation(trace, "fn capture_syscall_invocation")
    decode = implementation(trace, "fn decode_supported_syscall")
    path_read = implementation(trace, "fn read_tracee_string")
    socket_read = implementation(trace, "fn capture_socket_address")
    exact_read = implementation(trace, "fn read_exact_tracee_memory")
    raw_read = implementation(sys, "pub(crate) fn trace_read_process_memory")
    syscall_info = implementation(sys, "fn decode_trace_syscall_stop")
    prepare = implementation(adapter, "pub fn prepare_observer")
    protocol_new = implementation(observer, "pub fn new(\n        root")
    resume = implementation(trace, "fn resume_before_deadline(")

    if entry.index("capture_syscall_invocation") > entry.index(
        "self.resume_before_deadline(process)?"
    ):
        raise AssertionError("operand capture must precede tracee resume")
    if resume.index("self.session.deadline.expired()") > resume.index(
        "trace_syscall(process.get())"
    ):
        raise AssertionError("tracee resume must not precede the deadline check")
    for required in [
        "AUDIT_ARCH_X86_64",
        "AUDIT_ARCH_AARCH64",
        "decode_x86_64_syscall",
        "decode_aarch64_syscall",
        "X32_SYSCALL_BIT",
    ]:
        if required not in trace:
            raise AssertionError(f"missing architecture decoder term: {required}")
    for number in [
        "open: Some(2)",
        "socket: 41",
        "connect: 42",
        "sendto: 44",
        "bind: 49",
        "clone: 56",
        "fork: Some(57)",
        "vfork: Some(58)",
        "execve: 59",
        "creat: Some(85)",
        "readlink: Some(89)",
        "openat: 257",
        "newfstatat: 262",
        "readlinkat: 267",
        "execveat: 322",
        "statx: 332",
        "openat: 56",
        "readlinkat: 78",
        "newfstatat: 79",
        "socket: 198",
        "bind: 200",
        "connect: 203",
        "sendto: 206",
        "clone: 220",
        "execve: 221",
        "execveat: 281",
        "statx: 291",
        "clone3: 435",
        "openat2: 437",
    ]:
        if number not in trace:
            raise AssertionError(f"missing architecture-qualified number: {number}")
    for required in [
        "OPEN_HOW_BYTES: u64 = 24",
        "CLONE3_MAX_BYTES: u64 = 88",
        "SyscallFormUnsupported",
        "read_exact_tracee_memory",
    ]:
        if required not in capture:
            raise AssertionError(f"missing closed syscall form: {required}")
    if "limits.tracee_string_bytes()" not in path_read:
        raise AssertionError("tracee string read bound is absent")
    if "limits.path_bytes()" not in path_read or "PathLimitExceeded" not in path_read:
        raise AssertionError("independent path bound is absent")
    if "limits.socket_address_bytes()" not in socket_read:
        raise AssertionError("socket-address bound is absent")
    if "SocketAddressLimitExceeded" not in socket_read:
        raise AssertionError("socket-address overflow is not typed")
    if "trace_read_process_memory" not in exact_read or "count == 0" not in exact_read:
        raise AssertionError("partial tracee reads are not completed or rejected")
    if "libc::process_vm_readv" not in raw_read or "process_vm_writev" in raw_read:
        raise AssertionError("raw operation is not read-only process_vm_readv")
    prepare_compact = re.sub(r"\s+", "", prepare)
    protocol_new_compact = re.sub(r"\s+", "", protocol_new)
    if "bounds.validate()" not in prepare_compact:
        raise AssertionError(
            "observation bounds must validate before trace preparation"
        )
    if prepare_compact.index("bounds.validate()") > prepare_compact.index(
        "prepare_traced_launcher"
    ):
        raise AssertionError(
            "observation bounds must validate before trace preparation"
        )
    if "bounds.validate()" not in protocol_new_compact:
        raise AssertionError(
            "pure observer construction must revalidate observation bounds"
        )
    for required in [
        "available > core::mem::size_of::<RawSyscallInfo>()",
        "information.reserved != 0",
        "information.flags != 0",
        "available != SYSCALL_INFO_ENTRY_BYTES",
        "available != SYSCALL_INFO_EXIT_BYTES",
        "SYSCALL_INFO_SECCOMP_BYTES: usize = 84",
        "available == SYSCALL_INFO_SECCOMP_BYTES",
    ]:
        if required not in syscall_info:
            raise AssertionError(f"syscall-info form is not closed: {required}")
    if "payload_bytes: Some(arguments[2])" not in decode:
        raise AssertionError("send payload length is not retained")
    sendto = decode[decode.index("number == syscalls.sendto") :]
    sendto = sendto[: sendto.index("} else if number == syscalls.clone")]
    if (
        "address: arguments[4]" not in sendto
        or "address_bytes: arguments[5]" not in sendto
    ):
        raise AssertionError("sendto address operands are not selected")
    if "arguments[1]" in sendto:
        raise AssertionError("sendto payload pointer must never be consumed")
    for forbidden in ["process_vm_writev", "PTRACE_POKEDATA", "ptrace(PTRACE_POKE"]:
        if forbidden in trace or forbidden in sys:
            raise AssertionError(
                f"write-capable trace operation is forbidden: {forbidden}"
            )
    assert_load_bearing_constants(trace, sys)
    assert_load_bearing_bodies(trace, sys, adapter, observer, artifact)


class DiagnosticSyscallDecoderContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()
        self.adapter = ADAPTER.read_text()
        self.observer = OBSERVER.read_text()
        self.artifact = ARTIFACT.read_text()

    def test_architecture_tables_and_bounds_are_closed(self):
        assert_decoder_contract(
            self.trace, self.sys, self.adapter, self.observer, self.artifact
        )

    def test_raw_memory_read_is_confined_to_syscall_module(self):
        self.assertNotIn("process_vm_readv", self.trace)
        self.assertNotIn("libc::", self.trace)
        self.assertIn("process_vm_readv", self.sys)
        for source in ROOT.glob("crates/*/src/**/*.rs"):
            if source == SYS:
                continue
            self.assertNotIn("process_vm_readv", source.read_text(), source)

    def test_adapter_derives_capture_limits_from_validated_protocol(self):
        adapter = implementation(ADAPTER.read_text(), "pub fn release")
        for required in [
            "TraceCaptureLimits::new",
            "self.protocol.path_byte_limit()",
            "self.protocol.socket_address_byte_limit()",
            "self.protocol.symlink_hop_limit()",
            "self.protocol.tracee_string_byte_limit()",
        ]:
            self.assertIn(required, adapter)
        observer = OBSERVER.read_text()
        for required in [
            "self.bounds.path_bytes",
            "self.bounds.socket_address_bytes",
            "self.bounds.symlink_hops",
            "self.bounds.tracee_string_bytes",
        ]:
            self.assertIn(required, observer)

    def test_load_bearing_decoder_bodies_are_exact(self):
        assert_load_bearing_bodies(
            self.trace, self.sys, self.adapter, self.observer, self.artifact
        )

    def test_compiler_and_crate_selection_closure_is_exact(self):
        assert_source_closure()

    def test_mutations_break_the_decoder_contract(self):
        mutations = {
            "architecture router opened": (
                self.trace.replace(
                    "_ => Err(TraceObservationError::ArchitectureUnsupported)",
                    "_ => Ok(None)",
                    1,
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "syscall-stop routing bypassed": (
                self.trace.replace(
                    "self.handle_syscall_stop(reported)",
                    "Ok(None)",
                    1,
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "x86 open renumbered": (
                self.trace.replace("open: Some(2)", "open: Some(3)", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "x86 audit architecture changed": (
                self.trace.replace("0xc000_003e", "0xc000_003f", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "aarch64 audit architecture changed": (
                self.trace.replace("0xc000_00b7", "0xc000_00b8", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "aarch64 openat renumbered": (
                self.trace.replace("openat: 56", "openat: 57", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "x32 rejection removed": (
                self.trace.replace("if number & X32_SYSCALL_BIT != 0", "if false", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "signed width check removed": (
                self.trace.replace(
                    "if upper != 0 && upper != u64::from(u32::MAX)", "if false", 1
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "little endian reversed": (
                self.trace.replace(
                    "u64::from_le_bytes(field)", "u64::from_be_bytes(field)", 1
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "tracee string bound removed": (
                self.trace.replace("limits.tracee_string_bytes()", "usize::MAX", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "path bound removed": (
                self.trace.replace("bytes.len() > limits.path_bytes()", "false", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "socket bound removed": (
                self.trace.replace(
                    "address_bytes > limits.socket_address_bytes()", "false", 1
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "capture path accessor swapped": (
                self.trace.replace(
                    "self.path_bytes.get() as usize",
                    "self.socket_address_bytes.get() as usize",
                    1,
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "trace release capture limits substituted": (
                self.trace.replace(
                    "                capture_limits,",
                    "                capture_limits: TraceCaptureLimits::new(1_048_576, 4096, 1_048_576).unwrap(),",
                    1,
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "payload pointer substituted": (
                self.trace.replace("address: arguments[4]", "address: arguments[1]", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "pure path maximum widened": (
                self.trace,
                self.sys,
                self.adapter,
                self.observer,
                self.artifact.replace("1..=1_048_576", "1..=u64::MAX", 1),
            ),
            "effectful path maximum widened": (
                self.trace.replace("1_048_576", "1_048_577", 1),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "effectful socket maximum widened": (
                self.trace.replace(
                    "MAX_TRACE_SOCKET_ADDRESS_BYTES: u32 = 4096",
                    "MAX_TRACE_SOCKET_ADDRESS_BYTES: u32 = 4097",
                    1,
                ),
                self.sys,
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "protocol revalidation removed": (
                self.trace,
                self.sys,
                self.adapter,
                self.observer.replace(".validate()", ".clone()", 1),
                self.artifact,
            ),
            "adapter prevalidation removed": (
                self.trace,
                self.sys,
                self.adapter.replace(".validate()", ".clone()", 1),
                self.observer,
                self.artifact,
            ),
            "observer spawn bounds substituted": (
                self.trace,
                self.sys,
                self.adapter.replace(
                    "bounds: self.bounds",
                    "bounds: ObservationBounds { path_bytes: 1_048_576, socket_address_bytes: 4096, tracee_string_bytes: 1_048_576, ..self.bounds }",
                    1,
                ),
                self.observer,
                self.artifact,
            ),
            "adapter limit swapped": (
                self.trace,
                self.sys,
                self.adapter.replace(
                    "self.protocol.path_byte_limit()",
                    "self.protocol.socket_address_byte_limit()",
                    1,
                ),
                self.observer,
                self.artifact,
            ),
            "syscall reserved accepted": (
                self.trace,
                self.sys.replace("information.reserved != 0", "false", 1),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "ptrace syscall-info request changed": (
                self.trace,
                self.sys.replace(
                    "PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420e",
                    "PTRACE_GET_SYSCALL_INFO: libc::c_uint = 0x420f",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "syscall flags accepted": (
                self.trace,
                self.sys.replace("information.flags != 0", "false", 1),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "syscall-info C layout removed": (
                self.trace,
                self.sys.replace(
                    "#[repr(C)]\nstruct RawSyscallInfo",
                    "struct RawSyscallInfo",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "syscall-info scalar endianness changed": (
                self.trace,
                self.sys.replace("u64::from_ne_bytes", "u64::from_be_bytes", 1),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "syscall-info scalar range check removed": (
                self.trace,
                self.sys.replace(
                    ".checked_add(core::mem::size_of::<i64>())",
                    ".wrapping_add(core::mem::size_of::<i64>())",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "oversized syscall form accepted": (
                self.trace,
                self.sys.replace(
                    "available > core::mem::size_of::<RawSyscallInfo>()", "false", 1
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "extended entry form accepted": (
                self.trace,
                self.sys.replace(
                    "available != SYSCALL_INFO_ENTRY_BYTES",
                    "available < SYSCALL_INFO_ENTRY_BYTES",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "extended exit form accepted": (
                self.trace,
                self.sys.replace(
                    "available != SYSCALL_INFO_EXIT_BYTES",
                    "available < SYSCALL_INFO_EXIT_BYTES",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "truncated none form accepted": (
                self.trace,
                self.sys.replace(
                    "available == SYSCALL_INFO_HEADER_BYTES",
                    "available <= SYSCALL_INFO_HEADER_BYTES",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "truncated entry form accepted": (
                self.trace,
                self.sys.replace(
                    "available != SYSCALL_INFO_ENTRY_BYTES",
                    "available > SYSCALL_INFO_ENTRY_BYTES",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "truncated exit form accepted": (
                self.trace,
                self.sys.replace(
                    "available != SYSCALL_INFO_EXIT_BYTES",
                    "available > SYSCALL_INFO_EXIT_BYTES",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "truncated seccomp form accepted": (
                self.trace,
                self.sys.replace(
                    "available == SYSCALL_INFO_SECCOMP_BYTES",
                    "available <= SYSCALL_INFO_SECCOMP_BYTES",
                    1,
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
            "raw write substituted": (
                self.trace,
                self.sys.replace(
                    "libc::process_vm_readv", "libc::process_vm_writev", 1
                ),
                self.adapter,
                self.observer,
                self.artifact,
            ),
        }
        for name, (trace, sys, adapter, observer, artifact) in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_decoder_contract(trace, sys, adapter, observer, artifact)


if __name__ == "__main__":
    unittest.main()
