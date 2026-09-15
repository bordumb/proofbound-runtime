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
TOOLCHAIN = ROOT / "rust-toolchain.toml"
DIAGNOSE_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose/Cargo.toml"
DIAGNOSE_LIB = ROOT / "crates/proofbound-runtime-diagnose/src/lib.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
DIAGNOSE_LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
DIAGNOSE_LINUX_LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
CLAIM = ROOT / "claims/PBR-OBSERVER-025.toml"
DECODER_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-syscall-decoder-contract.toml"
ADAPTER_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-observer-adapter-contract.toml"
ADAPTER_COMPILE_EVIDENCE = (
    ROOT / "proofbound/evidence/diagnostic-syscall-decoder-adapter.toml"
)


def implementation(source: str, signature: str) -> str:
    start = source.index(signature)
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
    "adapter-release": "d065697972422e21df3fe679539ec72bb4094c49e21577a24cc12230cb8f8a6e",
    "adapter-next-event": "8feed0c364401f4506ee0874106d2f0482b16c01a2c07f73b7957f66c6e04d7c",
    "aarch64-table": "45fe041bd934a083c660e316a30c289c5d2ce3d1b3dcf1d2ce430cd30b0b9c11",
    "capture": "e03c8d8f690304b9865ea829f026da17babea4c3175f8aff81b0a8c472a1dd48",
    "entry-order": "61c86cd672019c110cae4efbccf25eac1b22e0df4a6b927468b7bf7b8ac803fa",
    "exact-read": "4e4099b351e973ff312431159f64eac771b748820e5ec2d06daaaf6816efa452",
    "i32-argument": "48640c1efe3c88ce6281053cbc2385160faa326f92713f81c2874fe6210a243c",
    "little-endian-reader": "8669e2dac5832ba4dd7eb1708f3992af050868ab67fd791661c005957203cadd",
    "limits": "d592eadabb61f02e70e3d65a5641ebcc1c5a369ac0a3485531dafc8f06714476",
    "path-limit": "a1f57b2d41134fd23d07262bec9cb74cc859e9386675809369068105b04e7623",
    "raw-read": "0330210e9d4092a932240580c2f161a42374ac625cc28c89510f7a13ca44b5be",
    "router": "5d7181dc73c1a5f99ee30e5787fdf27dede851ba882fd989a451ea91b9a03b66",
    "socket-address-read": "8622490a7207ba8b4e29f75c66994d39f411b15b102986b4077c9be1acb52fb6",
    "socket-limit": "5abf245a10ffd0ce08305686d98acb204459c3a1a853a6dc854a578a26de6e65",
    "string-limit": "a839a837690914354efd25be3073c3ad8c1e21491d274004f54cb4464317eb3a",
    "supported-families": "928ac43d5c23a7e3bcbd24edf3d895597a55aa7a855ca4e2fdb8cfea4fa94f88",
    "syscall-info-fetch": "0b5e52f129fc45db01bd022959e42237ae68f7c44aff9f0b483a278546bb8084",
    "syscall-info-parser": "015a1a982bece9f59fca93b4a4d4425405eafffa40db25cb06adfb8869c6a12f",
    "tracee-string-read": "54fec5ee2c46ba8bd614c0da4e769b311ca6ff65637e7685be6e086369f7189c",
    "trace-next-event": "7c367d988aca81e12e6fa970c51e6c647b82edb2a3bacdaaaf35a605d94b0cfc",
    "u32-argument": "9a611e944f835a154c65dc1745c111c20a12d97323954af68e80fee6e74d391e",
    "x86-64-table": "64ecbc45be34c91cbbd7e12bbfb1bab005186d0b4cbbd47554a8fd2a9af16dcc",
}


EXPECTED_CLOSURE_FILES = {
    "adapter-compile-evidence": "1d9a1de8e312278a92a62a142e0e5da1662bc7529f2eff8029578386a61d7847",
    "adapter-evidence": "bf94a7ab9b7975a533620f92db4a09a73bbf13b1ff17cf2eec4c2fa2f386b56e",
    "claim": "835202bd5a43b383ee39f8f668e421015b1f6e3e1124e514861de7851d70d2ad",
    "decoder-evidence": "0da000ef1e970a345cc30c957d8160f3a6a75b85ec32f7495a20ce81f5d73349",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-linux-lib": "17f18aee43873ec8f645705c5dd66ccc978c23840782326ceefee9185e05aa69",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "diagnose-linux-manifest": "43995764926c9b24b23f6fcf33b34661ac8f9f188bd826601637c80cf4f5b120",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "linux-lib": "5e17e13cfe6da73bc3d22a00cc38909296b0b03c14b2709fe2e70f8b481486e1",
    "lock": "caee65ddd420057b080c0f8ef323318eaf650b0fade5077ad8cde50742011e62",
    "root-manifest": "1ea75287f62129c6b15038b0c45df42e616fc4c92e59e61bc03358746fd5d7d6",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
}


def assert_load_bearing_bodies(
    trace: str, sys: str, adapter: str, observer: str
) -> None:
    actual = {
        "adapter-release": body_sha256(adapter, "pub fn release(self)"),
        "adapter-next-event": body_sha256(adapter, "pub fn next_event(\n        mut self"),
        "aarch64-table": body_sha256(trace, "fn decode_aarch64_syscall"),
        "capture": body_sha256(trace, "fn capture_syscall_invocation"),
        "entry-order": body_sha256(trace, "fn handle_syscall_stop"),
        "exact-read": body_sha256(trace, "fn read_exact_tracee_memory"),
        "i32-argument": body_sha256(trace, "fn trace_i32_argument"),
        "little-endian-reader": body_sha256(trace, "fn read_little_endian_u64"),
        "limits": body_sha256(trace, "pub const fn new(\n        path_bytes"),
        "path-limit": body_sha256(observer, "pub const fn path_byte_limit"),
        "raw-read": body_sha256(sys, "pub(crate) fn trace_read_process_memory"),
        "router": body_sha256(trace, "fn decode_trace_syscall"),
        "socket-address-read": body_sha256(trace, "fn capture_socket_address"),
        "socket-limit": body_sha256(observer, "pub const fn socket_address_byte_limit"),
        "string-limit": body_sha256(observer, "pub const fn tracee_string_byte_limit"),
        "supported-families": body_sha256(trace, "fn decode_supported_syscall"),
        "syscall-info-fetch": body_sha256(sys, "pub(crate) fn trace_syscall_stop"),
        "syscall-info-parser": body_sha256(sys, "fn decode_trace_syscall_stop"),
        "tracee-string-read": body_sha256(trace, "fn read_tracee_string"),
        "trace-next-event": body_sha256(trace, "pub fn next_event(\n        &mut self"),
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
        "diagnose-linux-lib": hashlib.sha256(DIAGNOSE_LINUX_LIB.read_bytes()).hexdigest(),
        "diagnose-manifest": hashlib.sha256(DIAGNOSE_MANIFEST.read_bytes()).hexdigest(),
        "diagnose-linux-manifest": hashlib.sha256(DIAGNOSE_LINUX_MANIFEST.read_bytes()).hexdigest(),
        "linux-manifest": hashlib.sha256(LINUX_MANIFEST.read_bytes()).hexdigest(),
        "linux-lib": hashlib.sha256(LINUX_LIB.read_bytes()).hexdigest(),
        "lock": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
        "root-manifest": hashlib.sha256(ROOT_MANIFEST.read_bytes()).hexdigest(),
        "toolchain": hashlib.sha256(TOOLCHAIN.read_bytes()).hexdigest(),
    }
    if actual != EXPECTED_CLOSURE_FILES:
        raise AssertionError(f"decoder source-closure mismatch: {actual!r}")


def assert_decoder_contract(trace: str, sys: str, adapter: str, observer: str) -> None:
    entry = implementation(trace, "fn handle_syscall_stop")
    capture = implementation(trace, "fn capture_syscall_invocation")
    decode = implementation(trace, "fn decode_supported_syscall")
    path_read = implementation(trace, "fn read_tracee_string")
    socket_read = implementation(trace, "fn capture_socket_address")
    exact_read = implementation(trace, "fn read_exact_tracee_memory")
    raw_read = implementation(sys, "pub(crate) fn trace_read_process_memory")
    syscall_info = implementation(sys, "fn decode_trace_syscall_stop")

    if entry.index("capture_syscall_invocation") > entry.index("trace_syscall(process.get())"):
        raise AssertionError("operand capture must precede tracee resume")
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
    for required in [
        "available > core::mem::size_of::<RawSyscallInfo>()",
        "information.reserved != 0",
        "information.flags != 0",
        "available != SYSCALL_INFO_ENTRY_BYTES",
        "available != SYSCALL_INFO_EXIT_BYTES",
        "available == SYSCALL_INFO_SECCOMP_BYTES",
    ]:
        if required not in syscall_info:
            raise AssertionError(f"syscall-info form is not closed: {required}")
    if "payload_bytes: Some(arguments[2])" not in decode:
        raise AssertionError("send payload length is not retained")
    sendto = decode[decode.index("number == syscalls.sendto") :]
    sendto = sendto[: sendto.index("} else if number == syscalls.clone")]
    if "address: arguments[4]" not in sendto or "address_bytes: arguments[5]" not in sendto:
        raise AssertionError("sendto address operands are not selected")
    if "arguments[1]" in sendto:
        raise AssertionError("sendto payload pointer must never be consumed")
    for forbidden in ["process_vm_writev", "PTRACE_POKEDATA", "ptrace(PTRACE_POKE"]:
        if forbidden in trace or forbidden in sys:
            raise AssertionError(f"write-capable trace operation is forbidden: {forbidden}")
    assert_load_bearing_bodies(trace, sys, adapter, observer)


class DiagnosticSyscallDecoderContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()
        self.adapter = ADAPTER.read_text()
        self.observer = OBSERVER.read_text()

    def test_architecture_tables_and_bounds_are_closed(self):
        assert_decoder_contract(self.trace, self.sys, self.adapter, self.observer)

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
            "self.protocol.tracee_string_byte_limit()",
        ]:
            self.assertIn(required, adapter)
        observer = OBSERVER.read_text()
        for required in ["self.bounds.path_bytes", "self.bounds.socket_address_bytes", "self.bounds.tracee_string_bytes"]:
            self.assertIn(required, observer)

    def test_load_bearing_decoder_bodies_are_exact(self):
        assert_load_bearing_bodies(self.trace, self.sys, self.adapter, self.observer)

    def test_compiler_and_crate_selection_closure_is_exact(self):
        assert_source_closure()

    def test_mutations_break_the_decoder_contract(self):
        mutations = {
            "architecture router opened": (self.trace.replace("_ => Err(TraceObservationError::ArchitectureUnsupported)", "_ => Ok(None)", 1), self.sys, self.adapter, self.observer),
            "x86 open renumbered": (self.trace.replace("open: Some(2)", "open: Some(3)", 1), self.sys, self.adapter, self.observer),
            "aarch64 openat renumbered": (self.trace.replace("openat: 56", "openat: 57", 1), self.sys, self.adapter, self.observer),
            "x32 rejection removed": (self.trace.replace("if number & X32_SYSCALL_BIT != 0", "if false", 1), self.sys, self.adapter, self.observer),
            "signed width check removed": (self.trace.replace("if upper != 0 && upper != u64::from(u32::MAX)", "if false", 1), self.sys, self.adapter, self.observer),
            "little endian reversed": (self.trace.replace("u64::from_le_bytes(field)", "u64::from_be_bytes(field)", 1), self.sys, self.adapter, self.observer),
            "tracee string bound removed": (self.trace.replace("limits.tracee_string_bytes()", "usize::MAX", 1), self.sys, self.adapter, self.observer),
            "path bound removed": (self.trace.replace("bytes.len() > limits.path_bytes()", "false", 1), self.sys, self.adapter, self.observer),
            "socket bound removed": (self.trace.replace("address_bytes > limits.socket_address_bytes()", "false", 1), self.sys, self.adapter, self.observer),
            "payload pointer substituted": (self.trace.replace("address: arguments[4]", "address: arguments[1]", 1), self.sys, self.adapter, self.observer),
            "adapter limit swapped": (self.trace, self.sys, self.adapter.replace("self.protocol.path_byte_limit()", "self.protocol.socket_address_byte_limit()", 1), self.observer),
            "syscall reserved accepted": (self.trace, self.sys.replace("information.reserved != 0", "false", 1), self.adapter, self.observer),
            "syscall flags accepted": (self.trace, self.sys.replace("information.flags != 0", "false", 1), self.adapter, self.observer),
            "oversized syscall form accepted": (self.trace, self.sys.replace("available > core::mem::size_of::<RawSyscallInfo>()", "false", 1), self.adapter, self.observer),
            "extended entry form accepted": (self.trace, self.sys.replace("available != SYSCALL_INFO_ENTRY_BYTES", "available < SYSCALL_INFO_ENTRY_BYTES", 1), self.adapter, self.observer),
            "extended exit form accepted": (self.trace, self.sys.replace("available != SYSCALL_INFO_EXIT_BYTES", "available < SYSCALL_INFO_EXIT_BYTES", 1), self.adapter, self.observer),
            "raw write substituted": (self.trace, self.sys.replace("libc::process_vm_readv", "libc::process_vm_writev", 1), self.adapter, self.observer),
        }
        for name, (trace, sys, adapter, observer) in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_decoder_contract(trace, sys, adapter, observer)


if __name__ == "__main__":
    unittest.main()
