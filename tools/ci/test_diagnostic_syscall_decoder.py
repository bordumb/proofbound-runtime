import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
ADAPTER = ROOT / "crates/proofbound-runtime-diagnose-linux/src/adapter.rs"
OBSERVER = ROOT / "crates/proofbound-runtime-diagnose/src/observer.rs"


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
    "capture": "e03c8d8f690304b9865ea829f026da17babea4c3175f8aff81b0a8c472a1dd48",
    "decode": "928ac43d5c23a7e3bcbd24edf3d895597a55aa7a855ca4e2fdb8cfea4fa94f88",
    "path-read": "54fec5ee2c46ba8bd614c0da4e769b311ca6ff65637e7685be6e086369f7189c",
    "socket-read": "8622490a7207ba8b4e29f75c66994d39f411b15b102986b4077c9be1acb52fb6",
    "exact-read": "4e4099b351e973ff312431159f64eac771b748820e5ec2d06daaaf6816efa452",
    "raw-read": "0330210e9d4092a932240580c2f161a42374ac625cc28c89510f7a13ca44b5be",
}


def assert_load_bearing_bodies(trace: str, sys: str) -> None:
    actual = {
        "capture": body_sha256(trace, "fn capture_syscall_invocation"),
        "decode": body_sha256(trace, "fn decode_supported_syscall"),
        "path-read": body_sha256(trace, "fn read_tracee_string"),
        "socket-read": body_sha256(trace, "fn capture_socket_address"),
        "exact-read": body_sha256(trace, "fn read_exact_tracee_memory"),
        "raw-read": body_sha256(sys, "pub(crate) fn trace_read_process_memory"),
    }
    if actual != EXPECTED_LOAD_BEARING_BODIES:
        raise AssertionError(f"load-bearing decoder body mismatch: {actual!r}")


def assert_decoder_contract(trace: str, sys: str) -> None:
    entry = implementation(trace, "fn handle_syscall_stop")
    capture = implementation(trace, "fn capture_syscall_invocation")
    decode = implementation(trace, "fn decode_supported_syscall")
    path_read = implementation(trace, "fn read_tracee_string")
    socket_read = implementation(trace, "fn capture_socket_address")
    exact_read = implementation(trace, "fn read_exact_tracee_memory")
    raw_read = implementation(sys, "pub(crate) fn trace_read_process_memory")

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


class DiagnosticSyscallDecoderContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()

    def test_architecture_tables_and_bounds_are_closed(self):
        assert_decoder_contract(self.trace, self.sys)

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
        assert_load_bearing_bodies(self.trace, self.sys)

    def test_mutations_break_the_decoder_contract(self):
        mutations = {
            "x86 open renumbered": self.trace.replace("open: Some(2)", "open: Some(3)", 1),
            "aarch64 openat renumbered": self.trace.replace("openat: 56", "openat: 57", 1),
            "tracee string bound removed": self.trace.replace("limits.tracee_string_bytes()", "usize::MAX"),
            "path bound removed": self.trace.replace("bytes.len() > limits.path_bytes()", "false"),
            "socket bound removed": self.trace.replace("address_bytes > limits.socket_address_bytes()", "false", 1),
            "payload pointer substituted": self.trace.replace("address: arguments[4]", "address: arguments[1]", 1),
            "raw write substituted": self.sys.replace("libc::process_vm_readv", "libc::process_vm_writev", 1),
        }
        for name, mutated in mutations.items():
            trace = mutated if name != "raw write substituted" else self.trace
            sys = mutated if name == "raw write substituted" else self.sys
            with self.subTest(name=name), self.assertRaises(AssertionError):
                assert_decoder_contract(trace, sys)


if __name__ == "__main__":
    unittest.main()
