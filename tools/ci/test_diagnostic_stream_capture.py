import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
TRACE_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-TRACE-AX-016.toml"
STREAM_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-STREAM-CHECK-AX-020.toml"
CLAIM = ROOT / "claims/PBR-OBSERVER-027.toml"
CORE_MANIFEST = ROOT / "crates/proofbound-runtime-core/Cargo.toml"
AUTHORITY = ROOT / "crates/proofbound-runtime-core/src/authority.rs"
RECEIPT = ROOT / "crates/proofbound-runtime-core/src/receipt.rs"
ADAPTER_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
ADAPTER = ROOT / "crates/proofbound-runtime-diagnose-linux/src/adapter.rs"
ADAPTER_LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
UNIT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-stream-capture.toml"
CONTRACT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-stream-capture-contract.toml"


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


def structure(source: str, type_name: str) -> str:
    start = source.find(f"struct {type_name}")
    if start == -1:
        raise AssertionError(f"missing structure: {type_name}")
    end = source.index("\n}", start)
    return source[start : end + 2]


def before(source: str, first: str, second: str) -> None:
    first_index = source.find(first)
    second_index = source.find(second)
    if first_index == -1 or second_index == -1 or first_index >= second_index:
        raise AssertionError(f"required order absent: {first!r} before {second!r}")


def assert_stream_contract(trace: str, adapter: str, sys: str) -> None:
    prepare = implementation(trace, "pub fn prepare_traced_launcher")
    spawn = implementation(trace, "pub fn spawn(mut self)")
    start = implementation(trace, "fn start(")
    capture = implementation(trace, "fn capture_trace_stream(")
    reader_finish = implementation(trace, "fn finish(&mut self)")
    natural_finish = implementation(trace, "pub fn finish(mut self)")
    complete_drain = implementation(trace, "fn complete_drain(")
    child_drop = implementation(trace, "impl Drop for TraceChild")
    child_terminate = implementation(trace, "fn terminate_and_wait(")
    reader_drop = implementation(trace, "impl Drop for TraceStreamReaders")
    set_nonblocking = implementation(sys, "pub(crate) fn set_nonblocking(")
    session = structure(trace, "TraceSession")
    active_step = implementation(adapter, "pub fn next_event(")
    drain_finish = implementation(adapter, "pub fn finish(")

    for term in [
        ".stdout(Stdio::piped())",
        ".stderr(Stdio::piped())",
        "output_limits: TraceOutputLimits",
        "TraceOutputLimits::new(limits.stdout(), limits.stderr())",
    ]:
        if term not in prepare:
            raise AssertionError(f"missing prepared stream term: {term}")
    for term in [
        "TraceStreamReaders::start(&mut child, self.output_limits)?",
        "drop(self.launcher_channel)",
        "streams,",
    ]:
        if term not in spawn:
            raise AssertionError(f"missing spawn stream term: {term}")
    before(spawn, "TraceStreamReaders::start", "drop(self.launcher_channel)")
    before(spawn, "TraceStreamReaders::start", "Ok(SpawnedTrace")

    for term in [
        ".stdout\n                .take()",
        ".stderr\n                .take()",
        'spawn_trace_capture("stdout", stdout, limits.stdout(),',
        '"stderr",\n                stderr,\n                limits.stderr(),',
        "crate::sys::set_nonblocking(stdout.as_raw_fd())",
        "crate::sys::set_nonblocking(stderr.as_raw_fd())",
        "child.terminate_and_wait()",
        "let _ = stdout.join()",
    ]:
        if term not in start:
            raise AssertionError(f"missing start or rollback term: {term}")

    for term in [
        "reader.read(&mut buffer)",
        "cancellation.load(Ordering::Acquire)",
        "io::ErrorKind::WouldBlock",
        "std::thread::sleep(TRACE_POLL_INTERVAL)",
        "saturating_sub",
        "bytes.extend_from_slice(&buffer[..retained])",
        "truncated |= retained < count",
        "StreamCapture::Truncated",
        "StreamCapture::Complete",
    ]:
        if term not in capture:
            raise AssertionError(f"missing bounded drain term: {term}")
    if capture.count("break;") != 1 or "if count == 0" not in capture:
        raise AssertionError("stream drain must stop only at end of file")

    for term in ["libc::F_GETFL", "libc::F_SETFL", "libc::O_NONBLOCK"]:
        if term not in set_nonblocking:
            raise AssertionError(f"missing nonblocking pipe configuration: {term}")

    before(reader_finish, "let stdout = join_trace_capture", "stdout: stdout?")
    before(reader_finish, "let stderr = join_trace_capture", "stdout: stdout?")
    for stream in ["stdout", "stderr"]:
        if f"self.{stream}.take()" not in reader_drop or f"let _ = {stream}.join()" not in reader_drop:
            raise AssertionError(f"drop does not join {stream}")
    before(reader_drop, "cancellation.store(true, Ordering::Release)", "stdout.join()")
    before(session, "_child: TraceChild", "streams: TraceStreamReaders")
    before(child_terminate, "self.0.kill()", "self.0.wait()")
    if "self.terminate_and_wait()" not in child_drop:
        raise AssertionError("child drop does not terminate and wait")

    before(natural_finish, "if !self.is_drained()", "self.session.finish_terminal()?")
    before(complete_drain, "if self.tree_reconciliation_failed", "self.session.finish_terminal()?")
    for variant in [
        "StreamUnavailable",
        "StreamDrainStartFailed",
        "StreamConfigurationFailed",
        "StreamReadFailed",
    ]:
        if variant not in trace:
            raise AssertionError(f"missing closed stream failure: {variant}")

    before(active_step, "self.trace.finish()?.into_terminal()", "self.protocol.finish()?")
    before(drain_finish, "report.into_terminal()", "self.protocol.confirm_tree_drained()?")
    before(drain_finish, "self.protocol.confirm_tree_drained()?", "self.protocol.finish()?")
    if adapter.count("terminal: TraceTerminalCapture") != 1:
        raise AssertionError("completed adapter terminal ownership is not singular")


EXPECTED_BODIES = {
    "adapter-active-step": "e7d57ca91f85832b6fb3310418e2a0df9ee0fb4b40fa29203bac66423c8620cb",
    "adapter-drain-finish": "5f5ee9835cf2bacc73f10cd50b0e9a20f6d91d23c4d2905c84af181e22d05848",
    "capture": "a6783ae914ce32557ca90f72c44b56efc617958bfb6587514ba6de9a3542299c",
    "child-drop": "4b0736ae93ba2cc1524cce0bd88b7750ed536ff7fc5c6f2066c5ea7d8e01e786",
    "child-terminate": "d4a0ffbd63170c1856fa0f813f83f384a2b15115b4de2e06137dbdd3a1906a5b",
    "complete-drain": "db92609df0e5e00a33ce9848422783d7ce5e2ef8b4157c7e7bdafae6bfb1e49e",
    "natural-finish": "b1feb2846c2a896e67a10874aa44e8f1675c76f8ba992d06a232538ec191324d",
    "reader-finish": "ae999a795d79ff901cb4a33b1dcbb3865b055cb0c754770aa5da813826174024",
    "reader-start": "8d00f7968b3498b8c59e4cac187a38908673edb446ad20b600aacab971e21f5c",
    "spawn": "5b97c0af4ae4000f43dd8b7eb1288edb03bbc61df89f77f0c332c81fbf16a071",
}

EXPECTED_FILES = {
    "adapter": "72b8868fb0d50a65e4306f754051dec1e3aace4ee7da33825bb990f4d7bab70b",
    "adapter-lib": "ccad4545cfd41802c32d66a692d65aca9a69d0e59b0a3cb7c5c34da42830a198",
    "adapter-manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "authority": "9d1945b590a3a9f44f6af95d3090ad0a8d1bc0cfa601c35273cd0a72c86cbddc",
    "claim": "2692fab5bad0104a45d97f124cb9b20dc7bef590ca53830318823793af5cf6a8",
    "contract-evidence": "ff704f1339587c05a05836649fe05e92f1eca826412e7cecdbb8334c49def250",
    "core-manifest": "0d22823a1d4f397fb58693c7d9fe7498969ce242b5da0f372d8cc8f55f960b9b",
    "linux-lib": "47ef2cdd61b7c0854f0ee9fcfb5d32ffcebfec5b5820477636a3d513a7ccf33d",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "lock": "376572c5d111f5ea72e38667b5813a7c051e9fa128d5af355468e5294889a0c6",
    "receipt": "fc27edf189014a49af8af380902fe90b12cbbd71a2b49301064b589c8a4c4024",
    "root-manifest": "1ea75287f62129c6b15038b0c45df42e616fc4c92e59e61bc03358746fd5d7d6",
    "stream-assumption": "b06c323edd3dceaa6c7c52b17b4ecd5c1bfc56dee10a95413f000f090cd69459",
    "sys": "c7433f4485aa12829c87ef10210fa766676bc24729361e0a82ac93a2267eb06f",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "3c766e2767d8622ee40e45825b863c75d3be49aa52aa62b6dd41bd311da6bd07",
    "trace-assumption": "40a483142f19a6e3c1ece498b07b55463040354e98172a271abd623363414bb0",
    "unit-evidence": "93e3d90c452ea85f6d2fdaa1c222d436e8528302f4a6af3508bc008b450b606d",
}


class DiagnosticStreamCaptureContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = TRACE.read_text()
        self.adapter = ADAPTER.read_text()
        self.sys = SYS.read_text()

    def test_bounded_concurrent_stream_contract(self) -> None:
        assert_stream_contract(self.trace, self.adapter, self.sys)

    def test_stream_contract_mutations_are_rejected(self) -> None:
        mutations = [
            (
                "stdout inherited",
                self.trace.replace(
                    ".stdout(Stdio::piped())", ".stdout(Stdio::inherit())", 1
                ),
                self.adapter,
                self.sys,
            ),
            (
                "stderr inherited",
                self.trace.replace(
                    ".stderr(Stdio::piped())", ".stderr(Stdio::inherit())", 1
                ),
                self.adapter,
                self.sys,
            ),
            (
                "stdout uses stderr limit",
                self.trace.replace("limits.stdout(),", "limits.stderr(),", 1),
                self.adapter,
                self.sys,
            ),
            (
                "drain stops at retained limit",
                self.trace.replace(
                    "truncated |= retained < count;",
                    "if retained < count { break; }",
                    1,
                ),
                self.adapter,
                self.sys,
            ),
            (
                "partial start skips child cleanup",
                self.trace.replace("child.terminate_and_wait();", "", 1),
                self.adapter,
                self.sys,
            ),
            (
                "streams drop before child and cgroup",
                self.trace.replace(
                    "_child: TraceChild,\n    cgroup: Option<FreshCgroup>,\n"
                    "    streams: TraceStreamReaders,",
                    "streams: TraceStreamReaders,\n    cgroup: Option<FreshCgroup>,\n"
                    "    _child: TraceChild,",
                    1,
                ),
                self.adapter,
                self.sys,
            ),
            (
                "natural completion accepts live tree",
                self.trace.replace("if !self.is_drained()", "if self.is_drained()", 1),
                self.adapter,
                self.sys,
            ),
            (
                "publication precedes natural terminal capture",
                self.trace,
                self.adapter.replace(
                    "let terminal = self.trace.finish()?.into_terminal();\n"
                    "            let publication = self.protocol.finish()?;",
                    "let publication = self.protocol.finish()?;\n"
                    "            let terminal = self.trace.finish()?.into_terminal();",
                    1,
                ),
                self.sys,
            ),
            (
                "pipe remains blocking",
                self.trace,
                self.adapter,
                self.sys.replace(" | libc::O_NONBLOCK", "", 1),
            ),
        ]
        for name, trace, adapter, sys in mutations:
            mutation = hashlib.sha256((trace + adapter + sys).encode()).hexdigest()[:12]
            with self.subTest(name=name, mutation=mutation):
                with self.assertRaises(AssertionError):
                    assert_stream_contract(trace, adapter, sys)

    def test_exact_load_bearing_source(self) -> None:
        bodies = {
            "adapter-active-step": implementation(self.adapter, "pub fn next_event("),
            "adapter-drain-finish": implementation(self.adapter, "pub fn finish("),
            "capture": implementation(self.trace, "fn capture_trace_stream("),
            "child-drop": implementation(self.trace, "impl Drop for TraceChild"),
            "child-terminate": implementation(self.trace, "fn terminate_and_wait("),
            "complete-drain": implementation(self.trace, "fn complete_drain("),
            "natural-finish": implementation(self.trace, "pub fn finish(mut self)"),
            "reader-finish": implementation(self.trace, "fn finish(&mut self)"),
            "reader-start": implementation(self.trace, "fn start("),
            "spawn": implementation(self.trace, "pub fn spawn(mut self)"),
        }
        actual_bodies = {
            name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()
        }
        self.assertEqual(actual_bodies, EXPECTED_BODIES)

        files = {
            "adapter": ADAPTER,
            "adapter-lib": ADAPTER_LIB,
            "adapter-manifest": ADAPTER_MANIFEST,
            "authority": AUTHORITY,
            "claim": CLAIM,
            "contract-evidence": CONTRACT_EVIDENCE,
            "core-manifest": CORE_MANIFEST,
            "linux-lib": LINUX_LIB,
            "linux-manifest": LINUX_MANIFEST,
            "lock": LOCK,
            "receipt": RECEIPT,
            "root-manifest": ROOT_MANIFEST,
            "stream-assumption": STREAM_ASSUMPTION,
            "sys": SYS,
            "toolchain": TOOLCHAIN,
            "trace": TRACE,
            "trace-assumption": TRACE_ASSUMPTION,
            "unit-evidence": UNIT_EVIDENCE,
        }
        actual_files = {
            name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()
        }
        self.assertEqual(actual_files, EXPECTED_FILES)


if __name__ == "__main__":
    unittest.main()
