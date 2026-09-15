import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
STREAM_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-STREAM-CHECK-AX-020.toml"
STREAM_RUNTIME_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-STREAM-AX-022.toml"
CLAIM = ROOT / "claims/PBR-OBSERVER-027.toml"
CORE_MANIFEST = ROOT / "crates/proofbound-runtime-core/Cargo.toml"
AUTHORITY = ROOT / "crates/proofbound-runtime-core/src/authority.rs"
CORE_LIB = ROOT / "crates/proofbound-runtime-core/src/lib.rs"
RECEIPT = ROOT / "crates/proofbound-runtime-core/src/receipt.rs"
DIAGNOSE_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose/Cargo.toml"
DIAGNOSE_ARTIFACT = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"
DIAGNOSE_LIB = ROOT / "crates/proofbound-runtime-diagnose/src/lib.rs"
DIAGNOSE_OBSERVER = ROOT / "crates/proofbound-runtime-diagnose/src/observer.rs"
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

    before(natural_finish, "if !self.is_drained()", "self.session.finish_streams()?")
    before(complete_drain, "if self.tree_reconciliation_failed", "self.session.finish_streams()?")
    for variant in [
        "StreamUnavailable",
        "StreamDrainStartFailed",
        "StreamConfigurationFailed",
        "StreamReadFailed",
    ]:
        if variant not in trace:
            raise AssertionError(f"missing closed stream failure: {variant}")

    before(active_step, "self.trace.finish()?.into_output()", "self.protocol.finish()?")
    before(drain_finish, "report.into_output()", "self.protocol.confirm_tree_drained()?")
    before(drain_finish, "self.protocol.confirm_tree_drained()?", "self.protocol.finish()?")
    if adapter.count("output: TraceOutputCapture") != 1:
        raise AssertionError("completed adapter output ownership is not singular")


EXPECTED_BODIES = {
    "adapter-active-step": "568f692fcad7317da1b04dc61b4857b43462f443053e793f4a7771feaa57e850",
    "adapter-drain-finish": "1d8bfca468a28f92d7e7aa546b31fee19770654cc1f44e0522a7985257f8496f",
    "capture": "a6783ae914ce32557ca90f72c44b56efc617958bfb6587514ba6de9a3542299c",
    "child-drop": "4b0736ae93ba2cc1524cce0bd88b7750ed536ff7fc5c6f2066c5ea7d8e01e786",
    "child-terminate": "d4a0ffbd63170c1856fa0f813f83f384a2b15115b4de2e06137dbdd3a1906a5b",
    "complete-drain": "cbf23efa7521a4e7d5d9e1e1257fe777fa12c2a127a71e78e3508788952c173f",
    "natural-finish": "22e8d661d69a8476386221dc3f9b84e742422f9ebd11c2ae12263f1084b96b2b",
    "reader-finish": "ae999a795d79ff901cb4a33b1dcbb3865b055cb0c754770aa5da813826174024",
    "reader-start": "8d00f7968b3498b8c59e4cac187a38908673edb446ad20b600aacab971e21f5c",
    "spawn": "573433ea5b30f93e4ecfb4cbc75d6ba13cff4103cd2ba812c9ba505d1000dc82",
}

EXPECTED_FILES = {
    "adapter": "b6e619eb9983b405470256296440831fcdbb4166835e4b7b0d23e4f063f0f5b0",
    "adapter-lib": "967270aa9c886b9ead6c80fbeae2c44fce868aa36fbb0c5d6071c77c2fa6ca16",
    "adapter-manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "authority": "9d1945b590a3a9f44f6af95d3090ad0a8d1bc0cfa601c35273cd0a72c86cbddc",
    "claim": "90729ba496cc037146213651fdbfabecc792d281a0ef3cc3e5efa04985eb3bcd",
    "contract-evidence": "52ea0e12fbf342e8d22c873e24c8f79fe0e3ac08cc25f826abf1e2db32d3a789",
    "core-manifest": "0d22823a1d4f397fb58693c7d9fe7498969ce242b5da0f372d8cc8f55f960b9b",
    "core-lib": "2039d8c789844cddaaabbf432a0a6ef465f77300577f3b57922d7bcbcc930450",
    "diagnose-artifact": "ad7cce45d286623dcfd55c21189cb7d58e29f1943960d0a061d6f85c2640baa3",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "diagnose-observer": "e6cfb0a92d7bf7e235c7fac8180f488b7b1d9474986791fac4adf2917dae7d12",
    "linux-lib": "a1d7d31fb602afd59aab41aa4153fa2a6fcc0923518118bf956e5939f29c97a8",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "lock": "376572c5d111f5ea72e38667b5813a7c051e9fa128d5af355468e5294889a0c6",
    "receipt": "fc27edf189014a49af8af380902fe90b12cbbd71a2b49301064b589c8a4c4024",
    "root-manifest": "1ea75287f62129c6b15038b0c45df42e616fc4c92e59e61bc03358746fd5d7d6",
    "stream-assumption": "b06c323edd3dceaa6c7c52b17b4ecd5c1bfc56dee10a95413f000f090cd69459",
    "stream-runtime-assumption": "660304ed492713250e1595f2ed19e2b84196240016d857d3265fb6c6a0c9d78d",
    "sys": "c7433f4485aa12829c87ef10210fa766676bc24729361e0a82ac93a2267eb06f",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "461abf2a7640bbda35399d158491e57dd60bbaa99bb95e328f7a1176ba5644f7",
    "unit-evidence": "bb5fb600446926f464226a4a01948296513db266639140c9f7695c6327540a63",
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
                self.trace.replace(
                    ".stdout(Stdio::piped())", ".stdout(Stdio::inherit())", 1
                ),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace(
                    ".stderr(Stdio::piped())", ".stderr(Stdio::inherit())", 1
                ),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace("limits.stdout(),", "limits.stderr(),", 1),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace(
                    "truncated |= retained < count;",
                    "if retained < count { break; }",
                    1,
                ),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace("child.terminate_and_wait();", "", 1),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace(
                    "_child: TraceChild,\n    streams: TraceStreamReaders,",
                    "streams: TraceStreamReaders,\n    _child: TraceChild,",
                    1,
                ),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace("if !self.is_drained()", "if self.is_drained()", 1),
                self.adapter,
                self.sys,
            ),
            (
                self.trace,
                self.adapter.replace(
                    "let output = self.trace.finish()?.into_output();\n"
                    "            let publication = self.protocol.finish()?;",
                    "let publication = self.protocol.finish()?;\n"
                    "            let output = self.trace.finish()?.into_output();",
                    1,
                ),
                self.sys,
            ),
            (
                self.trace,
                self.adapter,
                self.sys.replace(" | libc::O_NONBLOCK", "", 1),
            ),
        ]
        for trace, adapter, sys in mutations:
            mutation = hashlib.sha256((trace + adapter + sys).encode()).hexdigest()[:12]
            with self.subTest(mutation=mutation):
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
            "core-lib": CORE_LIB,
            "diagnose-artifact": DIAGNOSE_ARTIFACT,
            "diagnose-lib": DIAGNOSE_LIB,
            "diagnose-manifest": DIAGNOSE_MANIFEST,
            "diagnose-observer": DIAGNOSE_OBSERVER,
            "claim": CLAIM,
            "contract-evidence": CONTRACT_EVIDENCE,
            "core-manifest": CORE_MANIFEST,
            "linux-lib": LINUX_LIB,
            "linux-manifest": LINUX_MANIFEST,
            "lock": LOCK,
            "receipt": RECEIPT,
            "root-manifest": ROOT_MANIFEST,
            "stream-assumption": STREAM_ASSUMPTION,
            "stream-runtime-assumption": STREAM_RUNTIME_ASSUMPTION,
            "sys": SYS,
            "toolchain": TOOLCHAIN,
            "trace": TRACE,
            "unit-evidence": UNIT_EVIDENCE,
        }
        actual_files = {
            name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in files.items()
        }
        self.assertEqual(actual_files, EXPECTED_FILES)


if __name__ == "__main__":
    unittest.main()
