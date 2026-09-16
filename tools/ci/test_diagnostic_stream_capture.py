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
PATH_RECEIPT_MANIFEST = ROOT / "crates/proofbound-runtime-receipt/Cargo.toml"
PATH_RECEIPT_LIB = ROOT / "crates/proofbound-runtime-receipt/src/lib.rs"
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
    reader_finish_before = implementation(trace, "fn finish_before(")
    reader_cancel = implementation(trace, "fn cancel_and_join(")
    natural_finish = implementation(trace, "pub fn finish(mut self)")
    complete_drain = implementation(trace, "fn complete_drain(")
    child_drop = implementation(trace, "impl Drop for TraceChild")
    child_terminate = implementation(trace, "fn terminate_and_wait(")
    child_disarm = implementation(trace, "fn disarm_after_trace_wait(")
    child_pidfd_disarm = implementation(
        trace, "fn disarm_after_identity_stable_handle("
    )
    record_terminal = implementation(trace, "fn record_terminal_process(")
    exact_stop = implementation(trace, "fn wait_for_exact_stop(")
    release = implementation(trace, "pub fn release(")
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

    for term in [
        "checked_add(TRACE_STREAM_FINISH_TIMEOUT)",
        "TraceObservationError::StreamDrainTimedOut",
        "self.finish_before(deadline)",
    ]:
        if term not in reader_finish:
            raise AssertionError(f"missing terminal stream deadline term: {term}")
    for term in [
        "while !self.capture_threads_finished()",
        "Instant::now() >= deadline",
        "self.cancel_and_join()",
        "return Err(TraceObservationError::StreamDrainTimedOut)",
        "std::thread::sleep(TRACE_POLL_INTERVAL)",
    ]:
        if term not in reader_finish_before:
            raise AssertionError(f"missing terminal stream timeout term: {term}")
    if reader_finish_before.count("Instant::now() >= deadline") != 3:
        raise AssertionError("ready drains or joins can win after terminal expiry")
    before(
        reader_finish_before,
        "self.cancel_and_join()",
        "return Err(TraceObservationError::StreamDrainTimedOut)",
    )
    before(reader_finish_before, "let stdout = join_trace_capture", "stdout: stdout?")
    before(reader_finish_before, "let stderr = join_trace_capture", "stdout: stdout?")
    for stream in ["stdout", "stderr"]:
        if (
            f"self.{stream}.take()" not in reader_cancel
            or f"let _ = {stream}.join()" not in reader_cancel
        ):
            raise AssertionError(f"cancellation does not join {stream}")
    before(
        reader_cancel, "cancellation.store(true, Ordering::Release)", "stdout.join()"
    )
    if "self.cancel_and_join()" not in reader_drop:
        raise AssertionError("reader drop does not cancel and join")
    before(session, "_child: TraceChild", "streams: TraceStreamReaders")
    before(child_terminate, "self.0.kill()", "self.0.wait()")
    before(child_terminate, "requires_cleanup()", "self.0.kill()")
    before(child_terminate, "self.0.wait()", "record_trace_wait_reap()")
    if "self.1.record_trace_wait_reap()" not in child_disarm:
        raise AssertionError("raw trace wait cannot disarm numeric child cleanup")
    if "self.1.record_identity_stable_handle()" not in child_pidfd_disarm:
        raise AssertionError("pidfd ownership cannot disarm numeric child cleanup")
    before(
        release,
        "trace_open_process_handle(root.get())",
        "record_root_identity_stable_handle()",
    )
    before(
        release,
        "trace_syscall(root.get())",
        "record_root_identity_stable_handle()",
    )
    before(release, "record_root_identity_stable_handle()", "Ok(ActiveTrace")
    before(
        record_terminal, "self.processes.remove", "self.session.record_root_reaped()"
    )
    if "if process == self.session.process" not in record_terminal:
        raise AssertionError("terminal child cleanup is not confined to the exact root")
    if "self.terminate_and_wait()" not in child_drop:
        raise AssertionError("child drop does not terminate and wait")
    if "session: &mut TraceSession" not in exact_stop:
        raise AssertionError("setup wait cannot update child cleanup ownership")
    if exact_stop.count("session.record_root_reaped();") != 2:
        raise AssertionError("terminal setup waits leave numeric child cleanup armed")

    before(natural_finish, "if !self.is_drained()", "self.session.finish_streams()?")
    before(
        complete_drain,
        "if self.tree_reconciliation_failed",
        "self.session.finish_streams()?",
    )
    for variant in [
        "StreamUnavailable",
        "StreamDrainStartFailed",
        "StreamConfigurationFailed",
        "StreamReadFailed",
        "StreamDrainTimedOut",
    ]:
        if variant not in trace:
            raise AssertionError(f"missing closed stream failure: {variant}")

    before(active_step, "self.trace.finish()?.into_output()", "self.protocol.finish()?")
    before(
        drain_finish, "report.into_output()", "self.protocol.confirm_tree_drained()?"
    )
    before(
        drain_finish, "self.protocol.confirm_tree_drained()?", "self.protocol.finish()?"
    )
    if adapter.count("output: TraceOutputCapture") != 1:
        raise AssertionError("completed adapter output ownership is not singular")


EXPECTED_BODIES = {
    "adapter-active-step": "568f692fcad7317da1b04dc61b4857b43462f443053e793f4a7771feaa57e850",
    "adapter-drain-finish": "1d8bfca468a28f92d7e7aa546b31fee19770654cc1f44e0522a7985257f8496f",
    "capture": "a6783ae914ce32557ca90f72c44b56efc617958bfb6587514ba6de9a3542299c",
    "child-drop": "4b0736ae93ba2cc1524cce0bd88b7750ed536ff7fc5c6f2066c5ea7d8e01e786",
    "child-disarm": "573522b819713c764133d1ee66fa52cd8b9d9c7d085cf75a201773849c5b2df2",
    "child-pidfd-disarm": "47d90711e30be1b77dd750af5d39be069df6f33734dac1aa8db0a3ebaf50962d",
    "child-terminate": "8cacb6f54d429d3319a586ef2a0afcec3aa53ee709406798de2aef17374fe5aa",
    "complete-drain": "cbf23efa7521a4e7d5d9e1e1257fe777fa12c2a127a71e78e3508788952c173f",
    "natural-finish": "22e8d661d69a8476386221dc3f9b84e742422f9ebd11c2ae12263f1084b96b2b",
    "reader-finish": "fd900504cf37bbf8ceb94f1cdb1c330b1e7822e68cd56512973b8ce545196710",
    "reader-finish-before": "ca94b24d17e16baa9f7c89b784593aa021aa1dcf21241a565dec71be8893dd8e",
    "reader-cancel": "f8d1f73f2d46e508fe3a6dcb6ae5a3bb2749082808f368f9c21ba871c3e1ecdb",
    "reader-start": "8d00f7968b3498b8c59e4cac187a38908673edb446ad20b600aacab971e21f5c",
    "record-terminal": "1b039cd8a628df661083e7f65b8aeb4b691b7a476b851d06ab531826ca7365fa",
    "release": "33409206cf9f000d1e93b99610609b789ec8b1be18ad5bc64203922369b66837",
    "spawn": "6c62b3ede796721a78fa93b322fd58395317596d95fc69d6c69ee382fbe301f9",
    "wait-for-exact-stop": "ee7155892109c7e6103ad845db801ad1d397551863dda1f23ba590b38cd75d23",
}

EXPECTED_FILES = {
    "adapter": "b6e619eb9983b405470256296440831fcdbb4166835e4b7b0d23e4f063f0f5b0",
    "adapter-lib": "967270aa9c886b9ead6c80fbeae2c44fce868aa36fbb0c5d6071c77c2fa6ca16",
    "adapter-manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "authority": "9d1945b590a3a9f44f6af95d3090ad0a8d1bc0cfa601c35273cd0a72c86cbddc",
    "claim": "ca9d5bece8e1859cab3ee3173e72dd70652ce8edf8a19204a57d3c335af8ec1f",
    "contract-evidence": "8efddeb82d8cfcea95e6967b5d4b995f77215e159fc74b45a8f9cc0450a512c8",
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
    "path-receipt-lib": "f2f103cbc2c928f9a69211963788c1472c62a936de63a8f53dca2cd9c5469b01",
    "path-receipt-manifest": "4cb9c84da77bd72e3a49e2be1cbf52f2e5841ab15d9ae8fb07c2022f788518d6",
    "root-manifest": "1ea75287f62129c6b15038b0c45df42e616fc4c92e59e61bc03358746fd5d7d6",
    "stream-assumption": "b06c323edd3dceaa6c7c52b17b4ecd5c1bfc56dee10a95413f000f090cd69459",
    "stream-runtime-assumption": "ce57e1cab085cbd7b4f60ab03a607166a2dc77bdb924228b1f7c949a72bfeb19",
    "sys": "c7433f4485aa12829c87ef10210fa766676bc24729361e0a82ac93a2267eb06f",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "355f78d6d982f8385b88b66c39e9688958d31894d2c2f1649391a7b964252693",
    "unit-evidence": "c3265aa232ccf65fda04efd5706f3b85ca5d2fd006bf632dde4815090d076ccb",
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
                self.trace.replace(
                    ".checked_add(TRACE_STREAM_FINISH_TIMEOUT)",
                    ".checked_add(Duration::MAX)",
                    1,
                ),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace("self.cancel_and_join();", "", 1),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace(
                    "        if Instant::now() >= deadline {\n"
                    "            self.cancel_and_join();\n"
                    "            return Err(TraceObservationError::StreamDrainTimedOut);\n"
                    "        }\n"
                    "        let stdout = join_trace_capture(self.stdout.take());",
                    "        let stdout = join_trace_capture(self.stdout.take());",
                    1,
                ),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace("self.session.record_root_reaped();", "", 1),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace("session.record_root_reaped();", "", 1),
                self.adapter,
                self.sys,
            ),
            (
                self.trace.replace(
                    "self.session.record_root_identity_stable_handle();", "", 1
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
            "child-disarm": implementation(self.trace, "fn disarm_after_trace_wait("),
            "child-pidfd-disarm": implementation(
                self.trace, "fn disarm_after_identity_stable_handle("
            ),
            "child-terminate": implementation(self.trace, "fn terminate_and_wait("),
            "complete-drain": implementation(self.trace, "fn complete_drain("),
            "natural-finish": implementation(self.trace, "pub fn finish(mut self)"),
            "reader-finish": implementation(self.trace, "fn finish(&mut self)"),
            "reader-finish-before": implementation(self.trace, "fn finish_before("),
            "reader-cancel": implementation(self.trace, "fn cancel_and_join("),
            "reader-start": implementation(self.trace, "fn start("),
            "record-terminal": implementation(
                self.trace, "fn record_terminal_process("
            ),
            "release": implementation(self.trace, "pub fn release("),
            "spawn": implementation(self.trace, "pub fn spawn(mut self)"),
            "wait-for-exact-stop": implementation(
                self.trace, "fn wait_for_exact_stop("
            ),
        }
        actual_bodies = {
            name: hashlib.sha256(body.encode()).hexdigest()
            for name, body in bodies.items()
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
            "path-receipt-lib": PATH_RECEIPT_LIB,
            "path-receipt-manifest": PATH_RECEIPT_MANIFEST,
            "root-manifest": ROOT_MANIFEST,
            "stream-assumption": STREAM_ASSUMPTION,
            "stream-runtime-assumption": STREAM_RUNTIME_ASSUMPTION,
            "sys": SYS,
            "toolchain": TOOLCHAIN,
            "trace": TRACE,
            "unit-evidence": UNIT_EVIDENCE,
        }
        actual_files = {
            name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in files.items()
        }
        self.assertEqual(actual_files, EXPECTED_FILES)


if __name__ == "__main__":
    unittest.main()
