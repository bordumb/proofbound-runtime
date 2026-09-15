import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
ADAPTER_LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
ADAPTER_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
PRODUCTION_MANIFEST = ROOT / "crates/proofbound-runtime-cli/Cargo.toml"
PRODUCTION_LAUNCHER = (
    ROOT / "crates/proofbound-runtime-linux/src/bin/pbr-native-launcher.rs"
)


def implementation(source: str, type_name: str) -> str:
    start = source.index(f"impl {type_name} {{")
    next_impl = source.find("\nimpl ", start + 1)
    return source[start:] if next_impl == -1 else source[start:next_impl]


class DiagnosticTraceStartupContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()

    def test_feature_and_crate_keep_trace_out_of_production_path(self):
        linux_manifest = LINUX_MANIFEST.read_text()
        self.assertIn("default = []", linux_manifest)
        self.assertIn("diagnostic-observer = []", linux_manifest)
        self.assertRegex(
            LINUX_LIB.read_text(),
            re.compile(
                r'#\[cfg\(feature = "diagnostic-observer"\)\]\s+pub mod trace;',
                re.MULTILINE,
            ),
        )
        adapter_manifest = ADAPTER_MANIFEST.read_text()
        self.assertIn(
            'proofbound-runtime-linux = { workspace = true, features = ["diagnostic-observer"] }',
            adapter_manifest,
        )
        self.assertIn("#![deny(unsafe_code)]", ADAPTER_LIB.read_text())
        for production_source in [PRODUCTION_MANIFEST, PRODUCTION_LAUNCHER]:
            text = production_source.read_text()
            self.assertNotIn("proofbound-runtime-diagnose-linux", text)
            self.assertNotIn("diagnostic-observer", text)
            self.assertNotIn("prepare_traced_launcher", text)

    def test_raw_trace_calls_are_confined_to_the_syscall_module(self):
        self.assertNotIn("unsafe", self.trace)
        raw_calls = ["libc::ptrace(", "libc::waitpid(", "libc::kill("]
        for source in ROOT.glob("crates/*/src/**/*.rs"):
            if source == SYS:
                continue
            text = source.read_text()
            for raw_call in raw_calls:
                self.assertNotIn(raw_call, text, source)
        for raw_call in raw_calls:
            self.assertIn(raw_call, self.sys)
        for option in [
            "PTRACE_O_TRACESYSGOOD",
            "PTRACE_O_TRACEFORK",
            "PTRACE_O_TRACEVFORK",
            "PTRACE_O_TRACECLONE",
            "PTRACE_O_TRACEEXEC",
            "PTRACE_O_EXITKILL",
        ]:
            self.assertIn(option, self.sys)
        self.assertIn("REQUIRED_DIAGNOSTIC_TRACE_OPTIONS", self.sys)

    def test_typestates_order_acknowledgement_options_and_release(self):
        for state in [
            "PreparedTraceCommand",
            "SpawnedTrace",
            "InitialExecStop",
            "LauncherPause",
            "BoundaryRunning",
            "AcknowledgedTraceStop",
            "TraceReady",
            "ActiveTrace",
        ]:
            self.assertIn(f"pub struct {state}", self.trace)
            declaration = self.trace[: self.trace.index(f"pub struct {state}")]
            derive = declaration.rsplit("#[derive(", 1)[-1].split(")]", 1)[0]
            self.assertNotIn("Copy", derive, state)
            self.assertNotIn("Clone", derive, state)

        boundary = implementation(self.trace, "BoundaryRunning")
        self.assertLess(boundary.index("acknowledgement.identity()"), boundary.index("stop_trace"))
        self.assertLess(boundary.index("stop_trace"), boundary.index("wait_for_exact_stop"))

        acknowledged = implementation(self.trace, "AcknowledgedTraceStop")
        self.assertLess(
            acknowledged.index("install_diagnostic_trace_options"),
            acknowledged.index("Ok(TraceReady"),
        )

        ready = implementation(self.trace, "TraceReady")
        self.assertLess(ready.index("LauncherMessage::ExecRelease"), ready.index("trace_syscall"))
        self.assertLess(ready.index("trace_syscall"), ready.index("Ok(ActiveTrace"))

    def test_fail_closed_inputs_stops_and_errors_are_explicit(self):
        for required in [
            "descriptor < 3",
            "pair[0] == pair[1]",
            "pub fn spawn(mut self)",
            "_descriptors: inherited_descriptors.to_vec()",
            "impl Drop for TraceChild",
            "let _ = self.0.kill()",
            "let _ = self.0.wait()",
            "signal == expected_signal && event == expected_event",
            "SpawnFailed",
            "WaitTimedOut",
            "StopInvalid",
            "TraceeExited",
            "BoundaryIdentityMismatch",
            "OptionsInstallFailed",
            "ReleaseSendFailed",
            "ResumeFailed",
        ]:
            self.assertIn(required, self.trace)
        self.assertIn("if result != process_id", self.sys)
        self.assertIn('io::Error::other("unexpected traced wait status")', self.sys)


if __name__ == "__main__":
    unittest.main()
