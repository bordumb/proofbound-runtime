import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
SUPERVISOR = ROOT / "crates/proofbound-runtime-linux/src/supervisor.rs"
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


def structure(source: str, type_name: str) -> str:
    start = source.index(f"struct {type_name} {{")
    end = source.index("\n}", start)
    return source[start:end]


class DiagnosticTraceStartupContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()
        self.supervisor = SUPERVISOR.read_text()

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
        self.assertLess(
            boundary.index("receive_timeout"),
            boundary.index("acknowledgement.identity()"),
        )
        self.assertLess(
            boundary.index("acknowledgement.identity()"), boundary.index("stop_trace")
        )
        self.assertLess(
            boundary.index("stop_trace"), boundary.index("wait_for_exact_stop")
        )

        acknowledged = implementation(self.trace, "AcknowledgedTraceStop")
        self.assertLess(
            acknowledged.index("install_diagnostic_trace_options"),
            acknowledged.index("Ok(TraceReady"),
        )

        ready = implementation(self.trace, "TraceReady")
        self.assertLess(
            ready.index("LauncherMessage::ExecRelease"), ready.index("trace_syscall")
        )
        self.assertLess(ready.index("trace_syscall"), ready.index("Ok(ActiveTrace"))

    def test_session_moves_one_child_channel_identity_and_request_through_every_state(
        self,
    ):
        session = structure(self.trace, "TraceSession")
        for field in [
            "child: TraceChild",
            "process: TraceProcessId",
            "channel: LauncherChannel",
            "request: InstallRequest",
        ]:
            self.assertIn(field, session)
        for state in [
            "SpawnedTrace",
            "InitialExecStop",
            "LauncherPause",
            "BoundaryRunning",
            "AcknowledgedTraceStop",
            "TraceReady",
            "ActiveTrace",
        ]:
            body = structure(self.trace, state)
            self.assertIn("session: TraceSession", body, state)
            self.assertNotIn("child: TraceChild", body, state)
            self.assertNotIn("channel: LauncherChannel", body, state)
            self.assertNotIn("request: InstallRequest", body, state)
        self.assertEqual(self.trace.count("session: self.session"), 6)
        self.assertNotIn("pub fn child_mut", self.trace)
        self.assertNotIn("-> &mut Child", self.trace)

    def test_session_creates_and_uses_one_private_launcher_channel(self):
        prepare_start = self.trace.index("pub fn prepare_traced_launcher")
        prepare_end = self.trace.index(
            "\n#[derive(Debug)]\nstruct TraceChild", prepare_start
        )
        prepare = self.trace[prepare_start:prepare_end]
        for required in [
            "launcher: &'descriptor ResolvedFile",
            "request: InstallRequest",
            "ArtifactRole::LauncherBinary",
            ".revalidate_identity()",
            "LauncherChannel::pair()",
            'Command::new(format!("/proc/self/fd/{launcher_fd}"))',
            "request.identity()",
            "launcher_fd < 3",
            "supervisor_channel_fd < 3 || launcher_channel_fd < 3",
            "descriptors.push(launcher_fd)",
            "descriptors.push(launcher_channel_fd)",
            "retained_descriptors.push(launcher.as_fd())",
            "supervisor_channel,",
            "launcher_channel,",
            "request,",
        ]:
            self.assertIn(required, prepare)
        for forbidden in [
            "command: Command",
            "channel: LauncherChannel",
            "identity: LauncherIdentity",
        ]:
            self.assertNotIn(forbidden, prepare)

        spawned = implementation(self.trace, "PreparedTraceCommand<'_>")
        self.assertLess(
            spawned.index("revalidate_identity()"), spawned.index(".spawn()")
        )
        self.assertLess(
            spawned.index(".spawn()"), spawned.index("drop(self.launcher_channel)")
        )
        self.assertIn("channel: self.supervisor_channel", spawned)
        self.assertIn("request: self.request", spawned)

        pause = implementation(self.trace, "LauncherPause")
        self.assertLess(
            pause.index("continue_trace"), pause.index("LauncherMessage::Install")
        )
        pause_compact = re.sub(r"\s+", "", pause)
        self.assertIn("self.session.channel", pause_compact)

        boundary = implementation(self.trace, "BoundaryRunning")
        boundary_compact = re.sub(r"\s+", "", boundary)
        self.assertIn("self.session.channel", boundary_compact)
        self.assertIn("self.session.request.identity()", boundary_compact)
        self.assertNotIn("acknowledgement: BoundaryInstalled", boundary)
        self.assertNotIn("expected: LauncherIdentity", boundary)

        ready = implementation(self.trace, "TraceReady")
        ready_compact = re.sub(r"\s+", "", ready)
        self.assertIn("self.session.channel", ready_compact)
        self.assertIn("self.session.request.identity()", ready_compact)
        self.assertNotIn("channel: &LauncherChannel", ready)

    def test_fail_closed_inputs_stops_and_errors_are_explicit(self):
        for required in [
            "pub fn spawn(mut self)",
            "_descriptors: retained_descriptors",
            "impl Drop for TraceChild",
            "let _ = self.0.kill()",
            "let _ = self.0.wait()",
            "signal == expected_signal && event == expected_event",
            "SpawnFailed",
            "WaitTimedOut",
            "StopInvalid",
            "TraceeExited",
            "LauncherIdentityInvalid",
            "InstallSendFailed",
            "AcknowledgementTimedOut",
            "AcknowledgementReceiveFailed",
            "AcknowledgementInvalid",
            "BoundaryIdentityMismatch",
            "LauncherReportedFailure",
            "OptionsInstallFailed",
            "ReleaseSendFailed",
            "ResumeFailed",
        ]:
            self.assertIn(required, self.trace)
        for required in [
            "validate_descriptor_set(&request, inherited_descriptors)",
            "pair[0] == pair[1]",
            "actual != required",
        ]:
            self.assertIn(required, self.trace + self.supervisor)
        self.assertIn("if result != process_id", self.sys)
        self.assertIn('io::Error::other("unexpected traced wait status")', self.sys)


if __name__ == "__main__":
    unittest.main()
