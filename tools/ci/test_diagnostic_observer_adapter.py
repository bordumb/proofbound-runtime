import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ADAPTER = ROOT / "crates/proofbound-runtime-diagnose-linux/src/adapter.rs"
ADAPTER_LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
ADAPTER_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
PRODUCTION_MANIFESTS = [
    ROOT / "crates/proofbound-runtime-cli/Cargo.toml",
    ROOT / "crates/proofbound-runtime-linux/Cargo.toml",
]


def implementation(source: str, type_name: str) -> str:
    start = source.index(f"impl {type_name} {{")
    next_impl = source.find("\nimpl ", start + 1)
    return source[start:] if next_impl == -1 else source[start:next_impl]


def structure(source: str, type_name: str) -> str:
    start = source.index(f"pub struct {type_name}")
    end = source.index("\n}", start)
    return source[start:end]


class DiagnosticObserverAdapterContractTests(unittest.TestCase):
    def setUp(self):
        self.adapter = ADAPTER.read_text()
        self.adapter_lib = ADAPTER_LIB.read_text()
        self.trace = TRACE.read_text()

    def test_preparation_binds_validated_bounds_to_one_trace(self):
        prepare_start = self.adapter.index("pub fn prepare_observer")
        prepare_end = self.adapter.index("\n}\n\nimpl PreparedObserver", prepare_start)
        prepare = self.adapter[prepare_start:prepare_end]
        compact = re.sub(r"\s+", "", prepare)
        self.assertLess(
            compact.index("bounds.validate()"),
            compact.index("prepare_traced_launcher"),
        )
        self.assertIn("PreparedObserver { trace, bounds }", prepare)
        prepared = structure(self.adapter, "PreparedObserver")
        self.assertIn("trace: PreparedTraceCommand", prepared)
        self.assertIn("bounds: ObservationBounds", prepared)
        self.assertNotIn("protocol: ObserverProtocol", prepared)

    def test_states_move_one_private_trace_and_protocol_pair(self):
        for state, trace_type in [
            ("InitialObserver", "InitialExecStop"),
            ("LauncherPausedObserver", "LauncherPause"),
            ("BoundaryRunningObserver", "BoundaryRunning"),
            ("AcknowledgedObserver", "AcknowledgedTraceStop"),
            ("ReadyObserver", "TraceReady"),
            ("ActiveObserver", "ActiveTrace"),
        ]:
            body = structure(self.adapter, state)
            self.assertIn(f"trace: {trace_type}", body, state)
            self.assertIn("protocol: ObserverProtocol", body, state)
            declaration = self.adapter[: self.adapter.index(f"pub struct {state}")]
            derive = declaration.rsplit("#[derive(", 1)[-1].split(")]", 1)[0]
            self.assertNotIn("Copy", derive, state)
            self.assertNotIn("Clone", derive, state)

        public_functions = re.findall(r"pub (?:const )?fn ([a-z_]+)", self.adapter)
        self.assertNotIn("into_parts", public_functions)
        self.assertNotIn("trace_mut", public_functions)
        self.assertNotIn("protocol_mut", public_functions)

    def test_effects_and_pure_transitions_have_one_closed_order(self):
        initial = implementation(self.adapter, "SpawnedObserver")
        self.assertLess(
            initial.index("wait_for_initial_exec_stop"),
            initial.index("ObserverProtocol::new"),
        )
        self.assertLess(initial.index("ObserverProtocol::new"), initial.index("attach_root"))

        boundary = implementation(self.adapter, "BoundaryRunningObserver")
        self.assertLess(
            boundary.index("receive_acknowledgement_and_stop"),
            boundary.index("record_boundary_ready"),
        )

        acknowledged = implementation(self.adapter, "AcknowledgedObserver")
        self.assertLess(acknowledged.index("install_options"), acknowledged.index("enable_trace_options"))
        self.assertIn("DiagnosticTraceOptions::required()", acknowledged)

        ready = implementation(self.adapter, "ReadyObserver")
        self.assertLess(ready.index("release_target"), ready.index("self.trace.release"))
        self.assertIn("Ok(ActiveObserver { trace, protocol })", ready)

    def test_adapter_is_separate_and_hides_raw_trace_typestates(self):
        self.assertNotIn("unsafe", self.adapter)
        self.assertNotIn("pub use proofbound_runtime_linux::trace", self.adapter_lib)
        self.assertIn("proofbound-runtime-diagnose.workspace = true", ADAPTER_MANIFEST.read_text())
        self.assertIn("pub const fn process(&self) -> TraceProcessId", self.trace)
        self.assertNotIn("-> &mut Child", self.trace)
        for manifest in PRODUCTION_MANIFESTS:
            source = manifest.read_text()
            self.assertNotIn("proofbound-runtime-diagnose-linux", source, manifest)
            self.assertNotIn("proofbound-runtime-diagnose", source, manifest)


if __name__ == "__main__":
    unittest.main()
