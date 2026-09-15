import re
import unittest
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 evidence host
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
ADAPTER = ROOT / "crates/proofbound-runtime-diagnose-linux/src/adapter.rs"
ADAPTER_LIB = ROOT / "crates/proofbound-runtime-diagnose-linux/src/lib.rs"
ADAPTER_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose-linux/Cargo.toml"
DIAGNOSE_LIB = ROOT / "crates/proofbound-runtime-diagnose/src/lib.rs"
DIAGNOSE_MANIFEST = ROOT / "crates/proofbound-runtime-diagnose/Cargo.toml"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
LINUX_MANIFEST = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
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


def enum_structure(source: str, type_name: str) -> str:
    start = source.index(f"pub enum {type_name}")
    end = source.index("\n}", start)
    return source[start:end]


def compact(source: str) -> str:
    return re.sub(r"\s+", "", source)


def private_fields(source: str, type_name: str) -> list[str]:
    body = structure(source, type_name).split("{", 1)[1]
    return [line.strip() for line in body.splitlines() if ":" in line]


def public_function_signatures(source: str) -> list[str]:
    return [
        compact(signature[:-1])
        for signature in re.findall(r"pub\s+(?:const\s+)?fn\s+[^\{]+\{", source)
    ]


def all_function_signatures(source: str) -> list[str]:
    return [
        compact(signature[:-1])
        for signature in re.findall(
            r"(?m)^\s*((?:pub\s+)?(?:const\s+)?fn\s+[^\{]+\{)", source
        )
    ]


EXPECTED_PUBLIC_FUNCTIONS = [
    "pubfnprepare_observer<'descriptor>(launcher:&'descriptorResolvedFile,"
    "request:InstallRequest,inherited_descriptors:&[BorrowedFd<'descriptor>],"
    "architecture:Architecture,landlock_abi:NonZeroU32,bounds:ObservationBounds,)"
    "->Result<PreparedObserver<'descriptor>,ObserverAdapterError>",
    "pubfnspawn(self)->Result<SpawnedObserver,ObserverAdapterError>",
    "pubconstfnprocess(&self)->TraceProcessId",
    "pubfnwait_for_initial_exec_stop(self,deadline:TraceDeadline,)"
    "->Result<InitialObserver,ObserverAdapterError>",
    "pubfncontinue_to_launcher_pause(self,deadline:TraceDeadline,)"
    "->Result<LauncherPausedObserver,ObserverAdapterError>",
    "pubconstfnprocess(&self)->TraceProcessId",
    "pubfncontinue_for_boundary(self)"
    "->Result<BoundaryRunningObserver,ObserverAdapterError>",
    "pubfnreceive_acknowledgement_and_stop(self,deadline:TraceDeadline,)"
    "->Result<AcknowledgedObserver,ObserverAdapterError>",
    "pubfninstall_options(self)->Result<ReadyObserver,ObserverAdapterError>",
    "pubfnrelease(self)->Result<ActiveObserver,ObserverAdapterError>",
    "pubconstfnroot(&self)->TraceProcessId",
    "pubconstfnprotocol(&self)->&ObserverProtocol",
    "pubconstfncode(self)->&'staticstr",
]

EXPECTED_ADAPTER_LIB = """#![deny(unsafe_code)]

//! Owns the separate effectful Linux diagnostic-observer path.

mod adapter;

pub use adapter::{
    prepare_observer, AcknowledgedObserver, ActiveObserver, BoundaryRunningObserver,
    InitialObserver, LauncherPausedObserver, ObserverAdapterError, PreparedObserver, ReadyObserver,
    SpawnedObserver,
};
pub use proofbound_runtime_linux::{TraceDeadline, TraceProcessId};
"""

EXPECTED_ADAPTER_MANIFEST = """[package]
name = "proofbound-runtime-diagnose-linux"
description = "Separate Linux diagnostic observer for Proofbound Runtime"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
proofbound-runtime-diagnose.workspace = true
proofbound-runtime-linux = { workspace = true, features = ["diagnostic-observer"] }
"""

EXPECTED_DIAGNOSE_MANIFEST = """[package]
name = "proofbound-runtime-diagnose"
description = "Non-production diagnostic artifact construction for Proofbound Runtime"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
publish = false

[dependencies]
proofbound-runtime-core.workspace = true
serde.workspace = true
serde_json.workspace = true
sha2.workspace = true
"""

EXPECTED_LINUX_MANIFEST = """[package]
name = "proofbound-runtime-linux"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true
publish.workspace = true

[features]
default = []
diagnostic-observer = []

[dependencies]
proofbound-runtime-core.workspace = true
sha2.workspace = true

[target.'cfg(target_os = "linux")'.dependencies]
libc.workspace = true

[dev-dependencies]
serde.workspace = true
toml.workspace = true
"""


class DiagnosticObserverAdapterContractTests(unittest.TestCase):
    def setUp(self):
        self.adapter = ADAPTER.read_text()
        self.adapter_lib = ADAPTER_LIB.read_text()
        self.diagnose_lib = DIAGNOSE_LIB.read_text()
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()

    def test_preparation_binds_validated_bounds_to_one_trace(self):
        prepare_start = self.adapter.index("pub fn prepare_observer")
        prepare_end = self.adapter.index("\n}\n\nimpl PreparedObserver", prepare_start)
        prepare = self.adapter[prepare_start:prepare_end]
        compact_prepare = compact(prepare)
        self.assertLess(
            compact_prepare.index("bounds.validate()"),
            compact_prepare.index("prepare_traced_launcher"),
        )
        self.assertIn("PreparedObserver { trace, bounds }", prepare)
        self.assertEqual(
            private_fields(self.adapter, "PreparedObserver"),
            [
                "trace: PreparedTraceCommand<'descriptor>,",
                "bounds: ObservationBounds,",
            ],
        )
        self.assertEqual(
            private_fields(self.adapter, "SpawnedObserver"),
            ["trace: SpawnedTrace,", "bounds: ObservationBounds,"],
        )

    def test_states_move_one_private_trace_and_protocol_pair(self):
        for state, trace_type in [
            ("InitialObserver", "InitialExecStop"),
            ("LauncherPausedObserver", "LauncherPause"),
            ("BoundaryRunningObserver", "BoundaryRunning"),
            ("AcknowledgedObserver", "AcknowledgedTraceStop"),
            ("ReadyObserver", "TraceReady"),
            ("ActiveObserver", "ActiveTrace"),
        ]:
            self.assertEqual(
                private_fields(self.adapter, state),
                [f"trace: {trace_type},", "protocol: ObserverProtocol,"],
                state,
            )
            declaration = self.adapter[: self.adapter.index(f"pub struct {state}")]
            derive = declaration.rsplit("#[derive(", 1)[-1].split(")]", 1)[0]
            self.assertNotIn("Copy", derive, state)
            self.assertNotIn("Clone", derive, state)

        self.assertEqual(
            public_function_signatures(self.adapter),
            EXPECTED_PUBLIC_FUNCTIONS,
        )
        self.assertEqual(
            all_function_signatures(self.adapter),
            EXPECTED_PUBLIC_FUNCTIONS
            + [
                "fnfrom(error:TraceStartupError)->Self",
                "fnfrom(error:ObserverProtocolError)->Self",
                "fnfmt(&self,formatter:&mutfmt::Formatter<'_>)->fmt::Result",
            ],
        )
        public_types = re.findall(r"\bpub\s+(?:struct|enum)\s+([A-Za-z_][A-Za-z0-9_]*)", self.adapter)
        self.assertEqual(
            public_types,
            [
                "PreparedObserver",
                "SpawnedObserver",
                "InitialObserver",
                "LauncherPausedObserver",
                "BoundaryRunningObserver",
                "AcknowledgedObserver",
                "ReadyObserver",
                "ActiveObserver",
                "ObserverAdapterError",
            ],
        )
        self.assertNotRegex(
            self.adapter,
            r"\bpub\s+(?:use|type|mod|trait|static|union|unsafe|async|extern)\b",
        )
        self.assertNotRegex(self.adapter, r"\bpub\s+const\s+(?!fn\b)")
        self.assertNotIn("macro_rules!", self.adapter)
        self.assertNotIn("#[macro_export]", self.adapter)
        self.assertNotRegex(self.adapter, r"(?m)^\s*(?:pub\s+)?mod\s+")
        self.assertNotRegex(
            self.adapter,
            r"\b[A-Za-z_][A-Za-z0-9_]*!\s*[\(\{\[]",
        )
        self.assertEqual(
            re.findall(r"#\[[^\]]+\]", self.adapter),
            [
                "#[derive(Debug)]",
                "#[derive(Debug)]",
                "#[must_use]",
                "#[derive(Debug)]",
                "#[derive(Debug)]",
                "#[must_use]",
                "#[derive(Debug)]",
                "#[derive(Debug)]",
                "#[derive(Debug)]",
                "#[derive(Debug)]",
                "#[must_use]",
                "#[must_use]",
                "#[derive(Clone, Copy, Debug, Eq, PartialEq)]",
                "#[must_use]",
            ],
        )

        implementation_headers = [
            compact(header)
            for header in re.findall(r"(?m)^impl\s+([^\{]+)\{", self.adapter)
        ]
        self.assertEqual(
            implementation_headers,
            [
                "PreparedObserver<'_>",
                "SpawnedObserver",
                "InitialObserver",
                "LauncherPausedObserver",
                "BoundaryRunningObserver",
                "AcknowledgedObserver",
                "ReadyObserver",
                "ActiveObserver",
                "ObserverAdapterError",
                "From<TraceStartupError>forObserverAdapterError",
                "From<ObserverProtocolError>forObserverAdapterError",
                "fmt::DisplayforObserverAdapterError",
                "std::error::ErrorforObserverAdapterError",
            ],
        )
        error_body = enum_structure(self.adapter, "ObserverAdapterError").split("{", 1)[1]
        error_variants = [
            line.strip()
            for line in error_body.splitlines()
            if line.strip() and not line.strip().startswith("///")
        ]
        self.assertEqual(
            error_variants,
            [
                "BoundsInvalid,",
                "Trace(TraceStartupError),",
                "Protocol(ObserverProtocolError),",
            ],
        )
        self.assertNotIn("&mut ObserverProtocol", self.adapter)

    def test_effects_and_pure_transitions_have_one_closed_order(self):
        initial = implementation(self.adapter, "SpawnedObserver")
        compact_initial = compact(initial)
        exact_process_flow = (
            "letprocess=self.trace.process();"
            "lettrace=self.trace.wait_for_initial_exec_stop(deadline)?;"
            "letroot=DiagnosticProcessId::new(process.get())?;"
        )
        self.assertIn(exact_process_flow, compact_initial)
        self.assertEqual(
            compact_initial.count("DiagnosticProcessId::new(process.get())"), 1
        )
        self.assertLess(
            compact_initial.index("DiagnosticProcessId::new(process.get())"),
            compact_initial.index("ObserverProtocol::new(root,self.bounds)"),
        )
        self.assertLess(
            compact_initial.index("ObserverProtocol::new(root,self.bounds)"),
            compact_initial.index("attach_root"),
        )

        boundary = implementation(self.adapter, "BoundaryRunningObserver")
        self.assertLess(
            boundary.index("receive_acknowledgement_and_stop"),
            boundary.index("record_boundary_ready"),
        )

        acknowledged = implementation(self.adapter, "AcknowledgedObserver")
        compact_acknowledged = compact(acknowledged)
        exact_option_flow = (
            "lettrace=self.trace.install_options()?;"
            "letoptions=DiagnosticTraceOptions::from_bits(trace.options())?;"
            "letmutprotocol=self.protocol;"
            "protocol.enable_trace_options(options)?;"
        )
        self.assertIn(exact_option_flow, compact_acknowledged)
        self.assertNotIn("DiagnosticTraceOptions::required()", self.adapter)

        ready = implementation(self.adapter, "ReadyObserver")
        self.assertLess(ready.index("release_target"), ready.index("self.trace.release"))
        self.assertIn("Ok(ActiveObserver { trace, protocol })", ready)

    def test_adapter_is_separate_and_hides_raw_trace_typestates(self):
        self.assertNotIn("unsafe", self.adapter)
        self.assertEqual(self.adapter_lib, EXPECTED_ADAPTER_LIB)
        public_uses = [
            compact(statement)
            for statement in re.findall(r"pub use [^;]+;", self.adapter_lib, re.DOTALL)
        ]
        self.assertEqual(
            public_uses,
            [
                "pubuseadapter::{prepare_observer,AcknowledgedObserver,ActiveObserver,"
                "BoundaryRunningObserver,InitialObserver,LauncherPausedObserver,"
                "ObserverAdapterError,PreparedObserver,ReadyObserver,SpawnedObserver,};",
                "pubuseproofbound_runtime_linux::{TraceDeadline,TraceProcessId};",
            ],
        )
        self.assertNotIn("*", "".join(public_uses))
        self.assertNotRegex(
            self.adapter_lib,
            r"\bpub\s+(?:mod|type|trait|struct|enum|fn|const|static|macro)\b",
        )
        self.assertNotRegex(
            self.adapter_lib,
            r"\b[A-Za-z_][A-Za-z0-9_]*!\s*[\(\{\[]",
        )
        self.assertEqual(ADAPTER_MANIFEST.read_text(), EXPECTED_ADAPTER_MANIFEST)
        self.assertEqual(DIAGNOSE_MANIFEST.read_text(), EXPECTED_DIAGNOSE_MANIFEST)
        self.assertEqual(LINUX_MANIFEST.read_text(), EXPECTED_LINUX_MANIFEST)

        root_manifest = ROOT_MANIFEST.read_text()
        root_config = tomllib.loads(root_manifest)
        workspace = root_config["workspace"]
        for member in [
            "crates/proofbound-runtime-diagnose",
            "crates/proofbound-runtime-diagnose-linux",
            "crates/proofbound-runtime-linux",
        ]:
            self.assertIn(member, workspace["members"])
        for dependency, path in {
            "proofbound-runtime-diagnose": "crates/proofbound-runtime-diagnose",
            "proofbound-runtime-diagnose-linux": "crates/proofbound-runtime-diagnose-linux",
            "proofbound-runtime-linux": "crates/proofbound-runtime-linux",
        }.items():
            self.assertEqual(workspace["dependencies"][dependency], {"path": path})
        self.assertNotRegex(root_manifest, r"(?m)^\[(?:patch|replace)(?:\.|\])")

        self.assertEqual(self.diagnose_lib.count("pub mod artifact;"), 1)
        self.assertEqual(self.diagnose_lib.count("pub mod observer;"), 1)
        self.assertNotIn("#[path", self.diagnose_lib)
        spawned_trace = implementation(self.trace, "SpawnedTrace")
        self.assertIn(
            "pubconstfnprocess(&self)->TraceProcessId{self.session.process}",
            compact(spawned_trace),
        )
        self.assertNotIn("-> &mut Child", self.trace)
        for manifest in PRODUCTION_MANIFESTS:
            source = manifest.read_text()
            self.assertNotIn("proofbound-runtime-diagnose-linux", source, manifest)
            self.assertNotIn("proofbound-runtime-diagnose", source, manifest)

    def test_exact_installed_option_bits_cross_the_pure_validation_boundary(self):
        install_start = self.sys.index("pub(crate) fn install_diagnostic_trace_options")
        install_end = self.sys.index("\n}\n", install_start)
        install = compact(self.sys[install_start:install_end])
        self.assertIn("->io::Result<u32>", install)
        self.assertIn("REQUIRED_DIAGNOSTIC_TRACE_OPTIONSasusize", install)
        self.assertIn("Ok(REQUIRED_DIAGNOSTIC_TRACE_OPTIONS)", install)

        acknowledged_trace = compact(implementation(self.trace, "AcknowledgedTraceStop"))
        self.assertIn(
            "letoptions=crate::sys::install_diagnostic_trace_options("
            "self.session.process.get()).map_err(|_|"
            "TraceStartupError::OptionsInstallFailed)?;",
            acknowledged_trace,
        )
        self.assertIn("Ok(TraceReady{session:self.session,options,})", acknowledged_trace)
        self.assertEqual(
            private_fields(self.trace, "TraceReady"),
            ["session: TraceSession,", "options: u32,"],
        )
        ready_trace = implementation(self.trace, "TraceReady")
        self.assertIn(
            "pubconstfnoptions(&self)->u32{self.options}",
            compact(ready_trace),
        )


if __name__ == "__main__":
    unittest.main()
