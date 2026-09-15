import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
LIFECYCLE_ASSUMPTION = (
    ROOT / "assumptions/PBR-DIAGNOSTIC-LIFECYCLE-CHECK-AX-021.toml"
)
LIFECYCLE_RUNTIME_ASSUMPTION = (
    ROOT / "assumptions/PBR-DIAGNOSTIC-LIFECYCLE-AX-023.toml"
)
CLAIM = ROOT / "claims/PBR-OBSERVER-028.toml"
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
CGROUP = ROOT / "crates/proofbound-runtime-linux/src/cgroup.rs"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
LAUNCHER = ROOT / "crates/proofbound-runtime-linux/src/launcher.rs"
RESOLVE = ROOT / "crates/proofbound-runtime-linux/src/resolve.rs"
SUPERVISOR = ROOT / "crates/proofbound-runtime-linux/src/supervisor.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
UNIT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-lifecycle.toml"
CONTRACT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-lifecycle-contract.toml"


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


def signature(implementation_source: str) -> str:
    return implementation_source[: implementation_source.index("{")]


def assert_lifecycle_contract(
    trace: str,
    adapter: str,
    cgroup: str,
    linux_lib: str,
    adapter_lib: str,
) -> None:
    prepare = implementation(trace, "pub fn prepare_traced_launcher")
    spawn = implementation(trace, "pub fn spawn(mut self)")
    session = structure(trace, "TraceSession")
    finish_terminal = implementation(trace, "fn finish_terminal(")
    active = implementation(trace, "impl ActiveTrace")
    natural_finish = implementation(active, "pub fn finish(mut self)")
    next_event = implementation(active, "pub fn next_event(&mut self)")
    begin_termination = implementation(active, "pub fn begin_termination(mut self)")
    drain = implementation(active, "pub fn terminate_and_drain(self)")
    complete_drain = implementation(active, "fn complete_drain(")
    draining_trace = implementation(trace, "impl DrainingTrace")
    drain_finish = implementation(draining_trace, "pub fn finish(mut self)")
    deadline = implementation(trace, "impl TraceDeadline")
    configured = implementation(cgroup, "pub fn revalidate_resources(")
    adapter_active = implementation(adapter, "impl ActiveObserver")
    adapter_next = implementation(adapter_active, "pub fn next_event(mut self)")
    adapter_drain = implementation(adapter, "impl DrainingObserver")
    adapter_finish = implementation(adapter_drain, "pub fn finish(mut self)")
    lifecycle_type_test = implementation(
        trace,
        "fn diagnostic_lifecycle_does_not_accept_refreshable_deadlines",
    )

    for term in [
        "cgroup: FreshCgroup",
        "limits: ResourceLimits",
        ".revalidate_resources()",
        "request.identity().cgroup_id() != cgroup.identity()",
        "configured.processes() != limits.processes()",
        "Some(configured.memory()) != limits.memory()",
        "Some(configured.swap()) != limits.swap()",
        "configured.memory_oom_group() != 1",
    ]:
        if term not in prepare:
            raise AssertionError(f"missing exact cgroup binding term: {term}")

    before(spawn, "let deadline = TraceDeadline::after", ".command\n            .spawn()")
    before(spawn, ".revalidate_resources()", "let deadline = TraceDeadline::after")
    before(spawn, ".place_process(process.get())", "TraceStreamReaders::start")
    before(spawn, ".place_process(process.get())", "Ok(SpawnedTrace")
    for term in ["cgroup: Some(self.cgroup)", "deadline,"]:
        if term not in spawn:
            raise AssertionError(f"spawn did not retain lifecycle state: {term}")
    before(session, "_child: TraceChild", "cgroup: Option<FreshCgroup>")
    before(session, "cgroup: Option<FreshCgroup>", "streams: TraceStreamReaders")

    if "pub struct TraceDeadline" in trace:
        raise AssertionError("the execution deadline is public")
    if "TraceDeadline" in linux_lib or "TraceDeadline" in adapter_lib:
        raise AssertionError("the execution deadline is re-exported")
    for method in [
        "wait_for_initial_exec_stop",
        "continue_to_launcher_pause",
        "continue_for_boundary",
        "receive_acknowledgement_and_stop",
        "install_options",
        "release",
        "next_event",
        "begin_termination",
        "DrainingTrace::finish",
        "terminate_and_drain",
    ]:
        if method not in lifecycle_type_test:
            raise AssertionError(f"missing typed deadline-closure witness: {method}")
    if lifecycle_type_test.count("TraceDeadline") != 0:
        raise AssertionError("typed lifecycle method accepts a deadline")

    initial_wait = implementation(trace, "pub fn wait_for_initial_exec_stop(self)")
    launcher_continue = implementation(trace, "pub fn continue_to_launcher_pause(self)")
    boundary_continue = implementation(trace, "pub fn continue_for_boundary(self)")
    acknowledgement = implementation(trace, "pub fn receive_acknowledgement_and_stop(")
    install_options = implementation(trace, "pub fn install_options(self)")
    release = implementation(trace, "pub fn release(")
    for step in [
        initial_wait,
        launcher_continue,
        boundary_continue,
        acknowledgement,
        install_options,
        release,
    ]:
        if "self.session.deadline" not in step:
            raise AssertionError("setup step does not use the stored execution deadline")
        if "TraceDeadline" in signature(step):
            raise AssertionError("setup step accepts a replacement deadline")
    for step in [
        launcher_continue,
        boundary_continue,
        acknowledgement,
        install_options,
        release,
    ]:
        if "if self.session.deadline.expired()" not in step:
            raise AssertionError("effectful setup step can proceed after deadline expiry")
    before(release, "self.session.revalidate_cgroup()?", ".send(&LauncherMessage::ExecRelease")
    if "self.session.deadline" not in next_event:
        raise AssertionError("active observation does not use the stored execution deadline")
    before(next_event, "self.session.deadline.expired()", "self.held_process.take()")
    before(next_event, "self.session.deadline.expired()", "trace_wait_event_nonblocking")
    for term in ["TRACE_DRAIN_TIMEOUT", "checked_add(TRACE_DRAIN_TIMEOUT)"]:
        if term not in trace and term not in deadline:
            raise AssertionError(f"missing bounded cleanup deadline term: {term}")
    before(
        begin_termination,
        "let deadline = TraceDeadline::cleanup()?",
        "self.signal_all_process_groups()",
    )
    before(begin_termination, "self.signal_all_process_groups()", "Ok(DrainingTrace")
    if "self.begin_termination()?.finish()" not in drain:
        raise AssertionError("combined drain bypasses immediate termination typestate")
    if "self.deadline.expired()" not in drain_finish:
        raise AssertionError("forced drain does not enforce its cleanup deadline")
    if "while !self.trace.processes.is_empty()" not in drain_finish:
        raise AssertionError("forced drain does not empty the exact retained trace tree")

    for term in [
        ".cgroup\n            .take()",
        ".finish()",
        "ResourceObservation::Complete(resources)",
        "ResourceObservation::Legacy | ResourceObservation::Incomplete(_)",
        "TraceObservationError::ResourceObservationIncomplete",
        "output: self.streams.finish()?",
    ]:
        if term not in finish_terminal:
            raise AssertionError(f"missing terminal resource gate: {term}")
    before(finish_terminal, ".finish()", "self.streams.finish()?")
    before(natural_finish, "if !self.is_drained()", "self.session.finish_terminal()?")
    before(
        complete_drain,
        "if self.tree_reconciliation_failed",
        "self.session.finish_terminal()?",
    )
    before(adapter_next, "self.trace.finish()?.into_terminal()", "self.protocol.finish()?")
    if adapter_next.count("self.trace.begin_termination()?") != 2:
        raise AssertionError("adapter does not start termination before returning drain state")
    before(
        adapter_finish,
        "report.into_terminal()",
        "self.protocol.confirm_tree_drained()?",
    )
    before(
        adapter_finish,
        "self.protocol.confirm_tree_drained()?",
        "self.protocol.finish()?",
    )
    if adapter.count("terminal: TraceTerminalCapture") != 1:
        raise AssertionError("completed adapter terminal ownership is not singular")

    for variant in [
        "CgroupIdentityMismatch",
        "CgroupPlacementFailed",
        "ResourceCleanupFailed",
        "ResourceObservationIncomplete",
        "StreamReadFailed",
    ]:
        if variant not in trace:
            raise AssertionError(f"missing closed lifecycle failure: {variant}")
    for term in [
        'read_control(&self.descriptor, "pids.max")',
        'read_control(&self.descriptor, "memory.max")',
        'read_control(&self.descriptor, "memory.swap.max")',
        'read_control(&self.descriptor, "memory.oom.group")',
        "self.configured_resources != Some(observed)",
        "self.process_limit != observed.processes()",
        "Err(CgroupError::UnsupportedOperatingSystem)",
    ]:
        if term not in configured:
            raise AssertionError(f"cgroup resource revalidation is not closed: {term}")


EXPECTED_BODIES = {
    "active-begin-termination": "1674fee75a1464bc9c3a2444044cc8774cb33b80e0a64d2b08050101da6aa090",
    "active-drain": "93fb4ec3a1af8abcc2ad31dba4c23eb498b43a743137cbe3d0d1e04afdbd6ee3",
    "active-finish": "b1feb2846c2a896e67a10874aa44e8f1675c76f8ba992d06a232538ec191324d",
    "active-next": "975c888931c1f6bde654679101536fbb522cbc770347fdc0bbf8de975657baf0",
    "adapter-drain": "5f5ee9835cf2bacc73f10cd50b0e9a20f6d91d23c4d2905c84af181e22d05848",
    "adapter-next": "e7d57ca91f85832b6fb3310418e2a0df9ee0fb4b40fa29203bac66423c8620cb",
    "revalidate-resources": "30ecf689ab0e1c1846169130bf9c5efc2ef19d1208420023816df84ddee06fdf",
    "finish-terminal": "aae17be317674057b4cd11a1e95096d69844726a200f6a4ae121affb2226311a",
    "draining-trace-finish": "e0e9e0c0fb13e0e79f1ed7aa456102459d5d82cb39db9e8d421ec4020caafb13",
    "prepare": "cae95d38b19bbecbdf2d58053b5ec66a3d34afacfbe177cf585bc60a772ffc15",
    "spawn": "5b97c0af4ae4000f43dd8b7eb1288edb03bbc61df89f77f0c332c81fbf16a071",
}
EXPECTED_FILES = {
    "adapter": "72b8868fb0d50a65e4306f754051dec1e3aace4ee7da33825bb990f4d7bab70b",
    "adapter-lib": "ccad4545cfd41802c32d66a692d65aca9a69d0e59b0a3cb7c5c34da42830a198",
    "adapter-manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "authority": "9d1945b590a3a9f44f6af95d3090ad0a8d1bc0cfa601c35273cd0a72c86cbddc",
    "claim": "2e21b4a60d498fadbf4e64ca227f0b42b455b7a6028cd338ed0c7a4335ca3fb5",
    "contract-evidence": "c97aa661d101a8cd3dcc01ad7622b7a56a73de0f11235c9aa6639b50a81447cd",
    "core-manifest": "0d22823a1d4f397fb58693c7d9fe7498969ce242b5da0f372d8cc8f55f960b9b",
    "core-lib": "2039d8c789844cddaaabbf432a0a6ef465f77300577f3b57922d7bcbcc930450",
    "cgroup": "ce465e6ddba11a0d54db6e964cc8fc3c24ba54a64424ca4353aa038094db010e",
    "diagnose-artifact": "ad7cce45d286623dcfd55c21189cb7d58e29f1943960d0a061d6f85c2640baa3",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "diagnose-observer": "e6cfb0a92d7bf7e235c7fac8180f488b7b1d9474986791fac4adf2917dae7d12",
    "launcher": "5b2f251091b01fe9fa9bfb4018fac4971f22c9a7d55a5a92f5fdc24ca2673b83",
    "lifecycle-assumption": "ee12854496d97ecce949d1ff85067003a2fc48880d02d2850cff6fe807090017",
    "lifecycle-runtime-assumption": "8f2f8e1674a1329b808bfe605208bdb190557a0eb5700a1f3c7f2c3f3301cae3",
    "linux-lib": "47ef2cdd61b7c0854f0ee9fcfb5d32ffcebfec5b5820477636a3d513a7ccf33d",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "lock": "376572c5d111f5ea72e38667b5813a7c051e9fa128d5af355468e5294889a0c6",
    "root-manifest": "1ea75287f62129c6b15038b0c45df42e616fc4c92e59e61bc03358746fd5d7d6",
    "receipt": "fc27edf189014a49af8af380902fe90b12cbbd71a2b49301064b589c8a4c4024",
    "resolve": "66ab088fbadbff3b71deb6edc76d3f7069932949f6cdde08f1fa3cf133892eca",
    "supervisor": "5f1b80181b01c3ea189643995617aeab60f390c1f5fc6930cf0acd577b88cdd8",
    "sys": "c7433f4485aa12829c87ef10210fa766676bc24729361e0a82ac93a2267eb06f",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "3c766e2767d8622ee40e45825b863c75d3be49aa52aa62b6dd41bd311da6bd07",
    "unit-evidence": "2507f5c08798117203e5d8e543986eb22f6e6a38742738b7bdc4736c8e19c9bb",
}


class DiagnosticLifecycleContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = TRACE.read_text()
        self.adapter = ADAPTER.read_text()
        self.cgroup = CGROUP.read_text()
        self.linux_lib = LINUX_LIB.read_text()
        self.adapter_lib = ADAPTER_LIB.read_text()

    def test_exact_cgroup_deadline_and_terminal_order(self) -> None:
        assert_lifecycle_contract(
            self.trace,
            self.adapter,
            self.cgroup,
            self.linux_lib,
            self.adapter_lib,
        )

    def test_lifecycle_mutations_are_rejected(self) -> None:
        mutations = [
            (
                "memory-control mismatch accepted",
                self.trace.replace(
                    "Some(configured.memory()) != limits.memory()",
                    "false",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "execution deadline replaced by cleanup deadline",
                self.trace.replace(
                    "let deadline = TraceDeadline::after(Duration::from_millis(self.wall_time.milliseconds()))?;",
                    "let deadline = TraceDeadline::cleanup().map_err(|_| TraceStartupError::DeadlineInvalid)?;",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "cgroup dropped after stream readers",
                self.trace.replace(
                    "cgroup: Option<FreshCgroup>,\n    streams: TraceStreamReaders,",
                    "streams: TraceStreamReaders,\n    cgroup: Option<FreshCgroup>,",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "spawn trusts cached cgroup controls",
                self.trace.replace(
                    "self.cgroup\n            .revalidate_resources()\n"
                    "            .map_err(|_| TraceStartupError::CgroupIdentityMismatch)?;",
                    "",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "setup expiry bypassed",
                self.trace.replace(
                    "if self.session.deadline.expired() {",
                    "if false {",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "incomplete resource observation accepted",
                self.trace.replace(
                    "ResourceObservation::Legacy | ResourceObservation::Incomplete(_)",
                    "ResourceObservation::Legacy",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "publication precedes terminal capture",
                self.trace,
                self.adapter.replace(
                    "let terminal = self.trace.finish()?.into_terminal();\n"
                    "            let publication = self.protocol.finish()?;",
                    "let publication = self.protocol.finish()?;\n"
                    "            let terminal = self.trace.finish()?.into_terminal();",
                    1,
                ),
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "adapter returns drain state before signalling",
                self.trace,
                self.adapter.replace(
                    "let trace = self.trace.begin_termination()?;",
                    "let trace = self.trace.terminate_and_drain()?;",
                    1,
                ),
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
        ]
        for name, trace, adapter, cgroup, linux_lib, adapter_lib in mutations:
            mutation = hashlib.sha256(
                (trace + adapter + cgroup + linux_lib + adapter_lib).encode()
            ).hexdigest()[:12]
            with self.subTest(name=name, mutation=mutation):
                with self.assertRaises(AssertionError):
                    assert_lifecycle_contract(
                        trace,
                        adapter,
                        cgroup,
                        linux_lib,
                        adapter_lib,
                    )

    def test_exact_load_bearing_source(self) -> None:
        active = implementation(self.trace, "impl ActiveTrace")
        adapter_active = implementation(self.adapter, "impl ActiveObserver")
        adapter_drain = implementation(self.adapter, "impl DrainingObserver")
        bodies = {
            "active-begin-termination": implementation(
                active,
                "pub fn begin_termination(mut self)",
            ),
            "active-drain": implementation(active, "pub fn terminate_and_drain(self)"),
            "active-finish": implementation(active, "pub fn finish(mut self)"),
            "active-next": implementation(active, "pub fn next_event(&mut self)"),
            "adapter-drain": implementation(adapter_drain, "pub fn finish(mut self)"),
            "adapter-next": implementation(adapter_active, "pub fn next_event(mut self)"),
            "revalidate-resources": implementation(
                self.cgroup,
                "pub fn revalidate_resources(",
            ),
            "finish-terminal": implementation(self.trace, "fn finish_terminal("),
            "draining-trace-finish": implementation(
                implementation(self.trace, "impl DrainingTrace"),
                "pub fn finish(mut self)",
            ),
            "prepare": implementation(self.trace, "pub fn prepare_traced_launcher"),
            "spawn": implementation(self.trace, "pub fn spawn(mut self)"),
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
            "claim": CLAIM,
            "contract-evidence": CONTRACT_EVIDENCE,
            "core-manifest": CORE_MANIFEST,
            "core-lib": CORE_LIB,
            "cgroup": CGROUP,
            "lifecycle-assumption": LIFECYCLE_ASSUMPTION,
            "lifecycle-runtime-assumption": LIFECYCLE_RUNTIME_ASSUMPTION,
            "diagnose-artifact": DIAGNOSE_ARTIFACT,
            "diagnose-lib": DIAGNOSE_LIB,
            "diagnose-manifest": DIAGNOSE_MANIFEST,
            "diagnose-observer": DIAGNOSE_OBSERVER,
            "launcher": LAUNCHER,
            "linux-lib": LINUX_LIB,
            "linux-manifest": LINUX_MANIFEST,
            "lock": LOCK,
            "root-manifest": ROOT_MANIFEST,
            "receipt": RECEIPT,
            "resolve": RESOLVE,
            "supervisor": SUPERVISOR,
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
