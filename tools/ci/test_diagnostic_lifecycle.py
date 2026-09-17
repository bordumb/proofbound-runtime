import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ROOT_MANIFEST = ROOT / "Cargo.toml"
LOCK = ROOT / "Cargo.lock"
TOOLCHAIN = ROOT / "rust-toolchain.toml"
LIFECYCLE_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-LIFECYCLE-CHECK-AX-021.toml"
LIFECYCLE_RUNTIME_ASSUMPTION = ROOT / "assumptions/PBR-DIAGNOSTIC-LIFECYCLE-AX-023.toml"
CLAIM = ROOT / "claims/PBR-OBSERVER-028.toml"
CORE_MANIFEST = ROOT / "crates/proofbound-runtime-core/Cargo.toml"
AUTHORITY = ROOT / "crates/proofbound-runtime-core/src/authority.rs"
IDENTITY = ROOT / "crates/proofbound-runtime-core/src/identity.rs"
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
CGROUP = ROOT / "crates/proofbound-runtime-linux/src/cgroup.rs"
LINUX_LIB = ROOT / "crates/proofbound-runtime-linux/src/lib.rs"
LAUNCHER = ROOT / "crates/proofbound-runtime-linux/src/launcher.rs"
PROBE = ROOT / "crates/proofbound-runtime-linux/src/probe.rs"
RESOLVE = ROOT / "crates/proofbound-runtime-linux/src/resolve.rs"
SUPERVISOR = ROOT / "crates/proofbound-runtime-linux/src/supervisor.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
UNIT_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-lifecycle.toml"
ADAPTER_EVIDENCE = ROOT / "proofbound/evidence/diagnostic-lifecycle-adapter.toml"
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
    fresh = implementation(cgroup, "pub(crate) fn revalidate_fresh(")
    cgroup_finish = implementation(cgroup, "pub(crate) fn finish_before(")
    cgroup_drain = implementation(cgroup, "fn drain_in_place_before(")
    cgroup_drop = implementation(cgroup, "impl Drop for FreshCgroup")
    exact_stop = implementation(trace, "fn wait_for_exact_stop(")
    resume = implementation(active, "fn resume_before_deadline(")
    signal_all = implementation(active, "fn signal_all_process_groups(")
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
        ".revalidate_fresh()",
        "request.identity().cgroup_id() != cgroup.identity()",
        "configured.processes() != limits.processes()",
        "Some(configured.memory()) != limits.memory()",
        "Some(configured.swap()) != limits.swap()",
        "configured.memory_oom_group() != 1",
    ]:
        if term not in prepare:
            raise AssertionError(f"missing exact cgroup binding term: {term}")

    before(
        spawn, "let deadline = TraceDeadline::after", ".command\n            .spawn()"
    )
    before(spawn, ".revalidate_resources()", "let deadline = TraceDeadline::after")
    before(spawn, ".revalidate_fresh()", "let deadline = TraceDeadline::after")
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

    initial_wait = implementation(trace, "pub fn wait_for_initial_exec_stop(mut self)")
    launcher_continue = implementation(trace, "pub fn continue_to_launcher_pause(mut self)")
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
            raise AssertionError(
                "setup step does not use the stored execution deadline"
            )
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
            raise AssertionError(
                "effectful setup step can proceed after deadline expiry"
            )
    before(
        release,
        "self.session.revalidate_cgroup()?",
        ".send(&LauncherMessage::ExecRelease",
    )
    release_after_send = release[release.index(".send(&LauncherMessage::ExecRelease") :]
    before(
        release_after_send,
        "if self.session.deadline.expired()",
        "trace_syscall(root.get())",
    )
    if "TraceeState::released_mid_syscall(root)" not in release:
        raise AssertionError("release does not account for its in-flight launcher syscall")
    if "self.session.deadline" not in next_event:
        raise AssertionError(
            "active observation does not use the stored execution deadline"
        )
    before(next_event, "self.session.deadline.expired()", "self.held_process.take()")
    before(
        next_event, "self.session.deadline.expired()", "trace_wait_event_nonblocking"
    )
    before(next_event, "trace_wait_event_nonblocking", "let handled =")
    if next_event.count("self.session.deadline.expired()") < 4:
        raise AssertionError("active observation does not reject late-ready events")
    before(exact_stop, "if deadline.expired()", "trace_wait_nonblocking")
    if exact_stop.count("if deadline.expired()") != 2:
        raise AssertionError("exact setup wait does not reject a late-ready stop")
    for term in [
        "session: &mut TraceSession",
        "TraceWaitStatus::Exited { .. }",
        "TraceWaitStatus::Signaled { .. }",
        "session.record_root_reaped();",
    ]:
        if term not in exact_stop:
            raise AssertionError(f"terminal setup wait leaves numeric cleanup armed: {term}")
    post_wait = exact_stop[exact_stop.index("let observation =") :]
    before(post_wait, "session.record_root_reaped();", "if deadline.expired()")
    for term in [
        "if self.session.deadline.expired()",
        "TraceObservationError::WaitTimedOut",
        "trace_syscall(process.get())",
    ]:
        if term not in resume:
            raise AssertionError(f"target resume lacks final deadline gate: {term}")
    for term in ["TRACE_DRAIN_TIMEOUT", "checked_add(TRACE_DRAIN_TIMEOUT)"]:
        if term not in trace and term not in deadline:
            raise AssertionError(f"missing bounded cleanup deadline term: {term}")
    before(
        begin_termination,
        "let deadline = TraceDeadline::cleanup()?",
        "self.signal_all_process_groups()",
    )
    before(begin_termination, "self.signal_all_process_groups()?", "Ok(DrainingTrace")
    for term in ["let mut failed = false", ".is_err()", "if failed", "Err("]:
        if term not in signal_all:
            raise AssertionError(f"explicit signal failure is discarded: {term}")
    if "self.begin_termination()?.finish()" not in drain:
        raise AssertionError("combined drain bypasses immediate termination typestate")
    if "self.deadline.expired()" not in drain_finish:
        raise AssertionError("forced drain does not enforce its cleanup deadline")
    if "while !self.trace.processes.is_empty()" not in drain_finish:
        raise AssertionError(
            "forced drain does not empty the exact retained trace tree"
        )

    for term in [
        "let resources = self.cgroup.take().map_or_else(",
        "|| Err(TraceObservationError::ResourceCleanupFailed)",
        ".finish_before(deadline.instant())",
        "let output = self.streams.finish_before(deadline.instant());",
        "let resources = match resources?",
        "ResourceObservation::Complete(resources)",
        "ResourceObservation::Legacy | ResourceObservation::Incomplete(_)",
        "TraceObservationError::ResourceObservationIncomplete",
        "output: output?",
    ]:
        if term not in finish_terminal:
            raise AssertionError(f"missing terminal resource gate: {term}")
    if finish_terminal.count("deadline.instant()") != 2:
        raise AssertionError("cgroup and stream completion do not share one deadline")
    before(
        finish_terminal,
        ".finish_before(deadline.instant())",
        "let output = self.streams.finish_before(deadline.instant());",
    )
    before(
        finish_terminal,
        "let output = self.streams.finish_before(deadline.instant());",
        "let resources = match resources?",
    )
    stream_index = finish_terminal.index(
        "let output = self.streams.finish_before(deadline.instant());"
    )
    if "resources?" in finish_terminal[:stream_index]:
        raise AssertionError("resource failure can skip deadline-aware stream cleanup")
    if "let _ = self.cleanup_in_place();" not in cgroup_drop:
        raise AssertionError("fallback cgroup cleanup can remove before bounded drain")
    for term in [
        "group.drop_cleanup = DropCleanup::DeadlineBound;",
        "group.drain_in_place_before(deadline)?",
    ]:
        if term not in cgroup_finish:
            raise AssertionError(f"deadline cleanup can restart in Drop: {term}")
    before(
        cgroup_finish,
        "group.drop_cleanup = DropCleanup::DeadlineBound;",
        "group.drain_in_place_before(deadline)?",
    )
    for term in [
        "DropCleanup::Abandoned =>",
        "DropCleanup::DeadlineBound =>",
        "let _ = self.cleanup_in_place();",
        "let _ = self.remove_in_place();",
    ]:
        if term not in cgroup_drop:
            raise AssertionError(f"cgroup Drop cleanup mode is incomplete: {term}")
    before(
        natural_finish,
        "if !self.is_drained()",
        "self.session.finish_terminal(deadline)?",
    )
    for term in [
        "if self.session.deadline.expired()",
        "let deadline = TraceDeadline::cleanup()?",
        "self.session.finish_terminal(deadline)?",
        "return Err(TraceObservationError::WaitTimedOut)",
    ]:
        if term not in natural_finish:
            raise AssertionError(f"terminal-event timeout escapes bounded cleanup: {term}")
    before(
        natural_finish,
        "self.session.finish_terminal(deadline)?",
        "return Err(TraceObservationError::WaitTimedOut)",
    )
    before(
        complete_drain,
        "if self.tree_reconciliation_failed",
        "self.session.finish_terminal(deadline)?",
    )
    before(
        adapter_next, "self.trace.finish()?.into_terminal()", "self.protocol.finish()?"
    )
    if adapter_next.count("self.trace.begin_termination()?") != 2:
        raise AssertionError(
            "adapter does not start termination before returning drain state"
        )
    for term in [
        "TraceObservationError::WaitTimedOut =>",
        "DrainPublication::Forbidden(error)",
        "publication,",
    ]:
        if term not in adapter_next:
            raise AssertionError(f"execution timeout can reach publication: {term}")
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
    for term in [
        "if let DrainPublication::Forbidden(error) = self.publication",
        "return Err(ObserverAdapterError::Observation(error));",
    ]:
        if term not in adapter_finish:
            raise AssertionError(f"forbidden drain can reach publication: {term}")
    before(
        adapter_finish,
        "if let DrainPublication::Forbidden(error) = self.publication",
        "self.protocol.finish()?",
    )
    if adapter.count("terminal: TraceTerminalCapture") != 1:
        raise AssertionError("completed adapter terminal ownership is not singular")

    for variant in [
        "CgroupIdentityMismatch",
        "CgroupNotFresh",
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
    for term in [
        "read_resource_snapshot(&self.descriptor)",
        "!initial.is_zero()",
        "observed != initial",
        "populated(&self.descriptor)?",
        "!processes(&self.descriptor)?.is_empty()",
    ]:
        if term not in fresh:
            raise AssertionError(f"cgroup freshness is not revalidated: {term}")
    for term in ["Instant::now() >= deadline", "drain_in_place_before(deadline)"]:
        if term not in cgroup_finish and term not in cgroup_drain:
            raise AssertionError(
                f"terminal cgroup work is outside the deadline: {term}"
            )
    if "sleep(" in cgroup_drop:
        raise AssertionError("cgroup drop embeds an unbounded wait loop")


EXPECTED_BODIES = {
    "active-begin-termination": "e52f7855e3e0bd7d538fa18963b1a404be004736fd029db4c1af4e092c495ed2",
    "active-drain": "93fb4ec3a1af8abcc2ad31dba4c23eb498b43a743137cbe3d0d1e04afdbd6ee3",
    "active-finish": "dc2f63886b0d9bb418062462f69f3b4c9073cb079be36b7a883f37599fb8f64c",
    "active-next": "d338650ed48b9e795519e78b67f2b23052c42f5d09de1c2fe76f019688d98efb",
    "adapter-drain": "abd829e86e881f9c28981c43d3832c6b707dd90aad22500109f3d25b384a7ab0",
    "adapter-next": "98e8b121729094ec65ba7fedb38da6c11e3dc6c3666e9c529cfc2d01a1647825",
    "cgroup-drain-before": "caa3f99baee132f20cfb3ca42fda7d8b93c046f83e6d3fa35d2fcea3d4deeda5",
    "cgroup-drop": "951e530b5cac51993c7bd73ea9d2c534b234d8e4131fef2f04c0bbd90f77b1f3",
    "cgroup-finish-before": "65d19b3c9ebec391228d2068d88fb4857e437bc5cb0c02d8e7ddaa736c3b6037",
    "revalidate-resources": "30ecf689ab0e1c1846169130bf9c5efc2ef19d1208420023816df84ddee06fdf",
    "revalidate-fresh": "277b2ee0776fb7942d6d63a91183bc88cd9531716b5f1078d06f46d622e18c9e",
    "finish-terminal": "5ebf6b5b98b5809b6278e342806e6d0b0cb9b952d6f743bd6755358b39676ced",
    "draining-trace-finish": "57620c4257f982a79a1396b1d7e9c3d31dda4b7217ea2ba796e986c73fd61148",
    "prepare": "3274dfd85f027ca69c6cf0d95ff359f630d43c2c813292e52881cdb6490091af",
    "resume-before-deadline": "bff9c1e06b805663e587a4dd5a5313bb7e04a6aceeb68aa017e4c09a4953f502",
    "signal-all-process-groups": "cc6ac7670b610a46d35cdcdb6e720ab44f75e29479fcec88e3a2fe7ca6eb6244",
    "spawn": "1faca0106ae138c1f98807b3d21371eace9a69d41892a8a13c6d94a72b30f681",
    "wait-for-exact-stop": "d7d42625b210d8aeed50f75176c09c728887bcd085d9311789a73a0a0ff7a831",
}
EXPECTED_FILES = {
    "adapter": "b2d4b7b8461e40d55d3016334d73dece92240c86a4d2fe6ff9db262d8f203d63",
    "adapter-evidence": "87bc8da1a2cab8f6e3b380d38e2017852abe4cee0039854a4ea0dd3b8571d8b4",
    "adapter-lib": "8859f99339377b7034d43dd9d4fd20713824b5ad2708cd52d76412272a3858e2",
    "adapter-manifest": "ef7c613a66781c4b64d75435524166329b5239b8172f97b28cff2d6d609c8d78",
    "authority": "9d1945b590a3a9f44f6af95d3090ad0a8d1bc0cfa601c35273cd0a72c86cbddc",
    "claim": "40e7e16c6231bebce538e759cdf5a8ad577cfd9f2b70a36e36372da2e2629d24",
    "contract-evidence": "deda6ad938018d660fc4f8fd4bd83e2123936023ff73cca64ab12f13c69ea5b2",
    "core-manifest": "0d22823a1d4f397fb58693c7d9fe7498969ce242b5da0f372d8cc8f55f960b9b",
    "core-lib": "2039d8c789844cddaaabbf432a0a6ef465f77300577f3b57922d7bcbcc930450",
    "cgroup": "8f708a93b08c18037345f5ecee58aa67e945397688b41c0f2fc3e15f614784b9",
    "diagnose-artifact": "bb353a2c06312a034bfba7ed687430e102284f05495fee58df3ee88acc056bee",
    "diagnose-lib": "f7c7f460fe810dab2bdde0d55a0cfb3a468dbfc4f7465c8907e60bb5e97c68de",
    "diagnose-manifest": "097ec2b4cef98a43bee09c64c289251ab2060808d4fb8e050de3077f541ff2f1",
    "diagnose-observer": "eb688d43f61b6d628341f73f2b43e887e3df4a81905406e2b89c1592d31c19a7",
    "launcher": "5b2f251091b01fe9fa9bfb4018fac4971f22c9a7d55a5a92f5fdc24ca2673b83",
    "lifecycle-assumption": "ee12854496d97ecce949d1ff85067003a2fc48880d02d2850cff6fe807090017",
    "lifecycle-runtime-assumption": "16ca1aa8d7e6c9b41eed370fd2e53e4ea4de181a51e8e176046369a744ea1cd6",
    "identity": "176bb4e1cc50e8b0efc285a80cf3091e81ee3f8502067a380ac5fa49ad863bc5",
    "linux-lib": "10dddcf330422289b7ab1f5ac5ee9574ce63ea9c29ac86fa1ba1f1909eff6c2a",
    "linux-manifest": "e7311e3cada91690da87f42910c96e133538439956a0db78de79dea9294d6c9b",
    "lock": "5fb7c8b16c4b865630a8e7e80f16919d443c3c276970959cd80ab26581229640",
    "root-manifest": "8cd67ea78720c5637340140ac6ea94a9d76ddeaf4fb0df40881c4e8dab371466",
    "receipt": "fc27edf189014a49af8af380902fe90b12cbbd71a2b49301064b589c8a4c4024",
    "path-receipt-lib": "f2f103cbc2c928f9a69211963788c1472c62a936de63a8f53dca2cd9c5469b01",
    "path-receipt-manifest": "4cb9c84da77bd72e3a49e2be1cbf52f2e5841ab15d9ae8fb07c2022f788518d6",
    "probe": "2bf141cf9ee8b2943cd3e63305399030ae8829a040ed06c9cc65de8533e0a692",
    "resolve": "66ab088fbadbff3b71deb6edc76d3f7069932949f6cdde08f1fa3cf133892eca",
    "supervisor": "5f1b80181b01c3ea189643995617aeab60f390c1f5fc6930cf0acd577b88cdd8",
    "sys": "8b7dfd2fee307d937f71dcbab8098d026715dc2e4f7d03c72fa9ee7bd4734168",
    "toolchain": "0ceb751d66f44e50985538d239e0f5712acccb9f7e71a8afb56878f8fc2ba74a",
    "trace": "2470990206dc60b301ebef11fe0e85fec3c7be91cba72e093f691f9e4080d963",
    "unit-evidence": "47394cbf7d03c115c3140f6a593c7ab76a031e34594a235b87fd0d7de555b51c",
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
                "fallback cgroup removal bypasses bounded drain",
                self.trace,
                self.adapter,
                self.cgroup.replace(
                    "            let _ = self.cleanup_in_place();",
                    "            let _ = self.remove_in_place();",
                    1,
                ),
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "deadline cgroup failure restarts fallback wait budget",
                self.trace,
                self.adapter,
                self.cgroup.replace(
                    "            group.drop_cleanup = DropCleanup::DeadlineBound;",
                    "            group.drop_cleanup = DropCleanup::Abandoned;",
                    1,
                ),
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
                "spawn accepts a pre-used cgroup",
                self.trace.replace(
                    "self.cgroup\n            .revalidate_fresh()\n"
                    "            .map_err(|_| TraceStartupError::CgroupNotFresh)?;",
                    "",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "release loses its in-flight launcher syscall",
                self.trace.replace(
                    "TraceeState::released_mid_syscall(root)",
                    "TraceeState::observing(root)",
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
                "late-ready event wins over deadline",
                self.trace.replace(
                    "let handled = self.handle_wait_observation(requested, observation);\n"
                    "                if self.session.deadline.expired() {\n"
                    "                    self.must_drain = true;\n"
                    "                    return Err(TraceObservationError::WaitTimedOut);\n"
                    "                }",
                    "let handled = self.handle_wait_observation(requested, observation);",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "terminal-event timeout bypasses bounded cleanup",
                self.trace.replace(
                    "            let deadline = TraceDeadline::cleanup()?;\n"
                    "            self.session.finish_terminal(deadline)?;\n"
                    "            return Err(TraceObservationError::WaitTimedOut);",
                    "            return Err(TraceObservationError::WaitTimedOut);",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "late-ready setup stop wins over deadline",
                self.trace.replace(
                    "let observation = crate::sys::trace_wait_nonblocking(process.get())\n"
                    "                .map_err(|_| TraceStartupError::WaitFailed)?;\n"
                    "            if matches!(\n"
                    "                observation,\n"
                    "                Some(\n"
                    "                    crate::sys::TraceWaitStatus::Exited { .. }\n"
                    "                        | crate::sys::TraceWaitStatus::Signaled { .. }\n"
                    "                )\n"
                    "            ) {\n"
                    "                session.record_root_reaped();\n"
                    "            }\n"
                    "            if deadline.expired() {\n"
                    "                return Err(TraceStartupError::WaitTimedOut);\n"
                    "            }",
                    "let observation = crate::sys::trace_wait_nonblocking(process.get())\n"
                    "                .map_err(|_| TraceStartupError::WaitFailed)?;\n"
                    "            if matches!(\n"
                    "                observation,\n"
                    "                Some(\n"
                    "                    crate::sys::TraceWaitStatus::Exited { .. }\n"
                    "                        | crate::sys::TraceWaitStatus::Signaled { .. }\n"
                    "                )\n"
                    "            ) {\n"
                    "                session.record_root_reaped();\n"
                    "            }",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "terminal setup reap leaves numeric cleanup armed",
                self.trace.replace("                session.record_root_reaped();\n", "", 1),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "explicit signal failures are discarded",
                self.trace.replace(
                    "self.signal_all_process_groups()?;",
                    "let _ = self.signal_all_process_groups();",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "stream completion receives a fresh deadline",
                self.trace.replace(
                    "self.streams.finish_before(deadline.instant())",
                    "self.streams.finish_before(Instant::now())",
                    1,
                ),
                self.adapter,
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "resource failure skips deadline-aware stream cleanup",
                self.trace.replace(
                    "let output = self.streams.finish_before(deadline.instant());",
                    "let _ = resources?;\n"
                    "        let output = self.streams.finish_before(deadline.instant());",
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
            (
                "execution timeout remains publication eligible",
                self.trace,
                self.adapter.replace(
                    "TraceObservationError::WaitTimedOut => DrainPublication::Forbidden(error)",
                    "TraceObservationError::WaitTimedOut => DrainPublication::Eligible",
                    1,
                ),
                self.cgroup,
                self.linux_lib,
                self.adapter_lib,
            ),
            (
                "forbidden timeout drain reaches protocol publication",
                self.trace,
                self.adapter.replace(
                    "        if let DrainPublication::Forbidden(error) = self.publication {\n"
                    "            return Err(ObserverAdapterError::Observation(error));\n"
                    "        }\n",
                    "",
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
            "adapter-next": implementation(
                adapter_active, "pub fn next_event(mut self)"
            ),
            "revalidate-resources": implementation(
                self.cgroup,
                "pub fn revalidate_resources(",
            ),
            "revalidate-fresh": implementation(
                self.cgroup,
                "pub(crate) fn revalidate_fresh(",
            ),
            "cgroup-finish-before": implementation(
                self.cgroup,
                "pub(crate) fn finish_before(",
            ),
            "cgroup-drain-before": implementation(
                self.cgroup,
                "fn drain_in_place_before(",
            ),
            "cgroup-drop": implementation(self.cgroup, "impl Drop for FreshCgroup"),
            "finish-terminal": implementation(self.trace, "fn finish_terminal("),
            "wait-for-exact-stop": implementation(
                self.trace,
                "fn wait_for_exact_stop(",
            ),
            "resume-before-deadline": implementation(
                active,
                "fn resume_before_deadline(",
            ),
            "signal-all-process-groups": implementation(
                active,
                "fn signal_all_process_groups(",
            ),
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
            "adapter-evidence": ADAPTER_EVIDENCE,
            "claim": CLAIM,
            "contract-evidence": CONTRACT_EVIDENCE,
            "core-manifest": CORE_MANIFEST,
            "core-lib": CORE_LIB,
            "cgroup": CGROUP,
            "identity": IDENTITY,
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
            "path-receipt-lib": PATH_RECEIPT_LIB,
            "path-receipt-manifest": PATH_RECEIPT_MANIFEST,
            "probe": PROBE,
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
