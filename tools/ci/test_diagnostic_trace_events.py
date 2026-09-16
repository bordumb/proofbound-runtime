import hashlib
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"


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
    "active-begin-termination": "e52f7855e3e0bd7d538fa18963b1a404be004736fd029db4c1af4e092c495ed2",
    "active-next-event": "d338650ed48b9e795519e78b67f2b23052c42f5d09de1c2fe76f019688d98efb",
    "active-drain": "93fb4ec3a1af8abcc2ad31dba4c23eb498b43a743137cbe3d0d1e04afdbd6ee3",
    "active-complete-drain": "aaeab9d4290dd85e24d981b32d84061041a0c2eb2d80b68e9810fe3c7e63b546",
    "draining-finish": "b253199d4f51364a3db4af3c15d5e268a2c0be72d13cbbbb2de9aa3d485cf432",
    "active-wait-observation": "43f872fced14df3e3c29b9ff335acc52500a45613cb54c7cb7b001594530cda7",
    "active-drain-observation": "dceb35ed4c886eb36161331cf7106b07145a37d67e6714e359531e8fee06a7c9",
    "active-register-child": "e749a7f47624f313ba624ca850657240f2c0558e2f3b0b1544566b734eb6f3aa",
}


def assert_load_bearing_bodies(trace: str) -> None:
    actual = {
        "active-begin-termination": body_sha256(trace, "pub fn begin_termination"),
        "active-next-event": body_sha256(trace, "pub fn next_event"),
        "active-drain": body_sha256(trace, "pub fn terminate_and_drain"),
        "active-complete-drain": body_sha256(trace, "fn complete_drain"),
        "draining-finish": body_sha256(trace, "impl DrainingTrace"),
        "active-wait-observation": body_sha256(trace, "fn handle_wait_observation"),
        "active-drain-observation": body_sha256(trace, "fn handle_drain_observation"),
        "active-register-child": body_sha256(trace, "fn register_child"),
    }
    if actual != EXPECTED_LOAD_BEARING_BODIES:
        raise AssertionError(f"load-bearing trace body mismatch: {actual!r}")


class DiagnosticTraceEventContractTests(unittest.TestCase):
    def setUp(self):
        self.trace = TRACE.read_text()
        self.sys = SYS.read_text()

    def test_active_loop_polls_only_its_private_exact_tracee_set(self):
        active = implementation(self.trace, "impl ActiveTrace")
        next_event = implementation(active, "pub fn next_event")
        self.assertIn("self.processes.keys().copied().collect", next_event)
        self.assertIn("trace_wait_event_nonblocking(requested.get())", next_event)
        self.assertNotIn("waitpid", active)
        self.assertNotIn("-1", next_event)
        self.assertNotIn("pub processes:", self.trace)
        self.assertNotIn("pub process_handles:", self.trace)
        self.assertLess(
            next_event.index("self.held_process.take()"),
            next_event.index("trace_wait_event_nonblocking"),
        )

    def test_syscalls_are_paired_and_complete_events_hold_the_tracee(self):
        syscall = implementation(self.trace, "fn handle_syscall_stop")
        self.assertIn("TraceSyscallStop::Entry", syscall)
        self.assertIn("TraceSyscallStop::Exit", syscall)
        self.assertIn("capture_syscall_invocation", syscall)
        self.assertIn("PendingTraceSyscall::Captured", syscall)
        self.assertIn("PendingTraceSyscall::Ignored", syscall)
        self.assertIn(".pending\n                    .take()", syscall)
        self.assertIn("self.held_process = Some(process)", syscall)
        self.assertIn("ActiveTraceEvent::SyscallCompleted", syscall)
        self.assertIn("SyscallOrderInvalid", syscall)
        for required in [
            "PTRACE_GET_SYSCALL_INFO",
            "available != SYSCALL_INFO_ENTRY_BYTES",
            "available != SYSCALL_INFO_EXIT_BYTES",
            "information.reserved != 0",
            "information.flags != 0",
            "TraceSyscallStop::Entry",
            "TraceSyscallStop::Exit",
        ]:
            self.assertIn(required, self.sys)

    def test_private_wait_decision_has_no_large_custom_enum_or_heap_box(self):
        active = implementation(self.trace, "impl ActiveTrace")
        wait = implementation(active, "fn handle_wait_observation")
        syscall = implementation(active, "fn handle_syscall_stop")
        self.assertIn("Result<Option<ActiveTraceEvent>, TraceObservationError>", wait)
        self.assertIn("Result<Option<ActiveTraceEvent>, TraceObservationError>", syscall)
        self.assertNotIn("WaitDecision", active)
        self.assertNotIn("Box<ActiveTraceEvent>", active)

    def test_process_tree_registers_children_and_reconciles_exec_identity(self):
        active = implementation(self.trace, "impl ActiveTrace")
        register = implementation(active, "fn register_child")
        reconcile = implementation(active, "fn reconcile_exec_identity")
        reconcile_processes = implementation(self.trace, "fn reconcile_exec_processes")
        wait = implementation(active, "fn handle_wait_observation")
        drain = implementation(active, "fn handle_drain_observation")
        reconcile_compact = re.sub(r"\s+", "", reconcile_processes)
        self.assertIn("trace_event_process(reported.get())", active)
        self.assertIn("trace_process_creation_event(event)", active)
        self.assertLess(
            register.index("trace_open_process_handle"),
            register.index(".insert(child"),
        )
        self.assertIn("self.process_limit.drain_capacity()", register)
        self.assertIn("ProcessCapacityExceeded", register)
        self.assertIn("read_thread_group_id(child)", register)
        self.assertIn("reconcile_exec_processes(&mut self.processes", reconcile)
        self.assertIn("ifreported!=requested", reconcile_compact)
        self.assertIn("survivor_thread_group != reported", reconcile_processes)
        self.assertIn("former_thread_group != reported", reconcile_processes)
        self.assertIn("processes.remove(&former)", reconcile_compact)
        self.assertIn("state.thread_group == reported", reconcile_processes)
        self.assertIn("processes.insert(reported, exec_state)", reconcile_processes)
        self.assertIn("if reported != requested", wait)
        self.assertIn("if reported != requested", drain)
        self.assertIn("PTRACE_EVENT_FORK", self.sys)
        self.assertIn("PTRACE_EVENT_VFORK", self.sys)
        self.assertIn("PTRACE_EVENT_CLONE", self.sys)
        self.assertIn("PTRACE_EVENT_EXEC", self.sys)

    def test_registration_failure_permanently_blocks_successful_drain(self):
        active = implementation(self.trace, "impl ActiveTrace")
        wait = implementation(active, "fn handle_wait_observation")
        drain = implementation(self.trace, "impl DrainingTrace")
        complete = implementation(active, "fn complete_drain")
        self.assertLess(
            wait.index("self.tree_reconciliation_failed = true"),
            wait.index("trace_event_process(reported.get())"),
        )
        self.assertLess(
            wait.index("self.register_child(child)?"),
            wait.index("self.tree_reconciliation_failed = false"),
        )
        self.assertIn("self.trace.complete_drain(observations, self.deadline)", drain)
        self.assertIn("if self.tree_reconciliation_failed", complete)
        self.assertIn("TreeReconciliationFailed", complete)

    def test_load_bearing_trace_bodies_are_exact(self):
        assert_load_bearing_bodies(self.trace)

    def test_mutation_witnesses_reject_registration_and_false_empty_drain(self):
        mutations = {
            "omitted registration": self.trace.replace(
                "let capacity_exceeded = self.register_child(child)?;",
                "let capacity_exceeded = false;",
                1,
            ),
            "false empty drain": self.trace.replace(
                "if self.tree_reconciliation_failed {",
                "if false && self.tree_reconciliation_failed {",
                1,
            ),
            "omitted drain report": self.trace.replace(
                "observations.push(observation);",
                "let _ = observation;",
                1,
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(mutation, self.trace)
                with self.assertRaisesRegex(AssertionError, "load-bearing trace"):
                    assert_load_bearing_bodies(mutation)

    def test_nonleader_exec_keeps_entry_for_the_following_exit_stop(self):
        active = implementation(self.trace, "impl ActiveTrace")
        wait = implementation(active, "fn handle_wait_observation")
        regression = implementation(
            self.trace,
            "fn nonleader_exec_preserves_pending_syscall_until_exit_pair",
        )
        self.assertIn(".get(&change.survivor)", wait)
        self.assertIn("state.pending", wait)
        self.assertNotIn("state.pending.take()", wait)
        self.assertIn("reconcile_exec_processes", regression)
        self.assertIn("pending: Some(pending.clone())", regression)
        self.assertIn("state.pending.take()", regression)

    def test_exec_identity_falsifiers_cover_wrong_owner_and_foreign_thread(self):
        regression = implementation(
            self.trace,
            "fn exec_identity_rejects_wrong_wait_owner_and_foreign_former_thread",
        )
        self.assertEqual(regression.count("ProcessIdentityChanged"), 2)
        self.assertIn("former, leader, former", regression)
        self.assertIn("leader, leader, foreign", regression)

    def test_termination_uses_pidfds_and_never_numeric_kill(self):
        active = implementation(self.trace, "impl ActiveTrace")
        begin = implementation(active, "pub fn begin_termination")
        drain = implementation(self.trace, "impl DrainingTrace")
        drop = implementation(self.trace, "impl Drop for ActiveTrace")
        kill = implementation(self.sys, "pub(crate) fn trace_kill_process_handle")
        self.assertIn("signal_all_process_groups", begin)
        self.assertIn("handle_drain_observation", drain)
        self.assertIn("self.trace.processes.contains_key(&requested)", drain)
        self.assertIn("self.trace.processes.is_empty()", drain)
        self.assertIn("signal_all_process_groups", drop)
        self.assertNotIn("libc::", self.trace)
        self.assertIn("SYS_pidfd_open", self.sys)
        self.assertIn("SYS_pidfd_send_signal", self.sys)
        self.assertIn("trace_kill_process_handle", self.sys)
        self.assertIn("trace_signal_process_handle(handle.as_raw_fd(), 0)?", self.sys)
        self.assertNotIn("libc::kill(", kill)
        self.assertIn("The handle prevents PID reuse", self.sys)

    def test_unsupported_platform_paths_remain_typed(self):
        install = implementation(self.trace, "pub fn install_options")
        release = implementation(self.trace, "pub fn release")
        active = implementation(self.trace, "impl ActiveTrace")
        self.assertNotIn("process_limit", install)
        self.assertIn("let _ = (process_limit, capture_limits)", release)
        self.assertEqual(active.count("TraceObservationError::UnsupportedOperatingSystem"), 2)

    def test_raw_syscall_decoding_has_no_panicking_shortcuts(self):
        fetch = implementation(self.sys, "pub(crate) fn trace_syscall_stop")
        decode = implementation(self.sys, "fn decode_trace_syscall_stop")
        self.assertIn("decode_trace_syscall_stop", fetch)
        self.assertIn("trace_read_u64", decode)
        self.assertIn("trace_read_i64", decode)
        self.assertNotIn("expect(", fetch + decode)
        self.assertNotIn("unwrap(", fetch + decode)


if __name__ == "__main__":
    unittest.main()
