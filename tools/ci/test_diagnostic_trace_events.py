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
        self.assertIn("state.pending = Some(TraceSyscallInvocation", syscall)
        self.assertIn(".pending\n                    .take()", syscall)
        self.assertIn("self.held_process = Some(process)", syscall)
        self.assertIn("ActiveTraceEvent::SyscallCompleted", syscall)
        self.assertIn("SyscallOrderInvalid", syscall)
        for required in [
            "PTRACE_GET_SYSCALL_INFO",
            "available < 80",
            "available < 33",
            "TraceSyscallStop::Entry",
            "TraceSyscallStop::Exit",
        ]:
            self.assertIn(required, self.sys)

    def test_process_tree_registers_children_and_reconciles_exec_identity(self):
        active = implementation(self.trace, "impl ActiveTrace")
        register = implementation(active, "fn register_child")
        reconcile = implementation(active, "fn reconcile_exec_identity")
        reconcile_compact = re.sub(r"\s+", "", reconcile)
        self.assertIn("trace_event_process(reported.get())", active)
        self.assertIn("trace_process_creation_event(event)", active)
        self.assertLess(
            register.index("trace_open_process_handle"),
            register.index("self.processes"),
        )
        self.assertIn("read_thread_group_id(child)", register)
        self.assertIn("self.processes.remove(&former)", reconcile_compact)
        self.assertIn("former != requested || former_thread_group != reported", reconcile)
        self.assertIn("state.thread_group == reported", reconcile)
        self.assertIn("self.processes.insert(reported, exec_state)", reconcile)
        self.assertIn("PTRACE_EVENT_FORK", self.sys)
        self.assertIn("PTRACE_EVENT_VFORK", self.sys)
        self.assertIn("PTRACE_EVENT_CLONE", self.sys)
        self.assertIn("PTRACE_EVENT_EXEC", self.sys)

    def test_termination_uses_pidfds_and_never_numeric_kill(self):
        active = implementation(self.trace, "impl ActiveTrace")
        drain = implementation(active, "pub fn terminate_and_drain")
        drop = implementation(self.trace, "impl Drop for ActiveTrace")
        kill = implementation(self.sys, "pub(crate) fn trace_kill_process_handle")
        self.assertIn("signal_all_process_groups", drain)
        self.assertIn("handle_drain_observation", drain)
        self.assertIn("self.processes.contains_key(&requested)", drain)
        self.assertIn("self.processes.is_empty()", drain)
        self.assertIn("signal_all_process_groups", drop)
        self.assertNotIn("libc::", self.trace)
        self.assertIn("SYS_pidfd_open", self.sys)
        self.assertIn("SYS_pidfd_send_signal", self.sys)
        self.assertIn("trace_kill_process_handle", self.sys)
        self.assertIn("trace_signal_process_handle(handle.as_raw_fd(), 0)?", self.sys)
        self.assertNotIn("libc::kill(", kill)
        self.assertIn("The handle prevents PID reuse", self.sys)

    def test_raw_syscall_decoding_has_no_panicking_shortcuts(self):
        decode = implementation(self.sys, "pub(crate) fn trace_syscall_stop")
        self.assertIn("trace_read_u64", decode)
        self.assertIn("trace_read_i64", decode)
        self.assertNotIn("expect(", decode)
        self.assertNotIn("unwrap(", decode)


if __name__ == "__main__":
    unittest.main()
