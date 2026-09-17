import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
MAPPING = ROOT / "crates/proofbound-runtime-diagnose-linux/src/mapping.rs"
ARTIFACT = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"


def assert_object_resolution_contract(sys_source, trace, mapping, artifact):
    for marker in ["O_PATH", "O_CLOEXEC", "AT_EMPTY_PATH", "STATX_MNT_ID"]:
        assert marker in sys_source
    open_object = sys_source.split("fn trace_open_object", 1)[1].split("\n}", 1)[0]
    assert "libc::O_PATH | libc::O_CLOEXEC" in open_object
    descriptor = trace.split("fn eligible_selected_descriptor", 1)[1].split("\n}", 1)[0]
    for marker in [
        "retained_processes != 1",
        "is_error",
        "i32::try_from(result)",
        "filter(|descriptor| *descriptor >= 0)",
    ]:
        assert marker in descriptor
    selected = mapping.split("fn map_selected_parts", 1)[1].split("\n}", 1)[0]
    for marker in [
        "!is_normalized_absolute_path(&path)",
        'path.ends_with(" (deleted)")',
        "ObservationResolution::KernelSelected",
        "ObservationResolution::Unresolved",
    ]:
        assert marker in selected
    for field in ["device_major", "device_minor", "inode", "mode", "mount_id"]:
        assert field in sys_source
        assert field in mapping
    assert "resolution == ObservationResolution::KernelSelected" in artifact
    assert "object_before.is_some()" in artifact
    assert "!operands.has_path_observation()" in artifact
    exec_connection = """let selected_object =
                    self.observe_selected_object(change.survivor, TraceObjectSource::Executable);"""
    descriptor_connection = """let selected_object = self.observe_successful_descriptor(
                            process,
                            &invocation,
                            result,
                            is_error,
                        );"""
    assert exec_connection in trace
    assert descriptor_connection in trace
    exec_branch = trace.split(
        "if signal == SIGNAL_TRAP && crate::sys::trace_event_is_exec(event) =>", 1
    )[1].split("crate::sys::TraceWaitStatus::Stopped { signal, event }", 1)[0]
    exec_order = [
        exec_branch.index("self.reconcile_exec_identity(requested, reported)?"),
        exec_branch.index(exec_connection),
        exec_branch.index("ActiveTraceEvent::ImageReplaced"),
    ]
    assert exec_order == sorted(exec_order)
    assert "resume_before_deadline" not in exec_branch[: exec_order[2]]
    exit_branch = trace.split(
        "crate::sys::TraceSyscallStop::Exit { result, is_error } =>", 1
    )[1].split("crate::sys::TraceSyscallStop::Seccomp", 1)[0]
    captured_branch = exit_branch.split(
        "PendingTraceSyscall::Captured(invocation) => {", 1
    )[1].split("PendingTraceSyscall::Ignored =>", 1)[0]
    exit_order = [
        exit_branch.index(".finish_syscall()?"),
        exit_branch.index(descriptor_connection),
        exit_branch.index("ActiveTraceEvent::SyscallCompleted"),
    ]
    assert exit_order == sorted(exit_order)
    selected_position = captured_branch.index(descriptor_connection)
    event_position = captured_branch.index("ActiveTraceEvent::SyscallCompleted")
    assert selected_position < event_position
    assert "resume_before_deadline" not in captured_branch[:event_position]


class DiagnosticObjectResolutionContractTests(unittest.TestCase):
    def setUp(self):
        self.sys = SYS.read_text()
        self.trace = TRACE.read_text()
        self.mapping = MAPPING.read_text()
        self.artifact = ARTIFACT.read_text()

    def test_selected_object_is_retained_and_identity_complete(self):
        assert_object_resolution_contract(
            self.sys, self.trace, self.mapping, self.artifact
        )
        for marker in ["O_PATH", "O_CLOEXEC", "AT_EMPTY_PATH", "STATX_MNT_ID"]:
            self.assertIn(marker, self.sys)
        for field in ["device_major", "device_minor", "inode", "mode", "mount_id"]:
            self.assertIn(field, self.sys)
            self.assertIn(field, self.mapping)
        self.assertIn("trace_read_link", self.sys)
        self.assertIn("trace_object_metadata", self.sys)

    def test_descriptor_selection_is_bounded_to_supported_success_and_one_tracee(self):
        body = self.trace.split("fn eligible_selected_descriptor", 1)[1].split("\n}", 1)[0]
        self.assertIn("retained_processes != 1", body)
        self.assertIn("is_error", body)
        self.assertIn("i32::try_from(result)", body)
        self.assertIn("filter(|descriptor| *descriptor >= 0)", body)
        for syscall in ["Open", "Openat", "Openat2", "Creat"]:
            self.assertIn(f"TraceSyscallClass::{syscall}", body)

    def test_resolution_happens_while_tracee_is_stopped(self):
        self.assertIn("observe_selected_object", self.trace)
        self.assertIn("TraceObjectSource::Executable", self.trace)
        self.assertIn("selected_descriptor_requires_one_tracee_supported_success_and_linux_width", self.trace)

    def test_mapping_never_fabricates_kernel_selected_identity(self):
        self.assertIn("map_selected_parts", self.mapping)
        self.assertIn("is_normalized_absolute_path", self.mapping)
        self.assertIn("ObservationResolution::KernelSelected", self.mapping)
        self.assertIn("ObservationResolution::Unresolved", self.mapping)
        self.assertIn("selected_object_mapping_accepts_only_normalized_live_filesystem_paths", self.mapping)
        self.assertIn("resolution == ObservationResolution::KernelSelected", self.artifact)
        self.assertIn("object_before.is_some()", self.artifact)
        self.assertIn("!operands.has_path_observation()", self.artifact)

    def test_mutations_remove_required_guards(self):
        mutations = [
            (
                self.sys,
                self.trace.replace("retained_processes != 1", "false", 1),
                self.mapping,
                self.artifact,
            ),
            (
                self.sys,
                self.trace.replace(
                    "let change = self.reconcile_exec_identity(requested, reported)?;",
                    "__REORDER_EXEC_SELECTION__",
                    1,
                ).replace(
                    """let selected_object =
                    self.observe_selected_object(change.survivor, TraceObjectSource::Executable);""",
                    "let change = self.reconcile_exec_identity(requested, reported)?;",
                    1,
                ).replace(
                    "__REORDER_EXEC_SELECTION__",
                    """let selected_object =
                    self.observe_selected_object(change.survivor, TraceObjectSource::Executable);""",
                    1,
                ),
                self.mapping,
                self.artifact,
            ),
            (
                self.sys,
                self.trace.replace(
                    """let selected_object = self.observe_successful_descriptor(
                            process,""",
                    """self.resume_before_deadline(process)?;
                        let selected_object = self.observe_successful_descriptor(
                            process,""",
                    1,
                ),
                self.mapping,
                self.artifact,
            ),
            (
                self.sys,
                self.trace,
                self.mapping.replace("!is_normalized_absolute_path(&path)", "false"),
                self.artifact,
            ),
            (
                self.sys.replace(
                    "unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) }",
                    "unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) }",
                    1,
                ),
                self.trace,
                self.mapping,
                self.artifact,
            ),
            (
                self.sys,
                self.trace.replace(
                    """let selected_object =
                    self.observe_selected_object(change.survivor, TraceObjectSource::Executable);""",
                    "let selected_object = None;",
                    1,
                ),
                self.mapping,
                self.artifact,
            ),
            (
                self.sys,
                self.trace.replace(
                    """let selected_object = self.observe_successful_descriptor(
                            process,
                            &invocation,
                            result,
                            is_error,
                        );""",
                    "let selected_object = None;",
                    1,
                ),
                self.mapping,
                self.artifact,
            ),
        ]
        for mutation in mutations:
            with self.subTest(mutation=hash("".join(mutation))):
                with self.assertRaises(AssertionError):
                    assert_object_resolution_contract(*mutation)


if __name__ == "__main__":
    unittest.main()
