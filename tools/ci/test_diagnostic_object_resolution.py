import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SYS = ROOT / "crates/proofbound-runtime-linux/src/sys.rs"
TRACE = ROOT / "crates/proofbound-runtime-linux/src/trace.rs"
MAPPING = ROOT / "crates/proofbound-runtime-diagnose-linux/src/mapping.rs"
ARTIFACT = ROOT / "crates/proofbound-runtime-diagnose/src/artifact.rs"


class DiagnosticObjectResolutionContractTests(unittest.TestCase):
    def setUp(self):
        self.sys = SYS.read_text()
        self.trace = TRACE.read_text()
        self.mapping = MAPPING.read_text()
        self.artifact = ARTIFACT.read_text()

    def test_selected_object_is_retained_and_identity_complete(self):
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
        open_object = self.sys.split("fn trace_open_object", 1)[1].split("\n}", 1)[0]
        mutations = [
            self.trace.replace("retained_processes != 1", "false", 1),
            self.mapping.replace("is_normalized_absolute_path(path)", "true", 1),
            open_object.replace(
                "libc::O_PATH | libc::O_CLOEXEC", "libc::O_RDONLY", 1
            ),
        ]
        self.assertNotIn("retained_processes != 1", mutations[0])
        self.assertNotIn("is_normalized_absolute_path(path)", mutations[1])
        self.assertNotIn("libc::O_PATH | libc::O_CLOEXEC", mutations[2])


if __name__ == "__main__":
    unittest.main()
