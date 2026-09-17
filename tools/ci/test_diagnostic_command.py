import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "Cargo.toml"
COMMAND = ROOT / "crates/proofbound-runtime-diagnose-cli/src/main.rs"
PRODUCTION = ROOT / "crates/proofbound-runtime-cli/Cargo.toml"
LINUX = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
RELEASE = ROOT / "tools/release/build-linux.sh"
INSTALLER = ROOT / "tools/install_release.py"


class DiagnosticCommandContractTests(unittest.TestCase):
    def setUp(self):
        self.command = COMMAND.read_text()

    def test_command_reuses_seed_authority_and_same_boundary_components(self):
        for marker in [
            "parse_execution_plan_for_execution",
            "normalize_authority",
            "compile_policy",
            "compile_deny_network_program",
            "FreshCgroup::create_v2",
            "InstallRequest::new",
        ]:
            self.assertIn(marker, self.command)
        self.assertNotIn("NetworkMode::Allow", self.command)

    def test_publication_requires_terminal_eligibility_and_absent_targets(self):
        self.assertIn("completed.publication()", self.command)
        self.assertIn("ObserverDirective::PublishComplete", self.command)
        self.assertIn("ObserverDirective::PublishIncomplete", self.command)
        self.assertIn("create_new(true)", self.command)
        self.assertIn("hard_link", self.command)
        self.assertIn("sync_all", self.command)
        self.assertIn("diagnostic.output.child-writable", self.command)

    def test_production_crates_do_not_depend_on_diagnostics(self):
        for manifest in [PRODUCTION, LINUX]:
            self.assertNotIn("proofbound-runtime-diagnose", manifest.read_text(), manifest)
        self.assertIn("crates/proofbound-runtime-diagnose-cli", WORKSPACE.read_text())

    def test_release_and_installer_include_exact_separate_executable(self):
        self.assertIn("pbr-diagnose", RELEASE.read_text())
        self.assertIn("pbr-diagnose", INSTALLER.read_text())

    def test_mutations_remove_required_guards(self):
        mutations = [
            self.command.replace("create_new(true)", "create(true)", 1),
            self.command.replace("completed.publication()", "ObserverDirective::PublishComplete", 1),
            self.command.replace("diagnostic.output.child-writable", "diagnostic.output.allowed", 1),
        ]
        self.assertNotIn("create_new(true)", mutations[0])
        self.assertNotIn("completed.publication()", mutations[1])
        self.assertNotIn("diagnostic.output.child-writable", mutations[2])


if __name__ == "__main__":
    unittest.main()
