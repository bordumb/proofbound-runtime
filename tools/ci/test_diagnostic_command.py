import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKSPACE = ROOT / "Cargo.toml"
COMMAND = ROOT / "crates/proofbound-runtime-diagnose-cli/src/main.rs"
PRODUCTION = ROOT / "crates/proofbound-runtime-cli/Cargo.toml"
LINUX = ROOT / "crates/proofbound-runtime-linux/Cargo.toml"
RELEASE = ROOT / "tools/release/build-linux.sh"
INSTALLER = ROOT / "tools/install_release.py"
ACTION_RUNNER = ROOT / ".github/actions/proofbound-runtime/run.py"
OBSERVATION_INPUTS = ROOT / "tools/release/observation_inputs.py"
NATIVE_CONTEXT = ROOT / "tools/ci/native_context.py"
NATIVE_SCRIPT = ROOT / "tools/ci/native-linux.sh"
CURRENT_BUILDER = ROOT / "tools/release/build_current_integration.py"
CURRENT_VERIFIER = ROOT / "tools/release/verify_current_integration.py"
RELEASE_OBSERVATION = (
    ROOT / "crates/proofbound-runtime-compose/tests/release_observation.rs"
)


def assert_static_scaffold_contract(command):
    scaffold = command.split("fn load_static_scaffold", 1)[1].split(
        "\nfn draft_inputs", 1
    )[0]
    for marker in [
        "requested.as_os_str().is_empty() || requested.is_absolute()",
        "selected.identity().role() != ArtifactRole::ProjectInput",
        "let ResolvedReadPath::File(file) = selected else",
        "file.identity().size() > MAX_STATIC_SCAFFOLD_BYTES",
        ".read_bytes()",
        "diagnostic.static-scaffold.identity-drift",
        "serde_json::from_slice(&bytes)",
        "report.host_profile.supports(architecture)",
        "static_artifact_matches_file(&report.executable, target.executable())",
        "static_artifact_matches_file(interpreter, loader)",
        "static_artifact_matches_resolved(&dependency.selected, path)",
    ]:
        assert marker in scaffold


def assert_command_contract(sources):
    command = sources["command"]
    assert_static_scaffold_contract(command)
    for marker in [
        "parse_execution_plan_for_execution",
        "normalize_authority",
        "compile_policy",
        "compile_deny_network_program",
        "FreshCgroup::create_v2",
        "InstallRequest::new",
        "completed.publication()",
        "ObserverDirective::PublishComplete",
        "ObserverDirective::PublishIncomplete",
        "observer_error_codes.insert(error.code())",
        '"observer_error_codes": observer_error_codes',
        'OsStr::new("--static-scaffold")',
        "load_static_scaffold(",
        "diagnostic.static-scaffold.not-declared",
        "selected.identity().role() != ArtifactRole::ProjectInput",
        "ResolvedReadPath::File(file)",
        ".read_bytes()",
        "static_artifact_matches_file(&report.executable, target.executable())",
        "diagnostic.static-scaffold.dependency-not-declared",
        "DraftProvenance::StaticExecutableClosure",
        "DraftProvenance::PlatformRequiredClosure",
        "IdentifiedClosureEntry::new",
        "create_new(true)",
        "hard_link",
        "sync_all",
        "diagnostic.output.child-writable",
        '"PBR-DIAGNOSTIC-CANDIDATE-AX-027"',
        '"PBR-DIAGNOSTIC-COMMAND-AX-029"',
        '"PBR-DIAGNOSTIC-DECODE-AX-017"',
        '"PBR-DIAGNOSTIC-LIFECYCLE-AX-023"',
        '"PBR-DIAGNOSTIC-OBJECT-AX-025"',
        '"PBR-DIAGNOSTIC-STREAM-AX-022"',
        '"PBR-DIAGNOSTIC-TRACE-AX-016"',
    ]:
        assert marker in command
    assert "NetworkMode::Allow" not in command
    assumption_block = command.split(
        "const DIAGNOSTIC_ASSUMPTIONS: [&str; 7] = [", 1
    )[1].split("];", 1)[0]
    expected_assumptions = [
        "PBR-DIAGNOSTIC-CANDIDATE-AX-027",
        "PBR-DIAGNOSTIC-COMMAND-AX-029",
        "PBR-DIAGNOSTIC-DECODE-AX-017",
        "PBR-DIAGNOSTIC-LIFECYCLE-AX-023",
        "PBR-DIAGNOSTIC-OBJECT-AX-025",
        "PBR-DIAGNOSTIC-STREAM-AX-022",
        "PBR-DIAGNOSTIC-TRACE-AX-016",
    ]
    assert all(assumption_block.count(value) == 1 for value in expected_assumptions)
    assert assumption_block.count("PBR-DIAGNOSTIC-") == len(expected_assumptions)

    execute = command.split("fn execute(input: CommandInput)", 1)[1].split(
        "\nfn default_observation_bounds", 1
    )[0]
    ordered = [
        "parse_execution_plan_for_execution",
        "normalize_authority",
        "compile_policy",
        "load_static_scaffold",
        "compile_deny_network_program",
        "InstallRequest::new",
        "prepare_observer",
        "completed.publication()",
        "DiagnosticReceiptParts",
        "build_diagnostic_artifacts",
        "publish_pair",
    ]
    positions = [execute.index(marker) for marker in ordered]
    assert positions == sorted(positions)
    for marker in [
        "let output_authority = compiled",
        ".filesystem()",
        "compiled.environment()",
        "compiled.network()",
        "compiled.cgroup().limits()",
    ]:
        assert marker in execute

    publication = command.split("fn publish_pair", 1)[1].split(
        "\nfn stage_output", 1
    )[0]
    for marker in [
        "stage_output(receipt_target, receipt",
        "stage_output(draft_target, draft",
        "fs::hard_link(&draft_temp, draft_target)",
        "fs::hard_link(&receipt_temp, receipt_target)",
        "sync_parent(receipt_target)?",
        "sync_parent(draft_target)?",
    ]:
        assert marker in publication
    assert publication.index("stage_output(receipt_target") < publication.index(
        "fs::hard_link(&draft_temp"
    )
    assert publication.index("fs::hard_link(&receipt_temp") < publication.index(
        "sync_parent(receipt_target)?"
    )

    assert "proofbound-runtime-diagnose" not in sources["production"]
    assert "proofbound-runtime-diagnose" not in sources["linux"]
    assert "crates/proofbound-runtime-diagnose-cli" in sources["workspace"]
    for name in [
        "release",
        "installer",
        "action_runner",
        "current_builder",
        "current_verifier",
    ]:
        assert '"pbr-diagnose"' in sources[name]
    assert (
        '("PBR-OBSERVER-031", "diagnostic-release", "pbr-diagnose")'
        in sources["observation_inputs"]
    )
    assert (
        '("diagnostic-observer", "pbr-diagnose")' in sources["native_context"]
    )
    assert (
        "for binary in pbr pbr-native-launcher pbr-verify pbr-diagnose"
        in sources["native_script"]
    )
    assert "--static-scaffold plan-scaffold.json" in sources["native_script"]
    assert 'assert draft["static_scaffold"] == "sha256:"' in sources["native_script"]
    for marker in [
        'dynamic_executable="$e2e_root/dynamic-diagnostic-probe"',
        "experiments/performance/discover_runtime_libraries.py",
        "--id ci.native-diagnostic-dynamic-workload",
        '"platform-required-closure", "static-executable-closure"',
        'entry["provenance"] for entry in draft["identified_closure"]',
        'assert receipt["reusable"] is False',
        '"capsec-missing", "choose-environment", "choose-limits"',
    ]:
        assert marker in sources["native_script"]
    assert (
        'assert_manifest_artifact(&bundle, "pbr-diagnose")'
        in sources["release_observation"]
    )
    assert (
        'assert_version(&bundle.join("pbr-diagnose"), "pbr-diagnose")'
        in sources["release_observation"]
    )


class DiagnosticCommandContractTests(unittest.TestCase):
    def setUp(self):
        self.sources = {
            "command": COMMAND.read_text(),
            "workspace": WORKSPACE.read_text(),
            "production": PRODUCTION.read_text(),
            "linux": LINUX.read_text(),
            "release": RELEASE.read_text(),
            "installer": INSTALLER.read_text(),
            "action_runner": ACTION_RUNNER.read_text(),
            "observation_inputs": OBSERVATION_INPUTS.read_text(),
            "native_context": NATIVE_CONTEXT.read_text(),
            "native_script": NATIVE_SCRIPT.read_text(),
            "current_builder": CURRENT_BUILDER.read_text(),
            "current_verifier": CURRENT_VERIFIER.read_text(),
            "release_observation": RELEASE_OBSERVATION.read_text(),
        }

    def test_command_reuses_one_seed_authority_in_effect_order(self):
        assert_command_contract(self.sources)

    def test_production_crates_do_not_depend_on_diagnostics(self):
        self.assertNotIn("proofbound-runtime-diagnose", self.sources["production"])
        self.assertNotIn("proofbound-runtime-diagnose", self.sources["linux"])

    def test_release_and_native_observation_closure_is_exact(self):
        assert_command_contract(self.sources)

    def test_command_mutations_are_rejected(self):
        mutations = [
            self.sources["command"].replace("create_new(true)", "create(true)", 1),
            self.sources["command"].replace(
                "let publication = completed.publication();",
                "let publication = ObserverDirective::PublishComplete;",
                1,
            ),
            self.sources["command"].replace(
                "diagnostic.output.child-writable", "diagnostic.output.allowed", 1
            ),
            self.sources["command"].replace(
                "observer_error_codes.insert(error.code());", "", 1
            ),
            self.sources["command"].replace(
                "selected.identity().role() != ArtifactRole::ProjectInput", "false", 1
            ),
            self.sources["command"].replace(
                "static_artifact_matches_file(&report.executable, target.executable())",
                "true",
                1,
            ),
            self.sources["command"].replace(
                "requested.as_os_str().is_empty() || requested.is_absolute()",
                "false",
                1,
            ),
            self.sources["command"].replace(
                "file.identity().size() > MAX_STATIC_SCAFFOLD_BYTES",
                "false",
                1,
            ),
            self.sources["command"].replace(
                "let ResolvedReadPath::File(file) = selected else",
                "let ResolvedReadPath::Directory(file) = selected else",
                1,
            ),
            self.sources["command"].replace(
                "let bytes = file\n        .read_bytes()",
                "let bytes = file\n        .read_bytes_without_identity_check()",
                1,
            ),
            self.sources["command"].replace(
                "serde_json::from_slice(&bytes)",
                "serde_json::from_value(serde_json::Value::Null)",
                1,
            ),
            self.sources["command"].replace(
                "report.host_profile.supports(architecture)", "true", 1
            ),
            self.sources["command"].replace(
                "static_artifact_matches_file(interpreter, loader)", "true", 1
            ),
            self.sources["command"].replace(
                "static_artifact_matches_resolved(&dependency.selected, path)",
                "true",
                1,
            ),
            self.sources["command"].replace(
                "sync_parent(draft_target)?;", "sync_parent(receipt_target)?;", 1
            ),
            self.sources["command"].replace(
                '    "PBR-DIAGNOSTIC-LIFECYCLE-AX-023",\n', "", 1
            ),
        ]
        for mutation in mutations:
            sources = dict(self.sources, command=mutation)
            with self.subTest(mutation=hash(mutation)):
                with self.assertRaises((AssertionError, ValueError)):
                    assert_command_contract(sources)

    def test_release_closure_mutations_are_rejected(self):
        mutations = [
            (
                "action_runner",
                self.sources["action_runner"].replace(
                    '    "pbr-diagnose",\n', "", 1
                ),
            ),
            (
                "observation_inputs",
                self.sources["observation_inputs"].replace(
                    '    ("PBR-OBSERVER-031", "diagnostic-release", "pbr-diagnose"),\n',
                    "",
                    1,
                ),
            ),
            (
                "native_context",
                self.sources["native_context"].replace(
                    '    ("diagnostic-observer", "pbr-diagnose"),\n', "", 1
                ),
            ),
            (
                "current_builder",
                self.sources["current_builder"].replace(
                    '    "pbr-diagnose",\n', "", 1
                ),
            ),
            (
                "current_verifier",
                self.sources["current_verifier"].replace(
                    '    "pbr-diagnose",\n', "", 1
                ),
            ),
            (
                "native_script",
                self.sources["native_script"].replace(
                    'dynamic_executable="$e2e_root/dynamic-diagnostic-probe"\n',
                    "",
                    1,
                ),
            ),
        ]
        for name, mutation in mutations:
            sources = dict(self.sources, **{name: mutation})
            with self.subTest(name=name):
                with self.assertRaises(AssertionError):
                    assert_command_contract(sources)


if __name__ == "__main__":
    unittest.main()
