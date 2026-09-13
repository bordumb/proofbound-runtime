import re
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
MANUAL_EXPERIMENT_WORKFLOWS = (
    WORKFLOW_ROOT / "network-authority-experiment.yml",
    WORKFLOW_ROOT / "performance-baseline.yml",
)
CI_SCRIPT = REPOSITORY_ROOT / "tools" / "ci" / "ci.sh"
PRE_COMMIT_SCRIPT = REPOSITORY_ROOT / "tools" / "ci" / "pre-commit.sh"
CLAIMS_ROOT = REPOSITORY_ROOT / "claims"
PROOFBOUND_TOOL_DIGESTS = (
    REPOSITORY_ROOT
    / "proofbound"
    / "toolchains"
    / "proofbound-tools-linux-x86_64.sha256"
)
LEGACY_NATIVE_WORKFLOW = (
    REPOSITORY_ROOT / ".github" / "workflows" / "linux-enforcement.yml"
)
CHECKOUT_ACTION = (
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    " # v7.0.1"
)
UPLOAD_ARTIFACT_ACTION = (
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
    " # v7.0.1"
)
DOWNLOAD_ARTIFACT_ACTION = (
    "actions/download-artifact@70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3"
    " # v8.0.0"
)
RUST_TOOLCHAIN_ACTION = (
    "dtolnay/rust-toolchain@fef00d40025f7fd8f1ec759cbbb0f577ddfc3133"
    " # 1.94.0"
)


class RequiredWorkflowTests(unittest.TestCase):
    def test_required_workflow_has_one_fail_closed_aggregate(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("name: Current assurance gate"), 1)
        self.assertRegex(workflow, r"(?m)^  preflight:\n")
        self.assertRegex(workflow, r"(?m)^  rust:\n")
        self.assertRegex(workflow, r"(?m)^  formal:\n")
        self.assertRegex(workflow, r"(?m)^  proofbound-tools:\n")
        self.assertRegex(workflow, r"(?m)^  fresh-evidence:\n")
        self.assertRegex(workflow, r"(?m)^  native:\n")
        self.assertRegex(workflow, r"(?m)^  required:\n")
        self.assertGreaterEqual(workflow.count("needs: preflight"), 3)
        self.assertIn(
            "needs:\n      - preflight\n      - rust\n      - formal\n      - fresh-evidence\n      - native", workflow
        )
        self.assertIn("if: ${{ always() }}", workflow)
        for result in ("preflight", "rust", "formal", "fresh-evidence", "native"):
            self.assertIn(f'needs.{result}.result == \'success\'', workflow)

    def test_native_matrix_is_part_of_the_partition(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("name: Native boundary (${{ matrix.architecture }})", workflow)
        self.assertIn("architecture: x86_64", workflow)
        self.assertIn("architecture: aarch64", workflow)
        self.assertIn("bash tools/ci/native-linux.sh", workflow)
        self.assertFalse(LEGACY_NATIVE_WORKFLOW.exists())

    def test_each_lane_selects_one_shared_gate_partition(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        script = CI_SCRIPT.read_text(encoding="utf-8")

        for stage in ("preflight", "rust", "formal", "evidence"):
            self.assertEqual(workflow.count(f"bash tools/ci/ci.sh {stage}"), 1)
            self.assertRegex(script, rf'(?m)^if selected "{stage}"; then$')
        self.assertIn('stage="${1:-all}"', script)
        self.assertIn('all|preflight|rust|formal|evidence', script)

    def test_formal_and_fresh_evidence_have_independent_runtime_budgets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        formal = workflow[workflow.index("\n  formal:\n") : workflow.index("\n  proofbound-tools:\n")]
        tools = workflow[workflow.index("\n  proofbound-tools:\n") : workflow.index("\n  fresh-evidence:\n")]
        evidence = workflow[workflow.index("\n  fresh-evidence:\n") : workflow.index("\n  native:\n")]

        self.assertIn("bash tools/ci/ci.sh formal", formal)
        self.assertNotIn("Install pinned Proofbound tools", formal)
        self.assertNotIn("Install pinned Kani verifier", formal)
        self.assertIn("Install pinned Proofbound tools", tools)
        self.assertIn("bash tools/ci/ci.sh evidence", evidence)
        self.assertNotIn("Install pinned Proofbound tools", evidence)
        self.assertIn("Download pinned Proofbound tools", evidence)
        self.assertIn("Install pinned Kani verifier", evidence)

    def test_fresh_evidence_reuses_one_integrity_checked_proofbound_tool_bundle(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        tools = workflow[workflow.index("\n  proofbound-tools:\n") : workflow.index("\n  fresh-evidence:\n")]
        evidence = workflow[workflow.index("\n  fresh-evidence:\n") : workflow.index("\n  native:\n")]

        self.assertIn("name: Pinned Proofbound tools", tools)
        self.assertIn("needs: preflight", tools)
        self.assertEqual(workflow.count("Install pinned Proofbound tools"), 1)
        digest_check = (
            'sha256sum --check "$GITHUB_WORKSPACE/proofbound/toolchains/'
            'proofbound-tools-linux-x86_64.sha256"'
        )
        self.assertEqual(workflow.count(digest_check), 2)
        self.assertNotIn("> SHA256SUMS", tools)
        digest_lines = PROOFBOUND_TOOL_DIGESTS.read_text(encoding="ascii").splitlines()
        self.assertEqual(len(digest_lines), 5)
        self.assertEqual(
            {line.split("  ", 1)[1] for line in digest_lines},
            {
                "proofbound",
                "proofbound-adapter-aeneas",
                "proofbound-adapter-kani",
                "proofbound-adapter-lean",
                "proofbound-adapter-test",
            },
        )
        self.assertTrue(
            all(
                re.fullmatch(
                    r"[0-9a-f]{64}  proofbound(?:-adapter-[a-z]+)?", line
                )
                for line in digest_lines
            )
        )
        self.assertIn(
            "name: proofbound-tools-${{ env.PBR_EXACT_SHA }}",
            tools,
        )
        self.assertIn(
            "needs:\n      - preflight\n      - proofbound-tools",
            evidence,
        )
        self.assertIn(f"uses: {DOWNLOAD_ARTIFACT_ACTION}", evidence)
        self.assertIn(digest_check, evidence)
        self.assertIn('echo "$RUNNER_TEMP/proofbound-tools" >> "$GITHUB_PATH"', evidence)

    def test_fresh_evidence_matrix_is_a_closed_claim_partition(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        evidence = workflow[workflow.index("\n  fresh-evidence:\n") : workflow.index("\n  native:\n")]
        manifests = (REPOSITORY_ROOT / "tools/ci/manifests.sh").read_text(
            encoding="utf-8"
        )
        expected_kernel_shards = {
            "authority": "PBR-AUTH-001",
            "binding": "PBR-BINDING-005",
            "policy": "PBR-POLICY-002",
            "receipt": "PBR-RECEIPT-004",
        }
        claims = []
        for path in sorted(CLAIMS_ROOT.glob("*.toml")):
            content = path.read_text(encoding="utf-8")
            claim_id = re.search(r'(?m)^id = "([^"]+)"$', content)
            profile = re.search(r'(?m)^profile = "([^"]+)"$', content)
            self.assertIsNotNone(claim_id, path)
            self.assertIsNotNone(profile, path)
            claims.append({"id": claim_id.group(1), "profile": profile.group(1)})

        self.assertEqual(
            {claim["id"] for claim in claims if claim["profile"] == "kernel-with-assumptions"},
            set(expected_kernel_shards.values()),
        )
        self.assertTrue(
            all(claim["profile"] in {"kernel-with-assumptions", "ledger"} for claim in claims)
        )
        self.assertIn("fail-fast: false", evidence)
        for shard, selector in (*expected_kernel_shards.items(), ("ledger", "ledger")):
            self.assertIn(f"- shard: {shard}\n            selector: {selector}", evidence)
        self.assertIn("PBR_EVIDENCE_SELECTOR: ${{ matrix.selector }}", evidence)
        self.assertIn(
            "proofbound-runtime-ci-timing-fresh-evidence-"
            "${{ matrix.shard }}-${{ env.PBR_EXACT_SHA }}",
            evidence,
        )
        self.assertIn("ledger)", manifests)
        self.assertIn(
            "PBR-AUTH-001|PBR-BINDING-005|PBR-POLICY-002|PBR-RECEIPT-004)",
            manifests,
        )
        self.assertIn('check_args=(--profile ledger)', manifests)
        self.assertIn('check_args=(--claim "$selector")', manifests)

    def test_kernel_evidence_builds_lean_objects_before_theorem_audit(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        evidence = workflow[workflow.index("\n  fresh-evidence:\n") : workflow.index("\n  native:\n")]

        expected_targets = {
            "authority": "ProofboundRuntime.ReleaseArtifacts.Authority",
            "binding": "ProofboundRuntime.ReleaseArtifacts.ReceiptBinding",
            "policy": "ProofboundRuntime.ReleaseArtifacts.Policy",
            "receipt": "ProofboundRuntime.ReleaseArtifacts.ReceiptEligibility",
        }
        for shard, target in expected_targets.items():
            self.assertRegex(
                evidence,
                rf"- shard: {shard}\n"
                rf"            selector: [^\n]+\n"
                rf"            lean_target: {re.escape(target)}\n",
            )
        build_step = "Build pinned Lean project for theorem audit"
        self.assertIn(build_step, evidence)
        self.assertIn("if: ${{ matrix.selector != 'ledger' }}", evidence)
        self.assertIn("run: lake build ${{ matrix.lean_target }}", evidence)
        self.assertLess(evidence.index("Reject bootstrap lockfile drift"), evidence.index(build_step))
        self.assertLess(evidence.index(build_step), evidence.index("Run fresh evidence gate"))

    def test_fresh_evidence_installs_only_each_shards_required_toolchains(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        evidence = workflow[workflow.index("\n  fresh-evidence:\n") : workflow.index("\n  native:\n")]

        self.assertEqual(evidence.count("if: ${{ matrix.selector != 'ledger' }}"), 5)
        self.assertEqual(evidence.count("if: ${{ matrix.needs_kani }}"), 1)
        self.assertIn("- shard: authority\n            selector: PBR-AUTH-001\n", evidence)
        self.assertIn("needs_kani: true", evidence)
        self.assertIn("- shard: binding\n            selector: PBR-BINDING-005\n", evidence)
        self.assertIn("needs_kani: false", evidence)
        lean_install = evidence[
            evidence.index("- name: Install pinned Lean toolchain") :
            evidence.index("- name: Install Nix for pinned translation tools")
        ]
        self.assertNotIn("if:", lean_install)
        self.assertIn("name: Fetch locked Rust dependencies\n        run: cargo fetch --locked", evidence)
        self.assertIn(
            "name: Fetch locked Lean dependencies\n"
            "        run: lake update",
            evidence,
        )

    def test_fast_hook_excludes_fresh_evidence(self) -> None:
        hook = PRE_COMMIT_SCRIPT.read_text(encoding="utf-8")
        full_gate = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertNotIn("tools/ci/manifests.sh", hook)
        self.assertNotIn("cargo kani", hook)
        self.assertNotIn("lake build", hook)
        self.assertIn(
            "timed_unit fresh-evidence bash tools/ci/manifests.sh",
            full_gate,
        )

    def test_fresh_evidence_is_observable_while_it_runs(self) -> None:
        manifests = (REPOSITORY_ROOT / "tools/ci/manifests.sh").read_text(
            encoding="utf-8"
        )

        self.assertNotIn('check_output="$("$proofbound_bin" check', manifests)
        self.assertIn("Proofbound fresh check still running", manifests)
        self.assertIn('kill "$heartbeat_pid"', manifests)
        self.assertIn('check_output="$(<"$check_output_file")"', manifests)

    def test_preflight_runs_independent_performance_verifier_falsifiers(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "timed_unit performance-verifier-tests python3 -m unittest "
            "experiments.performance.test_discover_runtime_libraries "
            "experiments.performance.test_verify_pure "
            "experiments.performance.test_verify_native",
            script,
        )

    def test_preflight_validates_closed_performance_result_schema(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "timed_unit performance-schema-tests python3 -m unittest "
            "experiments.performance.test_pure_result_schema "
            "experiments.performance.test_native_result_schema",
            script,
        )

    def test_preflight_validates_performance_workflow(self) -> None:
        script = CI_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            "timed_unit performance-workflow-tests python3 -m unittest "
            "tools.ci.test_performance_workflow",
            script,
        )

    def test_each_lane_uploads_timing_outside_assurance_evidence(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertEqual(workflow.count("actions/upload-artifact@"), 7)
        self.assertEqual(workflow.count("if: ${{ always() }}"), 11)
        self.assertEqual(workflow.count("proofbound-runtime-ci-timing-"), 5)
        self.assertNotIn(".proofbound", "\n".join(
            line for line in workflow.splitlines() if "timing" in line.lower()
        ))

    def test_native_lane_retains_the_exact_assurance_evidence(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "PROOFBOUND_EVIDENCE_DIRECTORY: "
            "${{ github.workspace }}/target/native-evidence/${{ matrix.architecture }}",
            workflow,
        )
        self.assertIn("name: Upload native assurance evidence", workflow)
        self.assertIn(
            "name: proofbound-runtime-native-evidence-"
            "${{ matrix.architecture }}-${{ env.PBR_EXACT_SHA }}",
            workflow,
        )
        self.assertIn("path: ${{ env.PROOFBOUND_EVIDENCE_DIRECTORY }}", workflow)
        native_script = (REPOSITORY_ROOT / "tools/ci/native-linux.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("tools/ci/native_context.py", native_script)
        self.assertIn("native-context.json", native_script)
        self.assertIn("native-swap-matrix.json", native_script)

    def test_native_lane_falsifies_prelaunch_run_diagnostics(self) -> None:
        native_script = (REPOSITORY_ROOT / "tools/ci/native-linux.sh").read_text(
            encoding="utf-8"
        )

        for case in (
            "receipt-target-preexists",
            "plan-input-missing",
            "host-capability-unavailable",
            "output-root-preexists",
            "executable-resolution-failure",
        ):
            self.assertIn(f'assert_prelaunch_failure "{case}"', native_script)
        self.assertIn("pbr: phase=receipt-target rule=receipt-target-valid", native_script)
        self.assertIn("pbr: phase=plan-input rule=plan-source-readable", native_script)
        self.assertIn("pbr: phase=host-capabilities rule=host-supported", native_script)
        self.assertIn("pbr: phase=output-root rule=output-root-fresh", native_script)
        self.assertIn(
            "pbr: phase=executable-closure rule=executable-closure-resolved",
            native_script,
        )
        self.assertIn('test ! -e "$diagnostic_child_marker"', native_script)
        self.assertIn("native-run-diagnostics.json", native_script)

    def test_native_lane_retains_preflight_and_scaffold_release_inputs(self) -> None:
        native_script = (REPOSITORY_ROOT / "tools/ci/native-linux.sh").read_text(
            encoding="utf-8"
        )
        observation = (
            REPOSITORY_ROOT
            / "crates/proofbound-runtime-compose/tests/release_observation.rs"
        ).read_text(encoding="utf-8")

        self.assertIn('"$runtime_bin_directory/pbr" plan scaffold', native_script)
        self.assertIn("plan-scaffold.json", native_script)
        self.assertIn('"choose-environment", "choose-limits"', native_script)
        self.assertNotIn('"choose-environment-names"', native_script)
        self.assertIn("assert_native_preflight", observation)
        self.assertIn("assert_native_scaffold", observation)

    def test_each_lane_publishes_its_validated_timing_summary(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        for lane in ("preflight", "Rust", "formal", "fresh evidence", "native"):
            self.assertEqual(workflow.count(f"name: Publish {lane} timing summary"), 1)
        self.assertEqual(
            workflow.count("python3 tools/ci/summarize_timings.py"),
            5,
        )
        self.assertEqual(workflow.count('} >> "$GITHUB_STEP_SUMMARY"'), 5)

    def test_each_lane_checks_out_and_confirms_the_exact_pr_head(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        exact_sha = "${{ github.event.pull_request.head.sha || github.sha }}"

        self.assertIn(f"PBR_EXACT_SHA: {exact_sha}", workflow)
        self.assertEqual(workflow.count(f"uses: {CHECKOUT_ACTION}"), 6)
        self.assertEqual(workflow.count("ref: ${{ env.PBR_EXACT_SHA }}"), 6)
        self.assertEqual(
            workflow.count(
                'run: test "$(git rev-parse HEAD)" = "$PBR_EXACT_SHA"'
            ),
            6,
        )
        self.assertEqual(workflow.count("-${{ env.PBR_EXACT_SHA }}"), 8)
        self.assertNotIn('= "$GITHUB_SHA"', workflow)

    def test_first_party_actions_are_exact_node24_releases(self) -> None:
        uses_pattern = re.compile(
            r"(?m)^\s*uses:\s+"
            r"(actions/(?:checkout|upload-artifact|download-artifact)@[^\n]+)$"
        )
        observed: list[tuple[str, str]] = []
        for workflow_path in sorted(WORKFLOW_ROOT.glob("*.yml")):
            for action in uses_pattern.findall(
                workflow_path.read_text(encoding="utf-8")
            ):
                observed.append((workflow_path.name, action))

        self.assertTrue(observed)
        allowed = {CHECKOUT_ACTION, UPLOAD_ARTIFACT_ACTION, DOWNLOAD_ARTIFACT_ACTION}
        self.assertEqual(
            [(name, action) for name, action in observed if action not in allowed],
            [],
        )

    def test_every_external_action_is_pinned_to_one_commit(self) -> None:
        uses_pattern = re.compile(r"(?m)^\s*uses:\s+([^#\s]+)")
        observed: list[tuple[str, str]] = []
        for workflow_path in sorted(WORKFLOW_ROOT.glob("*.yml")):
            for action in uses_pattern.findall(
                workflow_path.read_text(encoding="utf-8")
            ):
                if not action.startswith("./"):
                    observed.append((workflow_path.name, action))

        self.assertTrue(observed)
        for workflow_name, action in observed:
            with self.subTest(workflow=workflow_name, action=action):
                self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
        rust_action = RUST_TOOLCHAIN_ACTION.split()[0]
        self.assertEqual(sum(action == rust_action for _, action in observed), 9)

    def test_triggers_and_cancellation_remain_closed(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("    branches:\n      - main\n", workflow)
        self.assertIn('      - "v*"\n', workflow)
        self.assertIn(
            "group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}",
            workflow,
        )
        self.assertIn(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", workflow
        )
        self.assertIsNone(re.search(r"(?m)^\s+continue-on-error:\s*true\s*$", workflow))

    def test_completed_experiment_workflows_are_manual_only(self) -> None:
        for workflow_path in MANUAL_EXPERIMENT_WORKFLOWS:
            with self.subTest(workflow=workflow_path.name):
                workflow = workflow_path.read_text(encoding="utf-8")
                self.assertIn("  workflow_dispatch:\n", workflow)
                self.assertIn("    inputs:\n      revision:\n", workflow)
                self.assertNotIn("  pull_request:\n", workflow)
                self.assertNotIn("github.event.pull_request", workflow)

    def test_network_experiment_requires_an_exact_revision(self) -> None:
        workflow = MANUAL_EXPERIMENT_WORKFLOWS[0].read_text(encoding="utf-8")

        self.assertIn("EXPERIMENT_SHA: ${{ inputs.revision }}", workflow)
        self.assertEqual(
            workflow.count('[[ "$EXPERIMENT_SHA" =~ ^[0-9a-f]{40}$ ]]'),
            workflow.count("Confirm the exact experiment head"),
        )


if __name__ == "__main__":
    unittest.main()
