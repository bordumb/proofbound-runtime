import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ADR = REPOSITORY_ROOT / "docs/adr/0003-deterministic-cbor-wire-objects.md"
MEMORY_SPEC = REPOSITORY_ROOT / "docs/specs/0007_memory_and_swap_profile.md"
SCHEMA_ROOT = REPOSITORY_ROOT / "schemas"
VECTOR_ROOT = SCHEMA_ROOT / "vectors/v2"
VERSION_TWO_OBJECTS = (
    "execution-plan",
    "compiled-policy",
    "run-result",
    "execution-receipt",
    "composed-receipt",
)


class WireTransitionTests(unittest.TestCase):
    def test_version_two_wire_contract_selects_text_map_keys(self) -> None:
        adr = ADR.read_text(encoding="utf-8")
        specification = MEMORY_SPEC.read_text(encoding="utf-8")

        self.assertIn("The deterministic-CBOR decision is accepted.", adr)
        self.assertIn("Version 2 schemas use text map keys.", adr)
        self.assertNotIn("The map-key representation is not yet selected", adr)
        self.assertIn("**Status:** Accepted implementation specification", specification)
        self.assertIn("Version 2 maps use text keys", specification)

    def test_memory_receipt_uses_cbor_integers_not_json_workarounds(self) -> None:
        specification = MEMORY_SPEC.read_text(encoding="utf-8")
        normalized = " ".join(specification.split())

        self.assertIn(
            "Each byte count and counter is encoded as an unsigned integer in the "
            "version 2 committed CBOR bytes.",
            normalized,
        )
        self.assertNotIn("so the JSON wire can represent", specification)
        self.assertIn(
            "the projection is not a wire object and is never a verification input",
            normalized,
        )

    def test_every_version_two_wire_object_has_schema_and_golden_pair(self) -> None:
        self.assertEqual(
            {path.stem.removesuffix("-v2") for path in SCHEMA_ROOT.glob("*-v2.cddl")},
            set(VERSION_TWO_OBJECTS),
        )
        self.assertEqual(
            {path.name.removesuffix(".cbor.hex") for path in VECTOR_ROOT.glob("*.cbor.hex")},
            set(VERSION_TWO_OBJECTS),
        )
        self.assertEqual(
            {path.name.removesuffix(".projection.json") for path in VECTOR_ROOT.glob("*.projection.json")},
            set(VERSION_TWO_OBJECTS),
        )

    def test_every_execution_entry_point_uses_the_v2_plan_decoder(self) -> None:
        for relative in (
            "crates/proofbound-runtime-cli/src/preflight.rs",
            "crates/proofbound-runtime-cli/src/run.rs",
        ):
            with self.subTest(relative=relative):
                source = (REPOSITORY_ROOT / relative).read_text(encoding="utf-8")
                self.assertIn("parse_execution_plan_for_execution(&plan_bytes)", source)
                self.assertNotIn("from_utf8(&plan_bytes)", source)

    def test_run_installs_v2_limits_and_retains_terminal_observations(self) -> None:
        run = (REPOSITORY_ROOT / "crates/proofbound-runtime-cli/src/run.rs").read_text(
            encoding="utf-8"
        )
        supervisor = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-linux/src/supervisor.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("FreshCgroup::create_v2(", run)
        self.assertNotIn("FreshCgroup::create(supported.cgroup_v2()", run)
        self.assertIn("let resources = cgroup.finish();", supervisor)
        self.assertIn("resources: resources?", supervisor)
        self.assertIn("pub const fn resources(&self) -> Option<TerminalResources>", supervisor)

    def test_native_execution_recipe_delegates_memory_and_pids(self) -> None:
        script = (REPOSITORY_ROOT / "tools/ci/native-linux.sh").read_text(encoding="utf-8")
        doctor = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-cli/src/doctor.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("Delegate=pids memory", script)
        self.assertIn("echo +memory +pids", script)
        self.assertIn("Delegate=pids memory", doctor)

    def test_native_recipe_exercises_swap_absent_and_present(self) -> None:
        script = (REPOSITORY_ROOT / "tools/ci/native-linux.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("PROOFBOUND_NATIVE_SWAP_MODE=absent", script)
        self.assertIn("PROOFBOUND_NATIVE_SWAP_MODE=present", script)
        self.assertIn("mkswap", script)
        self.assertIn("swapon", script)
        self.assertIn("swapoff", script)

    def test_tier_three_policy_domain_carries_memory_and_swap(self) -> None:
        model = (
            REPOSITORY_ROOT / "formal/ProofboundRuntime/Policy.lean"
        ).read_text(encoding="utf-8")
        generated = (
            REPOSITORY_ROOT / "formal/generated/ProofboundRuntimePolicy/Types.lean"
        ).read_text(encoding="utf-8")
        refinement = (
            REPOSITORY_ROOT
            / "formal/ProofboundRuntime/Refinement/PolicyCompilation.lean"
        ).read_text(encoding="utf-8")
        harness = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-policy-kani/src/lib.rs"
        ).read_text(encoding="utf-8")

        for source in (model, refinement):
            self.assertIn("memoryBytes", source)
            self.assertIn("swapBytes", source)
        for type_name in ("MemoryByteLimit", "SwapByteLimit"):
            self.assertIn(f"authority.{type_name}", generated)
        self.assertIn("memory : Option authority.MemoryByteLimit", generated)
        self.assertIn("swap : Option authority.SwapByteLimit", generated)
        self.assertIn("ResourceLimits::new_v2(", harness)
        self.assertIn("MemoryByteLimit::new(", harness)
        self.assertIn("SwapByteLimit::new(", harness)

    def test_authority_translation_inventory_includes_v2_limit_wrappers(self) -> None:
        translation = (
            REPOSITORY_ROOT / "proofbound/translations/authority-normalization.toml"
        ).read_text(encoding="utf-8")

        for type_name in ("MemoryByteLimit", "SwapByteLimit"):
            self.assertIn(
                'kind = "type"\n'
                f'rust_name = "proofbound_runtime_core::authority::{type_name}"',
                translation,
            )

    def test_native_swap_matrix_does_not_infer_events_from_swap_use(self) -> None:
        specification = MEMORY_SPEC.read_text(encoding="utf-8")
        normalized_specification = " ".join(specification.split())
        native = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-linux/tests/native_linux.rs"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "A nonzero peak alone is not a limit event.",
            normalized_specification,
        )
        self.assertNotIn("memory.reclaim", native)
        self.assertIn("resources.swap_peak_bytes() > 0", native)
        self.assertIn("resources.memory_events().oom() > 0", native)

    def test_public_docs_distinguish_v1_and_v2_resource_boundaries(self) -> None:
        readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
        threat_model = (
            REPOSITORY_ROOT / "docs/threat-model.md"
        ).read_text(encoding="utf-8")
        receipt_semantics = (
            REPOSITORY_ROOT / "docs/receipt-semantics.md"
        ).read_text(encoding="utf-8")

        for document in (threat_model, receipt_semantics):
            self.assertIn("Version 1", document)
            self.assertIn("Version 2", document)
        self.assertIn("process count, wall time, and captured stream bytes", threat_model)
        self.assertIn("memory.max", threat_model)
        self.assertIn("memory.swap.max", threat_model)
        self.assertIn("## Version 2 wire contract", receipt_semantics)
        self.assertIn("RFC 8949 section 4.2.1", receipt_semantics)
        self.assertIn("never a verification input", receipt_semantics)
        self.assertIn("tools/ci/encode_plan_v2.py", readme)
        self.assertIn("--memory-bytes", readme)
        self.assertIn("--swap-bytes", readme)

    def test_resource_boundary_has_an_honest_registered_claim(self) -> None:
        claim_path = REPOSITORY_ROOT / "claims/PBR-RESOURCE-010.toml"
        evidence_path = (
            REPOSITORY_ROOT / "proofbound/evidence/resource-boundary-attacks.toml"
        )
        self.assertTrue(claim_path.is_file())
        self.assertTrue(evidence_path.is_file())

        claim = claim_path.read_text(encoding="utf-8")
        evidence = evidence_path.read_text(encoding="utf-8")
        self.assertIn('tier = 0', claim)
        self.assertIn('not theorem-derived artifact soundness', claim)
        self.assertIn('"docs/specs/0007_memory_and_swap_profile.md"', claim)
        self.assertIn('"tests/attacks/native-linux/memory-v2.toml"', claim)
        self.assertIn('claims = ["PBR-RESOURCE-010"]', evidence)

        expected_claims = 'claims = ["PBR-RESOURCE-010", "PBR-RUN-007"]'
        for architecture in ("aarch64", "x86-64"):
            manifest = (
                REPOSITORY_ROOT
                / f"proofbound/evidence/release-observe-runtime-linux-{architecture}.toml"
            ).read_text(encoding="utf-8")
            self.assertIn(expected_claims, manifest)

        observations = (
            REPOSITORY_ROOT / "tools/release/observation_inputs.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '("PBR-RESOURCE-010", "runtime-release", "pbr")', observations
        )

    def test_v2_receipt_resources_cross_the_proven_binding_boundary(self) -> None:
        binding = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-binding/src/lib.rs"
        ).read_text(encoding="utf-8")
        receipt = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-core/src/receipt.rs"
        ).read_text(encoding="utf-8")
        model = (
            REPOSITORY_ROOT / "formal/ProofboundRuntime/Binding.lean"
        ).read_text(encoding="utf-8")
        claim = (REPOSITORY_ROOT / "claims/PBR-BINDING-005.toml").read_text(
            encoding="utf-8"
        )

        self.assertIn("pub resources: Option<Vec<u8>>", binding)
        self.assertIn("def requiredFieldsV1", model)
        self.assertIn("def requiredFieldsV2", model)
        self.assertIn("canonical_v2_binding_parts(receipt)?", receipt)
        self.assertIn("construct_and_project_receipt_binding(parts)", receipt)
        self.assertNotIn("all 20 version 1 top-level fields", claim)

    def test_v2_limit_events_cross_the_receipt_eligibility_proof_boundary(self) -> None:
        model = (
            REPOSITORY_ROOT / "formal/ProofboundRuntime/Receipt.lean"
        ).read_text(encoding="utf-8")
        generated = (
            REPOSITORY_ROOT / "formal/generated/ProofboundRuntimeReceipt/Types.lean"
        ).read_text(encoding="utf-8")
        refinement = (
            REPOSITORY_ROOT
            / "formal/ProofboundRuntime/Refinement/ReceiptEligibility.lean"
        ).read_text(encoding="utf-8")
        harness = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-receipt-kani/src/lib.rs"
        ).read_text(encoding="utf-8")
        claim = (REPOSITORY_ROOT / "claims/PBR-RECEIPT-004.toml").read_text(
            encoding="utf-8"
        )

        self.assertIn("limitEvents", model)
        self.assertIn("structure LimitEvents", generated)
        self.assertIn("limit_events : LimitEvents", generated)
        self.assertIn("toModelLimitEvents", refinement)
        self.assertIn("LimitEvents::new", harness)
        self.assertNotIn("exact version 1 model", claim)

    def test_binding_refinement_rebuilds_the_changed_model(self) -> None:
        script = (
            REPOSITORY_ROOT / "tools/ci/binding-refinement.sh"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "lake build Aeneas ProofboundRuntime.Binding",
            script,
        )

    def test_composer_has_separate_historical_and_v2_wire_paths(self) -> None:
        manifest = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-compose/Cargo.toml"
        ).read_text(encoding="utf-8")
        library = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-compose/src/lib.rs"
        ).read_text(encoding="utf-8")
        binary = (
            REPOSITORY_ROOT / "crates/proofbound-runtime-compose/src/main.rs"
        ).read_text(encoding="utf-8")

        self.assertIn("proofbound-runtime-verify", manifest)
        self.assertIn("COMPOSITION_SCHEMA_V2", library)
        self.assertIn("decode_receipt(inputs.execution_receipt.bytes)", library)
        self.assertIn("encode_composed_v2", library)
        self.assertIn("project_composed_receipt", library)
        self.assertIn("project_composed_receipt(&composed)", binary)

    def test_v2_composition_retains_structured_residual_obligations(self) -> None:
        schema = (SCHEMA_ROOT / "composed-receipt-v2.cddl").read_text(
            encoding="utf-8"
        )
        projection = __import__("json").loads(
            (VECTOR_ROOT / "composed-receipt.projection.json").read_text(
                encoding="utf-8"
            )
        )

        self.assertIn('"not_proved_out_of_scope": residual-obligations', schema)
        self.assertIn("residual-obligations = {", schema)
        self.assertEqual(
            set(projection["not_proved_out_of_scope"]),
            {"assumptions", "exclusions", "open_obligations", "undischarged_premises"},
        )


if __name__ == "__main__":
    unittest.main()
