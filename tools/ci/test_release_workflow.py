import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowTests(unittest.TestCase):
    def test_dispatch_requires_one_exact_revision(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("workflow_dispatch:\n    inputs:\n      revision:", workflow)
        self.assertIn("PBR_RELEASE_REVISION: ${{ inputs.revision }}", workflow)
        revision_input = workflow[workflow.index("      revision:") :]
        revision_input = revision_input[: revision_input.index("\n\nenv:")]
        self.assertIn("required: true", revision_input)
        self.assertIn("type: string", revision_input)

    def test_preflight_rejects_non_sha_and_non_mainline_revisions(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("\n  validate-revision:\n", workflow)
        validation_start = workflow.index("\n  validate-revision:\n")
        release_start = workflow.index("\n  release:\n")
        validation = workflow[validation_start:release_start]

        self.assertIn("fetch-depth: 0", validation)
        self.assertIn("ref: ${{ env.PBR_RELEASE_REVISION }}", validation)
        self.assertIn("[[ \"$PBR_RELEASE_REVISION\" =~ ^[0-9a-f]{40}$ ]]", validation)
        self.assertIn(
            'test "$(git rev-parse HEAD)" = "$PBR_RELEASE_REVISION"', validation
        )
        self.assertIn(
            "git merge-base --is-ancestor \"$PBR_RELEASE_REVISION\" origin/main",
            validation,
        )

    def test_both_release_architectures_depend_on_validated_exact_revision(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        release = workflow[workflow.index("\n  release:\n") :]

        self.assertIn("needs: validate-revision", release)
        self.assertIn("architecture: x86_64", release)
        self.assertIn("architecture: aarch64", release)
        self.assertIn("ref: ${{ env.PBR_RELEASE_REVISION }}", release)
        self.assertIn("fetch-depth: 0", release)
        self.assertIn(
            'run: test "$(git rev-parse HEAD)" = "$PBR_RELEASE_REVISION"', release
        )
        self.assertNotIn('= "$GITHUB_SHA"', release)

    def test_release_reproduction_remains_clean_and_uncached(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("cache-nix-action", workflow)
        self.assertIn("Build and byte-compare two release bundles", workflow)
        self.assertIn("Run the complete repository base gate", workflow)
        self.assertIn("Execute and verify the exact release binaries", workflow)

        builder = (REPOSITORY_ROOT / "tools/release/build-linux.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn('"$target_directory/$target/release/pbr-accept"', builder)
        self.assertIn('"$work_root/$build_name-$acceptor_name"', builder)
        self.assertIn(
            'cmp "$work_root/first-$acceptor_name" "$work_root/second-$acceptor_name"',
            builder,
        )
        self.assertIn('sha256sum "$acceptor_name"', builder)

    def test_version_two_release_chain_uses_cbor_and_a_decoded_projection(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            '--execution-receipt "$evidence_directory/execution-receipt.cbor"',
            workflow,
        )
        self.assertIn('--output "$evidence_directory/composed-receipt.cbor"', workflow)
        self.assertIn(
            '"$runtime_directory/pbr-compose" inspect',
            workflow,
        )
        self.assertGreaterEqual(
            workflow.count('"$evidence_directory/composed-receipt.cbor"'), 2
        )
        self.assertIn("composed-receipt.projection.json", workflow)
        self.assertNotIn("execution-receipt.json", workflow)
        self.assertNotIn("composed-receipt.json", workflow)

        observation = (
            REPOSITORY_ROOT
            / "crates/proofbound-runtime-compose/tests/release_observation.rs"
        ).read_text(encoding="utf-8")
        self.assertIn('execution-receipt.cbor', observation)
        self.assertNotIn('execution-receipt.json', observation)

    def test_contextual_release_evidence_uses_the_v2_receipt_carrier(self) -> None:
        evidence_root = REPOSITORY_ROOT / "proofbound" / "evidence"
        manifests = sorted(evidence_root.glob("release-observe-*.toml"))
        self.assertTrue(manifests)
        receipt_consumers = 0
        for manifest in manifests:
            source = manifest.read_text(encoding="utf-8")
            with self.subTest(manifest=manifest.name):
                self.assertNotIn("execution-receipt.json", source)
                if "execution-receipt.cbor" in source:
                    receipt_consumers += 1
        self.assertEqual(receipt_consumers, 6)


if __name__ == "__main__":
    unittest.main()
