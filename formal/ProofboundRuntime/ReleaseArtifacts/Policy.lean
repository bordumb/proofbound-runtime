import ProofboundRuntime.ReleaseArtifacts
import ProofboundRuntime.Refinement.PolicyCompilationClaim

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.ReleaseArtifacts.Policy

open ProofboundRuntime.Refinement.PolicyCompilation

def SourceRefinement : Prop :=
  ∀ authority : proofbound_runtime_core.normalize.NormalizedAuthority,
    ∃ compiled,
      proofbound_runtime_core.policy.compile_policy authority = ok compiled ∧
        toModelCompiledPolicy compiled =
          ProofboundRuntime.Policy.compile (toModelAuthority authority)

def Meaning (bytes : ByteArray) : Prop :=
  SourceRefinement ∧ artifactCarries bytes "PBR-POLICY-002"

@[proofbound_claim "PBR-POLICY-002"]
theorem policyReleaseArtifacts :
    Proofbound.Artifact.DigestBindingSetV1
      "PBR-POLICY-002"
      "proofbound-runtime-pbr/1"
      [
        {
          artifactLogicalName := "dist/release-observation/aarch64/pbr"
          expectedSha256 := "sha256:cb0c7d719aa4ab1cf07f189f4a8d770872b469dd7b97a51f7d9a4d35bfd9f1f9"
          bytes := aarch64PbrBytes
        },
        {
          artifactLogicalName := "dist/release-observation/x86_64/pbr"
          expectedSha256 := "sha256:9b69640708ddad502ee55d35be62cc4080ba4b5b31d8ecc92fc1cb7c73d80e2a"
          bytes := x86_64PbrBytes
        }
      ]
      Meaning := by
  constructor
  · intro member membership
    rcases List.mem_cons.mp membership with equality | membership
    · subst member
      exact toolchainWitness.aarch64Digest
    · rcases List.mem_cons.mp membership with equality | impossible
      · subst member
        exact toolchainWitness.x86_64Digest
      · exact (List.not_mem_nil impossible).elim
  · intro member membership
    rcases List.mem_cons.mp membership with equality | membership
    · subst member
      constructor
      · intro authority
        exact ProofboundRuntime.Refinement.PolicyCompilationClaim.compile_policy_refines authority
      · exact toolchainWitness.policyAarch64
    · rcases List.mem_cons.mp membership with equality | impossible
      · subst member
        constructor
        · intro authority
          exact ProofboundRuntime.Refinement.PolicyCompilationClaim.compile_policy_refines authority
        · exact toolchainWitness.policyX86_64
      · exact (List.not_mem_nil impossible).elim

end ProofboundRuntime.ReleaseArtifacts.Policy
