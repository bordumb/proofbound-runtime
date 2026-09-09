import ProofboundRuntime.ReleaseArtifacts
import ProofboundRuntime.Refinement.AuthorityNormalizationClaim

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.ReleaseArtifacts.Authority

open ProofboundRuntime.Refinement.AuthorityNormalization

def SourceRefinement : Prop :=
  ∀ plan : proofbound_runtime_core.authority.AuthorityPlan,
    proofbound_runtime_core.normalize.normalize_authority plan
      ⦃ result => ∃ out,
        result = core.result.Result.Ok out ∧
          out.paths.val.Nodup ∧
          ListSubset out.paths.val plan.paths.val ∧
          out.environment.val.Nodup ∧
          ListSubset out.environment.val plan.environment.val ∧
          out.limits = plan.limits ∧
          out.network = plan.network ⦄

def Meaning (bytes : ByteArray) : Prop :=
  SourceRefinement ∧ artifactCarries bytes "PBR-AUTH-001"

@[proofbound_claim "PBR-AUTH-001"]
theorem authorityReleaseArtifacts :
    Proofbound.Artifact.DigestBindingSetV1
      "PBR-AUTH-001"
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
      · intro plan
        exact ProofboundRuntime.Refinement.AuthorityNormalizationClaim.normalize_authority_refines plan
      · exact toolchainWitness.authorityAarch64
    · rcases List.mem_cons.mp membership with equality | impossible
      · subst member
        constructor
        · intro plan
          exact ProofboundRuntime.Refinement.AuthorityNormalizationClaim.normalize_authority_refines plan
        · exact toolchainWitness.authorityX86_64
      · exact (List.not_mem_nil impossible).elim

end ProofboundRuntime.ReleaseArtifacts.Authority
