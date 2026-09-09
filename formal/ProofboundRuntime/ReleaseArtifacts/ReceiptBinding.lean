import ProofboundRuntime.ReleaseArtifacts
import ProofboundRuntime.Refinement.ReceiptBindingClaim

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.ReleaseArtifacts.ReceiptBinding

open ProofboundRuntime.Refinement.ReceiptBinding

def SourceRefinement : Prop :=
  ∀ parts : proofbound_runtime_binding.ReceiptBindingParts,
    ∃ output,
      proofbound_runtime_binding.construct_and_project_receipt_binding parts =
        ok output ∧
      ProofboundRuntime.Binding.Complete (toModelCandidate parts) ∧
      ProofboundRuntime.Binding.RetainsExactly
        (toModelCandidate parts) (toModelReceipt output)

def Meaning (bytes : ByteArray) : Prop :=
  SourceRefinement ∧ artifactCarries bytes "PBR-BINDING-005"

@[proofbound_claim "PBR-BINDING-005"]
theorem receiptBindingReleaseArtifacts :
    Proofbound.Artifact.DigestBindingSetV1
      "PBR-BINDING-005"
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
      · intro parts
        exact ProofboundRuntime.Refinement.ReceiptBindingClaim.construct_and_project_receipt_binding_refines parts
      · exact toolchainWitness.receiptBindingAarch64
    · rcases List.mem_cons.mp membership with equality | impossible
      · subst member
        constructor
        · intro parts
          exact ProofboundRuntime.Refinement.ReceiptBindingClaim.construct_and_project_receipt_binding_refines parts
        · exact toolchainWitness.receiptBindingX86_64
      · exact (List.not_mem_nil impossible).elim

end ProofboundRuntime.ReleaseArtifacts.ReceiptBinding
