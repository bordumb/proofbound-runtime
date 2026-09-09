import ProofboundRuntime.ReleaseArtifacts
import ProofboundRuntime.Refinement.ReceiptEligibilityClaim

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.ReleaseArtifacts.ReceiptEligibility

open ProofboundRuntime.Refinement.ReceiptEligibility

def SourceRefinement : Prop :=
  ∀ facts : proofbound_runtime_receipt.ReceiptFacts,
    ∃ eligibility,
      proofbound_runtime_receipt.derive_receipt_eligibility facts = ok eligibility ∧
        toModelEligibility eligibility =
          ProofboundRuntime.Receipt.deriveEligibility (toModelFacts facts)

def Meaning (bytes : ByteArray) : Prop :=
  SourceRefinement ∧ artifactCarries bytes "PBR-RECEIPT-004"

@[proofbound_claim "PBR-RECEIPT-004"]
theorem receiptEligibilityReleaseArtifacts :
    Proofbound.Artifact.DigestBindingSetV1
      "PBR-RECEIPT-004"
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
      · intro facts
        exact ProofboundRuntime.Refinement.ReceiptEligibilityClaim.derive_receipt_eligibility_refines facts
      · exact toolchainWitness.receiptEligibilityAarch64
    · rcases List.mem_cons.mp membership with equality | impossible
      · subst member
        constructor
        · intro facts
          exact ProofboundRuntime.Refinement.ReceiptEligibilityClaim.derive_receipt_eligibility_refines facts
        · exact toolchainWitness.receiptEligibilityX86_64
      · exact (List.not_mem_nil impossible).elim

end ProofboundRuntime.ReleaseArtifacts.ReceiptEligibility
