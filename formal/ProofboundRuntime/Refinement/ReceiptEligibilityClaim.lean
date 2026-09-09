import Proofbound.Attribute
import ProofboundRuntime.Refinement.ReceiptEligibility

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.ReceiptEligibilityClaim

open ProofboundRuntime.Refinement.ReceiptEligibility

@[proofbound_exempt "Supporting source-refinement lemma consumed by the public release-artifact theorem."]
theorem derive_receipt_eligibility_refines
    (facts : proofbound_runtime_receipt.ReceiptFacts) :
    ∃ eligibility,
      proofbound_runtime_receipt.derive_receipt_eligibility facts = ok eligibility ∧
        toModelEligibility eligibility =
          ProofboundRuntime.Receipt.deriveEligibility (toModelFacts facts) :=
  ProofboundRuntime.Refinement.ReceiptEligibility.derive_receipt_eligibility_refines facts

end ProofboundRuntime.Refinement.ReceiptEligibilityClaim
