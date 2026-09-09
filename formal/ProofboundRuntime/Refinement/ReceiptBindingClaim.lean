import Proofbound.Attribute
import ProofboundRuntime.Refinement.ReceiptBinding

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.ReceiptBindingClaim

open ProofboundRuntime.Refinement.ReceiptBinding

@[proofbound_exempt "Supporting source-refinement lemma consumed by the public release-artifact theorem."]
theorem construct_and_project_receipt_binding_refines
    (parts : proofbound_runtime_binding.ReceiptBindingParts) :
    ∃ output,
      proofbound_runtime_binding.construct_and_project_receipt_binding parts =
        ok output ∧
      ProofboundRuntime.Binding.Complete (toModelCandidate parts) ∧
      ProofboundRuntime.Binding.RetainsExactly
        (toModelCandidate parts) (toModelReceipt output) :=
  ProofboundRuntime.Refinement.ReceiptBinding.construct_and_project_receipt_binding_refines
    parts

end ProofboundRuntime.Refinement.ReceiptBindingClaim
