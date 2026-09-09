import ProofboundRuntime.Binding
import Proofbound.Attribute

namespace ProofboundRuntime.Claims.Binding

@[proofbound_exempt "Abstract model theorem consumed by the production source-refinement claim."]
theorem constructed_receipt_is_complete_and_exact
    (candidate : ProofboundRuntime.Binding.Candidate)
    (receipt : ProofboundRuntime.Binding.Receipt)
    (constructed : ProofboundRuntime.Binding.construct candidate = some receipt) :
    ProofboundRuntime.Binding.Complete candidate ∧
      ProofboundRuntime.Binding.RetainsExactly candidate receipt := by
  exact ProofboundRuntime.Binding.construct_exact candidate receipt constructed

end ProofboundRuntime.Claims.Binding
