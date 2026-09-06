import Proofbound.Attribute
import ProofboundRuntime.Receipt

namespace ProofboundRuntime.Claims.Receipt

@[proofbound_claim "PBR-RECEIPT-004"]
theorem eligibility_is_exact (facts : ProofboundRuntime.Receipt.Facts) :
    (ProofboundRuntime.Receipt.deriveEligibility facts = .reusable ↔
      ProofboundRuntime.Receipt.IsReusable facts) ∧
    (¬ ProofboundRuntime.Receipt.IsReusable facts →
      ProofboundRuntime.Receipt.deriveEligibility facts =
        .nonReusable (ProofboundRuntime.Receipt.nonReusableReasons facts) ∧
      ProofboundRuntime.Receipt.nonReusableReasons facts ≠ []) := by
  exact ProofboundRuntime.Receipt.derive_exact facts

end ProofboundRuntime.Claims.Receipt
