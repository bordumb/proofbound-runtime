import Proofbound.Attribute
import ProofboundRuntime.Authority

namespace ProofboundRuntime.Claims.Authority

@[proofbound_claim "PBR-AUTH-001"]
theorem normalization_is_canonical_and_non_amplifying
    (plan : ProofboundRuntime.Authority.Plan) :
    ProofboundRuntime.Authority.IsCanonical
        (ProofboundRuntime.Authority.normalize plan) ∧
      ProofboundRuntime.Authority.IsSubset
        (ProofboundRuntime.Authority.normalize plan) plan := by
  exact ⟨
    ProofboundRuntime.Authority.normalize_canonical plan,
    ProofboundRuntime.Authority.normalize_no_amplification plan
  ⟩

end ProofboundRuntime.Claims.Authority
