import Proofbound.Attribute
import ProofboundRuntime.Policy

namespace ProofboundRuntime.Claims.Policy

@[proofbound_claim "PBR-POLICY-002"]
theorem compilation_does_not_amplify
    (authority : ProofboundRuntime.Policy.NormalizedAuthority) :
    ProofboundRuntime.Policy.NoAmplification
      (ProofboundRuntime.Policy.compile authority) authority := by
  exact ProofboundRuntime.Policy.compile_no_amplification authority

end ProofboundRuntime.Claims.Policy
