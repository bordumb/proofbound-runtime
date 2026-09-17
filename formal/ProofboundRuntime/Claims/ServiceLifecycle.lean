import Proofbound.Attribute
import ProofboundRuntime.ServiceLifecycle

namespace ProofboundRuntime.Claims.ServiceLifecycle

@[proofbound_claim "PBR-NETWORK-034"]
theorem lifecycle_transition_is_exact
    (state : ProofboundRuntime.ServiceLifecycle.State)
    (event : ProofboundRuntime.ServiceLifecycle.Event)
    (next : ProofboundRuntime.ServiceLifecycle.State) :
    ProofboundRuntime.ServiceLifecycle.transition state event = .ok next ↔
      ProofboundRuntime.ServiceLifecycle.AllowedTransition state event next := by
  exact ProofboundRuntime.ServiceLifecycle.transition_exact state event next

end ProofboundRuntime.Claims.ServiceLifecycle
