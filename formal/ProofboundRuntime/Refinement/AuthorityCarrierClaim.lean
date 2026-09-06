import Proofbound.Attribute
import ProofboundRuntime.Refinement.AuthorityNormalization

namespace ProofboundRuntime.Refinement.AuthorityCarrierClaim

open proofbound_runtime_core
open ProofboundRuntime.Refinement.AuthorityNormalization

@[proofbound_claim "PBR-AUTH-001"]
theorem authority_byte_carriers_bounded
    (plan : authority.AuthorityPlan) :
    AuthorityByteCarriersBounded plan :=
  authorityByteCarriersBounded plan

end ProofboundRuntime.Refinement.AuthorityCarrierClaim
