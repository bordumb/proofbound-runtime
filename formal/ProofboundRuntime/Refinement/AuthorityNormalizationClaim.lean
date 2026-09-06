import Proofbound.Attribute
import ProofboundRuntime.Refinement.AuthorityNormalization

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.AuthorityNormalizationClaim

open proofbound_runtime_core
open ProofboundRuntime.Refinement.AuthorityNormalization

@[proofbound_claim "PBR-AUTH-001"]
theorem normalize_authority_refines
    (plan : authority.AuthorityPlan)
    (hBounded : AuthorityStringsBounded plan) :
    normalize.normalize_authority plan
      ⦃ out =>
        out.paths.val.Nodup ∧
        ListSubset out.paths.val plan.paths.val ∧
        out.environment.val.Nodup ∧
        ListSubset out.environment.val plan.environment.val ∧
        out.limits = plan.limits ∧
        out.network = plan.network ⦄ :=
  ProofboundRuntime.Refinement.AuthorityNormalization.normalize_authority_refines
    plan hBounded

end ProofboundRuntime.Refinement.AuthorityNormalizationClaim
