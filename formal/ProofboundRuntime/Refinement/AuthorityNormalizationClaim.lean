import Proofbound.Attribute
import ProofboundRuntime.Refinement.AuthorityNormalization

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.AuthorityNormalizationClaim

open proofbound_runtime_core
open ProofboundRuntime.Refinement.AuthorityNormalization

@[proofbound_exempt "Supporting source-refinement lemma consumed by the public release-artifact theorem."]
theorem normalize_authority_refines
    (plan : authority.AuthorityPlan) :
    normalize.normalize_authority plan
      ⦃ result => ∃ out,
        result = core.result.Result.Ok out ∧
          out.paths.val.Nodup ∧
          ListSubset out.paths.val plan.paths.val ∧
          out.environment.val.Nodup ∧
          ListSubset out.environment.val plan.environment.val ∧
          out.limits = plan.limits ∧
          out.network = plan.network ⦄ :=
  ProofboundRuntime.Refinement.AuthorityNormalization.normalize_authority_refines
    plan

end ProofboundRuntime.Refinement.AuthorityNormalizationClaim
