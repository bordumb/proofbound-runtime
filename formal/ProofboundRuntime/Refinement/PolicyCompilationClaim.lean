import Proofbound.Attribute
import ProofboundRuntime.Refinement.PolicyCompilation

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.PolicyCompilationClaim

open ProofboundRuntime.Refinement.PolicyCompilation

@[proofbound_exempt "Supporting source-refinement lemma consumed by the public release-artifact theorem."]
theorem compile_policy_refines
    (authority : proofbound_runtime_core.normalize.NormalizedAuthority) :
    ∃ compiled,
      proofbound_runtime_core.policy.compile_policy authority = ok compiled ∧
        toModelCompiledPolicy compiled =
          ProofboundRuntime.Policy.compile (toModelAuthority authority) :=
  ProofboundRuntime.Refinement.PolicyCompilation.compile_policy_refines authority

end ProofboundRuntime.Refinement.PolicyCompilationClaim
