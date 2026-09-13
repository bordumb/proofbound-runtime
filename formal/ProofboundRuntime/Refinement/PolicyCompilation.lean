import ProofboundRuntime.Policy
import ProofboundRuntimePolicy.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.PolicyCompilation

def toModelFileAccess :
    proofbound_runtime_core.authority.FileAccess →
      ProofboundRuntime.Policy.FileAccess
  | .Read => .read
  | .Write => .write
  | .Execute => .execute

def toModelPathRole :
    proofbound_runtime_core.authority.PathRole →
      ProofboundRuntime.Policy.PathRole
  | .ProjectInput => .projectInput
  | .OutputRoot => .outputRoot
  | .RuntimeExecutable => .runtimeExecutable
  | .RuntimeLoaderExecutable => .runtimeLoaderExecutable
  | .RuntimeLibrary => .runtimeLibrary

def toModelPathAuthority
    (authority : proofbound_runtime_core.authority.PathAuthority) :
    ProofboundRuntime.Policy.PathAuthority := {
  identity := authority.path.text
  access := toModelFileAccess authority.access
  role := toModelPathRole authority.role
}

def toModelResourceLimits
    (limits : proofbound_runtime_core.authority.ResourceLimits) :
    ProofboundRuntime.Policy.ResourceLimits := {
  processes := limits.processes.val
  wallTimeMilliseconds := limits.wall_time.val
  standardOutputBytes := limits.stdout.val
  standardErrorBytes := limits.stderr.val
  memoryBytes := limits.memory.map fun value => value.val
  swapBytes := limits.swap.map fun value => value.val
}

def toModelEnvironmentName
    (name : proofbound_runtime_core.authority.EnvironmentName) : String :=
  name.text

def toModelAuthority
    (authority : proofbound_runtime_core.normalize.NormalizedAuthority) :
    ProofboundRuntime.Policy.NormalizedAuthority := {
  paths := authority.paths.val.map toModelPathAuthority
  environment := authority.environment.val.map toModelEnvironmentName
  limits := toModelResourceLimits authority.limits
}

def toModelCompiledPolicy
    (policy : proofbound_runtime_core.policy.CompiledPolicy) :
    ProofboundRuntime.Policy.CompiledPolicy := {
  filesystem := {
    rules := policy.filesystem.rules.val.map toModelPathAuthority
  }
  environment := policy.environment.val.map toModelEnvironmentName
  network := .denyNetworkV1
  cgroup := { limits := toModelResourceLimits policy.cgroup.limits }
  noNewPrivileges := .required
}

theorem compile_policy_refines
    (authority : proofbound_runtime_core.normalize.NormalizedAuthority) :
    ∃ compiled,
      proofbound_runtime_core.policy.compile_policy authority = ok compiled ∧
        toModelCompiledPolicy compiled =
          ProofboundRuntime.Policy.compile (toModelAuthority authority) := by
  rcases authority with ⟨paths, environment, limits, network⟩
  simp [proofbound_runtime_core.policy.compile_policy,
    proofbound_runtime_core.normalize.NormalizedAuthority.into_parts,
    toModelCompiledPolicy, toModelAuthority, ProofboundRuntime.Policy.compile]

end ProofboundRuntime.Refinement.PolicyCompilation
