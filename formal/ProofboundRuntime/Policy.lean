namespace ProofboundRuntime.Policy

inductive FileAccess where
  | read
  | write
  | execute
  deriving DecidableEq, Repr

inductive PathRole where
  | projectInput
  | outputRoot
  | runtimeExecutable
  | runtimeLoaderExecutable
  | runtimeLibrary
  deriving DecidableEq, Repr

structure PathAuthority where
  identity : String
  access : FileAccess
  role : PathRole
  deriving DecidableEq, Repr

structure ResourceLimits where
  processes : Nat
  wallTimeMilliseconds : Nat
  standardOutputBytes : Nat
  standardErrorBytes : Nat
  deriving DecidableEq, Repr

structure NormalizedAuthority where
  paths : List PathAuthority
  environment : List String
  limits : ResourceLimits
  deriving DecidableEq, Repr

structure FilesystemPolicy where
  rules : List PathAuthority
  deriving DecidableEq, Repr

inductive SeccompPolicy where
  | denyNetworkV1
  deriving DecidableEq, Repr

structure CgroupPolicy where
  limits : ResourceLimits
  deriving DecidableEq, Repr

inductive NoNewPrivileges where
  | required
  deriving DecidableEq, Repr

structure CompiledPolicy where
  filesystem : FilesystemPolicy
  environment : List String
  network : SeccompPolicy
  cgroup : CgroupPolicy
  noNewPrivileges : NoNewPrivileges
  deriving DecidableEq, Repr

def ListSubset {α : Type} (left right : List α) : Prop :=
  ∀ item, item ∈ left → item ∈ right

def LimitsNoMorePermissive (left right : ResourceLimits) : Prop :=
  left.processes ≤ right.processes ∧
    left.wallTimeMilliseconds ≤ right.wallTimeMilliseconds ∧
    left.standardOutputBytes ≤ right.standardOutputBytes ∧
    left.standardErrorBytes ≤ right.standardErrorBytes

def NoAmplification (policy : CompiledPolicy) (authority : NormalizedAuthority) : Prop :=
  ListSubset policy.filesystem.rules authority.paths ∧
    ListSubset policy.environment authority.environment ∧
    LimitsNoMorePermissive policy.cgroup.limits authority.limits ∧
    policy.network = .denyNetworkV1 ∧
    policy.noNewPrivileges = .required

def compile (authority : NormalizedAuthority) : CompiledPolicy :=
  {
    filesystem := { rules := authority.paths }
    environment := authority.environment
    network := .denyNetworkV1
    cgroup := { limits := authority.limits }
    noNewPrivileges := .required
  }

theorem compile_no_amplification (authority : NormalizedAuthority) :
    NoAmplification (compile authority) authority := by
  simp [NoAmplification, compile, ListSubset, LimitsNoMorePermissive]

end ProofboundRuntime.Policy
