namespace ProofboundRuntime.Authority

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

inductive Atom where
  | path (identity : Nat) (access : FileAccess) (role : PathRole)
  | environment (identity : Nat)
  | processLimit (count : Nat)
  | wallTimeLimit (milliseconds : Nat)
  | standardOutputLimit (bytes : Nat)
  | standardErrorLimit (bytes : Nat)
  | networkDenied
  deriving DecidableEq, Repr

abbrev Plan := List Atom

def normalize : Plan → Plan
  | [] => []
  | atom :: rest =>
      let normalizedRest := normalize rest
      if atom ∈ normalizedRest then normalizedRest else atom :: normalizedRest

def IsSubset (left right : Plan) : Prop :=
  ∀ atom, atom ∈ left → atom ∈ right

def IsCanonical (plan : Plan) : Prop :=
  plan.Nodup

theorem normalize_membership (plan : Plan) (atom : Atom) :
    atom ∈ normalize plan ↔ atom ∈ plan := by
  induction plan generalizing atom with
  | nil => simp [normalize]
  | cons head rest inductionHypothesis =>
      simp only [normalize]
      split <;> simp_all

theorem normalize_no_amplification (plan : Plan) :
    IsSubset (normalize plan) plan := by
  intro atom present
  exact (normalize_membership plan atom).mp present

theorem normalize_canonical (plan : Plan) :
    IsCanonical (normalize plan) := by
  induction plan with
  | nil => simp [IsCanonical, normalize]
  | cons head rest inductionHypothesis =>
      simp only [normalize]
      split <;> simp_all [IsCanonical]

theorem normalize_eq_self_of_canonical (plan : Plan) (canonical : IsCanonical plan) :
    normalize plan = plan := by
  induction plan with
  | nil => rfl
  | cons head rest inductionHypothesis =>
      have components := List.nodup_cons.mp canonical
      have headAbsent : head ∉ rest := by
        exact components.1
      have restCanonical : IsCanonical rest := by
        exact components.2
      simp [normalize, inductionHypothesis restCanonical, headAbsent]

theorem normalize_idempotent (plan : Plan) :
    normalize (normalize plan) = normalize plan := by
  exact normalize_eq_self_of_canonical (normalize plan) (normalize_canonical plan)

end ProofboundRuntime.Authority
