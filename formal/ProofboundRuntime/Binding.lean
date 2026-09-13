namespace ProofboundRuntime.Binding

/-- The closed top-level field inventory of supported execution receipts. -/
inductive ReceiptField where
  | assumptions
  | boundary
  | command
  | eligibility
  | environment
  | executionId
  | inputs
  | observations
  | outcome
  | outputRoot
  | outputs
  | plan
  | platform
  | policy
  | producer
  | productVersion
  | resources
  | runtime
  | schema
  | streams
  | trustedComputingBase
  deriving DecidableEq, Repr

/-- The accepted version 1 field order. -/
def requiredFieldsV1 : List ReceiptField := [
  .assumptions,
  .boundary,
  .command,
  .eligibility,
  .environment,
  .executionId,
  .inputs,
  .observations,
  .outcome,
  .outputRoot,
  .outputs,
  .plan,
  .platform,
  .policy,
  .producer,
  .productVersion,
  .runtime,
  .schema,
  .streams,
  .trustedComputingBase
]

/-- The accepted version 2 field order adds the required resource record. -/
def requiredFieldsV2 : List ReceiptField := [
  .assumptions,
  .boundary,
  .command,
  .eligibility,
  .environment,
  .executionId,
  .inputs,
  .observations,
  .outcome,
  .outputRoot,
  .outputs,
  .plan,
  .platform,
  .policy,
  .producer,
  .productVersion,
  .resources,
  .runtime,
  .schema,
  .streams,
  .trustedComputingBase
]

/-- Exact canonical bytes of one top-level field value. The model deliberately
does not assign domain meaning to the bytes; it proves that the production
binding boundary cannot omit, duplicate, reorder, or change them. -/
abbrev FieldIdentity := List Nat

/-- A pre-construction inventory. -/
structure Candidate where
  bindings : List (ReceiptField × FieldIdentity)
  deriving DecidableEq, Repr

/-- A constructed receipt retains the complete accepted binding inventory. -/
structure Receipt where
  bindings : List (ReceiptField × FieldIdentity)
  deriving DecidableEq, Repr

def Complete (candidate : Candidate) : Prop :=
  candidate.bindings.map Prod.fst = requiredFieldsV1 ∨
    candidate.bindings.map Prod.fst = requiredFieldsV2

instance (candidate : Candidate) : Decidable (Complete candidate) := by
  unfold Complete
  infer_instance

def RetainsExactly (candidate : Candidate) (receipt : Receipt) : Prop :=
  receipt.bindings = candidate.bindings

/-- The abstract constructor accepts only the complete closed inventory and
copies every associated identity without modification. -/
def construct (candidate : Candidate) : Option Receipt :=
  if Complete candidate then
    some { bindings := candidate.bindings }
  else
    none

theorem construct_exact
    (candidate : Candidate) (receipt : Receipt)
    (constructed : construct candidate = some receipt) :
    Complete candidate ∧ RetainsExactly candidate receipt := by
  by_cases complete : Complete candidate
  · simp [construct, complete] at constructed
    subst receipt
    exact ⟨complete, rfl⟩
  · simp [construct, complete] at constructed

end ProofboundRuntime.Binding
