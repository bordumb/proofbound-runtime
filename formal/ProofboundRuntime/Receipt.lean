namespace ProofboundRuntime.Receipt

inductive BoundaryInstallation where
  | installed
  | incomplete
  deriving DecidableEq, Repr

inductive ExecutionOutcome where
  | exited (code : Int)
  | signaled (signal : Nat)
  | timedOut
  | denied
  | launcherFailed
  | incomplete
  deriving DecidableEq, Repr

inductive StreamCapture where
  | complete
  | truncated
  deriving DecidableEq, Repr

inductive ReceiptStructure where
  | valid
  | malformed
  deriving DecidableEq, Repr

structure Facts where
  boundary : BoundaryInstallation
  outcome : ExecutionOutcome
  stdout : StreamCapture
  stderr : StreamCapture
  receiptStructure : ReceiptStructure
  deriving DecidableEq, Repr

inductive NonReusableReason where
  | boundaryIncomplete
  | exitCodeNonzero
  | processSignaled
  | timedOut
  | denied
  | launcherFailed
  | executionIncomplete
  | standardOutputTruncated
  | standardErrorTruncated
  | receiptMalformed
  deriving DecidableEq, Repr

inductive Eligibility where
  | reusable
  | nonReusable (reasons : List NonReusableReason)
  deriving DecidableEq, Repr

def boundaryReasons : BoundaryInstallation → List NonReusableReason
  | .installed => []
  | .incomplete => [.boundaryIncomplete]

def outcomeReasons : ExecutionOutcome → List NonReusableReason
  | .exited 0 => []
  | .exited _ => [.exitCodeNonzero]
  | .signaled _ => [.processSignaled]
  | .timedOut => [.timedOut]
  | .denied => [.denied]
  | .launcherFailed => [.launcherFailed]
  | .incomplete => [.executionIncomplete]

def outputReasons (stdout stderr : StreamCapture) : List NonReusableReason :=
  (if stdout = .truncated then [.standardOutputTruncated] else []) ++
    (if stderr = .truncated then [.standardErrorTruncated] else [])

def structureReasons : ReceiptStructure → List NonReusableReason
  | .valid => []
  | .malformed => [.receiptMalformed]

def nonReusableReasons (facts : Facts) : List NonReusableReason :=
  boundaryReasons facts.boundary ++
    outcomeReasons facts.outcome ++
    outputReasons facts.stdout facts.stderr ++
    structureReasons facts.receiptStructure

def IsReusable (facts : Facts) : Prop :=
  facts.boundary = .installed ∧
    facts.outcome = .exited 0 ∧
    facts.stdout = .complete ∧
    facts.stderr = .complete ∧
    facts.receiptStructure = .valid

instance (facts : Facts) : Decidable (IsReusable facts) := by
  unfold IsReusable
  infer_instance

def deriveEligibility (facts : Facts) : Eligibility :=
  if IsReusable facts then .reusable else .nonReusable (nonReusableReasons facts)

theorem nonReusableReasons_ne_nil_of_not_reusable
    (facts : Facts) (notReusable : ¬ IsReusable facts) :
    nonReusableReasons facts ≠ [] := by
  rcases facts with ⟨boundary, outcome, stdout, stderr, receiptStructure⟩
  cases boundary <;> cases outcome <;> cases stdout <;> cases stderr <;>
    cases receiptStructure <;> simp_all [IsReusable, nonReusableReasons, boundaryReasons,
      outcomeReasons, outputReasons, structureReasons]

theorem derive_exact (facts : Facts) :
    (deriveEligibility facts = .reusable ↔ IsReusable facts) ∧
      (¬ IsReusable facts →
        deriveEligibility facts = .nonReusable (nonReusableReasons facts) ∧
        nonReusableReasons facts ≠ []) := by
  constructor
  · simp [deriveEligibility]
  · intro notReusable
    exact ⟨
      by simp [deriveEligibility, notReusable],
      nonReusableReasons_ne_nil_of_not_reusable facts notReusable
    ⟩

end ProofboundRuntime.Receipt
