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

structure LimitEvents where
  memoryHigh : Bool
  memoryMax : Bool
  memoryOom : Bool
  memoryOomKill : Bool
  memoryOomGroupKill : Bool
  swapMax : Bool
  swapFail : Bool
  deriving DecidableEq, Repr

structure Facts where
  boundary : BoundaryInstallation
  outcome : ExecutionOutcome
  stdout : StreamCapture
  stderr : StreamCapture
  receiptStructure : ReceiptStructure
  limitEvents : LimitEvents
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
  | memoryHigh
  | memoryMax
  | memoryOom
  | memoryOomKill
  | memoryOomGroupKill
  | swapMax
  | swapFail
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

def limitEventReasons (events : LimitEvents) : List NonReusableReason :=
  (if events.memoryHigh then [.memoryHigh] else []) ++
    (if events.memoryMax then [.memoryMax] else []) ++
    (if events.memoryOom then [.memoryOom] else []) ++
    (if events.memoryOomKill then [.memoryOomKill] else []) ++
    (if events.memoryOomGroupKill then [.memoryOomGroupKill] else []) ++
    (if events.swapMax then [.swapMax] else []) ++
    (if events.swapFail then [.swapFail] else [])

def nonReusableReasons (facts : Facts) : List NonReusableReason :=
  boundaryReasons facts.boundary ++
    outcomeReasons facts.outcome ++
    outputReasons facts.stdout facts.stderr ++
    structureReasons facts.receiptStructure ++
    limitEventReasons facts.limitEvents

def IsReusable (facts : Facts) : Prop :=
  facts.boundary = .installed ∧
    facts.outcome = .exited 0 ∧
    facts.stdout = .complete ∧
    facts.stderr = .complete ∧
    facts.receiptStructure = .valid ∧
    facts.limitEvents.memoryHigh = false ∧
    facts.limitEvents.memoryMax = false ∧
    facts.limitEvents.memoryOom = false ∧
    facts.limitEvents.memoryOomKill = false ∧
    facts.limitEvents.memoryOomGroupKill = false ∧
    facts.limitEvents.swapMax = false ∧
    facts.limitEvents.swapFail = false

instance (facts : Facts) : Decidable (IsReusable facts) := by
  unfold IsReusable
  infer_instance

def deriveEligibility (facts : Facts) : Eligibility :=
  let reasons := nonReusableReasons facts
  if reasons = [] then .reusable else .nonReusable reasons

theorem boundaryReasons_eq_nil_iff (boundary : BoundaryInstallation) :
    boundaryReasons boundary = [] ↔ boundary = .installed := by
  cases boundary <;> simp [boundaryReasons]

theorem outcomeReasons_eq_nil_iff (outcome : ExecutionOutcome) :
    outcomeReasons outcome = [] ↔ outcome = .exited 0 := by
  cases outcome with
  | exited code =>
      by_cases codeZero : code = 0 <;> simp [outcomeReasons, codeZero]
  | signaled signal => simp [outcomeReasons]
  | timedOut => simp [outcomeReasons]
  | denied => simp [outcomeReasons]
  | launcherFailed => simp [outcomeReasons]
  | incomplete => simp [outcomeReasons]

theorem outputReasons_eq_nil_iff (stdout stderr : StreamCapture) :
    outputReasons stdout stderr = [] ↔ stdout = .complete ∧ stderr = .complete := by
  cases stdout <;> cases stderr <;> simp [outputReasons]

theorem structureReasons_eq_nil_iff (receiptStructure : ReceiptStructure) :
    structureReasons receiptStructure = [] ↔ receiptStructure = .valid := by
  cases receiptStructure <;> simp [structureReasons]

theorem limitEventReasons_eq_nil_iff (events : LimitEvents) :
    limitEventReasons events = [] ↔
      events.memoryHigh = false ∧ events.memoryMax = false ∧ events.memoryOom = false ∧
      events.memoryOomKill = false ∧ events.memoryOomGroupKill = false ∧
      events.swapMax = false ∧ events.swapFail = false := by
  rcases events with ⟨memoryHigh, memoryMax, memoryOom, memoryOomKill,
    memoryOomGroupKill, swapMax, swapFail⟩
  cases memoryHigh <;> cases memoryMax <;> cases memoryOom <;> cases memoryOomKill <;>
    cases memoryOomGroupKill <;> cases swapMax <;> cases swapFail <;>
    simp [limitEventReasons]

theorem nonReusableReasons_eq_nil_iff (facts : Facts) :
    nonReusableReasons facts = [] ↔ IsReusable facts := by
  simp [nonReusableReasons, IsReusable, boundaryReasons_eq_nil_iff,
    outcomeReasons_eq_nil_iff, outputReasons_eq_nil_iff, structureReasons_eq_nil_iff,
    limitEventReasons_eq_nil_iff, and_assoc]

theorem nonReusableReasons_ne_nil_of_not_reusable
    (facts : Facts) (notReusable : ¬ IsReusable facts) :
    nonReusableReasons facts ≠ [] := by
  intro reasonsNil
  exact notReusable ((nonReusableReasons_eq_nil_iff facts).mp reasonsNil)

theorem derive_exact (facts : Facts) :
    (deriveEligibility facts = .reusable ↔ IsReusable facts) ∧
      (¬ IsReusable facts →
        deriveEligibility facts = .nonReusable (nonReusableReasons facts) ∧
        nonReusableReasons facts ≠ []) := by
  constructor
  · simp [deriveEligibility, nonReusableReasons_eq_nil_iff]
  · intro notReusable
    have reasonsNotNil := nonReusableReasons_ne_nil_of_not_reusable facts notReusable
    exact ⟨
      by simp [deriveEligibility, reasonsNotNil],
      reasonsNotNil
    ⟩

end ProofboundRuntime.Receipt
