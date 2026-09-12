import ProofboundRuntime.Receipt
import ProofboundRuntimeReceipt.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 1000000

namespace ProofboundRuntime.Refinement.ReceiptEligibility

def toModelBoundary :
    proofbound_runtime_receipt.BoundaryInstallation →
      ProofboundRuntime.Receipt.BoundaryInstallation
  | .Installed => .installed
  | .Incomplete => .incomplete

def toModelOutcome :
    proofbound_runtime_receipt.ExecutionOutcome →
      ProofboundRuntime.Receipt.ExecutionOutcome
  | .Exited code => .exited code.val
  | .Signaled signal => .signaled signal.val
  | .TimedOut => .timedOut
  | .Denied => .denied
  | .LauncherFailed => .launcherFailed
  | .Incomplete => .incomplete

def toModelCapture :
    proofbound_runtime_receipt.StreamCapture →
      ProofboundRuntime.Receipt.StreamCapture
  | .Complete => .complete
  | .Truncated => .truncated

def toModelStructure :
    proofbound_runtime_receipt.ReceiptStructure →
      ProofboundRuntime.Receipt.ReceiptStructure
  | .Valid => .valid
  | .Malformed => .malformed

def toModelLimitEvents (events : proofbound_runtime_receipt.LimitEvents) :
    ProofboundRuntime.Receipt.LimitEvents := {
  memoryHigh := events.memory_high
  memoryMax := events.memory_max
  memoryOom := events.memory_oom
  memoryOomKill := events.memory_oom_kill
  memoryOomGroupKill := events.memory_oom_group_kill
  swapMax := events.swap_max
  swapFail := events.swap_fail
}

def toModelFacts (facts : proofbound_runtime_receipt.ReceiptFacts) :
    ProofboundRuntime.Receipt.Facts := {
  boundary := toModelBoundary facts.boundary
  outcome := toModelOutcome facts.outcome
  stdout := toModelCapture facts.stdout
  stderr := toModelCapture facts.stderr
  receiptStructure := toModelStructure facts.«structure»
  limitEvents := toModelLimitEvents facts.limit_events
}

def toModelReason :
    proofbound_runtime_receipt.NonReusableReason →
      ProofboundRuntime.Receipt.NonReusableReason
  | .BoundaryIncomplete => .boundaryIncomplete
  | .ExitCodeNonzero => .exitCodeNonzero
  | .ProcessSignaled => .processSignaled
  | .TimedOut => .timedOut
  | .Denied => .denied
  | .LauncherFailed => .launcherFailed
  | .ExecutionIncomplete => .executionIncomplete
  | .StandardOutputTruncated => .standardOutputTruncated
  | .StandardErrorTruncated => .standardErrorTruncated
  | .ReceiptMalformed => .receiptMalformed
  | .MemoryHigh => .memoryHigh
  | .MemoryMax => .memoryMax
  | .MemoryOom => .memoryOom
  | .MemoryOomKill => .memoryOomKill
  | .MemoryOomGroupKill => .memoryOomGroupKill
  | .SwapMax => .swapMax
  | .SwapFail => .swapFail

def toModelEligibility :
    proofbound_runtime_receipt.ReceiptEligibility →
      ProofboundRuntime.Receipt.Eligibility
  | .Reusable => .reusable
  | .NonReusable reasons => .nonReusable (reasons.val.map toModelReason)

def translatedLimitEventReasons (events : proofbound_runtime_receipt.LimitEvents) :
    List proofbound_runtime_receipt.NonReusableReason :=
  (if events.memory_high then [.MemoryHigh] else []) ++
    (if events.memory_max then [.MemoryMax] else []) ++
    (if events.memory_oom then [.MemoryOom] else []) ++
    (if events.memory_oom_kill then [.MemoryOomKill] else []) ++
    (if events.memory_oom_group_kill then [.MemoryOomGroupKill] else []) ++
    (if events.swap_max then [.SwapMax] else []) ++
    (if events.swap_fail then [.SwapFail] else [])

theorem translatedLimitEventReasons_length_le
    (events : proofbound_runtime_receipt.LimitEvents) :
    (translatedLimitEventReasons events).length ≤ 7 := by
  rcases events with ⟨memoryHigh, memoryMax, memoryOom, memoryOomKill,
    memoryOomGroupKill, swapMax, swapFail⟩
  cases memoryHigh <;> cases memoryMax <;> cases memoryOom <;> cases memoryOomKill <;>
    cases memoryOomGroupKill <;> cases swapMax <;> cases swapFail <;>
    simp [translatedLimitEventReasons]

@[step]
theorem append_reason_spec
    (reasons : alloc.vec.Vec proofbound_runtime_receipt.NonReusableReason)
    (present : Bool)
    (reason : proofbound_runtime_receipt.NonReusableReason)
    (capacity : reasons.val.length < Usize.max) :
    proofbound_runtime_receipt.append_reason reasons present reason
      ⦃ out => out.val = reasons.val ++ if present then [reason] else [] ⦄ := by
  unfold proofbound_runtime_receipt.append_reason
  split
  · simpa using alloc.vec.Vec.push_spec reasons reason capacity
  · simp_all

theorem optionalReason_length_le
    (present : Bool) (reason : proofbound_runtime_receipt.NonReusableReason) :
    (if present then [reason] else []).length ≤ 1 := by
  cases present <;> simp

@[step]
theorem append_limit_event_reasons_spec
    (reasons : alloc.vec.Vec proofbound_runtime_receipt.NonReusableReason)
    (events : proofbound_runtime_receipt.LimitEvents)
    (capacity : reasons.val.length + 7 < Usize.max) :
    proofbound_runtime_receipt.append_limit_event_reasons reasons events
      ⦃ out => out.val = reasons.val ++ translatedLimitEventReasons events ⦄ := by
  unfold proofbound_runtime_receipt.append_limit_event_reasons
  simp only [proofbound_runtime_receipt.LimitEvents.contains]
  step with append_reason_spec (reasons := reasons) (present := events.memory_high)
      (reason := .MemoryHigh) (capacity := by omega) as
    ⟨memoryHighReasons, memoryHighReasonsEq⟩
  have memoryHighLength : memoryHighReasons.val.length ≤ reasons.val.length + 1 := by
    rw [memoryHighReasonsEq]
    simp only [List.length_append]
    have eventLength := optionalReason_length_le events.memory_high .MemoryHigh
    omega
  step with append_reason_spec (reasons := memoryHighReasons) (present := events.memory_max)
      (reason := .MemoryMax) (capacity := by omega) as
    ⟨memoryMaxReasons, memoryMaxReasonsEq⟩
  have memoryMaxLength : memoryMaxReasons.val.length ≤ reasons.val.length + 2 := by
    rw [memoryMaxReasonsEq]
    simp only [List.length_append]
    have eventLength := optionalReason_length_le events.memory_max .MemoryMax
    omega
  step with append_reason_spec (reasons := memoryMaxReasons) (present := events.memory_oom)
      (reason := .MemoryOom) (capacity := by omega) as
    ⟨memoryOomReasons, memoryOomReasonsEq⟩
  have memoryOomLength : memoryOomReasons.val.length ≤ reasons.val.length + 3 := by
    rw [memoryOomReasonsEq]
    simp only [List.length_append]
    have eventLength := optionalReason_length_le events.memory_oom .MemoryOom
    omega
  step with append_reason_spec (reasons := memoryOomReasons) (present := events.memory_oom_kill)
      (reason := .MemoryOomKill) (capacity := by omega) as
    ⟨memoryOomKillReasons, memoryOomKillReasonsEq⟩
  have memoryOomKillLength : memoryOomKillReasons.val.length ≤ reasons.val.length + 4 := by
    rw [memoryOomKillReasonsEq]
    simp only [List.length_append]
    have eventLength := optionalReason_length_le events.memory_oom_kill .MemoryOomKill
    omega
  step with append_reason_spec (reasons := memoryOomKillReasons)
      (present := events.memory_oom_group_kill) (reason := .MemoryOomGroupKill)
      (capacity := by omega) as
    ⟨memoryOomGroupKillReasons, memoryOomGroupKillReasonsEq⟩
  have memoryOomGroupKillLength :
      memoryOomGroupKillReasons.val.length ≤ reasons.val.length + 5 := by
    rw [memoryOomGroupKillReasonsEq]
    simp only [List.length_append]
    have eventLength := optionalReason_length_le events.memory_oom_group_kill .MemoryOomGroupKill
    omega
  step with append_reason_spec (reasons := memoryOomGroupKillReasons)
      (present := events.swap_max) (reason := .SwapMax) (capacity := by omega) as
    ⟨swapMaxReasons, swapMaxReasonsEq⟩
  have swapMaxLength : swapMaxReasons.val.length ≤ reasons.val.length + 6 := by
    rw [swapMaxReasonsEq]
    simp only [List.length_append]
    have eventLength := optionalReason_length_le events.swap_max .SwapMax
    omega
  step with append_reason_spec (reasons := swapMaxReasons) (present := events.swap_fail)
      (reason := .SwapFail) (capacity := by omega) as
    ⟨swapFailReasons, swapFailReasonsEq⟩
  rw [swapFailReasonsEq, swapMaxReasonsEq, memoryOomGroupKillReasonsEq,
    memoryOomKillReasonsEq, memoryOomReasonsEq, memoryMaxReasonsEq, memoryHighReasonsEq]
  simp [translatedLimitEventReasons, List.append_assoc]

@[simp]
theorem translated_limit_event_reasons_map
    (events : proofbound_runtime_receipt.LimitEvents) :
    (translatedLimitEventReasons events).map toModelReason =
      ProofboundRuntime.Receipt.limitEventReasons (toModelLimitEvents events) := by
  rcases events with ⟨memoryHigh, memoryMax, memoryOom, memoryOomKill,
    memoryOomGroupKill, swapMax, swapFail⟩
  cases memoryHigh <;> cases memoryMax <;> cases memoryOom <;> cases memoryOomKill <;>
    cases memoryOomGroupKill <;> cases swapMax <;> cases swapFail <;>
    simp [translatedLimitEventReasons, toModelReason, toModelLimitEvents,
      ProofboundRuntime.Receipt.limitEventReasons]

@[simp]
theorem i32_zero_val : (0#i32 : I32).val = 0 := by
  rfl

@[simp]
theorem i32_pattern_zero_val : (0#32#iscalar : I32).val = 0 := by
  rfl

def translatedOutcomeReasons
    (outcome : proofbound_runtime_receipt.ExecutionOutcome) :
    List proofbound_runtime_receipt.NonReusableReason :=
  match outcome with
  | .Exited code =>
      match code with
      | 0#iscalar => []
      | _ => [.ExitCodeNonzero]
  | .Signaled _ => [.ProcessSignaled]
  | .TimedOut => [.TimedOut]
  | .Denied => [.Denied]
  | .LauncherFailed => [.LauncherFailed]
  | .Incomplete => [.ExecutionIncomplete]

@[step]
theorem append_outcome_reason_spec
    (reasons : alloc.vec.Vec proofbound_runtime_receipt.NonReusableReason)
    (outcome : proofbound_runtime_receipt.ExecutionOutcome)
    (capacity : reasons.val.length < Usize.max) :
    proofbound_runtime_receipt.append_outcome_reason reasons outcome
      ⦃ out => out.val = reasons.val ++ translatedOutcomeReasons outcome ⦄ := by
  cases outcomeCase : outcome <;>
    simp only [proofbound_runtime_receipt.append_outcome_reason]
  · split
    · simp [translatedOutcomeReasons]
    · simpa [translatedOutcomeReasons] using
        alloc.vec.Vec.push_spec reasons .ExitCodeNonzero capacity
  all_goals simpa [translatedOutcomeReasons] using
    alloc.vec.Vec.push_spec reasons _ capacity

@[simp]
theorem translated_outcome_reasons_map
    (outcome : proofbound_runtime_receipt.ExecutionOutcome) :
    (translatedOutcomeReasons outcome).map toModelReason =
      ProofboundRuntime.Receipt.outcomeReasons (toModelOutcome outcome) := by
  cases outcomeCase : outcome <;> simp [translatedOutcomeReasons,
    toModelOutcome, toModelReason, ProofboundRuntime.Receipt.outcomeReasons]
  split <;> simp_all [i32_pattern_zero_val, toModelReason]

theorem translatedOutcomeReasons_length_le
    (outcome : proofbound_runtime_receipt.ExecutionOutcome) :
    (translatedOutcomeReasons outcome).length ≤ 1 := by
  cases outcomeCase : outcome <;> simp [translatedOutcomeReasons]
  split <;> simp

private theorem derive_receipt_eligibility_refines_fields_spec
    (boundary : proofbound_runtime_receipt.BoundaryInstallation)
    (outcome : proofbound_runtime_receipt.ExecutionOutcome)
    (stdout stderr : proofbound_runtime_receipt.StreamCapture)
    (receiptStructure : proofbound_runtime_receipt.ReceiptStructure)
    (limitEvents : proofbound_runtime_receipt.LimitEvents) :
    proofbound_runtime_receipt.derive_receipt_eligibility {
      boundary := boundary
      outcome := outcome
      stdout := stdout
      stderr := stderr
      «structure» := receiptStructure
      limit_events := limitEvents
      } ⦃ eligibility =>
        toModelEligibility eligibility =
          ProofboundRuntime.Receipt.deriveEligibility (toModelFacts {
            boundary := boundary
            outcome := outcome
            stdout := stdout
            stderr := stderr
            «structure» := receiptStructure
            limit_events := limitEvents
          }) ⦄ := by
  unfold proofbound_runtime_receipt.derive_receipt_eligibility
  simp only [
    alloc.vec.Vec.with_capacity,
    proofbound_runtime_receipt.BoundaryInstallation.Insts.CoreCmpPartialEqBoundaryInstallation.eq]
  have usizeMinimum := Usize.cMax_bound_concrete.1
  step with append_reason_spec
      (reasons := alloc.vec.Vec.new proofbound_runtime_receipt.NonReusableReason)
      (present :=
        proofbound_runtime_receipt.BoundaryInstallation.read_discriminant boundary =
          proofbound_runtime_receipt.BoundaryInstallation.read_discriminant .Incomplete)
      (reason := .BoundaryIncomplete) (capacity := by simp; omega) as
    ⟨boundaryReasons, boundaryReasonsEq⟩
  have boundaryReasonsLength : boundaryReasons.val.length ≤ 1 := by
    rw [boundaryReasonsEq]
    simp only [alloc.vec.Vec.new, alloc.vec.Vec.from_val, List.nil_append]
    exact optionalReason_length_le _ _
  step with append_outcome_reason_spec (reasons := boundaryReasons) (outcome := outcome)
      (capacity := by omega) as
    ⟨outcomeReasons, outcomeReasonsEq⟩
  have outcomeReasonsLength : outcomeReasons.val.length ≤ 2 := by
    rw [outcomeReasonsEq, List.length_append]
    have outcomeLength := translatedOutcomeReasons_length_le outcome
    omega
  simp only [
    proofbound_runtime_receipt.StreamCapture.Insts.CoreCmpPartialEqStreamCapture.eq]
  step with append_reason_spec (reasons := outcomeReasons)
      (present :=
        proofbound_runtime_receipt.StreamCapture.read_discriminant stdout =
          proofbound_runtime_receipt.StreamCapture.read_discriminant .Truncated)
      (reason := .StandardOutputTruncated) (capacity := by omega) as
    ⟨stdoutReasons, stdoutReasonsEq⟩
  have stdoutReasonsLength : stdoutReasons.val.length ≤ 3 := by
    rw [stdoutReasonsEq, List.length_append]
    have eventLength := optionalReason_length_le
      (proofbound_runtime_receipt.StreamCapture.read_discriminant stdout =
        proofbound_runtime_receipt.StreamCapture.read_discriminant .Truncated)
      proofbound_runtime_receipt.NonReusableReason.StandardOutputTruncated
    omega
  step with append_reason_spec (reasons := stdoutReasons)
      (present :=
        proofbound_runtime_receipt.StreamCapture.read_discriminant stderr =
          proofbound_runtime_receipt.StreamCapture.read_discriminant .Truncated)
      (reason := .StandardErrorTruncated) (capacity := by omega) as
    ⟨stderrReasons, stderrReasonsEq⟩
  have stderrReasonsLength : stderrReasons.val.length ≤ 4 := by
    rw [stderrReasonsEq, List.length_append]
    have eventLength := optionalReason_length_le
      (proofbound_runtime_receipt.StreamCapture.read_discriminant stderr =
        proofbound_runtime_receipt.StreamCapture.read_discriminant .Truncated)
      proofbound_runtime_receipt.NonReusableReason.StandardErrorTruncated
    omega
  simp only [
    proofbound_runtime_receipt.ReceiptStructure.Insts.CoreCmpPartialEqReceiptStructure.eq]
  step with append_reason_spec (reasons := stderrReasons)
      (present :=
        proofbound_runtime_receipt.ReceiptStructure.read_discriminant receiptStructure =
          proofbound_runtime_receipt.ReceiptStructure.read_discriminant .Malformed)
      (reason := .ReceiptMalformed) (capacity := by omega) as
    ⟨structureReasons, structureReasonsEq⟩
  have structureReasonsLength : structureReasons.val.length ≤ 5 := by
    rw [structureReasonsEq, List.length_append]
    have eventLength := optionalReason_length_le
      (proofbound_runtime_receipt.ReceiptStructure.read_discriminant receiptStructure =
        proofbound_runtime_receipt.ReceiptStructure.read_discriminant .Malformed)
      proofbound_runtime_receipt.NonReusableReason.ReceiptMalformed
    omega
  step with append_limit_event_reasons_spec (reasons := structureReasons)
      (events := limitEvents) (capacity := by omega) as
    ⟨limitReasons, limitReasonsEq⟩
  have mappedReasons :
      limitReasons.val.map toModelReason =
        ProofboundRuntime.Receipt.nonReusableReasons (toModelFacts {
          boundary := boundary
          outcome := outcome
          stdout := stdout
          stderr := stderr
          «structure» := receiptStructure
          limit_events := limitEvents
        }) := by
    rw [limitReasonsEq, structureReasonsEq, stderrReasonsEq, stdoutReasonsEq,
      outcomeReasonsEq, boundaryReasonsEq]
    cases boundary <;> cases stdout <;> cases stderr <;> cases receiptStructure <;>
      simp [toModelFacts, toModelBoundary, toModelCapture, toModelStructure,
        toModelReason,
        proofbound_runtime_receipt.BoundaryInstallation.read_discriminant,
        proofbound_runtime_receipt.StreamCapture.read_discriminant,
        proofbound_runtime_receipt.ReceiptStructure.read_discriminant,
        ProofboundRuntime.Receipt.nonReusableReasons,
        ProofboundRuntime.Receipt.boundaryReasons,
        ProofboundRuntime.Receipt.outputReasons,
        ProofboundRuntime.Receipt.structureReasons, List.append_assoc]
  have reasonsNil :
      limitReasons.val = [] ↔
        ProofboundRuntime.Receipt.nonReusableReasons (toModelFacts {
          boundary := boundary
          outcome := outcome
          stdout := stdout
          stderr := stderr
          «structure» := receiptStructure
          limit_events := limitEvents
        }) = [] := by
    rw [← mappedReasons]
    simp
  step as ⟨empty, emptyEq⟩
  split <;> simp_all [toModelEligibility, ProofboundRuntime.Receipt.deriveEligibility]

theorem derive_receipt_eligibility_refines
    (facts : proofbound_runtime_receipt.ReceiptFacts) :
    ∃ eligibility,
      proofbound_runtime_receipt.derive_receipt_eligibility facts = ok eligibility ∧
        toModelEligibility eligibility =
          ProofboundRuntime.Receipt.deriveEligibility (toModelFacts facts) := by
  rcases facts with ⟨boundary, outcome, stdout, stderr, receiptStructure, limitEvents⟩
  have refinement := derive_receipt_eligibility_refines_fields_spec
    boundary outcome stdout stderr receiptStructure limitEvents
  cases result : proofbound_runtime_receipt.derive_receipt_eligibility {
      boundary := boundary
      outcome := outcome
      stdout := stdout
      stderr := stderr
      «structure» := receiptStructure
      limit_events := limitEvents
    } with
  | ok eligibility =>
      refine ⟨eligibility, rfl, ?_⟩
      rw [result] at refinement
      simpa using refinement
  | fail error =>
      rw [result] at refinement
      simp at refinement
  | div =>
      rw [result] at refinement
      simp at refinement

end ProofboundRuntime.Refinement.ReceiptEligibility
