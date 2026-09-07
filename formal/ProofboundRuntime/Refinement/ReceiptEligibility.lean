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

def toModelFacts (facts : proofbound_runtime_receipt.ReceiptFacts) :
    ProofboundRuntime.Receipt.Facts := {
  boundary := toModelBoundary facts.boundary
  outcome := toModelOutcome facts.outcome
  stdout := toModelCapture facts.stdout
  stderr := toModelCapture facts.stderr
  receiptStructure := toModelStructure facts.«structure»
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

def toModelEligibility :
    proofbound_runtime_receipt.ReceiptEligibility →
      ProofboundRuntime.Receipt.Eligibility
  | .Reusable => .reusable
  | .NonReusable reasons => .nonReusable (reasons.val.map toModelReason)

@[simp]
theorem i32_zero_val : (0#i32 : I32).val = 0 := by
  rfl

@[simp]
theorem i32_pattern_zero_val : (0#32#iscalar : I32).val = 0 := by
  rfl

private theorem derive_receipt_eligibility_refines_fields
    (boundary : proofbound_runtime_receipt.BoundaryInstallation)
    (outcome : proofbound_runtime_receipt.ExecutionOutcome)
    (stdout stderr : proofbound_runtime_receipt.StreamCapture)
    (receiptStructure : proofbound_runtime_receipt.ReceiptStructure) :
    ∃ eligibility,
      proofbound_runtime_receipt.derive_receipt_eligibility {
      boundary := boundary
      outcome := outcome
      stdout := stdout
      stderr := stderr
      «structure» := receiptStructure
      } = ok eligibility ∧
        toModelEligibility eligibility =
          ProofboundRuntime.Receipt.deriveEligibility (toModelFacts {
            boundary := boundary
            outcome := outcome
            stdout := stdout
            stderr := stderr
            «structure» := receiptStructure
          }) := by
  cases boundary <;> cases outcome
  all_goals cases stdout <;> cases stderr <;> cases receiptStructure <;>
    simp_all [proofbound_runtime_receipt.derive_receipt_eligibility,
      proofbound_runtime_receipt.BoundaryInstallation.Insts.CoreCmpPartialEqBoundaryInstallation.eq,
      proofbound_runtime_receipt.StreamCapture.Insts.CoreCmpPartialEqStreamCapture.eq,
      proofbound_runtime_receipt.ReceiptStructure.Insts.CoreCmpPartialEqReceiptStructure.eq,
      proofbound_runtime_receipt.BoundaryInstallation.read_discriminant,
      proofbound_runtime_receipt.StreamCapture.read_discriminant,
      proofbound_runtime_receipt.ReceiptStructure.read_discriminant,
      alloc.vec.Vec.new, alloc.vec.Vec.push, alloc.vec.Vec.is_empty,
      U32.max_eq,
      toModelEligibility, toModelReason, toModelFacts,
      toModelBoundary, toModelOutcome, toModelCapture, toModelStructure,
      ProofboundRuntime.Receipt.deriveEligibility, ProofboundRuntime.Receipt.IsReusable,
      ProofboundRuntime.Receipt.nonReusableReasons, ProofboundRuntime.Receipt.boundaryReasons,
      ProofboundRuntime.Receipt.outcomeReasons, ProofboundRuntime.Receipt.outputReasons,
      ProofboundRuntime.Receipt.structureReasons]
  all_goals split <;> simp_all [toModelReason]

theorem derive_receipt_eligibility_refines
    (facts : proofbound_runtime_receipt.ReceiptFacts) :
    ∃ eligibility,
      proofbound_runtime_receipt.derive_receipt_eligibility facts = ok eligibility ∧
        toModelEligibility eligibility =
          ProofboundRuntime.Receipt.deriveEligibility (toModelFacts facts) := by
  rcases facts with ⟨boundary, outcome, stdout, stderr, receiptStructure⟩
  exact derive_receipt_eligibility_refines_fields
    boundary outcome stdout stderr receiptStructure

end ProofboundRuntime.Refinement.ReceiptEligibility
