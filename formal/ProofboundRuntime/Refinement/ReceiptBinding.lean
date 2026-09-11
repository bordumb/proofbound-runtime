import ProofboundRuntime.Binding
import ProofboundRuntimeBinding.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

namespace ProofboundRuntime.Refinement.ReceiptBinding

def toModelBytes (bytes : alloc.vec.Vec U8) :
    ProofboundRuntime.Binding.FieldIdentity :=
  bytes.val.map (fun byte => byte.val)

def toModelCandidate
    (parts : proofbound_runtime_binding.ReceiptBindingParts) :
    ProofboundRuntime.Binding.Candidate :=
  match parts.resources with
  | none => {
      bindings := [
        (.assumptions, toModelBytes parts.assumptions),
        (.boundary, toModelBytes parts.boundary),
        (.command, toModelBytes parts.command),
        (.eligibility, toModelBytes parts.eligibility),
        (.environment, toModelBytes parts.environment),
        (.executionId, toModelBytes parts.execution_id),
        (.inputs, toModelBytes parts.inputs),
        (.observations, toModelBytes parts.observations),
        (.outcome, toModelBytes parts.outcome),
        (.outputRoot, toModelBytes parts.output_root),
        (.outputs, toModelBytes parts.outputs),
        (.plan, toModelBytes parts.plan),
        (.platform, toModelBytes parts.platform),
        (.policy, toModelBytes parts.policy),
        (.producer, toModelBytes parts.producer),
        (.productVersion, toModelBytes parts.product_version),
        (.runtime, toModelBytes parts.runtime),
        (.schema, toModelBytes parts.schema),
        (.streams, toModelBytes parts.streams),
        (.trustedComputingBase, toModelBytes parts.trusted_computing_base)
      ]
    }
  | some resources => {
      bindings := [
        (.assumptions, toModelBytes parts.assumptions),
        (.boundary, toModelBytes parts.boundary),
        (.command, toModelBytes parts.command),
        (.eligibility, toModelBytes parts.eligibility),
        (.environment, toModelBytes parts.environment),
        (.executionId, toModelBytes parts.execution_id),
        (.inputs, toModelBytes parts.inputs),
        (.observations, toModelBytes parts.observations),
        (.outcome, toModelBytes parts.outcome),
        (.outputRoot, toModelBytes parts.output_root),
        (.outputs, toModelBytes parts.outputs),
        (.plan, toModelBytes parts.plan),
        (.platform, toModelBytes parts.platform),
        (.policy, toModelBytes parts.policy),
        (.producer, toModelBytes parts.producer),
        (.productVersion, toModelBytes parts.product_version),
        (.resources, toModelBytes resources),
        (.runtime, toModelBytes parts.runtime),
        (.schema, toModelBytes parts.schema),
        (.streams, toModelBytes parts.streams),
        (.trustedComputingBase, toModelBytes parts.trusted_computing_base)
      ]
    }

def toModelReceipt
    (parts : proofbound_runtime_binding.ReceiptBindingParts) :
    ProofboundRuntime.Binding.Receipt := {
  bindings := (toModelCandidate parts).bindings
}

theorem construct_and_project_receipt_binding_refines
    (parts : proofbound_runtime_binding.ReceiptBindingParts) :
    ∃ output,
      proofbound_runtime_binding.construct_and_project_receipt_binding parts =
        ok output ∧
      ProofboundRuntime.Binding.Complete (toModelCandidate parts) ∧
      ProofboundRuntime.Binding.RetainsExactly
        (toModelCandidate parts) (toModelReceipt output) := by
  refine ⟨parts, ?_, ?_, ?_⟩
  · rfl
  · cases resources : parts.resources with
    | none => simp [
        toModelCandidate,
        resources,
        ProofboundRuntime.Binding.Complete,
        ProofboundRuntime.Binding.requiredFieldsV1
      ]
    | some value => simp [
        toModelCandidate,
        resources,
        ProofboundRuntime.Binding.Complete,
        ProofboundRuntime.Binding.requiredFieldsV2
      ]
  · rfl

end ProofboundRuntime.Refinement.ReceiptBinding
