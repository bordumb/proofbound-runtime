import Aeneas
import ProofboundRuntimeReceipt.Types

open Aeneas Aeneas.Std Result ControlFlow Error

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

@[rust_fun "alloc::vec::{alloc::vec::Vec<@T>}::is_empty"]
def alloc.vec.Vec.is_empty
    {T : Type} (_allocator : Type) (values : alloc.vec.Vec T) : Result Bool :=
  ok values.val.isEmpty

@[step]
theorem alloc.vec.Vec.is_empty_spec
    {T : Type} (allocator : Type) (values : alloc.vec.Vec T) :
    alloc.vec.Vec.is_empty allocator values
      ⦃ empty => empty = true ↔ values.val = [] ⦄ := by
  simp [alloc.vec.Vec.is_empty]
