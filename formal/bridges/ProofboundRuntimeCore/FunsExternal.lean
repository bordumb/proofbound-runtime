import Aeneas
import ProofboundRuntimeCore.Types

open Aeneas Aeneas.Std Result ControlFlow Error

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

@[rust_fun "alloc::vec::{alloc::vec::Vec<@T>}::truncate"]
def alloc.vec.Vec.truncate
    {T : Type} (_allocator : Type) (values : alloc.vec.Vec T)
    (length : Std.Usize) : Result (alloc.vec.Vec T) :=
  ok (.from (values.val.take length.val) (by
    simpa only [List.length_take] using
      (Nat.min_le_right length.val values.val.length).trans values.property))

@[step]
theorem alloc.vec.Vec.truncate_spec
    {T : Type} (allocator : Type) (values : alloc.vec.Vec T)
    (length : Std.Usize) :
    alloc.vec.Vec.truncate allocator values length
      ⦃ truncated => truncated.val = values.val.take length.val ⦄ := by
  simp [alloc.vec.Vec.truncate]
