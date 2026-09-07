# Translation units

The production subject for `PBR-AUTH-001` has a byte-pinned Charon and Aeneas
translation under `formal/generated/`. Its generated Types, reviewed external
bridges, and generated functions compile in order under the repository's Lean
4.33 toolchain via `tools/ci/authority-refinement.sh`.

The handwritten authority theorem connects
`proofbound_runtime_core.normalize.normalize_authority` to the registered
canonical, non-amplifying authority relation. Its theorem and translation
manifest pass the pinned Proofbound audits as Tier 3 source refinement.

Generated Lean must stay below `formal/generated/`. Handwritten refinement
modules must remain outside generated directories and must be byte-pinned.

`PBR-RECEIPT-004` uses its own production crate and generated
`ProofboundRuntimeReceipt` module. Keeping that translation unit separate from
`ProofboundRuntimeCore` gives each refinement theorem one exact source closure
and prevents receipt generation from changing the authority proof surface. Its
registered theorem proves equality between the translated Rust decision and
the exact receipt model for every represented input.

`PBR-POLICY-002` translates `compile_policy` into the separate generated
`ProofboundRuntimePolicy` module. Although it shares the Rust core crate with
authority normalization, the separate Lean module keeps each extraction's
closed function inventory and generated-tree ownership independent. The two
generated modules must not be imported into the same Lean environment because
they intentionally contain overlapping translated Rust declarations.
