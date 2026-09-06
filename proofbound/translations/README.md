# Translation units

The production subject for `PBR-AUTH-001` has a byte-pinned Charon and Aeneas
translation under `formal/generated/`. Its generated Types, reviewed external
bridges, and generated functions compile in order under the repository's Lean
4.33 toolchain via `tools/ci/authority-refinement.sh`.

The remaining Tier 3 obligation is a handwritten theorem connecting
`proofbound_runtime_core.normalize.normalize_authority` to the registered
canonical, non-amplifying authority relation. Until that theorem and its
translation manifest pass the pinned Proofbound audits, the claim remains
Tier 2 and model-only.

Generated Lean must stay below `formal/generated/`. Handwritten refinement
modules must remain outside generated directories and must be byte-pinned.

`PBR-RECEIPT-004` uses its own production crate and generated
`ProofboundRuntimeReceipt` module. Keeping that translation unit separate from
`ProofboundRuntimeCore` gives each refinement theorem one exact source closure
and prevents receipt generation from changing the authority proof surface.
