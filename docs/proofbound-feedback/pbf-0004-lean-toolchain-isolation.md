# PBF-0004: Lean toolchain isolation for theorem evidence

- **Status:** `resolved`
- **Priority:** `later`
- **Kind:** `workflow`
- **Created:** 2026-09-05
- **Last updated:** 2026-09-05
- **Runtime claim:** `PBR-AUTH-001`
- **Runtime milestone:** Milestone 1
- **Proofbound target:** Lean adapter and theorem evidence configuration
- **Upstream record:** deliberately deferred
- **Supersedes:** none
- **Superseded by:** none

## Summary

Runtime initially appeared to need evidence-specific Lean environments because
the selected translator support library and the Proofbound audit used
incompatible Lean releases. A local, byte-bound Lean 4.33 support profile now
compiles both evidence paths in one root Lake graph, so toolchain isolation is
not required for `PBR-AUTH-001`. This record remains as a fail-closed design for
a future consumer that genuinely needs independently versioned evidence.

## Runtime observation

On 2026-09-05, Runtime translated the defining symbol
`proofbound_runtime_core::normalize::normalize_authority`. The refactored
translation closure contains 16 local functions, 12 local types, no globals,
no trait declarations, and no trait implementations. Its two external
operations have executable handwritten Lean definitions outside
`formal/generated/`.

The exact Aeneas translator revision
`3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0` shipped a Lean backend for an older
release. Runtime and its exact Proofbound dependency use
`leanprover/lean4:v4.33.0`. Directly placing the older backend in Runtime's root
Lake graph failed at changed compiler and library APIs; moving the root project
backward instead made the registered Proofbound audit fail.

Runtime resolved the concrete incompatibility by vendoring the Aeneas Lean
support snapshot `f9a8e338188447c77f31246892cb9a7a742e58ef` and carrying a narrow,
documented Lean 4.33 compatibility patch. This does not change the byte-pinned
translator identity. `tools/ci/authority-refinement.sh` builds that support
library, the generated Types, the reviewed external bridges, and the generated
functions in dependency order under the root toolchain.

The remaining Tier 3 obligation is the handwritten source-refinement theorem,
not a toolchain conflict.

## Ownership test

The original conflict was between independent Lean evidence producers and the
generic Proofbound audit boundary. Any Proofbound consumer that truly must
compose incompatible theorem packages could encounter it. Runtime no longer
demonstrates that requirement because its selected evidence now shares one
compatible toolchain.

## Assurance risk

A consumer can be tempted to copy and patch an auditor, register a theorem
built outside the audited project, or silently substitute a support library.
Those shortcuts hide compiler, library, or audit identity and can turn an
unchecked compatibility assumption into source-refinement status.

The correct failure mode remains no linkage upgrade. A model theorem stays
model-only until the exact generated theorem, bridges, audit implementation,
and toolchains form one registered and reproducible evidence closure.

## Proposed upstream behavior

If a future concrete case cannot use one compatible toolchain, allow a theorem
evidence unit to select an isolated Lean project and exact Lean toolchain. The
unit should bind:

- the Lean project root and toolchain identity;
- the complete Lake dependency graph or its content identity;
- the audit executable and Proofbound audit implementation identity;
- every imported generated module and handwritten bridge digest; and
- the compiled claim declaration, axiom inventory, premises, and surfaces.

Proofbound should run the audit in that declared environment and carry its full
identity into the evidence record and receipt. A source-refinement unit may
cite the theorem only when the translation unit binds the same generated
outputs and bridges.

## Evidence meaning

### Establishes

- The registered theorem compiled and passed the registered Proofbound audit
  in its exact declared Lean environment.
- A source-refinement edge cites the same generated outputs and handwritten
  bridge bytes that the theorem imported.
- The receipt exposes each distinct Lean toolchain and audit identity.

### Does not establish

- Correctness of Lean, Lake, Charon, Aeneas, Rust, or their dependencies.
- Correctness of an external bridge merely because it compiled.
- Source refinement without a theorem that states and proves the required
  relation.
- Applicability to a different toolchain, dependency graph, or generated file.

## Acceptance criteria

1. A fixture can audit model and refinement theorems in distinct declared Lean
   environments, then admit the refinement edge only when both exact audits
   and the registered translation succeed.
2. A missing toolchain, incompatible dependency, unavailable audit executable,
   or failed theorem audit prevents the linkage upgrade.
3. Changing a toolchain, audit executable, imported generated file, bridge
   byte, dependency identity, or theorem declaration invalidates the evidence.
4. The producer and independent verifier derive the same evidence identities,
   linkage status, premise set, and trusted-computing-base inventory.
5. The receipt keeps every toolchain role, foundational axiom, representation
   premise, and supported-version bound visible.

## Compatibility and migration

Evidence-specific Lean environments would require versioned manifest and
receipt fields. Existing theorem evidence must retain its current root-project
meaning, and older producers and verifiers must reject an environment they
cannot interpret.

## Local treatment

Runtime uses one Lean 4.33 project and records the vendored support provenance
in `formal/vendor/aeneas/PROVENANCE.md`. `PBR-AUTH-001` remains Tier 2 with
`MODEL_ONLY` linkage until the handwritten refinement theorem and registered
translation evidence pass; compilation alone is not treated as refinement.

## Upstream handoff

- **Destination:** deliberately deferred
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Resolved locally on 2026-09-05 by using a documented Lean 4.33 Aeneas support
profile in the root Lake graph. The generic isolation proposal is deliberately
deferred until a consumer demonstrates a case that cannot be unified without
weakening or substituting evidence identity.
