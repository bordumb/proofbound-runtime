# PBF-0012: Deterministic parallel evidence scheduling

- **Status:** `upstream-ready`
- **Priority:** `near-term`
- **Kind:** `workflow`
- **Created:** 2026-09-09
- **Last updated:** 2026-09-09
- **Runtime claim:** `none`
- **Runtime milestone:** Milestone A: sustainable assurance development
- **Proofbound target:** CLI evidence scheduler and compiled project state
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound executes selected evidence units serially even when their registered
closures and output boundaries are independent. A bounded parallel scheduler
could reduce fresh-gate latency while preserving isolated execution,
deterministic compiled state, complete diagnostics, and identical status
derivation.

## Runtime observation

Proofbound Runtime version 0.1 registers 37 evidence manifests below
`proofbound/evidence/`. `tools/ci/manifests.sh` invokes
`proofbound check --fresh --json`, so the protected gate deliberately executes
the selected units without reusing evidence conclusions.

In Runtime Verify run `34345620529`, the fresh Proofbound stage took 14 minutes
53 seconds. At consumed Proofbound revision `70af5e6`,
`crates/proofbound-cli/src/compile.rs` iterates `selected_units` in one loop and
calls `execute_or_reuse` to completion before beginning the next unit. This
observation does not establish that every unit is safe to run concurrently;
some adapters or manifests may expose undeclared shared state.

## Ownership test

Evidence scheduling, state isolation, deterministic compilation, and unit-run
diagnostics apply to any Proofbound project. Runtime-specific claim semantics
are not needed. A second consumer with independent test, model-check, and Lean
units would encounter the same serialized critical path.

## Assurance risk

Naive process parallelism could let units share mutable generated files,
temporary roots, tool caches, or output paths. It could also make record order,
failure selection, cancellation, or diagnostics depend on completion timing.
Either defect could make compiled receipts nondeterministic or allow one unit
to affect another unit's evidence.

Parallel execution must not reuse stale evidence, skip a selected unit, hide a
failure, change status derivation, or weaken a closure or output boundary.

## Proposed upstream behavior

Add an opt-in bounded worker count for selected evidence units. Before a unit
can run concurrently, Proofbound must derive an isolated execution root and
validate that its declared inputs, generated state, and output boundary do not
overlap another active unit except through explicitly read-only shared inputs.

Collect every unit result by stable unit ID, then perform canonical record
ordering and status derivation after all required results are present. Define
fail-fast cancellation separately from final failure reporting: started work
may be stopped, but every omitted result must remain an explicit non-passing
unit outcome. Preserve the serial scheduler as a comparison mode.

## Evidence meaning

### Establishes

- Every selected unit ran or has an explicit non-passing outcome under one
  bounded scheduling policy.
- Unit outputs were isolated according to registered boundaries.
- Canonical compiled records and claim status do not depend on completion
  order.

### Does not establish

- That cached evidence is fresh.
- That an adapter or external tool is correct.
- That undeclared ambient tool state is safe to share.
- That a faster wall-clock time strengthens any claim facet.

## Acceptance criteria

1. A fixture with at least four independent units produces byte-identical
   compiled project state in serial mode and with worker counts two and four.
2. Overlapping writable boundaries, a worker that cannot start, or an
   unsupported isolation capability fails closed before the affected unit is
   admitted.
3. Delayed, reordered, failed, timed-out, canceled, duplicated, and omitted
   worker results cannot change canonical ordering or become passing evidence.
4. The final compiler and independent verifier derive the same evidence set,
   unit outcomes, assumptions, bounds, and claim statuses.
5. Every unit diagnostic remains attached to its stable unit and adapter
   identity, and every inherited TCB role remains visible.
6. `--fresh` with parallel workers still executes every selected unit and never
   restores a prior evidence receipt.

## Compatibility and migration

The initial scheduler can be opt-in and need not change evidence schemas if
existing `unit_runs` represent all outcomes. If scheduling policy or isolation
identity becomes portable release metadata, version the applicable compiled
and verification schemas before relying on it. Serial execution remains the
compatibility baseline.

## Local treatment

Runtime keeps `proofbound check --fresh` in protected and release gates and
accepts the current serial latency. CI may run unrelated Rust and native lanes
in parallel, but it does not parallelize Proofbound evidence units or reuse
`.proofbound` receipts to meet a timing target.

## Upstream handoff

- **Destination:** `proof-bound` CLI scheduler, compiled-state tests, and
  verifier conformance tests
- **Issue:** none
- **Specification or ADR:** not yet upstreamed
- **Commit or pull request:** none

## Resolution

Unresolved.
