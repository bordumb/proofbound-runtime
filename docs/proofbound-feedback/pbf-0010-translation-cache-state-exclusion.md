# PBF-0010: Translation cache state exclusion

- **Status:** `resolved`
- **Priority:** `blocking`
- **Kind:** `workflow`
- **Created:** 2026-09-07
- **Last updated:** 2026-09-07
- **Runtime claim:** `PBR-AUTH-001`, `PBR-POLICY-002`, and `PBR-RECEIPT-004`
- **Runtime milestone:** Version 0.1 release linkage
- **Proofbound target:** translation evidence cache
- **Upstream record:** `proof-bound@585c0e0`
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound's translation cache and translation adapter must close the same
repository input boundary. Generated language state excluded from the adapter
shadow must also be excluded from its cache key.

## Runtime observation

The complete Runtime gate ran the Lean 4.33 model and three generated
Charon/Aeneas refinement bridges successfully, then failed during Proofbound
status derivation with `PB-CACHE-0001`. The rejected path was
`formal/vendor/aeneas/.lake/packages/batteries/docs/README.md`, a symlink
created inside ignored Lean package state.

The Aeneas adapter's `shadow_project` excludes `.lake`, `.git`, `.proofbound`,
`target`, and the other registered language caches. The compiler's translation
cache instead added each external import root as a raw recursive directory
input. Runtime registers `formal` as an import root, so a normal preceding Lean
build made cache collection inspect files that the adapter could never execute.

## Ownership test

Cache-key completeness relative to an adapter's executable shadow is generic
Proofbound workflow behavior. Any Lean, Python, Node, or Rust project can place
generated tool state below a registered source root without sharing Runtime's
Linux execution semantics.

## Assurance risk

If cache inputs are narrower than the executable shadow, stale evidence can be
reused after a meaningful input changes. If they are broader, as here, ordinary
generated state can make a valid project permanently fail after its proof build
or encourage an unsafe delete-and-retry workaround. Either mismatch makes cache
reuse semantics depend on unregistered local state.

## Proposed upstream behavior

Expand translation import roots through Proofbound's canonical semantic-closure
builder. Bind every ordinary file reachable under those roots, retain bounded
inventory limits, and apply the same reserved-state exclusions used by the
adapter shadow. Continue to reject symlinks in explicit registered inputs and
in non-excluded source paths.

## Evidence meaning

### Establishes

- Translation cache identities bind every ordinary imported repository file
  that the adapter shadow can execute.
- Generated language and Proofbound state cannot perturb that cache identity.

### Does not establish

- Correctness of the translation, proof tool, or generated state exclusions.
- That symlinks are safe as explicit evidence inputs or ordinary source files.
- Any stronger formal or artifact-linkage status for Runtime claims.

## Acceptance criteria

1. A nested ordinary file below an external import root is present in the cache
   input inventory and changing it changes the cache identity.
2. Files and symlinks below `.lake` do not enter the translation cache input
   inventory because the adapter shadow excludes that directory.
3. A symlink at any non-excluded depth remains a fail-closed cache error.
4. The compiler uses the existing bounded semantic-closure rules rather than a
   second ad hoc ignore policy.
5. Existing claim assumptions, bounds, evidence meaning, and trusted-computing-
   base identities are unchanged.

## Compatibility and migration

No schema or receipt migration is required. Cache identities can change once
because inputs previously unreachable by the adapter are removed from the key.

## Local treatment

Runtime keeps the generated `.lake` directory intact and treats the failed
gate as invalid evidence. CI and release workflows pin the upstream correction
before retrying the status derivation.

## Upstream handoff

- **Destination:** `proof-bound/crates/proofbound-cli/src/compile.rs`
- **Issue:** none
- **Specification or ADR:** none; concrete implementation defect
- **Commit or pull request:** `proof-bound@585c0e0`

## Resolution

Proofbound now expands translation import roots with its canonical semantic
closure builder before constructing cache identities. The regression recreates
Runtime's nested `.lake` package file and symlink, proves they are excluded,
and retains the existing checks that nested ordinary import files are bound and
non-excluded symlinks fail closed. Runtime consumes the fix by pinning
`proof-bound@585c0e0` in both hosted workflows.
