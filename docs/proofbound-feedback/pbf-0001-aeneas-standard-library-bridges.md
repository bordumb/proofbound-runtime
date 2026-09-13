# PBF-0001: Reusable Aeneas standard-library bridges

- **Status:** `proposed`
- **Priority:** `near-term`
- **Kind:** `plugin-boundary`
- **Created:** 2026-09-04
- **Last updated:** 2026-09-09
- **Runtime claim:** `PBR-AUTH-001`
- **Runtime milestone:** Milestone 1
- **Proofbound target:** external integration or template
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Rust source refinement repeatedly needs semantics for common standard-library
operations that Aeneas emits as external templates. A versioned, independently
reviewed bridge pack could let Proofbound consumers reuse those semantics
without copying axioms or project-specific bridge code.

## Runtime observation

On 2026-09-04, a disposable Tier 3 pilot selected
`proofbound_runtime_core::normalize::normalize_authority` from
`crates/proofbound-runtime-core/src/normalize.rs`. Charon `0.1.225` extracted
the defining symbol, and Aeneas `3a8586fa` generated 25 local transparent
functions.

The generated `FunsExternal_Template.lean` required these four external
declarations before Runtime refactored the production proof subject:

- `alloc::string::String` equality;
- `alloc::string::String` ordering;
- `alloc::string::String` cloning; and
- `alloc::vec::Vec::dedup`.

The first pilot used the public re-export path
`proofbound_runtime_core::normalize_authority`. Charon returned success with an
empty translation inventory. Using the defining path produced the non-empty
closure. Proofbound's required translated-closure inventory can reject that
empty result, so the empty match is not itself a Proofbound defect.

The exact translator identities are recorded in
`proofbound/toolchains/translation.lock`. The disposable generated files are
not committed and are not evidence for `PBR-AUTH-001`.

On 2026-09-05, Runtime replaced generic comparison, cloning, and vector
deduplication in the proof subject with concrete, ownership-preserving
operations. The defining symbol now translates to 16 local functions and 12
local types. The translation inventory has no globals, trait declarations, or
trait implementations. Its remaining external template declarations are
`alloc::string::String::as_bytes` and `alloc::vec::Vec::truncate`. Executable
local Lean definitions for both declarations are committed under
`formal/bridges/` and compile with the documented Lean 4.33 Aeneas support
profile. They are not yet registered source-refinement evidence.

## Ownership test

String access and vector truncation are not agent, Linux, or Runtime policy.
Any Rust project that uses Charon and Aeneas can need these semantics. The
bridge implementations should remain outside Proofbound core, but Proofbound
can define how a reusable integration identifies, versions, audits, and binds
them.

## Assurance risk

A project can fill the generated template with unproved axioms and then present
the downstream refinement theorem as if it covered those operations. A copied
bridge can also drift from the exact Charon, Aeneas, Aeneas Lean library, or
Rust standard-library representation used by the translation.

The risk is an understated premise inside a nominally refined linkage edge.
The bridge must remain an explicit dependency with its axioms, version range,
and representation conditions visible.

## Proposed upstream behavior

Provide an external, versioned Aeneas bridge pack and a Proofbound adoption
template for common Rust standard-library operations. The integration should:

- contain executable Lean definitions and theorems instead of project axioms;
- state the exact Rust, Charon, Aeneas, Lean, and Aeneas library identities it
  supports;
- expose each operation as a separately inventoried bridge;
- let a translation unit byte-pin the selected bridge files;
- preserve any representation premise as a registered Proofbound premise; and
- fail closed when a generated external declaration has no exact bridge.

Proofbound core should continue to own only the generic registration,
inventory, and receipt rules. The integration should own the Rust and Aeneas
semantics.

## Evidence meaning

### Establishes

- A selected generated external declaration has a reviewed implementation for
  one exact supported translator and representation boundary.
- The consuming translation used the exact registered bridge bytes.
- The bridge theorem has the registered axiom and premise inventory.

### Does not establish

- The consuming project's refinement theorem.
- Correctness of Charon, Aeneas, Lean, Rust, or the standard library.
- Applicability to a different tool version or generated declaration shape.
- Semantics for an operation not present in the bridge inventory.

## Acceptance criteria

1. A fixture that uses one supported operation translates, imports the selected
   bridge, and passes the compiled Lean axiom audit without a project axiom.
2. A missing bridge or unsupported translator identity fails before the
   consuming refinement edge is admitted.
3. A changed bridge byte, substituted operation identity, or omitted
   representation premise causes producer and independent verifier rejection.
4. The producer and independent verifier derive the same bridge identity,
   operation inventory, and inherited premise set.
5. Every foundational axiom, toolchain role, representation premise, and
   supported-version bound remains visible in the compiled claim closure.

## Compatibility and migration

This proposal adds an optional external integration. Existing source-refinement
units remain valid only under their existing bridge and premise identities.
Adoption must not reinterpret an older receipt or silently replace a local
bridge.

## Local treatment

Runtime reduced the local bridge surface to `String::as_bytes` and
`Vec::truncate`, committed executable definitions for both, and byte-pinned
them in the registered translation and refinement closures. The pinned audit,
source-refinement theorem, and contextual exact-artifact bindings now admit
`PBR-AUTH-001` at Tier 3 for the released subjects while retaining the
translation-toolchain assumption.

This local success does not provide a reusable bridge pack or make the bridge
applicable to another project, translator version, declaration shape, or
representation. Runtime continues to own and review its exact bridge bytes;
the generic packaging and adoption workflow remains unresolved.

## Upstream handoff

- **Destination:** not upstreamed
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Unresolved.
