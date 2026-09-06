# PBF-0005: Source-refinement premise edges

- **Status:** `upstream-ready`
- **Priority:** `blocking`
- **Kind:** `evidence-semantics`
- **Created:** 2026-09-05
- **Last updated:** 2026-09-05
- **Runtime claim:** `PBR-AUTH-001`
- **Runtime milestone:** Milestone 1
- **Proofbound target:** typed assurance graph construction
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound requires every `source-refinement` unit to name at least one
representation premise, and the compiler emits an `Assumes` edge from that
unit to the premise. The typed graph rejects exactly that edge because its
endpoint table does not permit `TranslationUnit -> Premise`, so no conforming
source-refinement unit with a premise can compile.

## Runtime observation

Runtime produced the axiom-free Lean theorem
`ProofboundRuntime.Refinement.Authority.normalize_authority_refines` in
`formal/ProofboundRuntime/Refinement/AuthorityNormalization.lean`. The theorem
is directly about the Aeneas-generated translation of
`proofbound_runtime_core::normalize::normalize_authority`. It proves duplicate
freedom and input-subset preservation for paths and environment names, plus
exact preservation of resource limits and network mode.

The translation bridge for `String::as_bytes` is sound only when each UTF-8
byte sequence fits `U32`. Runtime therefore drafted
`PBR-STRING-REP-004` as a `representation-premise` and referenced it from a
draft `proofbound-evidence-unit/1` source-refinement unit, as required by
`proofbound-manifest/src/validate.rs`.

`proofbound check --root .` completed the Lean and two-run Charon/Aeneas work,
then failed while constructing the assurance graph:

```text
PB-GRAPH-0004: illegal Assumes edge
evidence:source-refinement:authority-normalization-refinement
-> premise:PBR-STRING-REP-004: edge Assumes cannot connect
TranslationUnit node to Premise node
```

The conflict is internal to Proofbound. `proofbound-core/src/graph.rs` permits
`Assumes` from claims and theorems to premises, but not from translation units,
while source-refinement validation requires a premise and compilation emits
that forbidden edge.

## Ownership test

This is generic assurance-graph behavior. Every consumer using a representation
premise for Charon/Aeneas, another translator, a serialization boundary, or an
FFI refinement will encounter the same contradiction. No Linux or Runtime
authority semantics are involved.

## Assurance risk

Removing the premise would hide a real translation bound. Reclassifying it as
an assumption or attaching it only to the claim would misstate which evidence
depends on the bound. Permitting a linkage upgrade despite the rejected graph
would launder an unregistered representation condition.

The required fail-closed result is no `REFINED` linkage until the graph can
carry the exact premise dependency.

## Proposed upstream behavior

Proofbound should permit a typed `Assumes` edge from a `TranslationUnit` node
to a `Premise` node when that premise is registered by the corresponding
source-refinement evidence unit. The producer and independent verifier must
retain and re-derive the same edge and premise burden.

No other translation-unit edge or free-form premise injection should become
valid as a side effect.

## Evidence meaning

### Establishes

- The source-refinement result depends on the exact registered representation
  premise.
- The premise remains visible in status, receipts, and independent
  verification.
- Linkage can become `REFINED` only when the theorem and translation evidence
  are both admitted under that premise.

### Does not establish

- That the representation premise holds for an arbitrary input.
- Correctness of the translator, bridge, compiler, or source merely because an
  edge is well typed.
- Artifact binding or any claim about shipping bytes.

## Acceptance criteria

1. A conforming source-refinement fixture with one registered representation
   premise compiles and derives `TranslationUnit -> Premise` as `Assumes`.
2. A missing, unknown, empty, or wrong-kind premise remains rejected.
3. Omitting the edge, changing the premise identity, or substituting an
   assumption for the premise causes producer or verifier failure.
4. The producer and independent verifier derive the same premise burden and
   linkage status from the portable receipt.
5. Status and receipt output keep the premise, theorem, translation toolchain,
   generated-code boundary, and bridge role visible.
6. Existing illegal endpoint pairs remain illegal.

## Compatibility and migration

The edge vocabulary does not change, but the typed endpoint table expands.
Receipts that already encode a source-refinement representation premise should
be accepted only by implementations that recognize this endpoint pair. Older
implementations must continue to fail closed rather than discard the edge.

## Local treatment

Runtime retains the compiled direct theorem and the registered translation
unit, but does not register the source-refinement evidence unit and does not
cite the theorem as admitted evidence. `PBR-AUTH-001` remains Tier 2,
`PROVED / MODEL_ONLY / ADMITTED`. Compilation of the direct theorem is a
development gate only and does not upgrade linkage.

## Upstream handoff

- **Destination:** not upstreamed
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Unresolved.
