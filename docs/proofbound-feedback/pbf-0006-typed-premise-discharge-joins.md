# PBF-0006: Typed premise discharge joins

- **Status:** `resolved`
- **Priority:** `blocking`
- **Kind:** `evidence-semantics`
- **Created:** 2026-09-06
- **Last updated:** 2026-09-06
- **Runtime claim:** `PBR-AUTH-001`
- **Runtime milestone:** Milestone 1
- **Proofbound target:** assumption manifest, assurance graph, status engine, and verifier
- **Upstream record:** `proof-bound@504d17d`
- **Supersedes:** none
- **Superseded by:** none

## Summary

Runtime needed to replace an active representation premise with an explicit,
policy-admitted theorem discharge. Proofbound could retain an undischarged
premise but had no manifest declaration that compiled the intended
`Premise -> Theorem` relationship into a portable graph edge.

## Runtime observation

The unconditional theorem
`ProofboundRuntime.Refinement.AuthorityNormalizationClaim.normalize_authority_refines`
derives the translated byte bounds from Aeneas `alloc.vec.Vec` invariants and
no longer accepts `PBR-STRING-REP-004` as a hypothesis. Merely changing the
assumption ledger status would not remove the premise burden: Proofbound's
status engine correctly requires first-class discharge evidence.

The first upstream implementation added typed scopes and compiled a
`DischargedBy` edge, but Runtime's full check then reported
`PB_CORE_INVALID_CYCLE`. The independently valid edges formed the intentional
join `Claim -> Premise -> Theorem -> Claim`; the older generic cycle guard had
not been exercised by the feature's separate manifest and graph-edge tests.

## Ownership test

Premise discharge is generic proof provenance. Any Proofbound consumer that
replaces a representation, decoder, FFI, or translator hypothesis with an
admitted theorem needs the same scoped relationship and fail-closed status
derivation. No Runtime authority or Linux policy semantics are involved.

## Assurance risk

A ledger-only `status = "discharged"` field could silently remove a real
hypothesis. Conversely, rejecting the exact typed join forever would leave a
proved premise permanently counted as assumed. Allowing arbitrary provenance
cycles would create a more serious self-justification path.

## Proposed upstream behavior

Proofbound should require a typed premise scope, a covering discharge scope,
and a separate cited theorem evidence unit that does not depend on the premise.
The compiler and verifier should admit only the exact discharge join while
continuing to reject additional internal edges and unrelated cycles.

## Evidence meaning

### Establishes

- An admitted theorem removes the exact scoped premise from the assumption
  facet while keeping the premise and discharging theorem visible.
- Producer and verifier agree on the typed `DischargedBy` graph edge.

### Does not establish

- That a theorem is admitted when its axiom audit, statement identity, or
  policy fails.
- That arbitrary graph cycles or ledger status labels discharge premises.
- Artifact linkage or correctness of a future enforcement mechanism.

## Acceptance criteria

1. A discharged assumption manifest compiles an exact
   `Premise -> Theorem` `DischargedBy` edge with a covering scope.
2. Missing, non-theorem, premise-dependent, or uncited discharge evidence is
   rejected.
3. An extra internal owner edge or a differently typed provenance cycle remains
   invalid.
4. The compiler and independent verifier accept and derive the same exact join.
5. The premise remains visible with `discharged_by`, while inherited project
   assumptions and theorem axioms remain unchanged.
6. A compiler-level fixture constructs the complete graph and calls graph
   validation, rather than testing manifest and edge emission in isolation.

## Compatibility and migration

The assumption manifest schema remains `proofbound-assumption/1` with optional
typed `premise_scope` and `discharge` fields. Older Proofbound versions reject
the new fields or fail closed on the resulting cycle; Runtime must pin a
Proofbound revision containing the complete feature.

## Local treatment

Runtime kept `PBR-STRING-REP-004` active until the upstream schema, compiler,
cycle rule, and verifier were available. Runtime commit `6117a26` now declares
the typed discharge and pins the new unconditional theorem statement identity.

## Upstream handoff

- **Destination:** `proof-bound` manifest, compiler, core graph, verifier, and specification
- **Issue:** none
- **Specification or ADR:** `docs/specs/0001_initial_spec.md` Section 8.1
- **Commit or pull request:** `8ca8977`, `b65a689`, `469d486`, and `504d17d`

## Resolution

Proofbound implemented scoped discharge manifests, bidirectional citation and
anti-circularity checks, first-class graph compilation, status derivation, and
independent verification. After Runtime exposed the cross-layer cycle conflict,
`504d17d` added the narrowly typed cycle rule plus core, verifier, and
compiler-level end-to-end regressions. A clean full Runtime check at `0e8def6`
reported `PBR-AUTH-001 PROVED / REFINED / ADMITTED` with no undischarged
premises.
