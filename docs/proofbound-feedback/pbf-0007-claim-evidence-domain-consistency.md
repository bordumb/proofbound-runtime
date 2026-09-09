# PBF-0007: Claim/evidence bounded-domain consistency

- **Status:** `upstream-ready`
- **Priority:** `near-term`
- **Kind:** `verifier`
- **Created:** 2026-09-06
- **Last updated:** 2026-09-09
- **Runtime claim:** `PBR-POLICY-002`
- **Runtime milestone:** Policy compilation
- **Proofbound target:** compiler, status engine, and independent verifier
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound admitted bounded evidence whose registered finite domain differed
from the bounded domain recorded by the claim. The status report then combined
the claim's stale public suffix with the evidence receipt's current domain.

## Runtime observation

At Runtime commit `d1ee23b`, `claims/PBR-POLICY-002.toml` still declared the
earlier 16-state domain `policy-two-path-two-environment-catalog`. The cited
model-check and evidence manifests both declared the four-state domain
`policy-one-path-one-environment-catalog`. A clean `proofbound check` reported
`PBR-POLICY-002 BOUNDED_CHECKED / MODEL_ONLY / ADMITTED` and printed the stale
16-state description in `public_statement`, while `bounded_domains` contained
the current four-state evidence domain.

## Ownership test

Cross-record domain consistency is generic Proofbound behavior. Any bounded
claim can otherwise publish language about a larger or different domain than
the admitted model-check receipt actually covered. No Runtime-specific Linux
policy semantics are needed to compare the typed records.

## Assurance risk

A stale claim domain can overstate cardinality, constraints, or the population
covered by bounded evidence while every visible status token remains admitted.
Independent verification that repeats the same omission cannot detect the
semantic mismatch.

## Proposed upstream behavior

When a claim cites bounded evidence, Proofbound should require the claim's
optional `bounded_domain` to equal every primary bounded evidence domain that
supports its bounded status. The compiler and verifier should reject differing
IDs, descriptions, cardinalities, or ordering keys with a typed diagnostic.

## Evidence meaning

### Establishes

- Public bounded-domain language and admitted bounded evidence describe the
  same registered finite population.
- Producer and verifier reject stale or substituted domain metadata.

### Does not establish

- That the registered domain is representative of production inputs.
- Any behavior outside the finite domain.
- The truth of a model-check receipt whose own verification failed.

## Acceptance criteria

1. An exact claim/evidence bounded-domain match remains admitted.
2. A mismatch in ID, description, cardinality, or ordering key invalidates the
   claim with a stable diagnostic.
3. Substituting a passing bounded receipt from a different domain is rejected.
4. The independent verifier derives the same failure from the compiled bundle.
5. Public language is never formed from claim-domain data that disagrees with
   the evidence used to derive bounded status.
6. Claims without bounded status continue to follow their profile-specific
   domain rules.

## Compatibility and migration

Existing projects with stale duplicated domain declarations will need to align
or remove the claim-level domain before adopting the stricter compiler. The
wire schemas need not change if equality is enforced over existing fields.

## Local treatment

Runtime aligns all three policy domain declarations manually and treats their
equality as a review invariant. `PBR-POLICY-002` now has admitted bounded,
model-theorem, source-refinement, and contextual exact-artifact evidence for
the version 0.1 subjects. None of that evidence makes the duplicated-domain
invariant generic or independently enforced.

The next bounded resource-policy claim remains blocked on PBF-0007 or an
equivalent local fail-closed checker. Runtime will not rely on review-only
domain equality for the memory and swap claim wave.

## Upstream handoff

- **Destination:** `proof-bound` compiler, verifier, and conformance tests
- **Issue:** none
- **Specification or ADR:** not yet upstreamed
- **Commit or pull request:** none

## Resolution

Open. Record the exact upstream decision and Runtime migration here.
