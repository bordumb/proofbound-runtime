# Specification 0006: Local bounded-domain consistency guard

**Status:** Accepted implementation specification

**Version:** 0.2.0

**Date:** 2026-09-09

This specification defines a fail-closed Runtime repository check for the
bounded-domain mismatch recorded in
[PBF-0007](../proofbound-feedback/pbf-0007-claim-evidence-domain-consistency.md).
The guard is a local prerequisite for new bounded claim waves while the generic
Proofbound compiler and independent verifier fix remains open. It does not
resolve PBF-0007, change Proofbound status derivation, or strengthen existing
evidence.

## Claim and exact subject

For every Runtime claim that cites primary `bounded-check` evidence, the claim,
evidence unit, and bounded model-check manifest must register one byte-for-byte
equal typed domain before the repository may invoke Proofbound.

The exact subject is a repository-only Rust integration test over committed
TOML files below `claims/`, `proofbound/evidence/`, and
`proofbound/model-checks/`, plus its placement before Proofbound manifest
compilation in every maintained gate. The guard is not part of the Runtime
binaries or their trusted computing base.

## Typed domain

A bounded domain consists of exactly these fields:

- `id`, a non-empty string;
- `description`, a non-empty string;
- `cardinality`, a positive integer; and
- `ordering_key`, a non-empty array of non-negative integers without duplicate
  entries.

Equality means equality of all four decoded values. A matching identifier does
not excuse a different description, cardinality, or ordering key. TOML key
order and whitespace have no meaning.

## Selection and ownership

The guard loads every `proofbound-claim/1` manifest in `claims/`. For each
entry in the claim's `evidence` array with the exact reference prefix
`bounded-check:`, it must:

1. resolve exactly one `proofbound-evidence-unit/1` manifest with matching
   `kind = "bounded-check"` and `id`;
2. require the evidence unit's `claims` array to contain the owning claim ID;
3. require a valid claim-level `bounded_domain` and evidence-level
   `bounded_domain`;
4. resolve the evidence operation's repository-relative `manifest` path;
5. require a `proofbound-model-check-unit/1` manifest at that path;
6. require the model-check `id` to equal the evidence ID and its `claims` array
   to contain the owning claim ID; and
7. require the model-check `domain` to equal both duplicated domains.

The path must remain below `proofbound/model-checks/`, name a regular file, and
must not traverse a symlink. Duplicate claim IDs, evidence IDs, or bounded
references fail closed. An uncited bounded evidence unit is outside this
guard's claim; Proofbound remains responsible for general inventory rules.

A claim without a `bounded-check` reference does not require a bounded domain.
A claim that cites more than one bounded evidence unit must match every cited
unit to the same claim-level domain. This deliberately rejects a claim that
tries to combine differently described finite populations under one public
bounded-domain statement.

## Diagnostics and exit behavior

The guard writes no repository file. Success returns without output. Failure
fails the integration test and reports one diagnostic per detected problem in
stable claim, reference, and field order. Each line starts with
`bounded-domain check failed:` and includes a stable code from this closed set:

- `manifest.invalid`
- `claim.id-duplicate`
- `reference.invalid`
- `evidence.missing`
- `evidence.id-duplicate`
- `evidence.claim-missing`
- `model.path-invalid`
- `model.missing`
- `model.identity-mismatch`
- `model.claim-missing`
- `domain.missing`
- `domain.invalid`
- `domain.mismatch`

For `domain.mismatch`, the diagnostic identifies the owning claim, bounded
evidence ID, comparison pair, and first differing field. It does not print the
free-form domain description or other unbounded manifest content.

## Gate placement

The integration test runs as part of the workspace test stage before
`proofbound check --fresh` in both the fast contributor gate and the complete
repository gate. A later Proofbound failure cannot be used to mask or
reinterpret a local mismatch. The hosted and release workflows inherit the
guard by invoking those maintained gates.

The guard uses the workspace's exact pinned Rust and TOML dependencies. It must
not add a parser or package dependency, consult Git state, read environment
configuration, execute an evidence adapter, or rewrite a manifest.

## Falsification and acceptance

Implementation is complete only when isolated fixtures establish all of these
results:

1. exact equality across claim, evidence, and model-check manifests passes;
2. an `id`, `description`, `cardinality`, or `ordering_key` mismatch fails with
   `domain.mismatch` and names the first differing field;
3. substituting a passing bounded evidence unit from another claim fails;
4. two cited evidence units with different domains fail regardless of citation
   order;
5. a missing or malformed domain fails before Proofbound runs;
6. a missing, escaping, absolute, non-model-check, or symlinked model manifest
   path fails closed;
7. duplicate claim or evidence identities fail deterministically; and
8. a claim without bounded evidence remains accepted without a domain.

## Residual obligations

This guard compares Runtime's committed declarations. It does not establish
that a bounded adapter visited the registered population, that the population
represents production inputs, or that Proofbound's portable compiled bundle is
safe from substitution. PBF-0007 remains open until the Proofbound compiler and
independent verifier enforce the same invariant and Runtime migrates to that
reviewed release. The local guard must then be removed or reduced through a
separate reviewed change; silent duplication is not the end state.
