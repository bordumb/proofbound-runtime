# PBF-0002: Lean theorem identity update

- **Status:** `proposed`
- **Priority:** `near-term`
- **Kind:** `workflow`
- **Created:** 2026-09-04
- **Last updated:** 2026-09-09
- **Runtime claim:** `PBR-AUTH-001`
- **Runtime milestone:** Milestone 1
- **Proofbound target:** CLI and Lean adapter
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound can observe the current identity of an attributed Lean theorem, but
its update workflow cannot write that identity into the owning claim manifest.
The CLI requires a non-empty output boundary while the Lean adapter returns
observed evidence without changing any file.

## Runtime observation

`PBR-AUTH-001` initially omitted `formal_declaration`, `statement_encoding`,
`statement_sha256`, and `foundational_axioms`. This correctly caused
`proofbound check` to reject the theorem inventory before running the adapter.

Running
`proofbound update authority-normalization-model --root .` in a disposable,
committed copy then failed with `PB-UPDATE-0005` because
`proofbound/evidence/authority-normalization-model.toml` has no output boundary.
Declaring the claim manifest as an output would not resolve the mismatch: the
Lean adapter's `update` operation observes the compiled theorem and returns a
drifted evidence record, but it does not modify the claim manifest in the
sealed update tree.

The compiled audit identified:

- declaration
  `ProofboundRuntime.Claims.Authority.normalization_is_canonical_and_non_amplifying`;
- statement encoding `lean-expr-cbor/1`;
- statement digest
  `sha256:640cbfbce1da910d98d4762488ac31600c9d2264af0ff7f9eec0a3505458b73f`;
  and
- foundational axiom `propext`.

Runtime computed the digest with Proofbound core's
`lean_statement_wire_digest` over the compiled `expr_wire`, inserted the four
fields through a reviewed patch, and then obtained
`PROVED · MODEL_ONLY · ASSUMED` from `proofbound check`. No source-refinement or
artifact-binding status was inferred.

## Ownership test

The problem applies to any Proofbound project that registers a new Lean theorem
or intentionally changes a theorem statement. It is independent of Runtime,
agents, and Linux policy, so the update contract belongs to Proofbound.

## Assurance risk

A user must currently reproduce an internal digest procedure or edit a security
identity by hand. An incorrect declaration, digest, encoding, or axiom list
fails closed later, but the awkward path encourages stale pins and makes the
intended reviewed-update boundary unusable for Lean claims.

The change must not let an update silently accept theorem drift. Observation
and review may prepare new pins; only the subsequent verify-only run may admit
the theorem.

## Proposed upstream behavior

Let `proofbound update <lean-unit>` update the exact registered claim manifest
fields for the unit's uniquely attributed theorem. Proofbound should derive the
declaration, statement encoding, canonical statement digest, and foundational
axiom inventory from the compiled audit, modify only an explicit claim-manifest
boundary in the sealed tree, and require review of that diff.

The update must reject ambiguous claim ownership, multiple possible output
manifests, an unexpected attributed inventory, project axioms forbidden by
policy, or any attempted write outside the declared manifest.

## Evidence meaning

### Establishes

- A reviewed claim manifest pins the identity observed from one compiled Lean
  declaration.
- The next verify-only run can detect statement, declaration, inventory, and
  axiom drift against those pins.

### Does not establish

- That the theorem is admitted before a subsequent verify-only run.
- Source refinement, artifact binding, or correctness of shipping code.
- Trust in Lean, the audit executable, or the registered toolchain beyond their
  visible trusted-computing-base roles.

## Acceptance criteria

1. Updating a single registered Lean theorem changes only its owning claim's
   four identity fields and reports the exact reviewed path.
2. A missing or empty claim output boundary, ambiguous claim ownership, or
   unregistered attributed theorem fails closed with actionable diagnostics.
3. A substituted declaration, omitted attributed theorem, extra attributed
   theorem, or write outside the output boundary is rejected.
4. The following verify-only run independently derives the same statement and
   axiom identities and admits the theorem only under its claim policy.
5. The receipt retains the exact toolchain identities, foundational and project
   axiom inventories, assumptions, and model-only linkage.

## Compatibility and migration

The behavior can be additive to the existing claim and evidence schemas. Older
projects remain valid. Updating a pin must always produce a reviewable manifest
diff and must never reinterpret an existing receipt.

## Local treatment

Runtime uses the compiled Lean audit and Proofbound core's canonical digest
implementation to prepare reviewed claim-manifest patches. It immediately runs
the verify-only gate afterward. The same manual workflow now seals the theorem
identities for all four source-refined Runtime claims, including
`PBR-AUTH-001`; their version 0.1 receipts record source refinement and
contextual exact-artifact binding under visible toolchain assumptions.

The workaround still requires a maintainer to construct the patch outside the
sealed update operation. It does not make `proofbound update` capable of
preparing those identities, and it does not admit a changed theorem until the
subsequent verify-only run succeeds.

## Upstream handoff

- **Destination:** not upstreamed
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Unresolved.
