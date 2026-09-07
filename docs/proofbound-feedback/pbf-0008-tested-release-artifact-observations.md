# PBF-0008: Tested release-artifact observations

- **Status:** `upstream-ready`
- **Priority:** `blocking`
- **Kind:** `evidence-semantics`
- **Created:** 2026-09-07
- **Last updated:** 2026-09-07
- **Runtime claim:** `PBR-RUN-007`, `PBR-SEQUENCE-003`, `PBR-VERIFY-006`, and
  `PBR-COMPOSE-008`
- **Runtime milestone:** Version 0.1 release linkage
- **Proofbound target:** evidence semantics, status engine, release receipt, and independent verifier
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound Runtime needs to record that bounded native tests executed exact
release artifacts without converting those tests into a theorem-to-bytes
claim. Proofbound's production evidence algebra currently gives sampled and
mutation evidence only `TESTED · MODEL_ONLY`, while `ARTIFACT_BOUND` requires
an admitted theorem whose exact outer proposition is
`Proofbound.Artifact.DigestBindingV1`.

## Runtime observation

The version 0.1 release workflow builds reproducible `x86_64` and `aarch64`
bundles containing `pbr`, `pbr-native-launcher`, `pbr-verify`, and
`pbr-compose`. It extracts each completed bundle and runs
`tools/ci/native-linux.sh` with `PROOFBOUND_RUNTIME_BIN_DIR` set to that exact
extracted directory. The script retains the plan, canonical execution receipt,
externally transported receipt commitment and execution identity, and
independent verification result under its requested evidence directory. The
workflow then uses that exact `pbr-compose` binary to join those records to the
independently verified Proofbound release envelope.

Those observations are relevant to four admitted claims:

- `PBR-RUN-007` concerns the production `pbr run` orchestration path;
- `PBR-SEQUENCE-003` concerns boundary installation before child start; and
- `PBR-VERIFY-006` concerns the separately built `pbr-verify` executable; and
- `PBR-COMPOSE-008` concerns complete, typed composition of the exact release
  and execution records without upgrading any admitted facet.

All four claims are intentionally supported by tests or bounded native
observations, not by universal theorems about the executable bytes. Their
current evidence therefore derives `TESTED · MODEL_ONLY`.

The temporary release envelope produced at Runtime commit `c67bd07` verified
as `receipt-consistent`, but it could only preserve the claims' open release-
artifact obligations. The production rules in Proofbound specification 0001,
sections 6.3 and 9.4, require artifact soundness plus an admitted theorem with
the exact `DigestBindingV1` root before deriving `ARTIFACT_BOUND`. Adding such
a theorem to these empirical claims would change their meaning and
unjustifiably promote their formal standing.

Proofbound experiment 0017 demonstrates the desired high-level distinction in
a research kernel: callers can retain a tested formal ceiling while recording
an exact native-artifact strengthening. That result is not a production
manifest family, compiler rule, receipt field, or independent-verifier rule.

## Ownership test

The distinction between semantic theorem-to-bytes binding and an observation
that exact identified bytes were exercised is generic assurance algebra. A
database migration tester, compiler conformance suite, or cryptographic module
test lab could need the same record without sharing Runtime's Linux, Landlock,
seccomp, cgroup, launcher, or receipt semantics.

Runtime owns the native test procedure and the meaning of its retained
execution evidence. Proofbound owns whether that evidence has a portable typed
representation, how it composes with status, and how an independent verifier
rejects substitution or downgrade.

## Assurance risk

Without a separate representation, a consumer must choose between two unsafe
outcomes: leave the identity relationship invisible, or misuse
`ARTIFACT_BOUND` and imply a theorem-to-bytes correspondence that does not
exist. A sidecar JSON file or checker-authored Boolean would also let producer
output manufacture linkage and recreate the class of defect closed by
Proofbound ADR 0012.

The missing distinction risks artifact substitution, cross-architecture
replay, evidence omission, loss of platform or toolchain assumptions, and an
accidental upgrade from `TESTED` to `PROVED`.

## Proposed upstream behavior

Add a generic, typed evidence family for an **exact-artifact observation**. It
must join a registered artifact identity to one or more typed observation
records that identify the procedure, result, subject role, platform, and
complete dependency closure. The status algebra must preserve the evidence's
existing formal ceiling. In particular, sampled, mutation, and bounded native
evidence remains at most `TESTED`.

Proofbound should either expose the observation as a distinct non-semantic
linkage facet or as an orthogonal receipt relation that does not occupy the
current theorem-derived linkage facet. The name and representation are an
upstream design decision. Existing `ARTIFACT_BOUND` semantics must remain
unchanged and reserved for theorem-derived semantic correspondence.

The compiler and independent verifier must recompute the artifact digest and
size, validate the complete typed join, preserve all inherited bounds and
assumptions, and derive the same result without trusting producer-authored
status or linkage fields.

## Evidence meaning

### Establishes

- The named observation procedure consumed the exact registered artifact
  bytes with the recorded logical role, digest, size, architecture, platform,
  toolchain, and evidence dependencies.
- Producer and independent verifier agree on the complete observation join.
- The claim's formal standing is no stronger than the admitted observation
  family permits.

### Does not establish

- A theorem-to-artifact semantic correspondence.
- Universal behavior beyond the registered tests, attacks, inputs, bounds,
  platforms, or architectures.
- Correctness of the host, kernel, toolchain, observation procedure, or
  external commitment channel beyond their visible assumptions.
- That a passing artifact is the artifact a later operator actually executes.

## Acceptance criteria

1. A registered sampled, mutation, or bounded observation over an exact
   artifact can retain `TESTED` formal standing while the receipt records the
   exact digest, size, logical role, platform, and complete evidence closure.
2. Missing artifact bytes, an unsupported evidence family, an undeclared
   platform, or an incomplete dependency inventory fails closed.
3. Artifact substitution, role substitution, architecture replay, evidence
   omission, status upgrade, and replacement of a theorem-derived
   `ARTIFACT_BOUND` relation by an observation are rejected with stable typed
   diagnostics.
4. The producer and independent verifier recompute byte-identical portable
   relation identities and equivalent claim status from the registered bytes
   and records.
5. Every inherited assumption, finite bound, platform identity, toolchain
   identity, and trusted-computing-base role remains visible in the claim and
   release receipt.
6. Existing `DigestBindingV1` evidence continues to derive
   `ARTIFACT_BOUND`; an exact-artifact observation alone never does.
7. A release receipt can compose the exact-artifact observation with a
   separately verified domain receipt without claiming that either receipt
   proves the other's producer honest.

## Compatibility and migration

This capability requires a versioned evidence record and portable receipt
representation. Older compilers and verifiers must reject the unknown family
or relation rather than ignore it. Existing artifact-soundness and
`DigestBindingV1` records retain their current meaning and require no
migration.

## Local treatment

Runtime keeps the exact release binaries, native execution evidence, and
release-envelope verification as separate records. It does not label the
empirical claims `ARTIFACT_BOUND`, does not add a vacuous digest theorem, and
keeps the Wave 5 release-linkage milestone blocked until the exact observation
can be represented and independently verified. The native and release
workflows still fail closed if exact-binary execution or receipt verification
fails.

## Upstream handoff

- **Destination:** `proof-bound` evidence algebra, schemas, compiler, release receipt, and verifier
- **Issue:** none
- **Specification or ADR:** not yet upstreamed
- **Commit or pull request:** none

## Resolution

Unresolved.
