# PBF-0009: Reviewed release evidence contexts

- **Status:** `upstream-ready`
- **Priority:** `blocking`
- **Kind:** `workflow`
- **Created:** 2026-09-07
- **Last updated:** 2026-09-07
- **Runtime claim:** `PBR-RUN-007`, `PBR-SEQUENCE-003`, `PBR-VERIFY-006`, and
  `PBR-COMPOSE-008`
- **Runtime milestone:** Version 0.1 release linkage
- **Proofbound target:** project and claim manifests, compiler, release command, and receipts
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound needs reviewed, named evidence contexts for evidence that exists only
while building a release. A project must be able to run ordinary source checks
without generated release bytes and then activate a preregistered native
release context that is mandatory for the corresponding release receipt.

## Runtime observation

Proofbound Runtime's `.github/workflows/release.yml` builds separate reproducible
Linux bundles on native `x86_64` and `aarch64` runners. ADR 0020 in the sibling
`proof-bound` repository now provides evidence-unit schema version 5 for exact
artifact observations, but every evidence unit matched by `proofbound.toml` is
currently mandatory during every full-project check.

A static `x86_64` observation unit cannot run during an `aarch64` release, and
neither native bundle exists during ordinary macOS or source-only Linux checks.
Keeping generated manifests under an ignored directory would let unreviewed
configuration select claims, roles, platforms, dependencies, and artifact
paths while the release still appears to have a clean reviewed tree. Removing
Proofbound from ordinary checks or treating skipped native work as passing
evidence would weaken the existing gate.

## Ownership test

Evidence activation and reviewed-manifest provenance are generic Proofbound
workflow semantics. A wheel publisher with platform-specific integration tests
or a cryptographic library with hardware-backed release tests has the same
need without sharing Runtime's Linux policy or receipt model.

Runtime owns how it builds and exercises each bundle. Proofbound owns which
reviewed evidence declarations are active, whether an active context is
complete, and whether a release can be created from that compiled state.

## Assurance risk

Without a typed context, release evidence must either be mandatory on hosts
where its subject cannot exist, be omitted from the release receipt, or be
introduced through ignored mutable manifests. The last option permits evidence
smuggling across the clean-tree boundary. An architecture can also be replayed
under another context if context identity is not bound to compiled and released
state.

## Proposed upstream behavior

Let a project preregister a closed set of named evidence contexts and the
evidence-unit manifests owned by each context. Claim manifests must explicitly
cite any context-owned evidence they accept. Ordinary checks activate only the
base evidence set. A caller can request exactly one reviewed context for a full
check, and a project can require that every release select one member of a
reviewed release-context set.

The compiler must load every context manifest from the reviewed tree before
selection, reject duplicate or unknown evidence identities across contexts,
and record the selected context in compiled state. `proofbound release` must
require the same selected context, reject stale or filtered compiled state, and
carry the context identity into the portable receipt. Context selection changes
availability only; it cannot change evidence meaning, claim ceilings, profiles,
assumptions, bounds, or dependency rules.

## Evidence meaning

### Establishes

- Every evidence unit used by a context came from a preregistered reviewed
  manifest and was executed during the selected full-project check.
- A context-required release contains the complete admitted evidence for that
  selected context.

### Does not establish

- That evidence inactive in the selected context passed or applied.
- That a release for one platform says anything about another platform.
- Any stronger formal or linkage facet than the activated evidence derives.

## Acceptance criteria

1. A clean project can run a base check without generated release inputs, then
   run a full check for one reviewed release context and create a receipt that
   records that exact context and its evidence.
2. An unknown context, missing active input, absent required release context,
   or context manifest outside the reviewed tree fails closed.
3. Context omission, context substitution after checking, architecture-context
   replay, duplicate evidence identity, and ignored-manifest injection are
   rejected with stable typed diagnostics.
4. The producer and independent verifier derive the same context identity and
   reject a portable receipt whose context or context evidence is changed.
5. Every assumption, premise, finite bound, toolchain identity, and
   trusted-computing-base role inherited by active evidence remains visible.

## Compatibility and migration

Projects without evidence contexts retain their current base-check and release
behavior. Projects that declare release contexts require a versioned project,
claim, compiled-state, and portable-receipt migration. Older tools must reject
the new schema rather than silently ignore context-owned evidence.

## Local treatment

Runtime keeps ordinary Proofbound checks intact and does not generate ignored
evidence manifests. Version 0.1 exact release-artifact observation remains
blocked until reviewed release contexts can be activated independently on the
two native architecture runners.

## Upstream handoff

- **Destination:** `proof-bound` manifest schemas, compiler, release receipt, and verifier
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Unresolved.
