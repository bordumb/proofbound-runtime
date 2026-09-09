# PBF-0011: Contextual semantic artifact binding

- **Status:** `upstream-ready`
- **Priority:** `blocking`
- **Kind:** `evidence-semantics`
- **Created:** 2026-09-08
- **Last updated:** 2026-09-08
- **Runtime claim:** `PBR-AUTH-001`, `PBR-POLICY-002`, `PBR-RECEIPT-004`, and
  `PBR-BINDING-005`
- **Runtime milestone:** Version 0.1 release linkage
- **Proofbound target:** artifact-binding proposition, reviewed evidence contexts,
  compiler, portable receipt, and independent verifier
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound needs a theorem-derived artifact-binding path for artifacts that
exist only inside a preregistered reviewed release context. The path must let
one admitted semantic claim apply to each member of a closed platform-specific
artifact set without treating an empirical exact-byte observation as semantic
evidence.

## Runtime observation

Proofbound Runtime builds separate reproducible bundles on native `x86_64` and
`aarch64` Linux runners in `.github/workflows/release.yml`. Four claims now have
kernel-checked source-refinement evidence over the production Rust functions:

- `PBR-AUTH-001`;
- `PBR-POLICY-002`;
- `PBR-RECEIPT-004`; and
- `PBR-BINDING-005`.

Each claim retains `PBR-TOOLCHAIN-AX-003`, which states the compiler, linker,
dependencies, and build preserve the registered Rust behavior in the produced
Runtime artifacts. The exact release binaries do not exist during an ordinary
source-only check. They exist only after `tools/release/build-linux.sh` runs in
one of the reviewed contexts `release-linux-x86-64` or
`release-linux-aarch64`.

Proofbound evidence-unit schema version 5 solves that lifecycle for
`example-test` exact-artifact observations. It deliberately does not admit
`artifact-soundness`, and the manifest validator rejects every other
context-owned evidence kind with `PB-CTX-0001`. This keeps the empirical claims
`PBR-RUN-007`, `PBR-SEQUENCE-003`, `PBR-VERIFY-006`, and `PBR-COMPOSE-008` at
`TESTED / MODEL_ONLY`, as required.

The theorem-derived route is also singular. `Proofbound.Artifact.DigestBindingV1`
names one literal logical artifact and digest, while a claim manifest has one
formal declaration and statement identity. Reusing one architecture's theorem
for the other would be digest substitution. Registering both unconditional
artifact units would make ordinary checks require generated Linux binaries and
would attempt the wrong architecture on each native runner. Binding a digest
catalog instead of the executable would bind the catalog, not the release
bytes that carry the claim.

The concrete blocked checklist item is `docs/implementation-plan.md`, Wave 5:
"Bind all admitted claims to exact release artifacts." The local base check
correctly reports the four source claims as `PROVED / REFINED / ASSUMED` and
keeps their release-artifact obligations open.

## Ownership test

Context activation, theorem identity, artifact correspondence, status
derivation, and portable verification are generic Proofbound semantics. A
Python project publishing architecture-specific wheels, a cryptographic
library publishing CPU-specific binaries, or a compiler publishing several
target executables has the same requirement without sharing Runtime's Linux,
Landlock, seccomp, cgroup, or receipt semantics.

Runtime owns which binaries carry each Runtime claim and how those binaries are
built and exercised. Proofbound owns whether a reviewed contextual theorem and
checked artifact identity can derive `ARTIFACT_BOUND`, and whether the
standalone verifier reaches the same result.

## Assurance risk

A local workaround can overstate assurance in four ways:

1. treating `bytes-observed` as theorem-derived semantic correspondence;
2. binding a manifest or digest catalog while describing the executable as
   bound;
3. letting an unreviewed generated theorem or manifest choose the claim,
   architecture, path, or digest after the release bytes exist; or
4. replaying one architecture's artifact evidence in another release context.

Each would violate the distinction between identity, empirical observation,
source refinement, and semantic artifact binding. A checker-authored Boolean
or a successful release job must not create `ARTIFACT_BOUND`.

## Proposed upstream behavior

Add a versioned, generic way for a reviewed release context to activate
theorem-derived `artifact-soundness` evidence over exact generated artifacts.
The admitted theorem must remain the sole source of the claim ID, artifact
schema, logical name, digest, and semantic meaning. The artifact checker may
only recompute and report exact artifact identity.

The design must support one registered semantic claim across a closed set of
context-specific artifacts. This may be represented by a single typed theorem
whose exact root binds a closed artifact set, or by context-indexed formal
identities with an equally strict proof that every contextual theorem carries
the registered claim meaning. It must not admit an auxiliary theorem that binds
arbitrary `True` while an unrelated theorem supplies the claim's formal facet.

Base checks must exclude the contextual artifact units. A full check may
activate exactly one registered context. Release production and the independent
verifier must retain and re-derive the selected context, theorem statement
identity, selected artifact identity, assumptions, and the exact member of the
closed artifact set that was checked.

Existing exact-artifact observation records remain orthogonal. Activating this
capability must not upgrade `example-test`, bounded, property, or independent
evidence to `ARTIFACT_BOUND`.

## Evidence meaning

### Establishes

- In the selected reviewed context, the exact checked artifact identity equals
  one identity derived from the admitted theorem's exact elaborated root.
- The theorem establishes its registered semantic meaning for the theorem's
  bound bytes, subject to every recorded project and native-evaluation
  assumption.
- The portable release records which context and exact artifact member supplied
  the correspondence.

### Does not establish

- Correctness of SHA-256, the compiler, linker, build environment, operating
  system, hardware, or independent verifier beyond their explicit assumptions
  and trusted-computing-base roles.
- That an inactive architecture's artifact was built or checked in the selected
  context.
- Semantic artifact binding for a claim supported only by tests or
  observations.
- Correspondence to a digest catalog, archive member, or adjacent manifest when
  the checked subject is the executable itself.

## Acceptance criteria

1. A source-only base check succeeds without generated release bytes and keeps
   the four Runtime semantic claims source-refined with their artifact
   obligations open.
2. A full `release-linux-x86-64` check can derive theorem-backed correspondence
   for the exact registered x86_64 executables, and the equivalent aarch64
   check can do so for the exact registered aarch64 executables.
3. A missing artifact, wrong digest, wrong byte size, wrong logical name,
   inactive-context unit, untracked context manifest, or theorem whose claim
   meaning is unrelated to the registered claim fails closed.
4. Context omission, architecture replay, member omission, duplicate member,
   artifact substitution, theorem substitution, and downgrade to an empirical
   observation are rejected with stable typed diagnostics.
5. The compiler and `proofbound-verify` independently parse the theorem form,
   select the same context-specific artifact member, require the same exact
   checked identity, and derive the same claim facets.
6. Every source-refinement premise, project assumption, native-evaluation
   premise, artifact-checker identity, and trusted-computing-base role remains
   visible in the portable release.
7. Existing projects and version 5 exact observations retain their current
   meaning, and older tools reject any new manifest or receipt schema instead
   of silently ignoring it.

## Compatibility and migration

The capability requires versioned manifest and portable-receipt semantics.
Existing unconditional `DigestBindingV1` claims and schema version 5 contextual
observations must continue to validate unchanged. A project opts in only by
registering the new contextual artifact-binding form. Older producers and
verifiers must fail closed on the new form.

## Local treatment

Runtime leaves the four semantic claims at `PROVED / REFINED / ASSUMED`, keeps
their release-artifact obligations open, and does not publish version 0.1. The
existing contextual observations continue to identify and exercise the exact
four release binaries per architecture without changing any claim's semantic
linkage facet.

## Upstream handoff

- **Destination:** `proof-bound` specification or ADR, manifest schemas,
  artifact theorem parser, compiler, release receipt, and independent verifier
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Unresolved.
