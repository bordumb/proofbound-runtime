# Implementation plan

This document is the durable work queue for the first useful Proofbound Runtime
release. The normative requirements remain in
[`specs/0001_initial_spec.md`](specs/0001_initial_spec.md). This plan records
dependency order, commit boundaries, and completion evidence.

## Working rules

- Start each security-relevant slice by refining its claim closure and adding a
  falsifier.
- Keep each commit focused on one reviewable step.
- Run the smallest relevant gate before each commit and `just ci` after each
  completed claim wave.
- Never promote a claim beyond the evidence admitted by Proofbound.
- Treat source refinement and release-artifact binding as separate linkage
  obligations.
- Keep unsupported Linux hosts unsupported. Do not use a mock as enforcement
  evidence.

## Current baseline

- `PBR-AUTH-001` is source-refined at Tier 3 and contextually bound to the exact
  native `pbr` member in both reviewed release contexts.
- `PBR-POLICY-002` is source-refined at Tier 3 and contextually bound to the
  exact native `pbr` member in both reviewed release contexts.
- `PBR-RECEIPT-004` is source-refined at Tier 3 and contextually bound to the
  exact native `pbr` member in both reviewed release contexts.
- `PBR-BINDING-005` is source-refined at Tier 3 through the production-used
  binding constructor and canonical wire projection, then contextually bound
  to the exact native `pbr` member in both reviewed release contexts.
- `PBR-SEQUENCE-003` has tested protocol-state evidence and bounded native
  `x86_64`/`aarch64` Linux evidence at Tier 0, plus exact launcher-role
  observations in both release contexts.
- `PBR-VERIFY-006` has tested model-only evidence over all 22 registered
  carrier attacks and exact verifier-role observations in both release
  contexts.
- The repository has a standalone `pbr-verify` executable, the native Linux
  enforcement crate, and the first fail-closed `pbr doctor` product command.
- Independent verification covers closed decoding, canonical bytes, external
  receipt commitment, identities, relationships, and eligibility derivation.
- `PBR-COMPOSE-008` has tested model-only evidence over its closed 16-case
  cross-receipt attack corpus and exact composer-role observations in both
  native release contexts.

## Current completion boundary

The Tier 3 release-observation implementation is complete in the repository:

- both required native release contexts are registered;
- all eight architecture-and-role observation units are registered;
- observation inputs are generated as a closed canonical manifest;
- release receipt production requires the reviewed context and exact inputs;
- the independent verifier must return `bytes-observed`; and
- the release workflow builds, observes, verifies, composes, and retains each
  native release independently on `x86_64` and `aarch64` Linux.

Revision `ced2871` produced and independently verified both native context
receipts and their composed Runtime receipts in GitHub Actions run
`34346773261`. Each contextual release contains four distinct theorem-derived
bindings to the exact `pbr` bytes and four distinct empirical observations of
the Runtime, launcher, verifier, and composer roles. The former retain their
toolchain assumption; the latter do not promote tested/model-only claims. A
final exact-SHA reproduction is still required after merge before tagging and
publishing 0.1.0.

## Ordered work queue

Each checkbox is a commit boundary unless a proof-generated artifact must be
committed with the source that generated it.

### Wave 0: contracts and falsifiers

- [x] Refresh project status and CI language after the receipt Tier 3 work.
- [x] Record explicit target evidence and source closures for the four open
  claims.
- [x] Freeze the version 1 execution-plan schema and negative vectors.
- [x] Freeze the version 1 launcher-message schema and protocol attacks.
- [x] Freeze the version 1 execution-receipt schema, canonical encoding, and
  mutation inventory.

### Wave 1: pure product core

- [x] Implement strict plan decoding and validated domain conversion.
- [x] Implement typed artifact identities and stable role validation.
- [x] Implement the platform-neutral compiled-policy model.
- [x] Implement deterministic Linux policy compilation semantics.
- [x] Advance `PBR-POLICY-002` through its declared evidence path.
- [x] Implement closed execution outcomes and stable machine errors.
- [x] Implement canonical execution-receipt construction.
- [x] Advance `PBR-BINDING-005` through omission, substitution, replay,
  truncation, and assumption-loss evidence.

### Wave 2: independent verifier

- [x] Implement the independent closed receipt decoder.
- [x] Implement independent canonical-byte validation.
- [x] Implement independent identity and artifact-role validation.
- [x] Implement the `pbr-verify` CLI and stable exit behavior.
- [x] Record the external receipt-commitment requirement exposed by attack
  conformance analysis.
- [x] Implement mandatory expected-commitment verification and update the CLI.
- [x] Revise the frozen carrier-attack expectations to distinguish locally
  decidable defects from authenticated byte substitutions.
- [x] Run producer/verifier conformance over positive, negative, and attack
  vectors.
- [x] Advance `PBR-VERIFY-006` through its declared evidence path.

### Wave 3: native Linux boundary

- [x] Add capability probes for architecture, Landlock, seccomp, and cgroup v2.
- [x] Implement rooted path, executable, ELF interpreter, and loader resolution.
- [x] Implement fresh output roots and post-run output inventories.
- [x] Implement the fresh cgroup lifecycle and registered limits.
- [x] Implement privilege removal and `no_new_privs`.
- [x] Implement Landlock filesystem enforcement.
- [x] Implement deny-network seccomp enforcement.
- [x] Implement the paused launcher and private typed protocol.
- [x] Implement the supervisor, bounded streams, timeouts, outcomes, and cleanup.
- [x] Run the native Linux positive and denial corpus on identified hosts.
- [x] Advance `PBR-SEQUENCE-003` with the strongest honest evidence available
  for effectful code.

### Wave 4: product surface

- [x] Register the runtime-orchestration claim and adversarial cases.
- [x] Implement `pbr doctor`.
- [x] Implement `pbr plan check`.
- [x] Implement `pbr run` and canonical receipt emission.
- [x] Implement `pbr inspect` without validity decisions.
- [x] Verify one end-to-end supported Linux execution with `pbr-verify`.

### Wave 5: release linkage

- [x] Add the identified native-Linux enforcement workflow.
- [x] Add reproducible `x86_64` and `aarch64` release builds.
- [x] Require and preserve a reviewed exact-observation context in the receipt
  composer.
- [x] Register the exact release-binary observation procedures for both native
  architectures.
- [x] Implement context-bound release production, independent verification,
  and retention for both native architectures.
- [x] Produce and independently verify one context-bound release receipt on
  each native architecture.
- [x] Bind every source-refined claim to the exact native `pbr` artifacts and
  retain exact observations for every tested/model-only release role.
- [x] Verify the release receipt independently.
- [x] Run the complete context-bound release gate and publish the honest
  assurance language.
- [x] Update the quick start, supported-platform statement, receipt semantics,
  threat model, and changelog.
- [x] Reproduce the merged revision on both native architectures, tag it, and
  publish version 0.1 with checksummed runtime and assurance bundles.

### Wave 6: Proofbound composition

- [x] Define the typed Proofbound plugin outside Proofbound core.
- [x] Compose one verified runtime execution receipt with its verified Runtime
  release receipt.
- [x] Reject omission, substitution, downgrade, replay, and premise loss across
  the composed receipt chain.

## Definition of complete

Version 0.1 is complete only when a supported native Linux host can run the
registered command with the declared boundary, produce one canonical receipt,
validate it with the independent binary, and trace every public assurance claim
to current evidence and exact release bytes. All unavailable mechanisms must
fail closed, and every remaining assumption or exclusion must be visible.
