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

- `PBR-AUTH-001` is source-refined at Tier 3. Release-artifact binding is open.
- `PBR-RECEIPT-004` is source-refined at Tier 3. Release-artifact binding is
  open.
- `PBR-POLICY-002`, `PBR-SEQUENCE-003`, `PBR-BINDING-005`, and
  `PBR-VERIFY-006` remain at Tier 0.
- The repository has no executable runtime or native Linux enforcement crate.
- The independent verifier implements receipt-eligibility derivation only.

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
- [ ] Implement typed artifact identities and stable role validation.
- [ ] Implement the platform-neutral compiled-policy model.
- [ ] Implement deterministic Linux policy compilation semantics.
- [ ] Advance `PBR-POLICY-002` through its declared evidence path.
- [ ] Implement closed execution outcomes and stable machine errors.
- [ ] Implement canonical execution-receipt construction.
- [ ] Advance `PBR-BINDING-005` through omission, substitution, replay,
  truncation, and assumption-loss evidence.

### Wave 2: independent verifier

- [ ] Implement the independent closed receipt decoder.
- [ ] Implement independent canonical-byte validation.
- [ ] Implement independent identity and artifact-role validation.
- [ ] Implement the `pbr-verify` CLI and stable exit behavior.
- [ ] Run producer/verifier conformance over positive, negative, and attack
  vectors.
- [ ] Advance `PBR-VERIFY-006` through its declared evidence path.

### Wave 3: native Linux boundary

- [ ] Add capability probes for architecture, Landlock, seccomp, and cgroup v2.
- [ ] Implement rooted path, executable, ELF interpreter, and loader resolution.
- [ ] Implement fresh output roots and post-run output inventories.
- [ ] Implement the fresh cgroup lifecycle and registered limits.
- [ ] Implement privilege removal and `no_new_privs`.
- [ ] Implement Landlock filesystem enforcement.
- [ ] Implement deny-network seccomp enforcement.
- [ ] Implement the paused launcher and private typed protocol.
- [ ] Implement the supervisor, bounded streams, timeouts, outcomes, and cleanup.
- [ ] Run the native Linux positive and denial corpus on identified hosts.
- [ ] Advance `PBR-SEQUENCE-003` with the strongest honest evidence available
  for effectful code.

### Wave 4: product surface

- [ ] Implement `pbr doctor`.
- [ ] Implement `pbr plan check`.
- [ ] Implement `pbr run` and canonical receipt emission.
- [ ] Implement `pbr inspect` without validity decisions.
- [ ] Verify one end-to-end supported Linux execution with `pbr-verify`.

### Wave 5: release linkage

- [ ] Add the identified native-Linux enforcement workflow.
- [ ] Add reproducible `x86_64` and `aarch64` release builds.
- [ ] Bind all admitted claims to exact release artifacts.
- [ ] Verify the release receipt independently.
- [ ] Run the complete release gate and publish the honest assurance language.
- [ ] Update the quick start, supported-platform statement, receipt semantics,
  threat model, and changelog.
- [ ] Tag and publish version 0.1.

### Wave 6: Proofbound composition

- [ ] Define the typed Proofbound plugin outside Proofbound core.
- [ ] Compose one verified runtime execution receipt with its verified Runtime
  release receipt.
- [ ] Reject omission, substitution, downgrade, replay, and premise loss across
  the composed receipt chain.

## Definition of complete

Version 0.1 is complete only when a supported native Linux host can run the
registered command with the declared boundary, produce one canonical receipt,
validate it with the independent binary, and trace every public assurance claim
to current evidence and exact release bytes. All unavailable mechanisms must
fail closed, and every remaining assumption or exclusion must be visible.
