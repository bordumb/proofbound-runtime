# Documentation

This directory is the entry point for Proofbound Runtime specifications,
security boundaries, architecture decisions, and cross-repository feedback.
The document type determines its authority.

## Delivery tracking

- [Product development checklist](product-development-checklist.md) is the
  timestamped live execution ledger for the active dependency path, exact
  evidence checkpoints, external gates, and intentionally deferred work.
- [Proof-carrying agent software vision](vision-proof-carrying-agent-software.md)
  describes the non-normative ecosystem thesis across Proofbound, Runtime,
  Auths, and Capsec.
- [Product roadmap execution order](product-roadmap-execution-order.md) is the
  durable dependency order across Roadmap 1 release closure, Roadmap 2, and
  Roadmap 3 candidate promotion.
- [Product and delivery roadmap](product-roadmap.md) records the ordered
  post-0.1 product, workflow, cross-repository, and assurance work. It does not
  replace a specification, ADR, or claim manifest.
- [Product roadmap 2](product-roadmap-2.md) orders the capabilities the
  first roadmap deferred by trusted-computing-base delta: published crates,
  trace-assisted plan drafting, a multi-service network allow-list, a Linux
  VM host profile, a signing and transparency ADR with a receipt log, and an
  execution service. It does not replace a specification, ADR, or claim
  manifest.
- [Roadmap 2 execution records](roadmap-2/README.md) map the shared platform
  vocabulary, identity, composition, and compatibility obligations into each
  affected RT epic. They do not change roadmap order or native protocol
  meaning.
- [Roadmap 3 candidate register](product-roadmap-3-candidates.md) preserves
  decision-gated ideas for credential custody, operation mediation,
  organization policy, integration profiles, multi-language analysis, evidence
  discovery, and fleet identity. Its [candidate records](roadmap-3/README.md)
  are pre-planning documents, not scheduled implementation.
- [Upstream review records](product-roadmap-reviews.md) hold the exact
  independent review findings for Proofbound pull requests 2, 6, 7, 8,
  and 9. They are findings, not approvals.
- [Implementation plan](implementation-plan.md) records the ordered work queue,
  commit boundaries, and release completion criteria. It does not replace the
  normative specification or claim ledger.
- [Assurance plan](assurance-plan.md) records target tiers, source closures, and
  evidence paths. Claim manifests remain authoritative for current status.

## Normative specification

- [Specification 0001](specs/0001_initial_spec.md) defines the initial product,
  architecture, repository layout, development standards, and milestones.
- [Specification 0002](specs/0002_cli_surface.md) fixes the version 1 command
  grammar, user-visible behavior, and CLI component boundaries.
- [Specification 0003](specs/0003_release_receipt_composition.md) fixes the
  typed release/execution receipt join, preserved evidence, and cross-receipt
  attack inventory.
- [Specification 0004](specs/0004_doctor_explanations.md) defines the
  read-only host-readiness explanation projection without changing capability
  or support semantics.
- [Specification 0005](specs/0005_read_only_preflight.md) defines a read-only
  execution preflight that joins plan, host, path, and identity diagnostics
  without installing a boundary or starting child code.
- [Specification 0006](specs/0006_bounded_domain_consistency_guard.md) defines
  the temporary fail-closed Runtime guard for claim, evidence, and model-check
  bounded-domain equality while the generic Proofbound invariant remains open.
- [Specification 0007](specs/0007_memory_and_swap_profile.md) defines the accepted
  version 2 memory and swap execution profile, wire transition, terminal
  observations, and required native falsifiers.
- [Specification 0008](specs/0008_cross_receipt_linkage.md) drafts the
  cross-project linkage between one Auths execution receipt, one Runtime
  execution receipt, and the Proofbound release, using one profile claim and
  one declared plan input without changing any existing receipt schema.
- [Specification 0009](specs/0009_run_denial_diagnostics.md) drafts the closed
  prelaunch and Runtime failure diagnostics for `pbr run` without claiming to
  explain a kernel denial.
- [Specification 0010](specs/0010_receipt_acceptance_policy.md) defines bounded
  consumer policy over independently verified Runtime and Proofbound inputs.
- [Specification 0011](specs/0011_plan_scaffold.md) defines bounded static plan
  scaffolding with explicit provenance and unresolved human choices.
- [Specification 0012](specs/0012_plan_sdks.md) defines the separate-process
  Rust, Python, and TypeScript plan SDK boundaries and package contracts.
- [Specification 0013](specs/0013_platform_integration_contract.md) drafts the
  ownership, terminology, typed identity, composition, compatibility, and
  conformance contract across Runtime, Proofbound, Auths, and Capsec.
- [Specification 0014](specs/0014_public_compatibility_and_distribution.md)
  drafts RT-7's public version, package, registry, compatibility-matrix, and
  consumer-support contract. It does not authorize publication.

Normative product or wire behavior belongs in `docs/specs/`. A specification
revision requires explicit review because it can change claim meaning.

## User guides

- [Install and prepare version 0.1](guides/install-v0.1.md) verifies one exact
  release archive and prepares the supported systemd cgroup delegation.
- [Build and run the maintained static example](guides/maintained-example.md)
  packages one deterministic source bundle and reaches an independently
  verified execution receipt without relying on a dynamic runtime closure.

Guides describe maintained procedures. They do not strengthen a product claim,
replace a receipt, or remove a documented host or distribution assumption.

## Experiments

- [Experiment index](experiments/README.md)
- [Experiment 0001: Network authority mechanisms](experiments/0001-network-authority-mechanisms.md)

Experiments pre-register questions, fixtures, attacks, and decision criteria.
Their results remain bounded observations until a reviewed specification, ADR,
claim, and evidence path adopt them.

## Security model

- [Threat model](threat-model.md) defines protected assets, attackers, trusted
  components, enforced boundaries, and exclusions.
- [Receipt semantics](receipt-semantics.md) defines canonical receipt bytes,
  independent derivation, identity meaning, and limits.

The threat model constrains every security claim. An implementation detail MUST
NOT silently broaden or narrow it.

## Architecture decisions

- [ADR index](adr/README.md)
- [ADR 0001: Linux enforcement boundary](adr/0001-linux-enforcement-boundary.md)
- [ADR 0002: External receipt commitment](adr/0002-external-receipt-commitment.md)
- [ADR 0003: Deterministic CBOR for committed wire objects](adr/0003-deterministic-cbor-wire-objects.md)

Accepted trust-boundary and architecture decisions belong in `docs/adr/`.
ADRs explain why a decision exists and what would justify revisiting it.

## Proofbound feedback

- [Feedback process and index](proofbound-feedback/README.md)
- [Feedback item template](proofbound-feedback/TEMPLATE.md)

The feedback directory records concrete Runtime discoveries that need generic
Proofbound support. It is a handoff record, not a duplicate Proofbound
specification.

## Where new documents belong

| Material | Location |
| --- | --- |
| Cross-roadmap dependency and decision order | `docs/product-roadmap-execution-order.md` |
| Pre-planned product candidate with an evidence gate | `docs/product-roadmap-3-candidates.md` and `docs/roadmap-3/` |
| Normative Runtime behavior | `docs/specs/` |
| Accepted architecture or trust-boundary decision | `docs/adr/` |
| Runtime threat or trust analysis | `docs/threat-model.md` or a linked security document |
| Generic requirement discovered for Proofbound | `docs/proofbound-feedback/` |
| User procedure | `docs/guides/` after the first executable workflow exists |
| Pre-registered investigation and results | `docs/experiments/` after an experiment protocol exists |

Do not present notes, experiments, tests, or feedback items as normative product
behavior. Promote an accepted result to a specification or ADR when its meaning
must become durable.
