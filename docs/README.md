# Documentation

This directory is the entry point for Proofbound Runtime specifications,
security boundaries, architecture decisions, and cross-repository feedback.
The document type determines its authority.

## Delivery tracking

- [Product and delivery roadmap](product-roadmap.md) records the ordered
  post-0.1 product, workflow, cross-repository, and assurance work. It does not
  replace a specification, ADR, or claim manifest.
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
| Normative Runtime behavior | `docs/specs/` |
| Accepted architecture or trust-boundary decision | `docs/adr/` |
| Runtime threat or trust analysis | `docs/threat-model.md` or a linked security document |
| Generic requirement discovered for Proofbound | `docs/proofbound-feedback/` |
| User procedure | `docs/guides/` after the first executable workflow exists |
| Pre-registered investigation and results | `docs/experiments/` after an experiment protocol exists |

Do not present notes, experiments, tests, or feedback items as normative product
behavior. Promote an accepted result to a specification or ADR when its meaning
must become durable.
