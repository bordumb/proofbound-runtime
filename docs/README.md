# Documentation

This directory is the entry point for Proofbound Runtime specifications,
security boundaries, architecture decisions, and cross-repository feedback.
The document type determines its authority.

## Delivery tracking

- [Implementation plan](implementation-plan.md) records the ordered work queue,
  commit boundaries, and release completion criteria. It does not replace the
  normative specification or claim ledger.
- [Assurance plan](assurance-plan.md) records target tiers, source closures, and
  evidence paths. Claim manifests remain authoritative for current status.

## Normative specification

- [Specification 0001](specs/0001_initial_spec.md) defines the initial product,
  architecture, repository layout, development standards, and milestones.

Normative product or wire behavior belongs in `docs/specs/`. A specification
revision requires explicit review because it can change claim meaning.

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
