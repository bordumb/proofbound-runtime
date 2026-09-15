# RT-8 integration record: capability-informed drafting

**Status:** static scaffold and prelaunch diagnostics merged; diagnostic
contracts, closed schemas, source-level production non-reuse, and the pure
diagnostic artifact producer are implemented across the stacked RT-8 branches.
Hosted admission is pending. The live ptrace observer, command integration,
native attack corpus, and release binding remain open.

**Primary owner:** Proofbound Runtime

**Integration owner:** Capsec owns the meaning of its source observations.

**Roadmap:** [Epic RT-8](../product-roadmap-2.md#6-epic-rt-8-trace-assisted-plan-drafting)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

**Diagnostic contract:**
[Specification 0015](../specs/0015_diagnostic_execution_and_plan_drafting.md)

**Observer decision:**
[ADR 0008](../adr/0008-separate-ptrace-diagnostic-observer.md)

## Product result

A developer can compare source-level capability requirements, static executable
closure, and one diagnostic runtime path while preparing a Runtime plan. The
developer still chooses the authority.

## Provenance classes

The draft keeps these inputs separate:

- `human-authored`;
- `static-executable-closure`;
- `diagnostic-runtime-observation`;
- `capsec-source-observation`; and
- `platform-required-closure`.

The names are integration vocabulary. The accepted Runtime specification must
select the final closed wire values. Specification 0015 now selects those
values without making a draft an authority object.

## Required behavior

- Capsec reports are optional, content-identified, and bound to exact source.
- Runtime parses Capsec output outside the pure authority core.
- A report can suggest review items. It cannot add plan authority.
- Runtime displays requirements absent from the plan, plan authority absent
  from requirements, and observed effects absent from requirements.
- Unknown Capsec schema identities and stale source identities remain visible and
  unusable for automated comparison.
- Network, environment, write-root, and resource-limit choices remain human
  decisions.
- The observer is a separate ptrace-based diagnostic executable. Production
  Runtime and launcher artifacts contain no observer entry point.
- Diagnostic receipts are JSON diagnostic objects and are never accepted by
  the production verifier, composer, or acceptance policy.
- The pure producer accepts validated observations. It cannot observe a
  process, install a boundary, or add production authority.

## Additional falsifiers

- A Capsec report for different source bytes is rejected as a comparison input.
- A report that names a broad filesystem root cannot broaden a draft.
- A missing Capsec report does not weaken Runtime's production boundary.
- A diagnostic observation cannot be relabeled as a Capsec declaration.

## Integration exit

RT-8 is platform-ready when one maintained dynamic workload displays all
available provenance classes, requires human completion, and produces no
receipt that any production verifier or acceptance policy can reuse.
