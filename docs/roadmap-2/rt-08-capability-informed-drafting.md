# RT-8 integration record: capability-informed drafting

**Status:** static scaffold, prelaunch diagnostics, diagnostic contracts,
closed schemas, source-level production non-reuse, the pure diagnostic artifact
producer, and the pure observer protocol are merged through Runtime `b04382d`.
Exact-main Verify run `34946613122` passed. The identity-bound launcher
exec-release prerequisite for race-free trace setup merged as `3557cc9` after
exact-head hosted verification; exact-main run `34956564102` passed.
The separate feature-gated Linux trace-startup source merged as `9395050` and
exact-main run `34962882198` passed. The adapter that privately couples the
effectful and pure setup states passed hosted run `34964466007`, merged as
`d34eab1`, and has exact-main run `34969409215` in progress. The active-trace
admitted-main replay at `1db68a6` passed independent review; approval-only head
`c4b88c1` is in hosted verification. Event-and-drain source `af9f77d` and
restacked head `45b1c91` passed independent review. Hosted run `34972072843`
rejected two warnings-as-errors in the shared trace source and was cancelled.
The lint-only correction and refreshed exact-body checker require narrow exact
re-review; hosted admission and merge remain open. The wave passes the
validated process bound into the effectful trace, consumes complete events into
the matching pure protocol, permanently rejects an unreconciled process tree,
and makes successful effectful drain reconciliation precede pure tree-empty
acknowledgement. Its first exact review requested five corrections; the combined
correction closed them and received an explicit `APPROVE`.
Decoding, command integration, the native attack corpus, and release binding
remain open.

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

- Capsec reports are optional and usable only when their schema, source,
  analyzer, and report identities match the selected integration profile.
- Runtime parses Capsec output outside the pure authority core.
- A report can suggest review items. It cannot add plan authority.
- Runtime displays requirements absent from the plan, plan authority absent
  from requirements, and observed effects absent from requirements.
- Unknown Capsec schema identities, stale source identities, and mismatched
  analyzer or report identities remain visible and unusable for automated
  comparison.
- Network, environment, write-root, and resource-limit choices remain human
  decisions.
- The observer is a separate ptrace-based diagnostic executable. Production
  Runtime and launcher artifacts contain no observer entry point.
- Diagnostic receipts are JSON diagnostic objects and are never accepted by
  the production verifier, composer, or acceptance policy.
- The pure producer accepts validated observations. It cannot observe a
  process, install a boundary, or add production authority.
- One aggregate producer owns receipt and plan-draft construction. It streams
  both canonical objects through the declared output bound instead of
  materializing an unbounded complete JSON tree.
- A pure observer protocol orders attachment, boundary acknowledgement, exact
  trace options, target release, bounded collection, termination, drain, and
  publication eligibility before the Linux adapter exists. Terminated runs
  require a separate tree-empty acknowledgement before publication.
- The launcher waits for an identity-bound supervisor exec release after it
  acknowledges the production boundary. The diagnostic supervisor can stop
  that acknowledged launcher, install exact trace options, and then send the
  release without racing target exec.
- Only the separate Linux diagnostic crate enables the observer feature. The
  production CLI retains the Linux boundary crate's empty default feature set,
  and raw ptrace calls remain in the existing syscall module.
- The trace-startup session revalidates and retains one identified launcher,
  creates and retains one launcher channel and exact install request, receives
  the matching acknowledgement internally, and sends the identity-bound
  release through that same channel. Public transitions do not accept
  substitute commands, protocol values, or channels, and public states expose
  no mutable child handle that could replace the guarded process.
- The separate diagnostic adapter validates observation bounds before spawn.
  After the exact initial trace stop, each non-copy adapter state privately
  couples one trace typestate to the same pure protocol, seeded from that exact
  stopped process. Boundary success precedes its pure record. Exact option bits
  flow from the successful Linux installation through the closed pure validator
  before option readiness advances; pure authorization precedes target release.
  Public owner fields, raw trace states, and mutable protocol access are absent.
- The active trace polls only its private known tracee set. It registers a
  ptrace-created child and identity-stable thread-group handle before its
  stopped parent resumes, pairs syscall entry and exit information across exec
  events, reconciles leader and non-leader exec identity replacement, and holds
  each returned nonterminal event stopped until the next request. Observation
  failure requires drain. Termination uses retained pidfds and cannot target a
  reused numeric PID.
- The same consuming adapter state maps each live event into its matching pure
  transition. It passes the validated lifetime process bound to the effectful
  trace before release, retains overflow identities outside the bounded pure
  ledger, and exposes only a drain state after any failure or bound directive.
  A successful effectful empty-tree report and an empty overflow set must both
  precede pure tree-drain acknowledgement and publication selection.
  Process-creation message, identity, capacity, thread-group, or handle failures
  permanently prevent a successful effectful empty-tree report.
- Automatic candidates require an explicit normalized project or runtime
  scope. System, home, and configured temporary roots remain open review
  items.

## Additional falsifiers

- A Capsec report for different source bytes is rejected as a comparison input.
- A report that names a broad filesystem root cannot broaden a draft.
- A missing Capsec report does not weaken Runtime's production boundary.
- A diagnostic observation cannot be relabeled as a Capsec declaration.

## Integration exit

RT-8 is platform-ready when one maintained dynamic workload displays all
available provenance classes, requires human completion, and produces no
receipt that any production verifier or acceptance policy can reuse.
