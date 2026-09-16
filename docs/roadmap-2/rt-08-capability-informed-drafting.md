# RT-8 integration record: capability-informed drafting

**Status:** static scaffold, prelaunch diagnostics, diagnostic contracts,
closed schemas, source-level production non-reuse, the pure diagnostic artifact
producer, and the pure observer protocol are admitted. The identity-bound launcher
exec-release prerequisite for race-free trace setup merged as `3557cc9` after
exact-head hosted verification; exact-main run `34956564102` passed.
The separate feature-gated Linux trace-startup source merged as `9395050` and
exact-main run `34962882198` passed. The coupled adapter passed hosted run
`34964466007`, merged as `d34eab1`, and passed exact-main run `34969409215`.
Active-trace approval-only head `c4b88c1` is not admitted alone: run
`34970508987` failed only on the two Rust lints corrected by the following
reviewed batch.
The event-and-drain correction at `af9f77d` and its restacked exact head
`45b1c91` passed independent review. Its behavior-preserving Rust-lint
correction `a3f56b5` also passed exact review. Approval-only head `9f82afa`
passed replacement Verify run `34973401808`, and the combined active event and
drain series merged unsigned as Runtime `b2cb4b9`. Exact-main run `34978365970`
failed before required lanes started in an unrelated network-experiment
ready-file check. The merged source passes the validated process
bound into the effectful trace, consumes complete events into the matching
pure protocol, permanently
rejects an unreconciled process tree, and makes successful effectful drain
reconciliation precede pure tree-empty acknowledgement. The following decoder
identity passed exact-head review and hosted verification and is merged on
current main; exact-main admission run `34997195939` passed.
The architecture-qualified syscall decoder and bounded entry-time operand
capture are implemented locally under `PBR-OBSERVER-025`. The exact aggregate
subject, compiler and crate-selection closure, adapter build evidence, and all
load-bearing decoder bodies are registered in response to independent review.
The raw syscall-information parser also rejects nonzero reserved or flags
fields and any non-exact operation size, so a future UAPI extension fails
closed. Independently approved source `5d82dcd` and approval-only head
`858bfb9` reached hosted run `34979197795`; the formal, native, and all
fresh-evidence lanes passed, but the Rust lane rejected a large private enum.
Correction `5d479bd` uses the existing optional event state directly, adds no
per-event allocation, and refreshes the exact-body guards. Independent
re-review approved exact head `b027ddd`; approval-only head `4f66fc4` then
reached replacement run `34988148920`. Preflight, formal, both native lanes,
and all non-rate-limited fresh-evidence lanes passed. The receipt lane was
blocked by anonymous GitHub API rate exhaustion, and Rust lint found a separate
large public adapter observation enum. The current correction boxes only the
single event that selects terminal drain; normal trace waits and continuing
events receive no new boxing allocation. Independent exact-head re-review
approved head `fbd2d66`; approval-only head `db95947` passed complete
exact-head run `34992273744` and merged unsigned as `4783896`. Exact-main run
`34997195939` passed. The following `PBR-OBSERVER-026` wave maps the complete
registered trace events into closed diagnostic artifact events without
inventing object resolution. It passed exact-head Verify run `35018691928` and
merged unsigned as `a89b92d`; exact-main run `35025687602` passed for that
merge. The dependent `PBR-OBSERVER-027`
source and evidence start independent bounded stdout and stderr drains before
the spawned trace state returns, continue draining after a retained prefix is
full, and gate publication on fixed-deadline terminal collection that cancels
and fails closed when either reader withholds completion. They also await independent
review and hosted admission. Cgroup and wall-time coupling, object resolution,
command integration, the native attack corpus, and release binding remain open.

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
- The active trace chooses a closed x86_64 or aarch64 decoder from the Linux
  audit architecture before it interprets a syscall number. It rejects x32 and
  unsupported registered forms. It captures bounded path and socket-address
  operands before resume, completes partial read-only tracee-memory reads or
  fails, and retains only the `sendto` payload length, never payload bytes.
- The separate event mapper assigns contiguous sequence values and preserves
  the process, audit architecture, syscall class, bounded entry operands, and
  consistent result or Linux error. It emits an exec event only from a retained
  `execve` or `execveat` entry. Lifecycle-only observations do not become
  syscall records. Every mapped object remains `unresolved`; an unknown
  architecture, malformed result, invalid exec entry, non-UTF-8 version 1 path,
  artifact inconsistency, or sequence overflow fails closed.
- Automatic candidates require an explicit normalized project or runtime
  scope. System, home, and configured temporary roots remain open review
  items.

## Additional falsifiers

- A Capsec report for different source bytes is rejected as a comparison input.
- A report that names a broad filesystem root cannot broaden a draft.
- A missing Capsec report does not weaken Runtime's production boundary.
- A diagnostic observation cannot be relabeled as a Capsec declaration.

## Remaining implementation order

Complete RT-8 in these claim-sized waves:

1. `PBR-OBSERVER-026` is admitted on `a89b92d`. It maps complete trace events
   into unresolved diagnostic artifact events.
2. Admit `PBR-OBSERVER-027`, which gives the trace session independent bounded,
   cancellable, nonblocking stdout and stderr drains. Continue reading after
   either retained prefix is full, collect both streams only after terminal tree
   handling, and make pipe setup, reader startup, reads, or joins fail closed.
   This must
   precede the command because unread launcher pipes can otherwise block a
   target before the observer reaches completion.
3. Retain the same stopped child, place it in the prepared cgroup before target
   release, apply one absolute plan wall-time limit through observation and
   drain, finish resource observations after the tree is empty, and make every
   stream or cleanup failure block publication.
4. Resolve a successful descriptor or executable only from the still-stopped
   tracee. Resolve a denied path only as a bounded stable candidate with before
   and after identities. Preserve races and unsupported forms as explicit gaps.
5. Add the separate `pbr-diagnose` command. Reuse the seed plan's exact
   production authority, publish neither output before release, and publish the
   diagnostic receipt and draft with the existing no-replace durability model.
6. Run the registered native attack corpus on x86_64 and aarch64, including
   pipe saturation, wall-time expiry, process-tree races, observation-sensitive
   behavior, path drift, malformed operands, and publication interruption.
7. Add the exact diagnostic executable to release provenance and artifact
   inspection. Finish with one maintained dynamic workload that displays every
   available provenance class, requires human completion, and produces no
   reusable production evidence.

Do not merge waves 2 through 7 into one review subject. Each wave changes a
different security boundary and must retain its own exact-head review and
hosted admission before the next dependent wave is called complete.

## Integration exit

RT-8 is platform-ready when one maintained dynamic workload displays all
available provenance classes, requires human completion, and produces no
receipt that any production verifier or acceptance policy can reuse.
