# Product development checklist

- **Status:** active execution ledger
- **Last updated:** 2026-09-15T13:02:02+01:00 (Europe/London, BST)
- **Runtime baseline:** trace-startup merge `9395050`; exact-main Verify run
  `34962882198` is in progress
- **Active implementation wave:** the coupled setup adapter is at admitted-main
  head `8ab66e5` in PR 15 and hosted run `34964466007` is in progress. The live
  event-and-drain correction at `af9f77d` passed independent exact-head review.
  Its approval-only commit, admitted-stack replay, hosted gate, and merge remain
  pending.
- **Following implementation batch:** architecture-qualified syscall decoding
  and bounded operand capture are implemented locally as `PBR-OBSERVER-025`.
  Exact review, hosted admission, artifact mapping, and native attacks remain
  open.
- **Lifecycle:** prelaunch with zero external users

This checklist is the current operational view of the development path in the
[roadmap execution order](product-roadmap-execution-order.md). Specifications,
ADRs, threat-model records, and claim manifests remain authoritative for
meaning. This file records only execution state and the next dependency.

Update the timestamp, exact source identity, review subject, hosted run, and
merge identity whenever an item changes state. Check an item only after its
stated evidence exists. Do not check external adoption, registry publication,
or demand gates from a maintainer-controlled simulation.

## Current objective

Make one networked coding or artifact-producing agent easy to install, easy to
plan, constrained to one authenticated service, and independently verifiable
from exact release and execution identities.

```text
RT-7 distribution
        |
        v
RT-8 diagnostic plan drafting
        |
        v
RT-5 one authenticated service
        |
        v
Reference LLM workload
        |
        v
RT-9 multiple authenticated services
```

RT-11 design can proceed beside this path. RT-10, RT-12, RT-13, and Roadmap 3
implementation remain behind their recorded demand gates.

## Phase 0: finish RT-7 distribution

### Already admitted

- [x] Define the prelaunch current-distribution contract in Specification 0014.
- [x] Make `proofbound-runtime-verify` independently packageable with no
  Runtime workspace dependency.
- [x] Build the verifier package twice, compare exact bytes, inspect its closed
  source payload, and dogfood it from an unrelated temporary consumer.
- [x] Retain verifier and SDK package identities in release provenance.
- [x] Publish one immutable Proofbound tool-bundle release for source
  `9512469` with seven exact assets.
- [x] Pin, validate, install, and dogfood that bundle in Runtime.
- [x] Merge the isolated Runtime dogfood as `f2a06de` and pass exact-main
  Verify run `34908515545`.

### Active protected-path cutover

- [x] Replace the protected CI source-build job with direct installation of the
  exact public `linux-x86_64` bundle in every fresh-evidence shard.
- [x] Replace release source builds with the matching exact public bundle for
  `x86_64` and `aarch64`.
- [x] Remove the redundant cross-job Proofbound tool artifact and obsolete
  locally recorded five-binary checksum file.
- [x] Require all seven installed Proofbound executables before evidence or
  release production starts.
- [x] Preserve the GitHub, TLS, Python, digest, installer, runner, process, and
  filesystem premises in the claim closure.
- [x] Make every focused workflow, consumer, documentation, and claim-inventory
  test pass without a local Rust, Lean, Kani, or native build.
- [x] Commit the implementation and isolated review correction as an unsigned
  exact review series ending at `9d0cbb2`.
- [x] Obtain an independent exact-head review with an explicit verdict.
- [x] Record and endorse the non-author exact-subject approval in a separate
  unsigned documentation-only commit without changing the reviewed production
  subject.
- [x] Push once and pass the complete hosted exact-head Verify gate at
  `515fcbc` in run `34915891330`.
- [x] Merge unsigned as `4a0cfdb` and pass exact-main Verify run `34918706960`.
- [ ] Close `PBR-DISTRIBUTION-016` only after the review and hosted evidence
  above exist.

Review history:

- Exact base `f2a06de`, subject `ea5d8a2`: `REQUEST CHANGES`. The registered
  checker named the release-production cutover but did not invoke its release
  workflow falsifier. The required fix is isolated to adding
  `tools.ci.test_release_workflow` to that checker before re-review.
- Exact base `f2a06de`, corrected subject `9d0cbb2`: `APPROVE`. Independent
  reviewer task `/root/review_runtime_pr4` found no remaining blockers and
  confirmed the complete cutover properties after the checker correction.
  The maintainer endorses this exact-subject verdict. It records independent
  model review, not independent human review, and does not replace the pending
  hosted execution evidence.

### Package publication and consumer closure

- [x] Select the smallest current public set: independent verifier, Runtime
  SDK, Python SDK, and TypeScript SDK. Do not publish internal crates without a
  demonstrated consumer.
- [x] Add opt-in registry publication only to the exact approved release
  workflow, behind the protected `package-publish` environment.
- [ ] Publish from one exact approved `main` revision using registry
  credentials supplied through the release environment.
- [ ] Retrieve each registry artifact anonymously and compare its exact bytes
  or registered package identity with the approved artifact.
- [ ] Exercise each package from an unrelated consumer repository or other
  independently controlled consumer environment.
- [ ] Publish the machine-readable current-integration manifest and human
  rendering with exact Runtime, Proofbound, package, schema, verifier,
  platform, and optional integration-profile identities.
- [ ] Record registry and consumer observations without interpreting a checksum
  or package label as publisher authentication.

**Phase 0 exit:** selected packages are publicly consumable from exact
identities, unrelated consumption succeeds, and the current-integration
manifest describes the supported tuple.

## Phase 1: implement RT-8 diagnostic plan drafting

### Existing foundation

- [x] Ship the bounded static executable scaffold.
- [x] Ship typed prelaunch diagnostics that do not claim to explain kernel
  denials.
- [x] Define the cross-project provenance separation for human, static,
  diagnostic, Capsec, and platform-required observations.

### Remaining claim waves

- [x] Accept an ADR and specification for a distinct diagnostic execution
  profile and observer mechanism.
- [x] Define closed diagnostic-profile, observation, provenance, and failure
  types without changing production-receipt meaning.
- [ ] Keep observer implementation out of the production launcher path.
- [x] Put Linux trace-startup code behind an empty-by-default feature selected
  only by the separate diagnostic Linux crate; keep raw calls in `sys.rs`.
- [x] Keep the pure diagnostic artifact producer out of the production CLI and
  launcher dependency graphs.
- [x] Define a pure typed observer protocol that cannot release target code
  before attachment, boundary acknowledgement, and exact trace options.
- [x] Complete review and hosted admission of the identity-bound supervisor
  exec release that lets the diagnostic adapter stop the acknowledged launcher
  and install exact trace options before target exec. Source implementation and
  registered falsifiers passed exact-head review and hosted verification, then
  merged unsigned as `3557cc9`. Exact-main Verify run `34956564102` passed.
- [ ] Complete independent review and hosted admission of the non-copy Linux
  trace-startup typestates. Source implementation and bounded contract checks
  are replayed on exact main `3557cc9`. The earlier exact review required the
  session channel, request, acknowledgement, and release to share one private
  owner and required complete evidence and identity source closure. Its next
  review found a public mutable-child replacement escape, a missing falsifier,
  and incomplete checker-assumption language. The following review found that
  the ownership-only private child field would fail the warnings-as-errors
  gate. Those corrections are retained; refreshed review, hosted admission,
  and native effect evidence remain open.
- [ ] Couple the approved trace-startup typestates to the pure observer protocol
  in the separate diagnostic adapter. Validate bounds before spawn, move one
  private pair after the exact initial stop, advance pure states only in the
  declared effect order, and expose neither raw trace states nor mutable protocol
  access. The initial exact review at `4ea747f` required stronger falsifiers for
  private ownership and public escape paths, exact stopped-child identity flow,
  and exact installed-option flow. The correction carries Linux-installed bits
  through the closed pure validator and strengthens the registered source
  checks. The first correction review then required a closed public API
  allowlist and exact accessor bodies. The second correction adds both; exact
  review found one remaining trait-implementation and public-enum gap. The third
  correction exact-allowlists every implementation header and method, fixes the
  error variants, and rejects source macros. Its review found one remaining
  module-source redirection path. The fourth correction fixes the complete crate
  root and rejects nested modules. Its review found a remaining Cargo workspace
  dependency redirection path. The fifth correction pins the relevant member,
  dependency, target, and pure module-selection sources. Its review found
  conditional path redirection at both dependency crate roots. The sixth
  correction byte-pins those roots and registers the Linux root. Independent
  re-review approved exact source head `d0c2520`; the approval-only record and
  hosted verification remain open.
- [ ] Admit the active trace event source. The implementation polls only its
  private exact tracee set, registers ptrace children before parent resume,
  pairs syscall entry and exit information across exec events, reconciles
  leader and non-leader exec, and
  uses validated pidfds for identity-stable termination. Its source claim
  explicitly leaves the effectful process-map bound, Linux effects, adapter
  event coupling, and native attack evidence open. The first independent review
  found incorrect syscall-pair retention and non-leader exec identity checks;
  exact re-review approved corrected head `c20f6e3`. Hosted verification remains
  open.
- [ ] Admit live event-and-drain coupling. Exact source `af9f77d` passed
  independent review with an explicit `APPROVE`. The adapter passes the validated
  lifetime process bound to the effectful trace before release, consumes each
  trace event into the same pure protocol, retains overflow identities outside
  the bounded ledger, and requires a successful exact drain before the pure
  tree-empty acknowledgement. Its first exact review found a false successful
  drain after child-registration failure, weak load-bearing source falsifiers,
  three missing reciprocal assumption links, broken unsupported-platform
  compilation paths, and transferred approval language. The combined correction
  permanently blocks publication after an unreconciled tree, byte-pins the
  load-bearing bodies with five mutation classes, restores typed unsupported
  paths, closes assumption links, and marks every changed exact subject pending.
  Approval-only recording, admitted-stack replay, and hosted admission remain
  open.
- [ ] Admit architecture-qualified syscall decoding and bounded operand capture.
  The current source has separate x86_64 and aarch64 tables, rejects x32 and
  unsupported registered forms, captures path and socket-address bytes before
  resume under three independent limits, completes partial reads or fails, and
  never reads payload bytes. Exact review and hosted admission remain open.
- [x] Keep natural exact-capacity completion distinct from overflow, terminate
  on attempted overflow, and require terminal waits plus a separate tree-empty
  acknowledgement before publication.
- [x] Produce a distinct diagnostic receipt that is always non-reusable from
  validated, bounded observations.
- [x] Make the independent verifier, composer, and acceptance policy reject a
  diagnostic receipt for production reuse with an exact typed reason.
- [x] Convert validated file and execution observations into
  provenance-tagged draft entries without granting plan authority.
- [x] Keep network, environment, write roots, and resource limits as explicit
  human decisions.
- [x] Accept optional Capsec observations only when their schema, source,
  analyzer, and report identities match; retain missing or incomplete coverage
  visibly.
- [ ] Run the adversarial corpus for stale source, symlink redirection,
  observation-sensitive behavior, missing events, and attempted provenance
  relabeling.
- [ ] Demonstrate one maintained dynamic workload using every available
  provenance class.
- [ ] Complete independent review, exact-head hosted evidence, unsigned merge,
  and exact-main verification.

**Phase 1 exit:** a developer can produce and complete a useful dynamic plan
draft, while no diagnostic output can become reusable production evidence.

## Phase 2: implement Roadmap 1 RT-5

### Accepted decision

- [x] Complete the four-mechanism native experiment and measurement series.
- [x] Accept the connector-owned authenticated service session in ADR 0004.
- [x] Reject port-only or address-only policy as proof of remote service
  identity.

### Wave A: closed contracts and pure decisions

- [ ] Specify one authenticated-service plan, authority, policy, receipt,
  verifier, composition, acceptance, and error contract.
- [ ] Identify resolver, address-attempt order, TLS policy, service, connector,
  local channel, credential source, byte limits, and lifecycle roles.
- [ ] Add strict domain types, canonical encodings, negative vectors, and
  downgrade and substitution attacks.
- [ ] Model and prove the selected pure non-amplification, identity, and state
  transition properties in Lean where the subject is tractable.
- [ ] Link selected pure Rust decisions to their formal models without
  presenting effectful network behavior as a theorem.

### Wave B: connector and Linux boundary

- [ ] Implement the minimal connector-owned authenticated session.
- [ ] Transfer only the declared local channel to the child.
- [ ] Deny direct child IPv4, IPv6, raw, packet, resolver, proxy, Unix-socket,
  inherited-descriptor, and `io_uring` bypasses that fall within the claim.
- [ ] Bound request count, response count, bytes, time, connection lifecycle,
  and connector cleanup.
- [ ] Fail closed before child execution when identity or mechanism setup is
  incomplete.

### Wave C: receipts and evidence

- [ ] Record the exact service and connector identities without recording
  secret credential values.
- [ ] Independently verify the service-session receipt fields and lifecycle.
- [ ] Preserve all premises through composition and consumer acceptance.
- [ ] Run the complete native positive and attack corpus on both supported
  architectures.
- [ ] Complete independent review, exact-head hosted evidence, unsigned merge,
  and exact-main verification for each claim-sized wave.

**Phase 2 exit:** one maintained client reaches one authenticated service while
direct child networking remains denied and the receipt records the exact
bounded service session.

## Phase 3: validate the reference LLM workload

- [ ] Select one real coding or artifact-producing LLM client with one service.
- [ ] Freeze its exact source, dependency, executable, service, and input
  identities.
- [ ] Run it through RT-8 plan drafting and require human completion.
- [ ] Execute it through RT-5 with a fresh output root and bounded resources.
- [ ] Independently verify the Runtime receipt and apply an explicit acceptance
  policy.
- [ ] Measure time to first verified result, plan effort, unexplained denials,
  credential exposure, setup cost, authority breadth, verification time, and
  integration effort.
- [ ] Record whether an unrelated adopter will repeat the workflow. Do not
  infer adoption from a maintainer-controlled demonstration.
- [ ] Use the observed result to accept, revise, or reject the next candidate
  features.

**Phase 3 exit:** one real agent workload produces a useful output and a
consumer-verifiable execution chain under one authenticated service profile.

## Phase 4: implement RT-9 only after RT-5

- [ ] Replace the single service with a typed non-empty declared service set.
- [ ] Preserve a distinct Runtime service identity for each member.
- [ ] Map optional Auths action identities to Runtime service identities only
  through an exact reviewed integration profile.
- [ ] Reject missing, additional, ambiguous, redirected, or substituted
  services.
- [ ] Reject cross-service confusion, decision replay, action substitution, and
  service substitution with exact typed reasons.
- [ ] Preserve native Auths and Runtime receipt meaning and verifier ownership.
- [ ] Demonstrate one maintained agent using at least two declared services.
- [ ] Complete independent review, hosted evidence on both architectures,
  unsigned merge, and exact-main verification.

**Phase 4 exit:** the agent can reach exactly its declared authenticated
service set and every registered cross-service attack fails closed.

## Parallel decision track: RT-11

- [ ] Draft the signing and transparency ADR while Phases 0 through 2 proceed.
- [ ] Separate principal, workload, product, release, execution-service,
  receipt-log, and witness identities.
- [ ] Decide which identity signs which exact bytes and which verifier resolves
  the identity.
- [ ] Define custody, rotation, revocation, offline verification, and consumer
  pinning rules.
- [ ] Compare detached envelope and transparency statement options without
  changing native receipt bytes.
- [ ] State explicitly that signatures authenticate an origin under policy;
  they do not prove execution, correctness, or containment.
- [ ] Accept or reject the ADR through independent review.

## Roadmap 1 residual closure

- [x] RT-1 memory and swap containment is merged and admitted.
- [x] RT-4 network mechanism research and decision are complete.
- [x] RT-6 CPU and output-capacity decisions and performance baseline are
  complete.
- [ ] RT-0: complete the retained two-week latency and cache-retention decision
  after its observation window closes. **Time-gated, not implementation work.**
- [ ] RT-2: observe the exact released acceptor and obtain unrelated first-party
  Action dogfood. **External release/adoption evidence.**
- [ ] RT-3: close package-registry and unrelated-consumer observations through
  Phase 0 above.
- [ ] RT-5: close production authenticated networking through Phase 2 above.

## Intentionally gated work

These unchecked items are not on the active critical path. Their current
closed state is the correct engineering result until their gate becomes true.

- [ ] RT-10 guest host profile: open implementation only when a macOS or
  Windows workflow justifies the hypervisor, guest image, transport, and host
  orchestration trusted surface.
- [ ] RT-12 content-addressed receipt log: open implementation only after RT-11
  is accepted and two independent retention consumers exist.
- [ ] RT-13 execution service: open implementation only after one named adopter
  demonstrates repeated invocation demand and setup cost dominates.
- [ ] RT-13.5 multi-tenancy: decide separately only after the single-tenant
  service is measured.
- [ ] RT-14 credential custody: preserve interface discovery; implement only if
  the reference workload shows RT-5 credential isolation is insufficient.
- [ ] RT-15 operation-scoped mediation: implement only for a demonstrated
  consequential action requiring authority narrower than a service session.
- [ ] RT-16 organizational policy lifecycle: implement only after two
  organizational adopters expose the same lifecycle requirement.
- [ ] RT-17 integration-profile registry: implement only after RT-7, RT-11, and
  two maintained profiles exist.
- [ ] RT-18 multi-language capability analysis: implement analyzers only after
  RT-8 and one maintained workload per selected language exist.
- [ ] RT-19 evidence discovery and export: implement only after RT-12 and two
  retention consumers exist.
- [ ] RT-20 host and fleet identity: keep as research until a named fleet
  policy consumer requires it.

## Fast claim-wave procedure

Use this sequence for each security-relevant merge:

- [ ] Register or update the plain-language claim, exact subject, source
  closure, premises, exclusions, evidence, and falsifiers before implementation.
- [ ] Implement the smallest typed production slice.
- [ ] Run only focused non-build checks locally while another agent owns local
  build state.
- [ ] Create one unsigned implementation commit as the exact review subject.
- [ ] Obtain an independent review of that exact subject before the first
  expensive hosted run.
- [ ] Fix each blocker in a separate unsigned commit and repeat exact-head
  review.
- [ ] Add a non-author approval envelope only after an explicit `APPROVE`.
- [ ] Push the reviewed series once and run the complete protected hosted gate.
- [ ] Merge unsigned only when that exact reviewed series passes.
- [ ] Run and record exact-main verification.
- [ ] Update this timestamp and every affected roadmap, claim, evidence, and
  feedback status without strengthening the admitted result.

## Prelaunch scope guard

- [x] Treat package version fields as required tooling metadata only.
- [x] Keep closed schema identifiers and source, artifact, verifier, workflow,
  and integration identities exact.
- [ ] Do not add compatibility adapters, migration tools, deprecation windows,
  long-term-support policy, or coordinated cross-project version numbering.
- [ ] Do not broaden the active product path with a hosted service, universal
  receipt, shared semantic core, or speculative multi-tenancy.
