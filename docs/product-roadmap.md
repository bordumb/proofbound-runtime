# Proofbound Runtime product and delivery roadmap

- **Status:** execution in progress
- **Date:** 2026-09-09
- **Runtime baseline:** `0b83bfe` (`v0.1.0` is `c78e189`)
- **Proofbound baseline consumed by Runtime:** `70af5e6`
- **Planning horizon:** post-0.1 product and assurance waves

This roadmap turns the version 0.1 implementation into an adoptable execution
gateway without weakening its assurance boundary. It is not a normative
specification. A change to authority, receipt meaning, public schemas, the
trusted computing base, or repository structure still requires the applicable
specification, threat-model, ADR, claim, and evidence changes before production
code.

The roadmap uses these sources:

- [Specification 0001](specs/0001_initial_spec.md), including its explicit
  deferral of network allow-lists;
- [Specification 0002](specs/0002_cli_surface.md) and
  [Specification 0003](specs/0003_release_receipt_composition.md);
- the [threat model](threat-model.md),
  [assurance plan](assurance-plan.md), and
  [receipt semantics](receipt-semantics.md);
- [ADR 0001](adr/0001-linux-enforcement-boundary.md) and
  [ADR 0002](adr/0002-external-receipt-commitment.md);
- every record in [Proofbound feedback](proofbound-feedback/README.md);
- the Runtime and Proofbound source trees, commit histories, GitHub pull
  requests, branch controls, and representative CI and release runs; and
- the external product critique reproduced in the planning request.

### Execution checkpoint

As of 2026-09-10, Order 0 is implemented on the roadmap branch, the version
0.1 installation path and host-prerequisite explanations are implemented and
locally verified, and the two measured upstream workflow observations are
recorded. The read-only host preflight, its separate Proofbound claim, and a
deterministic maintained example source bundle are also implemented. Both are
wired into the required native jobs; their final installation-slice gate is a
green hosted run on both architectures followed by reviewed publication of the
example bundle. Neither is described as part of the existing `v0.1.0` binary
release.

The local bounded-domain consistency guard required before a new resource
claim wave is implemented at `9154c7f`. It fails the ordinary workspace test
stage when a claim, cited bounded evidence unit, and model-check manifest do
not declare the same closed domain. This satisfies the roadmap's temporary
local prerequisite for memory contract work. It does not resolve PBF-0007 or
permit Runtime to describe the generic Proofbound compiler and verifier as
fixed.

RT-1.1 contract work has started at `d24a1c7` with a draft version 2 memory and
swap profile. The draft fixes the intended schema transition, cgroup controls,
terminal observations, outcome separation, historical receipt behavior, and
native falsifier inventory. It is not yet an accepted production contract.
Memory implementation remains paused until review resolves the draft's
explicit decisions and the upstream consolidation boundary is satisfied.

RT-4.1 is pre-registered at `946c457`. Experiment 0001 freezes the first HTTPS
workload, controlled DNS/TLS fixture, four candidate mechanisms, common attack
matrix, exact result inventory, measurements, and decision criteria. The
port-only Landlock control ran at exact source `d8d468b` in GitHub Actions run
`34430301059` on x86_64 and aarch64 Linux. Both immutable result inventories
verified independently and reached the pre-registered conclusion:
`port-only-landlock-cannot-select-service`. This is an observation that rejects
port-only Landlock for a service-identity claim; it authorizes no network
production code. The cgroup-BPF endpoint control then ran at exact source
`8043ed0` in run `34433053261`. Both architectures selected the allowed routing
tuple, denied address and port substitutions, retained exact BPF/kernel
identities, and observed cleanup. This confirms endpoint selection, not DNS or
TLS service identity. The next experiment step is the per-execution broker.
The explicit broker control design is frozen in
[`0001c-explicit-broker-control.md`](experiments/0001c-explicit-broker-control.md):
one preconnected framed channel, direct child network denial, fixed broker-side
service/TLS policy, and a closed first native corpus. It records no result yet.

Upstream promotion is intentionally paused at its review boundary. Proofbound
PR 2 is green but still needs an independent approving review. A dry run of
the later integration promotion correctly failed because its head retained an
older approval envelope followed by newer changes. The obsolete envelope has
been retired in a local subject commit. After PR 2 merges, the promotion diff
must be recomputed against the new exact `main`, independently reviewed, and
sealed by a new approval-only envelope before the promotion PR can become a
merge candidate. No Runtime claim wave depends on treating that pending stack
as released.

## 1. Executive decision

The next production capability should be a cgroup v2 memory boundary. The
network problem is the larger market limitation, but it is not the first safe
implementation task. Network authority changes remote-identity semantics and
the trusted computing base. Memory uses an existing mechanism and closes a
current mismatch between the implemented limits and the threat model's broad
host-capacity language.

Work should proceed on four tracks:

1. Stabilize and accelerate the cross-repository assurance workflow.
2. Add memory and swap limits as the first post-0.1 claim wave.
3. Make receipts useful at an adoption boundary through a typed acceptance
   policy and a maintained CI integration.
4. Research network authority immediately, but implement it only after a
   reviewed ADR and native adversarial prototype select an honest mechanism.

The first three tracks make the existing deny-network product credible and
usable. The fourth expands its addressable workloads without representing a
DNS label as a kernel-enforced remote identity.

## 2. What the critique got right, and what changes

| Critique | Assessment | Roadmap decision |
| --- | --- | --- |
| Network has only `Deny` | Correct fact and the largest workload gap. It is also an intentional version 1 boundary. | Start the network experiment and ADR in parallel. Do not add a hostname enum until a mechanism and receipt meaning survive the attack corpus. |
| A single allocation loop can exhaust memory | Correct. Only `pids.max`, wall time, and stream sizes are bounded today. | Memory and swap become the first Runtime feature wave. Narrow the current host-capacity wording until it ships. |
| Nothing consumes a receipt | Overstated. `pbr-verify` and `pbr-compose` consume receipts and compose a verified execution with a verified release. The missing layer is an adopter policy decision, authenticated retention, and routine CI use. | Build a small acceptance-policy CLI and a first-party CI integration before a receipt service. |
| The product is not installable or embeddable | Partly stale. The `v0.1.0` release contains checksummed native binary and assurance archives for both architectures. It lacks an installation workflow, package channels, stable embedding API, and Python or TypeScript tooling. | Document checksum-verified binary installation first. Add plan/result SDKs after schemas stabilize; keep the launcher out of process. |
| Exact runtime closure has an ergonomics cliff | Correct. The ELF interpreter is discovered, but dynamic library roots remain manually declared and the quick start favors a static binary. | Add a host preflight and a reviewable plan scaffold. Never label generated authority as safe or inferred. |
| There is no denial explanation | Correct for child-time denials. `plan check` explains normalized input, but a handled `EPERM` or `EACCES` does not reveal the denied rule. | Improve pre-execution diagnostics first. Treat live tracing as a separate, non-reusable diagnostic profile with its own TCB analysis. |
| There is no performance story | Correct. | Establish benchmarks before considering a daemon or batch execution service. |
| Linux setup blocks a five-minute trial | Correct for execution, although plan validation and receipt inspection are portable. | Ship a maintained systemd delegation recipe, a readiness explainer, and a downloadable example bundle. Do not weaken unsupported-host behavior. |

### Network correction

Classic seccomp BPF cannot dereference pointer arguments. It can deny
`connect(2)` or classify its scalar arguments, but it cannot read the
destination `sockaddr` supplied through a pointer. The
[kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
states this restriction directly. Seccomp user notification would add a
stateful broker and new race, identity, lifecycle, and TCB questions.

Landlock network rules are useful but narrower than the market requirement.
The current kernel interface can restrict TCP and UDP actions by port; it does
not identify a hostname, IP address, certificate, or remote service. See the
[kernel Landlock documentation](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html).
Allowing remote port 443 would mean “any reachable endpoint on port 443,” not
“the Anthropic API.” The roadmap does not accept that substitution.

## 3. Delivery and review baseline

The code was produced quickly, but the current review unit is too large for the
assurance burden:

- the repository has 175 commits by one author across 2026-09-04 through
  2026-09-09;
- [Runtime PR 1](https://github.com/bordumb/proofbound-runtime/pull/1)
  contained 66 commits, 110 files, and 6,546 additions;
- Runtime PR 1 and the Proofbound PRs inspected for this roadmap had no GitHub
  review records;
- Runtime `main` now requires the three CI contexts and enforces those checks
  for administrators, but it does not require an approving review;
- GitHub metadata shows Runtime PR 1 merged before its latest-head assurance
  jobs completed. The present protection may have been configured later, so
  this needs a settings audit rather than an assumption about the historical
  cause; and
- the Proofbound `main` branch is not protected.

The branch topology also exposes an upstream release risk. Runtime installs
Proofbound at `70af5e6`, while the sibling repository's `main` remains at
`0a5c6b6`. The consumed commit is the head of
`codex/exact-artifact-observations`, which contains stacked merges for
Proofbound PRs 3 through 5. Exact commit pinning preserves byte identity, but
the dependency is not on the upstream mainline or a versioned release.

### CI timing baseline

Representative Runtime run `34345620529` took 54 minutes 34 seconds:

| Work | Observed duration |
| --- | ---: |
| Install Lean | 1 minute 27 seconds |
| Build pinned Charon and Aeneas through Nix | 20 minutes 51 seconds |
| Install `just` and `cargo-deny` | 3 minutes 4 seconds |
| Compile and install the pinned Proofbound tools | 4 minutes 36 seconds |
| Install and initialize Kani | 15 seconds |
| Run `just ci` | 23 minutes 47 seconds |
| Lean model and refinement stage inside `just ci` | 8 minutes 29 seconds |
| Fresh Proofbound evidence stage inside `just ci` | 14 minutes 53 seconds |

The native Linux jobs for the same revision completed in about 30 seconds.
Release run `34361101393` took 53 minutes 20 seconds on `x86_64` and 48 minutes
27 seconds on `aarch64`; each architecture repeated the tool installation and
base gate before the release-specific work.

Both `ci.yml` and `linux-enforcement.yml` currently run on every `push` and
every `pull_request`. A push to an open PR therefore launches two equivalent
Verify runs and two equivalent two-architecture native matrices for the same
commit. [Runtime PR 2](https://github.com/bordumb/proofbound-runtime/pull/2)
demonstrated this duplication at `0b83bfe`.

## 4. Ordered roadmap

| Order | Epic | Repository | Hard dependency | Exit condition |
| ---: | --- | --- | --- | --- |
| 0 | Eliminate duplicate PR workflows | Runtime | None | One Verify run and one native matrix execute per PR SHA, while the merge SHA still receives both gates. |
| 1 | Upstream consolidation and feedback hygiene | `proof-bound`, then Runtime | None | Runtime consumes a protected, mainline, versioned Proofbound revision and active feedback is current. |
| 2 | Fast, non-weakened delivery loop | Both | Upstream consolidation | One full fresh required run per PR SHA; median cached PR latency below 20 minutes; release evidence remains fresh. |
| 3 | Installation and host readiness slice | Runtime | Released 0.1 CLI | A new supported host can install the exact release, explain prerequisites, and reach a verified example through maintained instructions. |
| 4 | Memory-safe execution profile | Runtime | PBF-0007 or an equivalent local fail-closed invariant | Registered memory and swap controls are installed and read back before execution, and terminal behavior is typed within the documented cgroup accounting semantics. |
| 5 | Receipt acceptance and CI consumption | Runtime | Stable post-memory receipt contract | A repository can run, verify, apply policy, and retain a decision without custom glue. |
| 6 | Remaining first-run recovery and SDK work | Runtime | Stable post-memory and acceptance contracts | Plan scaffolding, denial diagnostics, and SDKs preserve versioned wire meaning without duplicating the security path. |
| 7 | Network authority research and decision | Runtime | None; starts in parallel with Order 1 | An ADR selects or rejects a mechanism after native attacks and exact claim-language review. |
| 8 | Network-enabled execution profile | Runtime | Order 7 accepted | One real agent calls one declared service while all undeclared network paths fail. |
| 9 | CPU, output-storage, and performance expansion | Runtime | Evidence from adopted workloads | Each capability has separate semantics, limits, and evidence; no daemon is added without measured need. |

Orders express merge dependencies, not a ban on parallel investigation.
RT-0.2 is Order 0 and should land immediately because it is already measured,
does not change evidence meaning, and does not depend on upstream
consolidation. RT-3.1 and RT-3.2 form the Order 3 installation and readiness
slice; plan scaffolding, live denial diagnostics, and SDKs remain later work.
Network experiments should start early. Network production code must wait for
the decision gate.

## 5. Epic UP-0: consolidate Proofbound before new claim waves

This epic is performed before new claim waves, after the immediate
duplicate-workflow correction, in
`/Users/bordumb/workspace/repositories/proof-bound`. Runtime must not implement
the work there as an incidental side effect of a Runtime feature PR.

### UP-0.1 Promote the consumed upstream state

- Complete the existing language-support PR 2 first. It must receive an
  independent approving review before merge; a green self-authored
  implementation check is not that review.
- Prepare one final subject commit on the integration line after PR 2 lands.
  Retire the superseded review envelope in that subject so the resulting
  `main..subject` tree comparison does not reinterpret an older approval.
- Re-run `proofbound diff` against the new exact `main` and the exact subject.
  An independent reviewer must inspect that regression set and add a later
  approval-envelope commit containing only the newly registered review
  manifest. Any post-envelope byte change invalidates the approval.
- Use that exact envelope head for the explicit promotion PR. The draft
  promotion PR may be used as a fail-closed preflight, but it is not a merge
  candidate while the exact envelope or independent approval is absent.
- Re-run the full Proofbound verify-only gate against the actual mainline merge
  base and the exact promotion envelope head.
- Review the merge topology regressions from Proofbound
  [PR 3](https://github.com/bordumb/proof-bound/pull/3),
  [PR 4](https://github.com/bordumb/proof-bound/pull/4), and
  [PR 5](https://github.com/bordumb/proof-bound/pull/5) as part of that
  promotion. Do not recreate them by cherry-picking only the feature commits.
- Require an approving review from a person other than the change author for
  changes to status derivation, schemas, independent verification, release
  composition, and trusted tool identities. Before making that approval a
  repository rule, name at least one eligible reviewer and the availability or
  escalation policy. Without an eligible reviewer, sensitive work may be
  prepared and verified but must remain visibly unapproved and unreleased.
- Protect Proofbound `main`: require the exact current-head gate, require
  conversation resolution, prevent force pushes and deletion, and enforce the
  rule for administrators.
- Tag a Proofbound release or publish an immutable tool bundle containing the
  CLI, independent verifier, and every adapter Runtime installs. Publish exact
  checksums and the toolchain identities.
- Change Runtime's hosted workflows from the integration-branch commit to the
  resulting mainline release identity. Keep an exact revision or digest; do
  not float on a branch or version range.

**Done when:** a clean Runtime CI worker can install the same complete
Proofbound tool set from one reviewed upstream release identity, and the
Runtime feedback records cite the promotion PR, merge commit, and release.

### UP-0.2 Resolve PBF-0007 before expanding bounded claims

[PBF-0007](proofbound-feedback/pbf-0007-claim-evidence-domain-consistency.md)
is the highest assurance-risk open feedback item. Today the claim's public
bounded-domain text and the cited evidence domain can diverge while status is
still admitted.

- Enforce equality of identifier, description, cardinality, and ordering key
  between a bounded claim and every primary bounded evidence record.
- Enforce the relation independently in `proofbound-verify`.
- Add exact-match, each-field mismatch, receipt substitution, and mixed-domain
  multi-evidence cases.
- Use a stable diagnostic and preserve existing assumptions, bounds, and
  evidence identities in the failed report.
- Migrate Runtime only after the upstream compiler and verifier agree.

This is required before a new resource-policy bounded domain is allowed to
contribute to a Runtime public statement.

### UP-0.3 Resolve PBF-0003 before multiplying evidence units

[PBF-0003](proofbound-feedback/pbf-0003-missing-adapter-diagnostics.md)
documents three separate expensive failures whose downstream symptom was only
“missing evidence.” `CompiledProject` retains `unit_runs`, but the normal human
and JSON status projections still omit the failed adapter diagnostic.

- Version the JSON report projection to include selected unit outcomes,
  adapter identity, stable code, bounded diagnostic, and remediation.
- Render the same cause in the human report and claim explanation.
- Distinguish unavailable executable, adapter protocol failure, timeout,
  evidence rejection, and an uncited or stale record.
- Keep failure closed. Diagnostics must never create or admit evidence.
- Add producer/verifier schema tests if the report becomes a portable input.

This work reduces failed-claim debugging time without reducing a single gate.

### UP-0.4 Make theorem-pin updates reviewable

[PBF-0002](proofbound-feedback/pbf-0002-lean-theorem-identity-update.md)
should be completed before repeated post-0.1 theorem work makes manual pinning
normal practice.

- Let `proofbound update` prepare only the uniquely owning claim manifest's
  declaration, statement encoding, statement digest, and axiom inventory.
- Require an explicit claim-manifest output boundary in the sealed update
  tree.
- Reject ambiguous ownership, extra attributed theorems, forbidden axioms, and
  every out-of-boundary write.
- Require the subsequent verify-only run to rederive the pins independently.

### UP-0.5 Package reusable Aeneas bridges

[PBF-0001](proofbound-feedback/pbf-0001-aeneas-standard-library-bridges.md)
is not a blocker for memory enforcement, but it is a recurring source-
refinement cost.

- Put the bridge pack outside Proofbound core.
- Version bridges by Rust, Charon, Aeneas, Lean, Aeneas library, declaration,
  and representation identities.
- Inventory and byte-pin each selected operation.
- Reject an uncovered generated external declaration rather than permitting a
  project axiom.
- Start with the `String::as_bytes` and `Vec::truncate` bridges already used by
  Runtime.

### UP-0.6 Record two new workflow observations before upstream work

The current feedback index does not cover the largest measured CI costs. Add
separate feedback records, using the required template, only after preserving
the exact Runtime observations above.

1. **Deterministic parallel evidence scheduling.** Proofbound currently runs
   selected evidence units serially. Specify bounded worker count, per-unit
   isolated shadows and output roots, deterministic final ordering, complete
   diagnostics, cancellation, and identical status derivation. Never let two
   units share mutable generated state implicitly.
2. **Versioned Proofbound tool distribution.** Runtime compiles five
   Proofbound executables for 4–5 minutes in every clean job. Define an
   immutable bundle or maintained CI action keyed by the exact Proofbound
   revision, platform, and artifact digest. State the distribution channel as
   a trust input. A checksum obtained beside an artifact establishes byte
   identity after the expected value is trusted; it is not publisher
   authentication by itself. A mutable “latest” installer is not acceptable.

The first item can shorten the 14–15 minute fresh evidence stage. The second
removes repeated compilation. Neither item authorizes reuse of stale evidence.

### UP-0.7 Repair local feedback drift

The unresolved records preserve useful observations but some “Local
treatment” text predates the completed Tier 3 work:

- PBF-0001 still says `PBR-AUTH-001` remains Tier 2 and model-only;
- PBF-0002 still says `PBR-AUTH-001` remains model-only; and
- PBF-0007 still says `PBR-POLICY-002` remains model-only.

Update those sections to describe the present local workaround and status
without marking the generic request resolved. After each upstream change,
record the exact Proofbound ADR, commit, PR, release, Runtime pin, and migration
before changing its feedback status.

## 6. Epic RT-0: make commits, PRs, and CI fast enough to sustain PDD

This epic changes delivery mechanics, not evidence meaning.

### RT-0.1 Use claim-wave review units

- Create one branch per claim wave or one tightly coupled workflow change.
- Open a draft PR after the contract, claim, and falsifier exist. Do not wait
  until implementation, proofs, release linkage, and documentation form a
  60-commit review unit.
- Keep hand-written changes in reviewable commits. Commit generated Lean and
  updated exact identities with the source step that generated them, as the
  contributor guide requires.
- Target fewer than 10 hand-written commits and roughly 1,000 changed
  non-generated lines per PR. Exceed this only when the PR explains the
  inseparable security boundary.
- Use stacked PRs only when every base is explicit and a final promotion PR
  moves the reviewed stack to the protected mainline. Runtime must not pin an
  upstream integration branch indefinitely.
- Add a PR template with the PDD fields: claim, exact production subject,
  assumptions, exclusions, falsifier, schema effect, evidence produced,
  residual obligations, and commands run.
- Add `CODEOWNERS` for specifications, ADRs, schemas, claims, formal bridges,
  `sys.rs`, launcher/supervisor code, independent verifier code, and release
  workflows. Every required owner entry must name an eligible, available
  reviewer rather than serving as aspirational metadata.
- Require one approving review for security and assurance surfaces. If no
  independent reviewer is available, leave the PR visibly unapproved rather
  than representing self-review as independent review.

### RT-0.2 Eliminate duplicate workflow runs

- Run `pull_request` workflows for PR heads.
- Limit ordinary `push` workflows to `main` and explicitly named release tags.
- Add a concurrency group keyed by workflow plus PR number or branch, with
  cancellation of superseded PR runs.
- Keep the mainline run after merge. It validates the merge commit and is not a
  duplicate of the PR-head run.
- Ensure the release workflow accepts an exact commit and verifies that exact
  head before producing artifacts.

**Metric:** one Verify run and one two-architecture native matrix per PR SHA,
plus one of each for the merge SHA.

### RT-0.3 Put cheap failures first and safe work in parallel

Use stable required job names and a final required aggregate job:

```text
preflight (docs, metadata, formatting, schemas)
    +--> rust (check, clippy, unit and conformance tests)
    +--> formal-and-proofbound (Lean, refinement, fresh evidence)
    +--> native-x86_64
    +--> native-aarch64
all-required --> required
```

- Complete preflight before installing proof tools.
- Run Rust, native Linux, and the formal/evidence lane concurrently after
  preflight.
- Keep every current check. Splitting the coordinator must not omit a stage or
  make a green aggregate possible after a skipped required job.
- Keep `proofbound check --fresh` for protected full gates and release
  contexts.
- If Proofbound gains verified impact analysis, it may select affected units
  from registered semantic closures. Do not use raw GitHub path filters as a
  substitute for the assurance graph.
- Emit per-stage and per-unit timing as build metadata. Timing is operational
  data, not evidence.
- Migrate required check names without a protection gap: add and observe the
  new aggregate alongside the old required contexts, update branch protection
  only after the new context is green on an exact head, and remove the old
  contexts and jobs last. A workflow rename must neither unlock `main` nor
  deadlock every PR.

### RT-0.4 Cache tools, not assurance conclusions

- Prefer an immutable runner image or signed binary cache containing exact
  Rust, Lean, Charon, Aeneas, Kani, `just`, `cargo-deny`, and Proofbound
  identities.
- Key downloaded source caches by the lockfiles and exact tool revisions.
- Verify the restored tool identities before use.
- Treat cache infrastructure as a declared toolchain dependency and TCB role.
- Do not restore `.proofbound` receipts into a protected fresh gate.
- Do not use mutable shared compiled objects for release evidence. Release
  builds remain clean and reproduce the final artifacts twice.
- Do not let cache hits change evidence kind, freshness labels, bounds, or
  public language.

**Targets after two weeks of measurements:**

- cached PR required gate: median below 20 minutes and p95 below 30 minutes;
- first actionable preflight failure: below 2 minutes;
- native boundary result: below 2 minutes after queueing; and
- release workflow: median below 30 minutes per architecture without removing
  double-build, native observation, independent verification, or composition.

### RT-0.5 Make release state lead documentation

- Prepare version and changelog changes before the release merge.
- Run the release workflow on the exact merge SHA.
- Publish the tag only after both native contexts pass and their artifacts are
  retained.
- Generate a canonical release provenance summary as a release asset instead
  of requiring hand-written documentation to carry transient Actions run IDs.
- If a post-publication documentation PR is still useful, keep it descriptive;
  it must not retroactively change the evidence or meaning of the tagged
  release.

## 7. Epic RT-1: memory and swap limits

### Claim and scope

Candidate plain-English claim:

> For a supported execution, the runtime installs the registered process,
> memory, and swap limits in the same fresh cgroup before child code starts,
> verifies the installed values, and records the cgroup's terminal memory
> observations without granting a larger modeled resource bound.

The exact production subjects are `ResourceLimits`, normalization, policy
compilation, the cgroup capability probe and lifecycle, launcher sequencing,
run orchestration, receipt construction, and the independent verifier. The
kernel memory controller remains an assumption. Kernel documentation describes
`memory.max` as the main hard cgroup memory limit and notes that a temporary
overshoot can occur; swap is controlled separately by `memory.swap.max`. See
the [cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).

### RT-1.1 Correct the contract before code

- Amend the threat model so “host process and resource capacity above
  registered limits” enumerates only the limits actually enforced until this
  wave ships.
- Add a new accepted specification for plan and receipt evolution. Version 1
  schemas are closed; do not silently add fields to them.
- Decide whether new executions require plan version 2 while the verifier
  continues to validate historical version 1 receipts.
- Define `MemoryByteLimit` and `SwapByteLimit` as validated newtypes. State
  units, minimums, maximums, and whether swap zero is required or selectable.
- Define whether `memory.high` is excluded. It is a throttle, not the hard
  boundary requested by this claim.
- Define terminal observations: peak memory, `memory.events` deltas, swap peak,
  OOM/OOM-kill counts, and the exact installed control values.
- Define outcome semantics. An OOM kill must not be indistinguishable from an
  unexplained signal when the cgroup event proves the narrower cause. A child
  that receives `ENOMEM`, handles it, and exits zero needs an explicit policy
  decision rather than accidental classification.

### RT-1.2 Extend the pure core

- Add typed memory and swap limits to `ResourceLimits` and every subset check.
- Extend canonical normalization and normalized-plan identity.
- Extend `CgroupPolicy` and installed-policy identity.
- Update plan conformance vectors, schemas, independent reference code, Kani
  domains, Lean model, translated source closure, and refinement theorem.
- Add negative cases for zero, overflow, missing fields, version downgrade,
  and more-permissive normalization.
- Retain the local bounded-domain consistency guard added at `9154c7f` until a
  reviewed Proofbound release resolves PBF-0007 in both the compiler and
  independent verifier. Extend its fixtures with the new resource domain in
  the same commit that registers that domain.

### RT-1.3 Install and verify the Linux boundary

- Require both `pids` and `memory` controllers in the delegated subtree.
- Update the maintained systemd delegation recipe to use
  `Delegate=pids memory` and verify both controllers after entry.
- In the fresh cgroup, write and read back `pids.max`, `memory.max`,
  `memory.swap.max`, and the selected `memory.oom.group` value before launcher
  release.
- Retain descriptor-relative cgroup access and the existing mount/inode
  identity checks.
- Snapshot memory events before execution and after the process tree drains.
- Treat a missing control file, unsupported controller, mismatched readback,
  counter parse failure, or lost cgroup identity as a fail-closed boundary
  failure.
- Ensure cleanup still drains and removes the exact group after OOM, timeout,
  launcher failure, and supervisor error.

### RT-1.4 Falsify and observe

- Allocate past the limit in one process.
- Allocate concurrently across the maximum allowed process tree.
- Exercise anonymous memory, mapped files, page cache, shared memory, and
  socket memory cases covered by the selected kernel accounting contract.
- Exercise swap disabled, swap limit reached, and host-without-swap cases.
- Race allocation with boundary installation; no allocation may occur before
  the launcher acknowledgement sequence permits execution.
- Confirm another cgroup and the supervisor are not selected by the workload
  cgroup's OOM event.
- Mutate each receipt observation and installed value and require independent
  rejection.
- Run the complete native corpus on both supported architectures and retain
  kernel, cgroup-controller, and artifact identities.

### RT-1.5 Publish only the admitted result

- Update `doctor`, `plan check`, `run`, `inspect`, and both verifiers.
- Update the quick start and examples with explicit memory and swap values.
- Update the release composer for the new receipt schema without reinterpreting
  historical receipts.
- Re-run affected Tier 0 through Tier 3 paths. Do not infer the Linux boundary
  claim from the pure policy theorem.
- Publish a new minor version only after both exact native release contexts
  reproduce, observe, verify, and compose the new artifacts.

**Done when:** a hostile process tree cannot consume unbounded cgroup-accounted
memory or swap; every configured value is read back before execution; terminal
memory events survive into a verified receipt; unsupported hosts fail closed;
and the public language names the remaining kernel and accounting assumptions.

## 8. Epic RT-2: receipt acceptance and CI consumption

`pbr-compose` already joins verified release and execution facts. This epic
adds the adopter's decision without turning it into another producer-authored
success Boolean.

### RT-2.1 Specify an acceptance policy

- Add a closed, versioned policy format owned by Runtime or by a separate
  consumer crate, not by Proofbound core.
- Require explicit acceptable execution schema, Runtime release identity,
  platform, architecture, plan ID, executable identity, authority, resource
  limits, eligibility, and receipt age or freshness policy where applicable.
  If age affects the decision, require a separately trusted current-time input
  and identify its source; a producer timestamp cannot prove its own freshness.
- Express Proofbound requirements by exact claim ID and explicit formal,
  linkage, assumption, and policy facets. Do not implement the shorthand
  “all claims at least Tier 3,” because Proofbound status is multi-facet and
  partially ordered.
- Allow policy to reject specific assumptions, exclusions, open obligations,
  or TCB roles.
- Define the independent trust inputs: execution commitment, execution ID,
  release bytes, raw receipt bytes, policy bytes, expected policy identity,
  and any trusted current-time input. Verification reports remain retained
  outputs unless a separate authenticated-report mode is explicitly specified.

### RT-2.2 Implement `pbr-accept`

- In the initial CLI, invoke the independent execution and release verifiers
  over the exact raw inputs before policy evaluation. Do not trust a portable
  verification report merely because it is present. A future mode that accepts
  reports must specify and enforce their authentication and binding policy.
- Emit canonical `accepted` or `rejected` output with every typed reason.
- Bind the policy identity and exact input identities into the decision.
- Never mutate or reserialize the input receipt as part of verification.
- Publish output with no-replace semantics.
- Add omission, substitution, downgrade, replay, stale-policy, assumption-loss,
  and forged-acceptance attacks.
- Keep acceptance separate from execution reuse eligibility: a reusable
  receipt can still be rejected by an adopter policy.

### RT-2.3 Ship a first-party GitHub Action

- Pin the Runtime bundle and acceptance policy by digest.
- Run a reviewed plan, capture the run-result commitment and execution ID on
  the control channel, verify the receipt, compose it with the release, apply
  policy, and upload all exact artifacts.
- Make the action output the canonical decision identity and typed reasons.
- Document retention and trust boundaries. An Actions artifact store is a
  carrier, not the independent trust anchor.
- Dogfood the action in a small external sample repository before calling it
  an adoption path.

### RT-2.4 Defer the service layer

- Start with content-addressed CI artifacts or an OCI artifact convention.
- Do not build a receipt database until two consumers need query and retention
  behavior.
- Evaluate DSSE, Sigstore, or a product signing identity only through a new ADR.
  A signature moves the external trust anchor to key and identity policy; it
  does not remove that premise or prove the recorded execution happened.

**Done when:** an adopter can state a reviewable policy, receive an independently
derived decision, reproduce the decision locally, and retain the exact inputs
without writing custom JSON logic.

## 9. Epic RT-3: installation and first-run recovery

### RT-3.1 Make the existing release installable

- Put checksum-verified download and extraction before source compilation in
  the README.
- Publish one small installer or package recipe per supported architecture that
  pins an explicit version and expected digest through a reviewed source, then
  verifies the downloaded bytes. Until a signing ADR selects a publisher
  identity, state the GitHub repository and release channel as distribution
  trust inputs; an adjacent checksum file is not an authentication mechanism.
- Keep all four colocated binaries together so `pbr` can identify the launcher
  and the composition flow can identify its tools.
- Add `pbr doctor --explain` output with the exact missing host prerequisite and
  a remediation that does not mutate the system automatically.
- Publish and test a systemd user/service recipe that creates the required
  empty delegation root and supervisor leaf.
- Add an end-to-end install test against the published archive in both release
  contexts.

### RT-3.2 Add a read-only host preflight

- Add a command that combines strict plan validation, capability probing,
  rooted path resolution, executable and interpreter discovery, runtime-root
  inspection, output/receipt path validation, and identity reporting without
  starting child code or installing a boundary.
- Report the exact phase and typed reason for every failure.
- Do not claim that a successful preflight guarantees the later run; identity
  drift and capability changes remain possible and must still be checked.

### RT-3.3 Generate a reviewable plan scaffold

- Add a command that accepts one exact executable and produces a draft plan
  with the executable, ELF interpreter, directly resolved dependencies, and
  diagnostic provenance for every suggested runtime root.
- Resolve transitive `DT_NEEDED`, interpreter, `RPATH`/`RUNPATH`, loader cache,
  architecture, and symlink behavior under an explicit host profile.
- Mark unresolved dynamic loads, language packages, plugins, configuration,
  and environment-dependent searches as open items.
- Never execute the target during scaffolding.
- Require the user to choose write roots, environment names, limits, and
  network mode. Generated output is not an inferred safe policy.
- Add fixtures for static ELF, glibc, musl, missing library, conflicting search
  path, plugin load, and identity drift.

### RT-3.4 Explain denials without changing receipt meaning

- First improve errors for failures Runtime already knows: capability,
  resolution, identity drift, output-root, launcher protocol, cgroup, and
  receipt construction.
- Add stable phase and rule identifiers to human diagnostics.
- Investigate Landlock audit/trace events, seccomp user notification, and
  ptrace only as diagnostic mechanisms. Each expands permissions or the TCB.
- If a live trace mode is added, give it a distinct profile and make its
  receipts non-reusable until the diagnostic observer's security meaning is
  specified and evidenced.
- Never infer a denial cause solely from an arbitrary child exit code.

### RT-3.5 Add SDKs after wire stability

- Publish a small Rust crate for validated plan construction and machine-result
  decoding only after the version 2 schemas settle.
- Publish Python and TypeScript packages that construct plans, invoke the
  separate `pbr` process, and validate result schemas.
- Do not embed raw syscalls, launcher sequencing, or producer/verifier semantic
  code in an SDK.
- Keep the independently implemented verifier independently distributable.

## 10. Epic RT-4: network authority research and ADR

This epic can begin immediately and must finish before a network-enabled plan
schema is accepted.

### RT-4.1 Freeze the requirement

Define separate concepts instead of one string allow-list:

- routing endpoint: IP address, address family, transport, and port;
- requested service name: for example `api.anthropic.com`;
- resolution authority: resolver identity, CNAME behavior, TTL, rebinding, and
  when resolution occurs;
- transport identity: TLS server authentication, cleartext, proxy tunnel, or
  an explicitly weaker claim;
- allowed direction and protocol: outbound TCP, UDP/QUIC, inbound bind, Unix
  socket, or inherited connected descriptor; and
- credential availability and binding: which secret source or name is made
  available with which declared service identity, without recording its value.
  Do not claim the child used that credential only for the service unless the
  selected mechanism actually enforces that restriction.

State the first workload exactly: one identified client calls one declared
HTTPS API endpoint on port 443, with direct DNS, UDP, QUIC, arbitrary TCP,
local sockets, and inherited network descriptors denied unless the selected
mechanism needs and records them.

### RT-4.2 Prototype and attack the viable mechanisms

Evaluate at least these profiles:

1. **Port-only Landlock.** Small and unprivileged, but it authorizes every
   remote endpoint on an allowed port. It is not sufficient for a service-name
   claim and should be rejected or named as an explicitly broad authority. The
   first native control recorded this expected limitation at `d8d468b` on both
   supported architectures; it did not test or accept a production profile.
2. **IP endpoint mediation.** A cgroup BPF `connect4`/`connect6` policy can
   enforce network endpoints but adds privilege, loader, attachment, pinning,
   and lifecycle requirements. DNS identity remains outside the kernel rule.
   The first native control selected one IPv4 tuple and denied endpoint and
   port substitutions on both architectures at `8043ed0`; it did not establish
   service identity or test a production lifecycle.
3. **Per-execution egress broker.** Deny direct child network syscalls and give
   the child only an identified channel to a broker that enforces declared
   service and port policy. The broker, resolver, protocol parser, lifecycle,
   logs, and configuration become TCB and receipt subjects.
4. **Preconnected descriptors.** Strong for a small protocol-specific client,
   but not transparent to ordinary package managers, Git, or LLM SDKs and
   difficult to bind to later remote identity changes.

The attack matrix must cover IPv4/IPv6, DNS rebinding, CNAME chains, literal
IPs, redirects, proxy protocol confusion, TLS SNI/Host mismatch, HTTP CONNECT,
UDP and QUIC, Unix sockets, inherited descriptors, `io_uring`, raw and packet
sockets, broker substitution, policy replay, resolver substitution, connection
reuse, and process descendants.

### RT-4.3 Decide the claim and TCB before implementation

The ADR must answer:

- What exact remote fact is enforced: endpoint, port, requested service name,
  proxy route, or authenticated service identity?
- Which component resolves names, and when?
- Can a malicious child speak arbitrary bytes to an allowed service?
- How are redirects and connection pooling represented?
- Which broker, BPF program, resolver configuration, CA roots, client library,
  or host manager joins the TCB?
- What is installed before child code, and what acknowledgement binds it to the
  compiled policy identity?
- What connection observations fit within a bounded receipt?
- Which missing mechanism or observation makes the run unsupported or the
  receipt non-reusable?

**Decision gate:** reject any design whose public example says “only
`api.anthropic.com`” while its kernel boundary actually says “any IP on port
443.”

## 11. Epic RT-5: implement the selected network profile

This epic exists only if RT-4 accepts a mechanism.

### RT-5.1 Version the domain and wire contracts

- Add a closed `NetworkAuthority` enum with only implemented modes.
- Preserve `Deny` without semantic change.
- Use typed non-empty destination collections, ports, protocols, and service or
  endpoint identities as the ADR requires.
- Version the plan, compiled policy, launcher protocol, receipt, run result,
  verifier, composition, and acceptance-policy schemas together.
- Reject unknown modes and incomplete destination records. Never fall back to
  `Deny` or broad egress after an unsupported allow mode is requested.

### RT-5.2 Keep the security boundary explicit

- Put raw syscalls only in `sys.rs`.
- Install every child-side network restriction before the existing bound
  acknowledgement.
- Create any broker or BPF attachment before child release, identify its exact
  bytes/configuration, and verify its lifecycle and cgroup association.
- Close direct and inherited bypasses, including UDP, `io_uring`, Unix sockets,
  and descendant processes.
- Bound connection count, diagnostic volume, and receipt observation size.

### RT-5.3 Take the claim through its declared tier

- Add pure non-amplification and deterministic compilation evidence for the
  new authority model.
- Keep effectful broker/kernel behavior at the strongest honest bounded native
  evidence level unless a valid refinement subject exists.
- Run the frozen network attack corpus on both architectures.
- Bind the selected release artifacts and retain every new assumption and TCB
  role through composition and acceptance.
- Demonstrate one real LLM API call with a test credential supplied outside
  plans, receipts, logs, fixtures, and artifacts. The test must prove no secret
  value entered retained evidence.

**Done when:** the allowed call succeeds, every registered bypass fails for the
expected typed reason, missing enforcement fails closed, and the receipt says
exactly what the mechanism enforced—no more.

## 12. Epic RT-6: remaining resource and performance work

### RT-6.1 CPU

- Distinguish CPU bandwidth from total CPU consumption. The cgroup `cpu.max`
  interface limits use per period; it is not a total CPU-time budget. The
  [cgroup v2 documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
  defines it as a bandwidth limit.
- Decide whether the product needs bandwidth, aggregate consumed CPU time, or
  both.
- For aggregate time, specify a supervisor decision over `cpu.stat` and its
  polling/overshoot bound. Do not present `RLIMIT_CPU` as a process-tree total.
- Version plans and receipts, require the `cpu` controller where applicable,
  and add busy-loop, multi-process, timeout-interaction, and counter-race cases.

### RT-6.2 Output-root capacity

- Treat disk capacity as a separate architecture problem. `io.max` throttles
  I/O; it is not a write-root byte quota.
- Compare an isolated tmpfs, filesystem project quota, loop/image filesystem,
  and a privileged storage broker against the non-root boundary.
- State whether a limit covers allocated blocks, logical file bytes, inodes,
  sparse files, metadata, deleted-open files, memory-mapped writes, and nested
  mounts.
- Do not rely only on post-run inventory: a hostile child can exhaust the host
  before post-run validation.

### RT-6.3 Performance

- Add criterion or a similarly stable benchmark harness for pure operations:
  plan parsing, normalization, policy compilation, receipt construction,
  canonical encoding, verification, and composition.
- Add native end-to-end measurements for static and dynamic executables,
  separating process creation, cgroup creation, closure inventory, Landlock,
  seccomp, output capture, receipt encoding, and cleanup.
- Publish median, p95, host/kernel identity, sample count, and workload. Do not
  turn a benchmark into an assurance claim.
- Measure repeated invocations before proposing a daemon or batch mode.
- If a daemon is justified, give it a new ADR and threat model. Long-lived
  state and multi-tenancy are explicit version 1 non-goals.

## 13. Cross-epic acceptance and release rules

Every security-relevant Runtime epic must use the same merge checklist:

1. State the plain-English claim and exact production subject.
2. Version the applicable specification, threat model, and ADR before or with
   the first implementation PR.
3. Register assumptions, exclusions, intended evidence, and target tier.
4. Add at least one falsifier before the positive implementation.
5. Implement the smallest typed behavior that can satisfy the claim.
6. Run the smallest relevant local gate per commit and the complete fresh gate
   per claim-wave PR head.
7. Confirm producer and independent verifier agreement for every changed wire
   or decision.
8. Inspect residual assumptions, bounded domains, open obligations, and TCB
   additions.
9. Reproduce and observe both native release contexts at the merge SHA.
10. Publish only the language admitted by the compiled evidence.

No optimization may:

- reuse an evidence receipt after any registered semantic closure changes;
- classify skipped, cached, unsupported, or mocked execution as fresh native
  evidence;
- hide a missing adapter, timeout, or failed unit behind a missing citation;
- let generated scaffolding add authority without review;
- make a mutable branch, cache entry, adjacent digest file, or CI status the
  trust anchor; or
- merge a security change because an older commit on the branch was green.

## 14. Product milestones

### Milestone A: sustainable assurance development

- Proofbound mainline and release contain the exact features Runtime consumes.
- PBF-0003 and PBF-0007 are resolved and consumed.
- Duplicate PR workflows are removed.
- Required checks cover the exact PR head and merge head.
- CI timing and unit diagnostics are visible.

### Milestone B: bounded local execution

- New executions require explicit memory and swap limits.
- Native evidence demonstrates enforcement on both architectures.
- The threat model no longer uses broader host-capacity language than the
  implemented controls.

### Milestone C: first adopter workflow

- A released archive has a checksum-verified install path.
- A maintained CI action runs, verifies, composes, applies policy, and retains
  one receipt chain.
- A new user can diagnose an unsupported host or invalid plan without reading
  source code.

### Milestone D: useful agent execution

- The reviewed network ADR has selected an honest mechanism.
- One network-enabled profile runs a real declared API client.
- The acceptance policy distinguishes that profile from deny-network
  executions and preserves all new assumptions.

### Milestone E: expansion based on evidence

- CPU and output-storage semantics are separately decided.
- Published benchmarks show whether repeated setup cost needs architectural
  work.
- SDKs stabilize around versioned plans and results without duplicating the
  child security path.

## 15. Explicitly deferred

The following work should not preempt Milestones A through C:

- a long-lived daemon or multi-tenant service;
- macOS or Windows under the Linux assurance label;
- a generic hosted receipt database;
- a hostname allow-list implemented as a port-only rule;
- automatic policy inference from arbitrary executed programs;
- publication of security-sensitive crates before their API and schema
  compatibility policy is defined; and
- promotion of every claim to Tier 3 regardless of its effectful subject or
  adoption value.

The roadmap favors a small, reviewable chain: protected upstream tools, a fast
fresh gate, bounded memory, a real receipt consumer, and then an honestly
specified network boundary.
