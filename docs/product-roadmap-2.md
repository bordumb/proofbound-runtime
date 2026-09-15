# Proofbound Runtime product roadmap 2: deferred capabilities

- **Status:** implementation; RT-7 publication routes merged, external
  registry setup and publication remain open, and the RT-8 contract foundation
  is under review; all complete Roadmap 2 epic exits remain open
- **Date:** 2026-09-13
- **Runtime baseline:** `acf8f24` on `main`; exact-main Verify run
  `34924535451` is pending, so `4a0cfdb` remains the latest admitted identity
- **Proofbound baseline consumed by Runtime evidence:** public immutable bundle
  for source `9512469`; protected-path cutover merged as Runtime `4a0cfdb` and
  passed exact-main Verify run `34918706960`
- **Proofbound distribution source:** `9512469`; exact-main Verify and public
  immutable bundle run passed; Runtime dogfood merged as `f2a06de`
- **Prerequisite:** [Product and delivery roadmap](product-roadmap.md)
  Milestones A through E, except where an epic below names a narrower
  prerequisite
- **Delivery order:** [Product roadmap execution order](product-roadmap-execution-order.md)
- **Planning horizon:** post-Milestone E product expansion
- **Lifecycle rule:** prelaunch with zero external users; do not add version
  migrations, compatibility layers, deprecation periods, or coordinated
  release numbering. Replace current contracts atomically and re-run every
  affected exact-identity gate.

This roadmap takes the six items that the first roadmap deferred in its
section 15 and orders them by the size of the trusted computing base change
each one requires. It is not a normative specification. A change to
authority, receipt meaning, public schemas, the trusted computing base, or
repository structure still requires the applicable specification,
threat-model, ADR, claim, and evidence changes before production code.

### Execution checkpoint

As of 2026-09-15, Runtime main commit `acf8f24` contains the version 2 memory
and deterministic CBOR wave, receipt composition and acceptance, a bounded
static plan scaffold,
typed prelaunch diagnostics, reproducible Rust, Python, and TypeScript SDK
packages, the network-mechanism decision, and the performance baseline. These
are prerequisites or partial foundations for RT-7, RT-8, RT-9, and RT-13. They
do not close a Roadmap 2 exit condition. Registry publication, consumer
dogfood, a diagnostic execution profile, production authenticated networking,
the guest profile, the signing ADR, the receipt log, and the execution service
remain open. RT-7.1 is governed by
[Specification 0014](specs/0014_public_compatibility_and_distribution.md).
The RT-7.2 verifier-package slice passed independent exact-head review and
hosted verification, merged as unsigned Runtime commit `7f989d3`, and passed
exact-main Verify run `34896209689`. It does not authorize registry
publication. Proofbound's public bundle path passed independent review, merged
as `9512469`, passed exact-main Verify run `34899222179`, and published
immutable release `388736918` from bundle run `34900896450`. Runtime pinned
that exact seven-asset release, passed independent review and hosted dogfood,
merged it as unsigned commit `f2a06de`, and passed exact-main Verify run
`34908515545`. The protected evidence and release source-build cutover passed
independent review and exact-head Verify run `34915891330`, then merged
unsigned as `4a0cfdb` and passed exact-main Verify run `34918706960`. The four
selected registry routes and their exact-byte observer contract merged
unsigned as `acf8f24`; exact-main Verify run `34924535451` is pending. The
protected GitHub `package-publish` environment, registry credentials or trusted
publishers, anonymous retrieval observations, external consumer dogfood, and
current-integration manifest remain open. No registry package is yet described
as published. The RT-8 diagnostic contract, observer decision, closed schemas,
and source-level production non-reuse checks are implemented on
`codex/rt8-diagnostic-profile`. The pure diagnostic receipt and plan-draft
producer is implemented on the stacked `codex/rt8-observer` branch. Hosted
admission, the live ptrace observer, command integration, native attack corpus,
and release binding remain open.
RT-9 is blocked until RT-5 implements the accepted single-service network
decision in production.

The roadmap uses these sources:

- section 15 of the [first roadmap](product-roadmap.md) and the epic text
  that deferred each item;
- the [threat model](threat-model.md), in particular its trusted computing
  base inventory and its out-of-scope list, which names macOS and Windows
  behavior, remote workload identity, and confidential-computing attestation;
- [ADR 0002](adr/0002-external-receipt-commitment.md), whose recorded
  negative consequence is that a carrier controlling both the receipt and the
  alleged commitment still wins;
- the component boundaries in
  [Specification 0002](specs/0002_cli_surface.md) and the composition inputs
  in [Specification 0003](specs/0003_release_receipt_composition.md);
- the draft ownership, terminology, identity, composition, and integration
  rules in
  [Specification 0013](specs/0013_platform_integration_contract.md), with
  epic-specific mappings in the
  [Roadmap 2 execution records](roadmap-2/README.md);
- the [contributor guide](../AGENTS.md) architecture boundaries, in
  particular that the independent verifier has no workspace dependency and
  shares no semantic code with the producer;
- the [Experiment 0001](experiments/0001-network-authority-mechanisms.md)
  series through its
  [measurement slice](experiments/0001i-network-measurement-slice.md); and
- the [Proofbound feedback index](proofbound-feedback/README.md).

## 1. Executive decision

Order the six items by trusted computing base delta, not by market pull. Two
items add no trusted role to the production profile. One adds a diagnostic
observer that never touches the production profile. One adds a hypervisor and
a guest image. One adds a signing identity and a log operator. One adds
long-lived state and, if a later decision accepts it, co-tenants.

One item is not scheduled. A hostname allow-list backed by a port-only rule
would make the receipt say "only this service" while the kernel enforces "any
endpoint on this port." That contradicts the one guarantee the product makes.
It is replaced by an honest multi-service extension of whatever mechanism the
network ADR accepts.

The resulting order:

1. Prelaunch packaging and published pure crates.
2. Trace-assisted plan drafting under a distinct diagnostic profile.
3. Multi-service network allow-list on the accepted mechanism.
4. Linux VM host profile for macOS and Windows, labeled as such.
5. Signing and transparency ADR, then a content-addressed receipt log.
6. Execution service, only after measured need, single-tenant first.

Orders 1 through 3 are prerequisites for the rest regardless of which buyer
arrives first. Orders 4 and 5 can swap when demand shows which one matters.
Neither can precede the schema stability that Order 3 completes. Order 6 stays
closed until the benchmark evidence the first roadmap requires exists.

Platform integration is a cross-cutting track, not a seventh product with a
shared semantic core. Proofbound Runtime continues to own enforcement,
Proofbound continues to own assurance status, Auths continues to own
authorization, and Capsec continues to own source-level capability
observations. The projects compose native receipts and exact identities under
[Specification 0013](specs/0013_platform_integration_contract.md). They do not
share one universal receipt or coordinated product releases.

## 2. Why each item was deferred, and what changes

| Deferred item | Why the first roadmap deferred it | Required before start | Roadmap 2 decision |
| --- | --- | --- | --- |
| Published crates | No exact package, schema, and integration-identity contract existed. | Version 2 plan and receipt schemas are accepted; RT-3.5 SDK work has settled the wire types. | Define the current distribution contract first. Publish only pure crates and the independent verifier. Never publish the launcher as a library. |
| Automatic policy inference | Authority generated from an arbitrary executed program would be labeled as inferred or safe. | RT-3.3 scaffold exists; RT-3.4 has decided whether a diagnostic profile is permitted. | Trace-assisted drafting under a distinct, non-reusable diagnostic profile. Every generated entry carries provenance. Write roots, environment names, limits, and network stay human choices. |
| Hostname allow-list as a port-only rule | It is the exact substitution the RT-4.3 decision gate rejects. | Never. | Rejected permanently. Replaced by a multi-service extension of the RT-5 mechanism. |
| macOS or Windows under the Linux label | No native equivalent of Landlock, seccomp, and cgroup v2 exists; a native profile would fork the assurance chain. | Milestone C install path and RT-6.3 setup-cost benchmarks exist. | Run the unchanged native Linux runtime inside an identified guest. Make the host profile distinguishable in the receipt. Add the hypervisor and guest image to the trusted computing base. |
| Hosted receipt database | No consumer needed query or retention; a signature moves the trust anchor rather than removing it. | RT-2 acceptance has shipped and two consumers exist. | Signing and transparency ADR first. Then an append-only, content-addressed log with inclusion and consistency proofs. No query database. Hosting is a later operator role. |
| Daemon or multi-tenant service | Long-lived state and multi-tenancy are initial-profile non-goals; there was no measured need. | RT-6.3 benchmarks show setup cost dominates and one adopter runs repeated invocations. | ADR and new threat-model section. Single-tenant service that never reuses a boundary. Multi-tenancy is a separate decision whose default answer is one instance per tenant. |

## 3. Trusted computing base delta

The first roadmap ordered memory before network because memory used an
existing mechanism. This roadmap applies the same rule to every item.

| Epic | New trusted roles | Receipt or schema effect | New adversary |
| --- | --- | --- | --- |
| RT-7 crates | None in the production profile. The crate registry becomes a distribution trust input beside the GitHub release channel. | None. | Registry substitution of crate bytes. |
| RT-8 trace-assisted drafting | None in the production profile. The diagnostic profile trusts its observer mechanism, which is enumerated in the diagnostic ADR. | A diagnostic receipt kind that is never reusable. No change to production receipts. | A program that behaves differently when observed. |
| RT-9 multi-service network | None beyond the roles RT-5 already added, multiplied by service count. | A typed non-empty service set in the current plan and receipt contracts. | Cross-service confusion within the allowed set. |
| RT-10 VM host profile | Hypervisor, guest image, guest kernel, host-guest transport, and the host-side orchestration tool. | Guest identity must be distinguishable; decided in RT-10.1. | Malicious host operating system, which is treated the same way as host root: out of scope. |
| RT-11 and RT-12 signing and log | Signing identity and key custody, log operator, and any witness set. | A signed envelope and inclusion proof retained beside the receipt. The receipt bytes do not change. | Equivocating log operator; compromised signing key. |
| RT-13 execution service | Long-lived supervisor state, API authentication, and shared immutable caches. | An execution-service identity and session binding in the run result. | Malicious API client; co-tenant if multi-tenancy is ever accepted. |

## 4. Ordered roadmap

| Order | Epic | Hard dependency | Exit condition | Size |
| ---: | --- | --- | --- | --- |
| 0 | RT-7 prelaunch packaging and published crates | Current plan and receipt schemas accepted; RT-3.5 SDKs stable | Selected crates are published under a current distribution contract, the verifier crate builds with no workspace dependency, and the release workflow proves crate bytes match the selected exact source. | S |
| 1 | RT-8 trace-assisted plan drafting | RT-3.3 scaffold; RT-3.4 diagnostic-profile decision | A dynamic executable's draft plan can be produced from one observed diagnostic run; the diagnostic receipt is rejected by both verifiers and by acceptance with a typed reason; every generated entry names its provenance. | M |
| 2 | RT-9 multi-service network allow-list | RT-5 shipped with one accepted mechanism; its ADR is accepted but production implementation remains open | Two or more declared services are reachable, every registered cross-service attack fails with its typed reason, and the receipt records the exact enforced service set. | M |
| 3 | RT-10 Linux VM host profile | Milestone C; RT-6.3 benchmarks | A macOS or Windows developer reaches an independently verified receipt through maintained instructions, and an acceptance policy can accept or reject guest-produced receipts by identity. | L |
| 4 | RT-11 signing and transparency ADR | RT-2 shipped | An ADR selects a signing identity and log model or rejects them with reasons. | M |
| 5 | RT-12 content-addressed receipt log | Order 4 accepted; two consumers | A third party holding a checkpoint and a receipt commitment verifies inclusion and consistency offline without trusting the operator. | L |
| 6 | RT-13 execution service ADR and single-tenant service | RT-6.3 benchmarks show need; one adopter with repeated invocations | Repeated executions reuse tool setup without reusing any boundary, and the per-execution launcher is byte-identical to the CLI path. | L |
| 7 | RT-13.5 multi-tenancy decision | Order 6 measured | An ADR accepts multi-tenancy with a co-tenant threat model or rejects it in favor of one instance per tenant. | M |

Size is measured in this project's units. S is one claim wave with no schema
identity replacement. M is one or two claim waves with one schema identity
replacement or one ADR. L is three or more claim waves with a new threat-model
section.

Orders express merge dependencies, not a ban on parallel investigation. The
RT-11 ADR can be drafted while RT-8 and RT-9 are in progress, because it is a
document. RT-10's guest image can be prototyped early, because it is a build
artifact that does not touch the runtime.

## 5. Epic RT-7: prelaunch packaging and published crates

The first roadmap deferred publication until package and schema identities were
explicit. The product is prelaunch with no users, so this epic does not spend
time on backward compatibility. It publishes only a closed current package set.
The
[RT-7 integration record](roadmap-2/rt-07-compatibility-and-distribution.md)
defines how exact Runtime, Proofbound, Auths, and Capsec identities enter a
tested platform tuple without coordinating their releases. Draft
[Specification 0014](specs/0014_public_compatibility_and_distribution.md)
defines the native Runtime prelaunch distribution contract.

### RT-7.1 Write the current distribution contract

- Treat package versions as required prelaunch labels, not compatibility
  promises. Bind support to exact source, package, schema, and tool identities.
- Keep wire schemas closed. Replace an identifier when bytes would otherwise
  acquire new security meaning, then replace the complete current tuple
  atomically.
- Version 2 and later wire objects are deterministic CBOR defined by CDDL
  under [ADR 0003](adr/0003-deterministic-cbor-wire-objects.md). Published
  crates ship the CDDL and golden vectors, and the JSON projection is
  documented as a view.
- Define which crates are public. The candidates are the pure core, the
  canonical receipt encoder, the independent verifier, and the composer. The
  launcher, supervisor, and `sys.rs` are never published as a library, because
  an embedding process would then run the child security path in its own
  address space.
- State that the crate registry is a distribution trust input, exactly as the
  GitHub release channel is today. A registry checksum names bytes; it does
  not authenticate a publisher until RT-11 selects one.
- Define the correction policy for any artifact that reaches a registry. Never
  replace bytes under an existing artifact identity.

### RT-7.2 Publish the independent verifier first

- The verifier crate already has no workspace dependency. Keep that property
  as a test that runs in the publish workflow.
- Publish it before any producer crate, so a consumer can vendor the verifier
  without pulling producer semantics.
- Record the published crate's SHA-256 in the release provenance summary from
  RT-0.5.

### RT-7.3 Publish the pure crates

- Flip `publish = false` only on the selected crates.
- Keep exact dependency pins and the existing `cargo-deny` gate.
- In the release workflow, run `cargo package`, compute the packaged tarball
  digest, and compare its file list and bytes against the selected exact source
  tree.
  A mismatch fails the release.
- Do not publish from a developer machine. Publication is a release-workflow
  step on the exact merge SHA.

### RT-7.4 Align the SDKs

- The Python and TypeScript packages from RT-3.5 identify the exact current
  schema set, not crate internals.
- Add a drift test that fails when a published crate's serialized form and the
  committed JSON schema disagree.

### RT-7.5 Falsify

- A crate that gains a workspace dependency fails the publish preflight.
- A schema meaning edit without a new schema identity fails the drift test.
- A consumer selecting a package outside the exact current tuple is rejected.
- A publish from a non-release context is refused.

**Done when:** a consumer can depend on the verifier and the pure core from
the selected distribution channel, reproduce the package bytes from the exact
source revision, and read one document that identifies the exact current
supported tuple.

## 6. Epic RT-8: trace-assisted plan drafting

The first roadmap rejected "automatic policy inference from arbitrary executed
programs" because generated authority would be presented as inferred or safe.
The honest form is a diagnostic run under a distinct profile whose output is a
draft that a human must complete. This epic extends RT-3.3 and depends on the
RT-3.4 decision that a live trace mode is permitted at all.
The [RT-8 integration record](roadmap-2/rt-08-capability-informed-drafting.md)
adds optional Capsec source observations as a separate provenance class. They
can identify review differences but can never grant Runtime authority.

### RT-8.1 Specify the diagnostic profile

- Add a closed `ExecutionProfile` with `Production` and `Diagnostic`. There is
  no third value.
- A diagnostic run installs the same Landlock, seccomp, and cgroup boundary as
  a production run for the declared plan, and adds an observer. It does not
  weaken the boundary to let the program succeed.
- Use the separate ptrace observer selected by
  [ADR 0008](adr/0008-separate-ptrace-diagnostic-observer.md). It expands only
  the diagnostic trusted computing base. No observer code or entry point enters
  the production profile.
- A diagnostic receipt has its own schema and is never reusable. Both
  verifiers and `pbr-accept` reject it with a stable typed reason.

### RT-8.2 Turn observations into a draft

- Start from the RT-3.3 static scaffold. Add observed entries with a distinct
  provenance kind, so a reviewer can tell an ELF-resolved dependency from an
  observed file access.
- Map observed denied and permitted opens, executes, and directory reads to
  candidate read, write, and executable roots using explicit collapse rules.
  State the rules. Never collapse toward the filesystem root, the home
  directory, or a temporary directory root.
- Record observed network attempts as open items. Never generate network
  authority from observation, under any mechanism.
- Require the user to choose write roots, environment names, resource limits,
  and network mode before `plan check` accepts the draft. A draft with an
  unmade choice is not a valid plan.
- Render authority breadth in the draft: the count of roots, whether any root
  is a home or system directory, and the count of observed denials that
  remain unexplained. A hostile program that touches everything produces a
  draft that visibly asks for everything.

### RT-8.3 State the coverage bound

- One observed run is one path through the program. The draft records the
  inputs, environment names, and arguments that produced it.
- A program that detects observation may behave differently. The draft states
  the observer mechanism so the reviewer knows what the program could detect.
- The draft is not a claim. Its file header says so.

### RT-8.4 Falsify

- A diagnostic receipt submitted to `pbr-verify`, `pbr-compose`, or
  `pbr-accept` is rejected with `profile.diagnostic.not-reusable` or the
  equivalent stable identifier.
- A draft with an unmade choice fails `plan check`.
- A program that opens a symlink to a system directory produces a draft entry
  naming the resolved target, not the link.
- A program that attempts network access produces an open item and no
  authority.
- The production profile binary contains no observer code path. Confirm by
  feature gate or separate binary and by a source-closure check.

**Done when:** a developer with a dynamic executable and no static build can
reach a reviewable draft plan in one diagnostic run, and no output of that run
can be mistaken for a production receipt or a safe policy.

## 7. Epic RT-9: multi-service network allow-list

This epic exists only if RT-4 accepted a mechanism and RT-5 shipped it for one
service. It replaces the rejected port-only hostname item. It does not add a
new mechanism. RT-4's ADR is accepted, but RT-5 production implementation is
still open, so RT-9 remains blocked. The
[RT-9 integration record](roadmap-2/rt-09-authorized-service-execution.md)
keeps Auths action authorization distinct from Runtime service identity and
defines the required identity-confusion attacks.

### RT-9.1 Extend the authority model

- Change the accepted single-service `NetworkAuthority` variant to carry a
  typed non-empty set of service declarations. Each entry carries the exact
  identity kind the ADR accepted: a routing endpoint, a broker-enforced
  service, or an authenticated service identity. No entry is a bare string.
- Keep `Deny` unchanged. Keep the single-service form valid as a set of one.
- Replace the plan, compiled policy, launcher protocol, receipt, run result,
  verifier, composer, and acceptance-policy schema identities together, as
  RT-5.1 requires. No transition surface is retained before launch.
- Bound the set size. State the bound and its reason.

### RT-9.2 Add the cross-service attack corpus

Extend the frozen network attack matrix with cases that only exist when more
than one service is allowed:

- service confusion, where the transport identity names service A and the
  application layer names service B;
- a redirect from allowed A to allowed B that carries A's credential;
- credential binding per service, so a secret made available for A is not
  presented to B;
- connection reuse across services;
- a resolver that returns B's address for A's name; and
- receipt observation growth with the maximum allowed set.

### RT-9.3 Record the enforced set

- The receipt records the exact enforced service set and per-service bounded
  connection observations.
- The acceptance policy can require an exact set, a subset, or reject any
  multi-service execution.

### RT-9.4 Named presets

- A convenience name such as an LLM provider preset is a reviewed bundle that
  expands to exact typed declarations before normalization. The plan identity
  binds the expansion, never the preset name alone.
- A preset lives in an identity-bound, reviewed file. A changed preset is a changed
  plan.

**Done when:** one agent calls two declared services, every cross-service
attack fails for its typed reason, and the receipt says exactly which services
the mechanism enforced and nothing broader.

## 8. Epic RT-10: Linux VM host profile for macOS and Windows

The threat model puts macOS and Windows behavior out of scope, and the first
roadmap deferred them "under the Linux assurance label." The objection is the
label. No native macOS or Windows mechanism provides Landlock, seccomp, and
cgroup v2 semantics, so a native profile would need its own threat model,
claim set, verifier profile, and evidence chain. This roadmap does not build
one.

The honest path runs the unchanged native Linux runtime inside an identified
guest. From the runtime's point of view the guest is a supported Linux host.
The new work is a host-side orchestration tool, a reproducible guest image,
and a way for a receipt consumer to tell a guest-produced receipt from a
bare-metal one.
The [RT-10 integration record](roadmap-2/rt-10-guest-identity.md) separates
host-tool, hypervisor, guest, guest-kernel, Runtime-release, workload, and
Proofbound-release identities.

### RT-10.1 Decide the host profile in an ADR

- Enumerate the added trusted roles: the hypervisor and its host framework,
  the guest image, the guest kernel, the host-guest transport, and the host
  orchestration tool.
- Decide how a consumer distinguishes a guest-produced receipt. The candidates
  are a maintained guest kernel with a distinct recorded identity that
  acceptance policy can pin, or an explicit host-profile field in replacement
  plan and receipt schema identities. Do not rely on convention.
- State the claim language: the native Linux boundary was installed inside an
  identified guest; the host operating system is a distribution and transport
  premise, not an enforcement mechanism. The phrase "macOS enforcement" does
  not appear.
- Decide whether an externally managed guest such as WSL2 is supported. The
  maintainers do not control that kernel's configuration. It is supported only
  if it passes the same capability probes as any other Linux host, and its
  receipts carry that kernel's identity. The maintained path is the
  Runtime-built image.

### RT-10.2 Build a reproducible guest image

- A minimal Linux image with a kernel that provides the required Landlock ABI,
  seccomp features, and a delegated cgroup v2 subtree with the `pids`,
  `memory`, and any later required controllers.
- Build it reproducibly twice in the release workflow and record its digest
  and kernel identity in the release provenance summary.
- Ship no swap unless the memory profile's swap semantics require it; state
  the choice.
- Include the exact `pbr` bundle for the guest architecture. The image and the
  bundle share one release identity.

### RT-10.3 Build the host orchestration tool

- A separate `pbr-host` executable, not a mode of `pbr`. It boots the guest,
  transfers the plan and declared inputs, invokes the guest `pbr run`, and
  retrieves the receipt, the output tree, and the run result.
- Transfer by copy with identity checks in both directions. Inputs are
  digested on the host and revalidated in the guest. Outputs are digested in
  the guest and revalidated on the host. Do not mount the host filesystem into
  the child's authority; Landlock over a shared filesystem would change the
  identity assumptions the threat model records.
- Carry the receipt commitment on the host-guest control channel, separately
  from the receipt bytes, so ADR 0002 holds across the guest boundary.
- The host tool cannot widen the plan. It passes plan bytes through unchanged
  and the guest `plan check` is the authority.
- Support the Apple virtualization framework on macOS and Hyper-V on Windows.
  Where nested virtualization or the framework is absent, fail closed with a
  `doctor --explain` remediation.

### RT-10.4 Meet the first-run target

- Measure guest boot plus one execution against the RT-6.3 baselines. Publish
  median and p95 with host identity.
- Target a five-minute path from download to a verified receipt on a macOS
  laptop. State what the path installs.

### RT-10.5 Falsify

- A mutated receipt on the transport is detected by the commitment.
- An input substituted between host digest and guest use is rejected in the
  guest.
- A guest image whose digest differs from the release identity is refused.
- A host tool that attempts to pass a modified plan is detected by the guest's
  plan identity.
- An acceptance policy that pins bare-metal kernel identities rejects a
  guest-produced receipt with a typed reason.

**Done when:** a macOS or Windows developer reaches an independently verified
receipt through maintained instructions, the receipt or its identities show
that a guest produced it, and no public text describes the host operating
system as an enforcement mechanism.

## 9. Epic RT-11: signing and transparency ADR

ADR 0002 records that a carrier controlling both the receipt and the alleged
commitment still wins, and that the channel supplying the commitment is a
visible premise. The first roadmap said signatures and transparency are
evaluated only through a new ADR. This epic writes it. It produces a document,
not code.
The
[RT-11 integration record](roadmap-2/rt-11-signing-and-platform-identity.md)
requires the ADR to map principal, workload, product, release, guest, service,
operator, and witness identities without treating any signature as execution
truth.

### RT-11.1 State what a signature can and cannot do

- A signature binds bytes to a key. It moves the trust anchor to key custody
  and identity policy. It does not prove the recorded execution happened, that
  the producer observed the claimed effects, or that the host was correct.
- The threat model already names a fallible producer. A producer's own
  signature attests origin, not truth. Any design that presents a
  self-signature as proof of execution is rejected.

### RT-11.2 Evaluate signing identities

Evaluate at least:

1. an ephemeral, workload-bound identity issued at run time, in the style of
   keyless signing tied to a CI provider's identity token;
2. a long-lived product or release identity for release bundles and guest
   images;
3. the maintainer's existing KERI-based delegated signing already used for
   commits and releases, evaluated on custody, revocation, and independent
   verification without a hosted service; and
4. a combination in which release artifacts carry a product identity and each
   execution carries the invoking workload identity.

For each, record custody, revocation, offline verifiability, which trusted
role holds the key, and what an adopter's acceptance policy must pin.

### RT-11.3 Evaluate envelopes and statements

- The payload is the exact deterministic CBOR receipt bytes under
  [ADR 0003](adr/0003-deterministic-cbor-wire-objects.md). Evaluate a
  detached signing envelope that wraps them without reserialization. The
  receipt bytes must not change.
- Evaluate whether the composed receipt and acceptance decision should be
  expressible as an attestation statement that existing policy engines can
  consume. Do not let an external statement format redefine receipt meaning;
  the Runtime schema remains authoritative.

### RT-11.4 Evaluate the log model

- An append-only Merkle log with signed checkpoints, inclusion proofs, and
  consistency proofs, keyed by receipt commitment.
- A witness set that co-signs checkpoints so a single operator cannot present
  two histories undetected.
- Self-hosted first. A public or hosted log is an operator role that a later
  decision adds.
- Reject any design in which the log operator can equivocate undetectably or
  in which a log timestamp is presented as proof of freshness. A log
  timestamp is the operator's claim and is treated as the separately trusted
  current-time input that RT-2.1 requires, with its source named.

**Decision gate:** reject any design whose public text says "signed, therefore
verified" or "logged, therefore happened."

**Done when:** an accepted ADR names the signing identity, envelope, log
model, witness policy, new trusted roles, and the exact acceptance-policy
facets an adopter can pin, or a rejected ADR says why none of the candidates
is honest.

## 10. Epic RT-12: content-addressed receipt log

This epic exists only if RT-11 accepts a design and two consumers exist. It
builds a log, not a database. Query and retention services stay deferred until
the log has consumers.
The [RT-12 integration record](roadmap-2/rt-12-composed-retention.md) defines
the complete native-object closure and verification order. The log retains
separate Capsec, Auths, Runtime, and Proofbound objects plus typed links; it does
not replace them with one semantic record.

### RT-12.1 Define the entry

- An entry is the exact receipt bytes, its commitment, the composed receipt
  when present, the acceptance decision when present, and the signing
  envelope. Entries are immutable and content-addressed by commitment.
  Entries and checkpoints are deterministic CBOR under ADR 0003.
- Entries contain no secret values. Receipts already exclude them; the log
  adds no field that could carry one.
- Define retention as a policy of the operator, recorded in the checkpoint
  metadata, not as a property of the entries.

### RT-12.2 Store as artifacts before servers

- Start with content-addressed artifacts in an object store or an OCI
  artifact convention, with a Merkle index and signed checkpoints.
- Add a server only when two consumers need concurrent submission.

### RT-12.3 Implement `pbr-log`

- Commands: submit, prove inclusion, verify a checkpoint, verify consistency
  between two checkpoints.
- The proof verifier is a separate implementation with no shared semantic
  code with the log writer, following the producer and verifier separation
  the contributor guide requires.
- Publish output with no-replace semantics, as every other tool does.

### RT-12.4 Make the log a policy input

- `pbr-accept` may require an inclusion proof against a pinned checkpoint and
  witness set. The policy names the checkpoint source as a trust input.
- Acceptance remains separate from inclusion. A logged receipt can still be
  rejected by policy, and an accepted receipt is not implied to be logged.

### RT-12.5 Falsify

- A split-view attack, where two consumers receive different checkpoints, is
  detected by witness co-signatures or consistency proofs.
- A rolled-back log fails consistency verification.
- A substituted entry fails inclusion verification against the commitment.
- A replayed old checkpoint is rejected by the pinned witness policy.
- An operator-forged inclusion proof fails without the operator's key
  compromising the witnesses.
- A receipt submitted without its independent commitment is refused.

### RT-12.6 Offer hosting only after two self-hosted consumers

- Hosting adds an operator role to every consumer's trusted computing base.
  Document it as such.
- The hosted log must be verifiable with the same offline tools. A consumer
  who cannot verify offline has no reason to trust the hosted one.

**Done when:** a third party who holds a checkpoint, a witness set, and a
receipt commitment can verify inclusion and consistency offline, without an
account, and without trusting the operator.

## 11. Epic RT-13: execution service

The first roadmap forbids a daemon without measured need and names long-lived
state and multi-tenancy as initial-profile non-goals. This epic opens only when the
RT-6.3 benchmarks show that repeated setup cost dominates and one adopter runs
repeated invocations. If the benchmarks do not show that, this epic stays
closed and the record says so.
The [RT-13 integration record](roadmap-2/rt-13-platform-execution-service.md)
defines the Auths caller, Runtime service, integration profile, response
commitment, native verifier, and optional Capsec drafting boundaries. It keeps
the per-execution launcher identical to the CLI path.

### RT-13.1 Confirm the need

- Cite the published RT-6.3 measurements for repeated invocations.
- Name the adopter and the workload.
- State which setup cost a service would remove: tool identification, closure
  inventory, or guest boot. A service may not remove boundary installation.

### RT-13.2 Write the ADR and threat-model section

- Add a long-lived supervisor, API authentication, and shared immutable caches
  as trusted roles.
- State what is shared across executions: exact tool identities and immutable
  digested artifacts only. Cgroups, Landlock rulesets, seccomp filters, output
  roots, launcher state, and control channels are never shared.
- State that the per-execution launcher is the same binary as the CLI path
  and is byte-identical in the bundle.
- Add a malicious API client to the adversary list.

### RT-13.3 Build the single-tenant service

- One operating-system user, one delegated cgroup subtree, one caller
  identity, a bounded queue, and bounded concurrency.
- Each execution still emits its receipt commitment on an authenticated
  control channel, so ADR 0002 holds when the channel is an API response.
- The service can be stopped and restarted without any execution surviving
  the restart. There is no resumable execution.
- The service records its own identity in each run result so a consumer can
  tell a service-produced receipt from a CLI-produced one.

### RT-13.4 Falsify

- Cross-execution state leakage through a shared cache is detected by a cache
  substitution attack.
- A replayed API request produces no second execution.
- Concurrent executions cannot confuse receipt and commitment channels.
- Queue exhaustion by one client is bounded and typed.
- A stale cached artifact whose digest no longer matches the plan is refused.
- A service process with an ambient capability or elevated identity refuses
  to start.

### RT-13.5 Decide multi-tenancy separately

- Write a separate ADR with a co-tenant adversary.
- The default answer is one service instance per tenant, each with its own
  operating-system user and cgroup subtree. This keeps the trusted boundary
  small and reuses the single-tenant evidence.
- Accept true multi-tenancy in one service only if the ADR shows a measured
  need that per-tenant instances cannot meet, and only with its own native
  attack corpus.

**Done when:** repeated executions on one host reuse tool setup without
reusing any boundary, the service adds no step to the child security path, a
consumer can identify service-produced receipts, and multi-tenancy has a
recorded decision rather than an assumption.

## 12. Cross-epic acceptance and release rules

Every epic in this roadmap uses the merge checklist from section 13 of the
first roadmap. These rules are added:

1. Enumerate every new trusted role in the threat model before the first
   implementation PR. The tables in section 3 are the starting inventory, not
   the record.
2. Do not change the meaning of an existing schema identifier. A prelaunch
   replacement can remove an older schema immediately, but it must use a new
   identifier and update the complete current tuple. Historical receipts remain
   bound to their original subjects.
3. Make every distinguishing property typed. A diagnostic receipt, a
   guest-produced receipt, and a service-produced receipt are distinguishable
   by a field or a pinned identity, never by convention or file location.
4. Treat every new distribution channel as a trust input: crate registry,
   guest image channel, log operator, and service operator. A digest beside
   an artifact names bytes; it authenticates nothing until RT-11 lands.
5. Keep the child security path in one place. No crate, SDK, host tool, log,
   or service duplicates launcher sequencing or boundary installation.
6. Encode every new committed object as deterministic CBOR under
   [ADR 0003](adr/0003-deterministic-cbor-wire-objects.md). JSON appears
   only as a rendered view.
7. Keep every foreign semantic decision with its owner protocol. Verify native
   objects first, then verify typed links, then apply consumer policy under
   [Specification 0013](specs/0013_platform_integration_contract.md).
8. Publish a tested integration tuple before describing a combination of
   Runtime, Proofbound, Auths, Capsec, schemas, SDKs, and verifiers as one
   supported platform profile.

No item in this roadmap may:

- present generated authority as safe, minimal, or inferred;
- describe a host operating system as an enforcement mechanism;
- present a signature or a log entry as proof that an execution happened;
- let a long-lived process hold a boundary across executions; or
- ship a hostname allow-list whose kernel rule is broader than its receipt
  language.

## 13. Product milestones

### Milestone F: embeddable

- The current distribution contract is published.
- The independent verifier and pure core are on the registry with
  reproducible bytes.
- The SDKs identify the exact current published schema set.
- The current-integration manifest names every supported integration tuple
  without coordinating product releases. A Runtime-only tuple can ship before an
  optional Auths or Capsec profile.

### Milestone G: first run without a static binary

- A diagnostic run produces a reviewable draft for a dynamic executable.
- No diagnostic output is accepted by any verifier or acceptance policy.
- Optional Capsec observations remain identifiable drafting provenance and
  cannot add authority.

### Milestone H: honest multi-service agents

- One agent calls two declared services under the accepted mechanism.
- The cross-service attack corpus passes on both architectures.
- One maintained flow binds an Auths authorization decision to the Runtime
  execution without equating action identity with service identity.

### Milestone I: laptop trial

- A macOS or Windows developer reaches a verified receipt in five minutes
  through the guest image and host tool.
- Acceptance policy can distinguish guest-produced receipts.
- The receipt chain distinguishes host, guest, Runtime release, and invoking
  workload identities.

### Milestone J: third-party-verifiable retention

- The signing and transparency ADR is accepted.
- A self-hosted log has two consumers and offline proof verification.
- A consumer can export and verify the separate Auths, Runtime, and Proofbound
  object closure plus its typed linkage and integration records.

### Milestone K: service on measured need

- Benchmarks justify a service or the record says they do not.
- A single-tenant service exists with an unchanged child security path.
- Multi-tenancy has a recorded decision.
- The CLI and service paths produce the same native and linked receipt
  semantics under one tested integration profile.

## 14. Explicitly rejected

These are not deferred. They are rejected unless the stated premise changes.

- **A hostname allow-list backed by a port-only rule.** The receipt would say
  "only this service" while the kernel enforces "any endpoint on this port."
  Rejected under the RT-4.3 decision gate. Revisit only if the kernel gains a
  service-identity enforcement primitive.
- **A native macOS or Windows boundary under the Linux assurance label.**
  Rejected because it forks the assurance chain. Revisit only with a separate
  threat model, claim set, and verifier profile that carry their own label.
- **Generated authority labeled safe, minimal, or inferred.** Rejected in
  every profile. A draft is a draft.
- **A producer self-signature presented as proof of execution.** Rejected
  because the threat model names a fallible producer.
- **Multi-tenancy in one service before a co-tenant threat model.** Rejected.
  One instance per tenant is the default.
- **A resumable or migratable execution.** Rejected because a boundary that
  survives its supervisor cannot be re-verified.

## 15. What this roadmap does not decide

- Which buyer arrives first. Orders 0 through 2 serve both. Orders 3 and 4
  can swap on evidence.
- Whether a hosted log or a service is ever operated by the maintainers.
  Both are operator roles that a later decision adds.
- Any confidential-computing or remote-attestation work. The threat model
  keeps it out of scope. A future roadmap may combine an identified guest
  with hardware attestation, but that requires its own ADR and is not implied
  by RT-10. The
  [RT-20 candidate record](roadmap-3/rt-20-host-fleet-identity.md) preserves the
  questions and promotion gate without reopening this scope.

The [Roadmap 3 candidate register](product-roadmap-3-candidates.md) also
preserves credential custody, operation-scoped mediation, organizational policy
lifecycle, integration profiles, multi-language analysis, and evidence
discovery. It cannot promote or reorder work in this roadmap.

The roadmap favors the same small, reviewable chain as the first one:
publish what is already pure, draft plans without pretending they are safe,
extend the network profile only on the mechanism that survived, put the Linux
boundary in a guest without renaming it, and add signatures and logs only
after writing down what they do not prove.
