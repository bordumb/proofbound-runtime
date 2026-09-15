# Vision: proof-carrying agent software

- **Status:** product vision; non-normative
- **Scope:** the Proofbound, Proofbound Runtime, Auths, and Capsec ecosystem
- **Stage:** prelaunch; zero external users

## Thesis

Frontier language models are making proof construction, theorem translation,
and Lean formalization cheap enough that continuously formalized software may
become practical. A development system can increasingly draft a proposition,
generate a model, attempt a proof, find counterexamples, revise the design, and
repeat this work whenever the source changes.

That changes the cost of formal work. It does not settle the harder product
problem: deciding what should be claimed and connecting the claim to the thing
a consumer must decide about.

Useful assurance requires an honest chain across different kinds of objects:

- a plain-language claim and its exact scope;
- a formal proposition, model, assumptions, and exclusions;
- production source and the functions that implement the modeled behavior;
- built artifacts and the release process that produced them;
- one execution, including its declared authority and observed result;
- the principals, workloads, grants, and delegations that authorized it;
- source-level capability observations that informed the plan; and
- the consumer policy that decides whether the resulting evidence is enough.

The vision is **proof-carrying agent software**: agent software whose releases
and consequential executions can be accompanied by a typed, independently
verifiable graph of claims, evidence, identities, assumptions, and receipts.
The graph does not assert that the software is universally correct. It gives a
consumer enough exact information to decide whether a bounded claim is
supported for a particular artifact, execution, and use.

The [initial Runtime specification](specs/0001_initial_spec.md) supplies the
first concrete foundation. It asks three narrow questions: what authority the
child received, whether the selected Linux boundary was installed, and what
exact result was observed. The broader ecosystem extends that foundation
without converting it into a universal proof system.

## Why this becomes possible now

Formal methods have traditionally been constrained by expert time. The costly
parts include selecting a tractable proposition, expressing it in a prover,
maintaining the proof as code changes, and investigating failed proof attempts.
Language models can reduce the mechanical cost of several of these activities.
They can propose invariants, translate closed domains, generate proof attempts,
construct adversarial examples, and explain mismatches between a theorem and
production code.

If those costs continue to fall, formalization can move from an exceptional
project to a continuous development activity. A claim-sized change can carry a
claim, a falsifier, a bounded check, a model theorem where appropriate, and an
exact source or artifact link. When the source closure changes, the relevant
evidence can be invalidated and rebuilt. The
[assurance plan](assurance-plan.md) demonstrates this progressive pattern for
current Runtime claims.

Cheap proof construction is not cheap judgment. A model can prove the wrong
proposition, omit a real effect, assume the behavior it should establish, or
remain disconnected from the shipped binary. Generated formal work also needs
review, reproducible tooling, independent checking, and exact identity. The
scarce capability therefore shifts toward:

1. stating claims that match a real consumer decision;
2. keeping the claimed subject and source closure exact;
3. exposing every assumption and trusted component;
4. linking model, source, artifact, execution, and authorization identities;
5. preventing evidence from acquiring meaning it does not have; and
6. making the final acceptance rule explicit and consumer-owned.

Proofbound's product opportunity is to supply that accountability structure
while models lower the cost of producing candidate evidence within it.

## Four products, four native meanings

The ecosystem contains four cooperating products in four repositories:
Proofbound (`bordumb/proof-bound`), Proofbound Runtime
(`bordumb/proofbound-runtime`), Auths (`auths-dev/auths-proof`), and Capsec
(`auths-dev/capsec`). They use typed links and exact identities, but they do
not share one semantic core or one receipt format. The draft
[platform integration contract](specs/0013_platform_integration_contract.md)
defines this separation in detail.

| Product | Owns | Does not claim |
| --- | --- | --- |
| **Proofbound** | Claims, evidence admission, assurance facets, assumptions, exclusions, source closures, release subjects, artifact linkage, and generic receipt composition | Authorization, domain policy, Linux containment, or truth of another product's native semantics |
| **Proofbound Runtime** | Execution plans, normalized authority, Linux policy compilation, boundary installation, observations, execution receipts, and Runtime receipt acceptance facets | Principal authorization, complete source capability analysis, generic assurance status, arbitrary program correctness, or Linux correctness |
| **Auths** | Principal and workload identity, grants, delegation and attenuation, authorization decisions, action profiles, and signed Auths receipts | Linux enforcement, Runtime execution meaning, Proofbound claim status, or source capability completeness |
| **Capsec** | Source-level capability observations, findings, analyzer identity, source closure, and analysis limitations | Authorization, production boundary installation, Runtime receipt meaning, or Proofbound assurance status |

This division is a security property, not an organizational preference. It
prevents a valid fact in one domain from silently becoming a stronger fact in
another. A Capsec observation can inform a draft plan, but it cannot grant
authority. An Auths decision can authorize an action, but it cannot show that a
Linux boundary was installed. A Runtime receipt can record a bounded execution,
but it cannot show that the action was authorized or the output was correct. A
Proofbound release receipt can describe admitted evidence for exact artifacts,
but it cannot turn an execution observation into a theorem.

The products compose as a directed graph:

```text
Capsec source observation ----> human-reviewed Runtime plan
                                      ^
Auths authorization decision --------+----> Runtime execution receipt
        |                                         |
        +------> Auths execution/linkage record <-+
                                                      \
Proofbound release and artifact evidence --------------> composed view
                                                             |
                                      consumer acceptance policy
                                                             |
                                                      bounded decision
```

Every arrow is an explicit typed relationship between exact bytes or exact
subjects. Each native object is verified by its owner's independent verifier
before cross-project linkage is evaluated. Composition retains the weakest
status, all assumptions, all trusted-computing-base roles, and each verifier's
identity. The [release composition specification](specs/0003_release_receipt_composition.md),
[cross-receipt linkage specification](specs/0008_cross_receipt_linkage.md), and
[receipt acceptance specification](specs/0010_receipt_acceptance_policy.md)
apply this pattern to concrete Runtime flows.

There is deliberately no universal receipt. A universal receipt would need to
reinterpret foreign semantics, couple release cycles, and create one large
trusted parser and policy engine. A platform SDK may orchestrate native tools
and present a coherent experience, but it must not replace their verifiers or
move their domain rules into shared code.

## End-to-end lifecycle

Proof-carrying agent software is a lifecycle, not a document generated at the
end of a build.

### 1. Define the consumer decision

Start with the decision a user, CI gate, operator, or downstream agent needs to
make. Examples include whether a release contains an independently verified
receipt verifier, whether an agent ran with no network authority, or whether a
particular provider action was both authorized and executed under a declared
boundary. A claim that cannot change a consumer decision should not drive an
expensive assurance wave.

### 2. Register an honest claim

State the claim in plain language. Identify its exact production subject,
source closure, assumptions, exclusions, target evidence tier, and falsifiers.
Separate properties of a pure model from effects performed by the operating
system. Use a new claim when the meaning changes rather than stretching an old
identity.

### 3. Observe source capabilities

Capsec can produce an optional observation bound to exact source and analyzer
bytes. Runtime can compare those observations with static executable closure,
diagnostic observations, and a human-authored plan. Unknown, stale, or
incomplete reports remain visible. The operator still selects final authority,
network access, environment names, write roots, and resource limits. This is
the boundary described by the
[RT-8 integration record](roadmap-2/rt-08-capability-informed-drafting.md).

### 4. Authorize the intended action

Auths identifies the principal and workload, resolves grants and delegation,
and produces its native authorization decision for a canonical action. An
integration profile maps that action to Runtime inputs without equating an
Auths provider alias with a Runtime service identity. The exact authorization
decision can become a declared Runtime input.

### 5. Build evidence progressively

For each claim, use the smallest adequate evidence:

- a claim ledger, assumptions, exclusions, source closure, and tests;
- bounded checks, negative cases, mutation witnesses, and independent
  conformance;
- a Lean theorem about a closed formal model; and
- source refinement and exact artifact linkage where the claim and cost
  justify it.

The tiers apply to individual claims. Effectful launcher sequencing may remain
tested and model-only while a small pure normalization function reaches source
refinement. A strong result for one claim must not promote adjacent claims.

### 6. Bind the release

The release path identifies exact source, workflows, toolchains, verifier
artifacts, Runtime artifacts, schemas, and package bytes. Independent
reproduction and artifact observation can connect an admitted claim to shipped
bytes under named premises. Labels required by package tools are metadata; the
authoritative identities are source revisions, schema identifiers, digests,
and tested integration tuples. The current prelaunch rules are in
[Specification 0014](specs/0014_public_compatibility_and_distribution.md).

### 7. Execute under a declared boundary

Runtime validates and normalizes the plan, resolves security-relevant files,
compiles a complete policy, installs the supported Linux boundary, and starts
child code only after all required witnesses exist. It records the exact plan,
mechanisms, inputs, outputs, limits, and terminal outcome in one execution
receipt. Unsupported or incomplete enforcement fails closed. The accepted
[Linux boundary ADR](adr/0001-linux-enforcement-boundary.md) defines the first
mechanism and its limits.

### 8. Verify native records and links

Each native verifier checks closed structure, canonical bytes, expected
identities, and owner-specific relationships. Runtime receipt verification
also needs a commitment supplied independently of the receipt carrier, as
required by [ADR 0002](adr/0002-external-receipt-commitment.md). Only after
native verification succeeds does a linkage verifier join exact objects and
check the acyclic identity graph.

### 9. Apply consumer policy

The consumer chooses acceptable claim facets, release subjects, Runtime
profiles, verifier identities, assumptions, authorization state, execution
outcomes, and integration tuples. Acceptance is a new bounded decision over
verified inputs. It does not alter those inputs, hide their weak facets, or
authorize reuse beyond the policy's scope.

### 10. Invalidate and repeat

Source, theorem, toolchain, workflow, artifact, policy, authorization, or
integration changes create new identities and invalidate affected evidence.
The system rebuilds only the claim-sized closure that changed, then rechecks
the complete downstream links. Historical records keep their original meaning.
This continuous invalidation and reconstruction is what turns formalization
from a one-time certification exercise into an engineering practice.

## What Lean acceptance establishes

Lean acceptance is a precise and valuable fact: a particular Lean kernel,
given exact declarations and admitted premises, accepted a proof term for an
exact proposition. When the proposition describes a closed authority model,
this can rule out entire classes of mistakes in that model. When combined with
reviewed source refinement, it can establish a relationship between the model
and a selected pure production function under explicit toolchain assumptions.

Lean acceptance alone does not establish that:

- the plain-language claim is useful, complete, or correctly formalized;
- the model contains every relevant production effect;
- the production source implements the model;
- the built binary came from that source;
- the compiler, linker, dependencies, hardware, kernel, or host are correct;
- Linux installed or enforced the represented policy for an execution;
- an observed execution had no unmodeled channel;
- the action was authorized by the intended principal;
- a remote provider performed the intended effect; or
- the agent's output is semantically correct.

Those are distinct propositions with different owners and evidence paths.
Exact source refinement, reproducible builds, artifact linkage, native Linux
tests, execution receipts, Auths records, and consumer acceptance can narrow
some of the gaps. They do not erase the remaining assumptions. Deterministic
encoding is similarly necessary for stable identity but does not establish
meaning; [ADR 0003](adr/0003-deterministic-cbor-wire-objects.md) records this
boundary for committed Runtime objects.

## Initial use cases

The vision should be tested against work that already has a consequential
boundary and a consumer willing to act on the result.

### Networked coding agent

An agent reads one identified source tree, communicates through one declared
service mechanism, writes only to a fresh output root, and returns a patch with
a verified execution receipt. Capsec observations can help draft the plan;
Auths can later bind who authorized the work; Proofbound can identify the exact
Runtime release and evidence. This workload tests whether the authority model
is usable without claiming that the patch is correct.

### CI artifact-producing agent

An agent reads an identified checkout, runs a declared toolchain, and writes an
artifact tree. CI retains the Runtime receipt, independent verification,
consumer acceptance decision, and Proofbound release evidence. This is a
strong initial commercial wedge because the workflow is repeatable, Linux CI
already has explicit gates, and the resulting artifacts have a natural
promotion decision.

### Authorized consequential action

Auths authorizes one repository write, disposable deployment change, or other
bounded provider action. Runtime confines and records the executing process.
The linked object graph lets a reviewer distinguish authorization, execution,
release assurance, and provider response. It does not equate a valid response
with proof of the external real-world effect.

### High-assurance release and dependency consumption

A producer connects selected source properties to exact release artifacts. A
consumer independently verifies the native objects and admits only an exact
package, verifier set, platform profile, and evidence floor. This is useful for
security-sensitive agent infrastructure where ordinary provenance identifies
inputs but says little about which behavioral claims were actually examined.

### Audit and offline review

A complete content-addressed object closure can support later offline
verification without making a query service or database the source of truth.
This becomes a product only after real consumers need retention, discovery,
and export; the demand gate is recorded in
[RT-12](roadmap-2/rt-12-composed-retention.md) and
[RT-19](roadmap-3/rt-19-evidence-discovery-and-export.md).

The [reference-workload plan](roadmap-3/reference-workload-validation.md)
defines concrete measurements: time to first verified receipt, plan completion
cost, unexplained denials, authority drift, verification time, export cost, and
whether an adopter will repeat the workflow outside a maintainer-controlled
repository.

## Product and platform thesis

The product is not a theorem-proving interface with a deployment feature. It
is an assurance control plane for software and agent actions, built from small
native products with explicit trust boundaries.

Proofbound supplies the claim and evidence accountability layer. Runtime
supplies the effectful execution boundary and observations. Auths supplies the
identity, delegation, and authorization layer. Capsec supplies bounded source
observations that reduce the cost of drafting authority. Together they can
answer a useful compound question:

> For these exact artifacts and this exact execution, which claims have which
> admitted support, which authority was authorized and installed, which result
> was observed, what remains assumed, and does this consumer accept the whole
> set for this purpose?

The initial commercial wedge is narrower: security, platform, and release
teams running artifact-producing or coding agents on controlled Linux workers.
The first product experience should make it practical to install exact tools,
draft and review a plan, run one agent, independently verify the receipt, and
enforce a consumer policy in CI. It should work without a hosted control plane
and without requiring Auths or Capsec for a Runtime-only adoption.

Expansion follows observed friction. Capability-informed drafting is justified
when manual plan construction is slow. Auths integration is justified when a
real action needs delegation or approval. Additional service sessions are
justified when a maintained workload needs them. Signing, retention, a profile
registry, organizational policy, credential custody, and an execution service
become products only after their stated consumer and threat-model gates are
met. The current dependency order is captured in the
[roadmap execution order](product-roadmap-execution-order.md).

## Defensibility

The durable asset is not the volume of generated Lean. Other systems will also
gain access to capable models and theorem provers. Defensibility comes from the
accumulated, reviewable structure that turns heterogeneous evidence into
decisions without overstating it:

- a precise claim vocabulary with historical source closures and residual
  obligations;
- independent verifiers and stable negative cases for each native protocol;
- typed identity joins across source, artifact, release, execution,
  authorization, and consumer policy;
- adversarial corpora that encode discovered failure modes;
- exact, reproducible distribution and integration tuples;
- a growing set of real workload profiles with measured authority and adoption
  costs; and
- a record of which consumers accepted which bounded facts under which
  assumptions.

This structure improves with use. A failed proof can expose a weak abstraction.
A failed native test can expose a missing platform premise. A consumer
rejection can expose an unusable claim or excessive authority. A cross-project
mutation can expose an identity-confusion path. Each finding becomes a durable
contract, falsifier, or verifier rule while the repositories retain separate
ownership.

Defensibility also depends on restraint. If the platform collapses meanings,
hides its trusted components, or markets bounded observations as universal
proof, it loses the property that makes the records useful.

## Explicit limitations and trusted computing base

The Runtime [threat model](threat-model.md) is the authoritative statement for
the initial execution profiles. At a high level, this vision retains at least
the following limitations:

- It does not protect against a malicious host administrator, host root,
  compromised kernel, hypervisor, firmware, or hardware.
- It does not prove Linux, Landlock, seccomp, cgroup v2, the compiler, the
  linker, dependencies, cryptographic implementations, or release services
  correct.
- It does not eliminate side channels, permitted covert channels, or denial of
  service within granted bounds.
- It does not stop data read under authorized authority from being copied to an
  authorized output or service.
- It does not infer that the human-selected plan matches the user's real
  intent.
- It does not infer complete behavior from source-level capability analysis,
  especially across dynamic loading, reflection, subprocesses, macros, FFI, or
  native extensions.
- It does not treat a digest as evidence of behavior, a signature as evidence
  that an execution occurred, reproducibility as compiler correctness, or log
  inclusion as authorization.
- It does not establish semantic correctness of an agent's output or the
  intended effect of a remote provider action.
- It does not claim fully verified Linux containment or correctness of
  arbitrary software.

The trusted computing base remains claim-specific and visible. Depending on
the flow, it includes identified Runtime, launcher, verifier, and composer
artifacts; kernel mechanisms; host hardware and firmware; toolchains and
dependencies; filesystem and process behavior; digest implementations;
distribution services; independently supplied commitments; Auths and Capsec
verifiers when used; integration-profile resolution; and the consumer's policy
and trust anchors. Composition unions these roles. It never discards them.

The Runtime receipt remains an account of one identified execution. The
[receipt semantics](receipt-semantics.md) explain why canonical form, exact
identities, and an independent commitment make the account verifiable without
turning it into proof of universal containment or output correctness.

## Roadmap implications

This vision changes what the ecosystem should optimize for.

First, invest in claim design and linkage as heavily as proof automation.
Models can generate many theorems; the platform should reward a small claim
whose subject, assumptions, falsifiers, source closure, artifact link, and
consumer are all explicit.

Second, advance assurance as a wavefront. Map the broad product at a claim-ledger
level, take one small foundational behavior through the strongest justified
tier, then expand claim by claim. Do not force effectful Linux behavior into a
pure proof category and do not hold every useful bounded claim until it reaches
source refinement.

Third, preserve repository and verifier independence. Standardize typed links,
content identities, integration profiles, and verification order. Do not
standardize away each product's semantic ownership. Cross-project changes use
exact tested tuples rather than coordinated release numbers.

Fourth, make distribution and first use part of assurance. A proof or verifier
that a consumer cannot safely install, identify, invoke, and connect to a
decision is incomplete as a product. The current Runtime-only packaging path
should close before optional cross-project profiles.

Fifth, follow workload evidence rather than speculative platform breadth. The
next practical sequence is exact public distribution, better plan drafting, a
single authenticated service workload, and then the smallest Auths/Capsec
integration that a real adopter needs. Multi-service networking, guests,
signing, logs, registries, organizational policy, credential custody, broader
language analysis, fleet identity, and hosted execution remain demand- and
threat-model-gated. The active and candidate choices are recorded in
[Roadmap 2](product-roadmap-2.md) and the
[Roadmap 3 candidate register](product-roadmap-3-candidates.md).

Finally, treat versions only as tooling metadata during the prelaunch,
zero-user stage. There is no compatibility, migration, deprecation, or
coordinated-version ceremony to design now. Closed schema identities and exact
source, artifact, package, workflow, verifier, and integration-tuple identities
carry security meaning. When a meaning changes, replace the current candidate
atomically and rebuild the affected evidence graph.

## Long-term outcome

If continuously formalized development becomes routine, software will carry
more machine-checkable evidence than teams can responsibly interpret by hand.
A useful platform will not be measured by proof count. It will be measured by
whether it preserves meaning across the distance from a claim to a consumer
decision.

Proof-carrying agent software makes that distance explicit. It lets formal
proofs contribute where their models are strong, native enforcement contribute
where operating-system effects matter, authorization contribute where human
and workload identity matter, source observations contribute where plans are
drafted, and consumer policy decide whether the combined but still limited
facts are sufficient. The result is not universal certainty. It is a narrower,
auditable basis for deploying increasingly capable agents with authority that
can be stated, checked, and contested.
