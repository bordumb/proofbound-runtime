# Product roadmap execution order

- **Status:** active delivery order
- **Date:** 2026-09-17
- **Applies to:** Roadmap 1 release closure, Roadmap 2, and Roadmap 3 candidate
  promotion
- **Current Runtime main:** `a94c21a9d1b399f9eff8771e06ce253fe9a6c4ca`;
  the RT-5 pure-policy wave passed PR 30 exact-head Verify run `35226379485`;
  exact-main Verify run `35231003515` is in progress
- **Current reviewed Roadmap 1 source head:** `d76f3b8`
- **Lifecycle:** prelaunch; zero external users; package labels are tooling
  metadata rather than compatibility promises

This document is the durable dependency and decision order across the product
roadmaps. It does not replace an epic, specification, architecture decision,
threat model, claim, or release approval. When another roadmap summarizes a
different order, this document controls delivery sequencing until an explicit
review updates it.

## 1. Current boundary

Runtime main `a94c21a` contains the complete reviewed RT-8 diagnostic workflow,
native adversarial corpus, RT-5 non-executable authenticated-service contract,
SDK construction, and pure policy compiler. PR 30 exact-head run `35226379485`
passed; exact-main run `35231003515` is in progress. Roadmap 1 RT-5 remains
open beyond the non-executable policy. Roadmap 2 delivery is active; RT-8 is
complete, RT-7 retains external publication gates, and later epics remain
open. Roadmap 3 contains candidates, not scheduled implementation.

The immediate internal objective is to remove the useful-network barrier with
RT-5 while RT-7's registry publication and unrelated-consumer observations
proceed as external gates. No version cut,
compatibility layer, or migration window is a prelaunch dependency.

## 2. Delivery graph

```text
Roadmap 1 source merged and exact current main admitted
        |
        v
RT-7 current distribution contract and published packages
        |
        +-------------------------------+
        |                               |
        v                               v
RT-8 diagnostic plan drafting     RT-11 signing ADR research
        |
        v
RT-5 one production authenticated service
        |
        v
Networked LLM reference workload
        |
        +-------------------------------+
        |                               |
        v                               v
RT-14 credential decision         RT-9 multi-service network
only if RT-5 is insufficient
        |
        v
RT-15 operation mediation
only for consequential actions
```

After the first networked reference workload, later work branches on measured
demand:

```text
macOS or Windows demand --> RT-10 guest --> RT-20 fleet identity candidate

two retention consumers --> RT-11 accepted --> RT-12 log --> RT-19 discovery

repeated execution need --> RT-13 service --> RT-13.5 tenancy decision

two organization needs --> RT-16 organization policy candidate

two integration profiles + RT-11 --> RT-17 profile registry candidate

measured Python or TypeScript drafting pain --> RT-18 analyzer candidate
```

## 3. Phase 0: admit the current mainline foundation

This phase closes Roadmap 1 assurance at one exact source identity. It does not
create a release-number or compatibility dependency.

Required steps:

1. Merge the pinned ARM dependency correction after its exact-head gates pass.
2. Select and record the resulting exact revision on `main`.
3. Run the complete candidate workflow on both native architectures.
4. Inspect the exact SDK-package, native-evidence, assurance, and
   composed-receipt artifacts.
5. Obtain the required independent exact-source approval.
6. Carry that exact source and artifact identity into RT-7.

No tag, package-version increment, registry write, or compatibility promise is
required to close this phase.

### Release freeze rule

The selected foundation is the exact reviewed Roadmap 1 source plus required
assurance corrections, not whichever branch has the newest product work. If
the maintainer selects a later revision, every affected exact-head review and
gate runs again. Product labels do not carry approval from one source identity
to another.

## 4. Phase 1: RT-7 prelaunch distribution

RT-7 is the first Roadmap 2 implementation epic. Its first claim-sized step is
the draft
[prelaunch packaging and distribution contract](specs/0014_public_compatibility_and_distribution.md).

Merge order:

1. Accept the prelaunch packaging and distribution specification.
2. Select the public package set and close its registry dependency graph.
3. Make the independent verifier packageable and publishable first.
4. Prepare the selected pure crates and existing SDK packages.
5. Add exact-source package byte and file-list comparison.
6. Add registry publication only from the exact approved release workflow.
7. Implement and independently verify the Runtime current-integration record.
8. Publish and anonymously observe every selected package.
9. Dogfood every package from an unrelated consumer repository.
10. Retain the current-integration record from that exact successful release.

The Runtime-only package set ships before optional Auths or Capsec integration
profiles. Platform support remains an explicit exact tuple. Maintaining older
interfaces is not a prelaunch gate.

### Current RT-7 checkpoint

The first independent-verifier package slice passed independent exact-head
review, hosted verification, and merged to Runtime `main` as `7f989d3`.
Exact-main Verify run `34896209689` passed.
The generic Proofbound tool-bundle source was independently approved at PR 10
head `693976f`, passed its hosted gate, and merged as `dd481a3`. Exact-main
Verify run `34887427661` and both jobs in tool-bundle run `34889426459` passed.
Proofbound PR 12 added public immutable exact-source publication. Its reviewed
subject `6072127` and approval envelope `5f190e0` merged as `9512469`;
exact-main Verify run `34899222179` and bundle/publication run `34900896450`
passed. Public release `388736918` is immutable and binds that exact source.
Runtime's isolated public-bundle dogfood wave pins those identities without
changing the existing evidence path. That wave passed independent review,
merged as Runtime `f2a06de`, and passed exact-main Verify run `34908515545`.
The protected-path cutover passed independent review at production subject
`9d0cbb2`, passed exact-head Verify run `34915891330` at approval-envelope head
`515fcbc`, and merged unsigned as `4a0cfdb`. Exact-main Verify run
`34918706960` passed. The protected registry route and anonymous exact-byte
observer are now merged. The deterministic-CBOR current-integration producer
and independent verifier passed independent review at source `a81e259` and are
replayed on current main under `PBR-DISTRIBUTION-025`. Current npm registry
rules exposed a missing first-publication route, so the admitted source also adds
an immediate-`404`-gated one-time bootstrap token and mandatory transition to
OIDC. That status does not prove package absence or lock registry state. The
later credential-scoping correction passed independent review and exact-head
PR 23 Verify run `35034962830`, merged unsigned as `a8df83d`, and passed
exact-main Verify run `35038304369`.
External registry configuration, publication, anonymous observations, and
unrelated consumer dogfood remain separate completion gates.
This work follows the admitted foundation as a separate exact-source wave. It
does not require a version transition or preserve an older candidate surface.

## 5. Phase 2: RT-8 drafting

**Complete.** The product-exit extension passed PR 27 run `35194713490`,
merged as `275e6e7`, and passed exact-main run `35198698472`. The final native
adversarial corpus passed PR 28 run `35203053015`, merged as `da8c96b`, and
passed exact-main run `35207382756`. The resulting diagnostic output remains
non-reusable production evidence.

After RT-7 stabilizes the public schemas and SDK expectations:

1. Accept the diagnostic-profile ADR and specification.
2. Add the closed production and diagnostic profile types.
3. Keep observer code out of the production binary path.
4. Produce a distinct, non-reusable diagnostic receipt.
5. Convert bounded observations into draft provenance.
6. Require human completion of authority and resource choices.
7. Reject diagnostic output in verification, composition, and acceptance.

RT-18 can define a language-neutral observation envelope during this phase.
No language analyzer becomes trusted or production-authoritative.

## 6. Phase 3: complete the RT-5 bridge

RT-5 is unfinished Roadmap 1 work and a hard dependency of RT-9. The accepted
network ADR is design evidence, not production implementation.

Merge one authenticated service before extending the authority to a set:

1. Build from the accepted non-executable
   [Specification 0016](specs/0016_authenticated_service_session.md) contract
   and merged pure policy, admit the forward-only lifecycle and its formal
   evidence, then freeze the remaining launcher, receipt, verifier, composer,
   and acceptance schemas before their effects ship.
2. Implement the connector-owned authenticated service session.
3. Deny direct, inherited, resolver, proxy, Unix-socket, and `io_uring`
   bypasses.
4. Record exact resolver, TLS, service, connector, local-channel, limit, and
   optional credential-source identities.
5. Execute the native attack corpus on both architectures.
6. Run one maintained real API client.

RT-14 interface discovery can run beside this work. RT-14 implementation stays
blocked unless the reference workload proves that RT-5's credential boundary
is insufficient.

## 7. Phase 4: reference workload and RT-9

Run the networked LLM workload from the
[Roadmap 3 validation plan](roadmap-3/reference-workload-validation.md) after
RT-5. Record service count, credential exposure, plan effort, unexplained
denials, setup cost, and consumer integration effort.

Then:

- promote RT-14 before RT-9 only if one-service credential handling is unsafe
  or operationally unusable;
- keep RT-15 deferred unless a consequential action needs authority narrower
  than an authenticated service session; and
- implement RT-9 only by extending the accepted RT-5 mechanism to a bounded
  non-empty service set.

The first strategic reassessment occurs when the current foundation, RT-7,
RT-8, RT-5,
the LLM reference workload, and RT-9 are complete.

## 8. Demand-selected branches

### RT-10 or RT-11

RT-10 and RT-11 can exchange order after the first reassessment:

- choose RT-10 when trial access from macOS or Windows blocks adoption;
- choose RT-11 when publisher identity, portable provenance, or cross-project
  profiles block adoption.

RT-11 ADR research can start earlier because it adds no production code. RT-10
implementation adds a large trusted boundary and waits for measured demand.

### RT-12

RT-12 starts only after RT-11 is accepted and two consumers need retention.
RT-19 starts only after two log consumers demonstrate a common discovery or
export problem.

### RT-13

The performance baseline satisfies only the measurement half of RT-13's gate.
A named adopter with repeated invocations is still required. RT-13.5 starts
only after the single-tenant service is measured. One instance per tenant is
the default.

## 9. Parallel work permitted now

These activities do not alter production behavior and can proceed without
changing the delivery order:

- draft and independently review RT-11;
- define RT-14 credential and descriptor ownership;
- define RT-17 integration-profile contents;
- define RT-18's language-neutral observation envelope;
- interview organizations for RT-16; and
- run design-partner discovery for the three reference workloads.

Do not merge parallel production waves that edit the same authority, plan,
receipt, verifier, or launcher contracts. Serialize those waves so each exact
subject receives fresh evidence.

## 10. Reordering rule

Change this order only when one of these records exists:

- a Roadmap 2 prerequisite is unavailable or rejected;
- a named adopter cannot proceed without a later capability;
- a measured workload disproves the expected bottleneck;
- a security review shows that the current order creates a weaker boundary; or
- a smaller design satisfies the same product outcome.

Record the observation, changed dependency, affected claims, and new order
before implementation. Market interest without a concrete workload can start
discovery, but it cannot bypass a security dependency.
