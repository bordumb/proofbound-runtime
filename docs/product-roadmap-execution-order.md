# Product roadmap execution order

- **Status:** active delivery order
- **Date:** 2026-09-13
- **Applies to:** Roadmap 1 release closure, Roadmap 2, and Roadmap 3 candidate
  promotion
- **Current Runtime main baseline:** `83e8bbc`
- **Current reviewed Roadmap 1 source head:** `d76f3b8`
- **Current public release:** `v0.1.0`

This document is the durable dependency and decision order across the product
roadmaps. It does not replace an epic, specification, architecture decision,
threat model, claim, or release approval. When another roadmap summarizes a
different order, this document controls delivery sequencing until an explicit
review updates it.

## 1. Current boundary

Roadmap 1 source work is merged. The public release still trails the source.
All Roadmap 2 exit conditions remain open. Roadmap 3 contains candidates, not
scheduled implementation.

The immediate objective is to turn the merged version 0.2 source into an exact
release, then remove the installability, first-run, and useful-network barriers
in that order.

## 2. Delivery graph

```text
Roadmap 1 source merged
        |
        v
Release and externally validate version 0.2
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

## 3. Phase 0: close and release version 0.2

Version 0.2 is Roadmap 1 closure. It must not absorb new Roadmap 2 production
behavior merely because that behavior is ready to begin.

Required steps:

1. Select and record one exact version 0.2 release revision on `main`.
2. Confirm the version and changelog describe only that revision.
3. Run the complete release workflow on both native architectures.
4. Inspect the exact release, SDK-package, native-evidence, assurance, and
   composed-receipt artifacts.
5. Obtain the required independent release approval.
6. Create the immutable `v0.2.0` tag from the approved revision.
7. Publish the checksummed Runtime, SDK, example, and assurance artifacts that
   the reviewed workflow produced.
8. Run the maintained install and external consumer workflows from published
   artifacts.
9. Record open registry-publication and adopter-dogfood obligations honestly.

### Release freeze rule

The recommended version 0.2 candidate is the already reviewed Roadmap 1 merge,
not the Roadmap 2 documentation or RT-7 implementation that follows it. If the
maintainer selects a later revision, every exact-head review and release gate
must run again. A tag is never moved to absorb later work.

Registry publication cannot be added retroactively to a tag whose exact source
does not contain the accepted package and publication contract. Such work uses
the next approved Runtime version.

## 4. Phase 1: RT-7 prelaunch distribution

RT-7 is the first Roadmap 2 implementation epic. Its first claim-sized step is
the draft
[prelaunch packaging and distribution contract](specs/0014_public_compatibility_and_distribution.md).

Merge order:

1. Accept the prelaunch packaging and distribution specification.
2. Select the public package set and close its registry dependency graph.
3. Make the independent verifier packageable and publishable first.
4. Prepare the selected pure crates and existing SDK packages.
5. Add exact-tag package byte and file-list comparison.
6. Add registry publication only from the exact approved release workflow.
7. Dogfood every package from an unrelated consumer repository.
8. Publish the Runtime current-integration manifest.

The Runtime-only package set ships before optional Auths or Capsec integration
profiles. Platform support remains an explicit exact tuple. Maintaining older
interfaces is not a prelaunch gate.

### Current RT-7 checkpoint

The first independent-verifier package slice is implemented in source. Its
local package, consumer, Rust, and targeted fresh-evidence checks pass. Its
specification review, clean exact-head hosted evidence, exact-head review, and
merge remain open. No registry publication step exists.
The generic Proofbound tool-bundle prerequisite is upstreamed as Proofbound PR
10 at exact head `1ceb40f`. Its complete local 12-stage gate passes with zero
assurance regressions. It still requires merge, successful mainline Verify,
both platform bundle candidates, and Runtime consumption of the exact bundle
identity.
This work does not retroactively enter the version 0.2 release candidate; the
release/version decision must preserve the Phase 0 freeze rule.

## 5. Phase 2: RT-8 drafting

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

1. Freeze the single-service plan, policy, launcher, receipt, verifier,
   composer, and acceptance schemas.
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

The first strategic reassessment occurs when version 0.2, RT-7, RT-8, RT-5,
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
