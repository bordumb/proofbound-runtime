# Proofbound platform Roadmap 3 candidate register

- **Status:** pre-planning only; no candidate is scheduled or accepted
- **Date:** 2026-09-13
- **Runtime baseline:** Roadmap 2 planning baseline `83e8bbc`
- **Platform contract:** draft
  [Specification 0013](specs/0013_platform_integration_contract.md)
- **Prerequisite:** Roadmap 2 exit conditions remain authoritative
- **Delivery order:** [Product roadmap execution order](product-roadmap-execution-order.md)

This register preserves product ideas that are likely to matter after or beside
Roadmap 2. It does not authorize implementation. It does not add a trusted role,
change a wire schema, accept an architecture, or promise a release.

Each candidate has a stable RT identifier so later evidence can refine or reject
it without rewriting history. The
[candidate execution records](roadmap-3/README.md) contain the detailed
ownership, trust, attack, promotion, and rejection gates.

## 1. Executive decision

Pre-plan seven ideas:

1. credential custody and secret delivery;
2. operation-scoped mediation;
3. organizational policy lifecycle and authority drift;
4. a signed integration-profile registry;
5. multi-language capability analysis;
6. evidence discovery and export; and
7. host and fleet identity with possible remote attestation.

Do not place all seven behind one platform release. Each opens only when its
named Roadmap 2 dependency and adopter evidence exist. Runtime-only work can
ship without Auths or Capsec. An integrated profile is supported only when its
complete compatibility tuple and attack corpus pass.

The [reference-workload validation plan](roadmap-3/reference-workload-validation.md)
starts before these candidates. It determines which candidates receive product
priority.

## 2. Candidate register

| Candidate | Product outcome | Required before implementation | Current disposition |
| --- | --- | --- | --- |
| [RT-14 credential custody](roadmap-3/rt-14-credential-custody.md) | An agent reaches a declared provider without receiving a reusable long-lived credential | RT-5 production authenticated session; one qualified Auths provider profile | Explore interfaces now; implementation blocked |
| [RT-15 operation-scoped mediation](roadmap-3/rt-15-operation-scoped-mediation.md) | An agent can invoke one authorized provider operation instead of receiving arbitrary session authority | RT-14 decision or equivalent credential isolation; one consequential adopter action | Preserve experiment results; implementation blocked |
| [RT-16 organizational policy lifecycle](roadmap-3/rt-16-organizational-policy-lifecycle.md) | A team governs policy versions, approvals, exceptions, revocation, and authority drift | Two organizational adopters with the same lifecycle need | Interview and model now; implementation blocked |
| [RT-17 integration-profile registry](roadmap-3/rt-17-integration-profile-registry.md) | Reviewed profiles bind exact Auths, Runtime, Capsec, SDK, verifier, and Proofbound versions | RT-7 compatibility; RT-11 identity decision; two maintained profiles | Define bundle contents now; registry blocked |
| [RT-18 multi-language analysis](roadmap-3/rt-18-multilanguage-capability-analysis.md) | Python and TypeScript workloads receive source-informed drafting alongside runtime observation | RT-8 diagnostic contract; one maintained workload in each language | Define adapter boundary now; analyzers blocked |
| [RT-19 evidence discovery](roadmap-3/rt-19-evidence-discovery-and-export.md) | Auditors can search and export a complete independently verifiable object closure | RT-12 log; two retention consumers | Preserve query/trust separation; implementation blocked |
| [RT-20 host and fleet identity](roadmap-3/rt-20-host-fleet-identity.md) | A remote consumer can evaluate identified host and guest evidence under an explicit attestation policy | RT-10 guest profile; remote execution demand; separate threat model | Research questions only; implementation closed |

## 3. Pre-planning priority

### Start discovery now

- Run the reference-workload validation plan.
- Define RT-14's credential and descriptor ownership boundary while RT-5 is
  designed. Do not implement secret delivery before RT-5.
- Define RT-18's language-neutral observation envelope while RT-8 defines
  provenance. Do not claim that an analyzer sees all behavior.
- Collect RT-16 policy-lifecycle interviews from every design partner.

### Preserve design space without implementation

- Retain the explicit-broker network experiment as one RT-15 input.
- Define RT-17 profile contents beside RT-7 compatibility work, but do not
  operate a registry before RT-11 authenticates publishers.
- Define RT-19 export closure beside RT-12, but do not build a query database
  before the content-addressed log has consumers.
- Keep RT-20 out of scope until RT-10 and remote-host demand exist.

## 4. Candidate promotion gate

A candidate becomes a scheduled epic only when all applicable conditions hold:

1. A named adopter and exact workload expose the need.
2. The owner repository for every semantic decision is identified.
3. The current safe workaround and its limitation are documented.
4. Every new trusted role, authority, identity, and operator is enumerated.
5. The proposed public claim states what the feature cannot establish.
6. At least one falsifier exists before positive implementation.
7. The required Roadmap 2 dependency is shipped, not only designed.
8. The work cannot be satisfied by a smaller profile or existing component.
9. The expected product metric and rejection threshold are recorded.
10. Every affected repository accepts its own part of the change.

Failure to meet a gate keeps the candidate in this register. It does not create
an open Runtime claim.

## 5. Repository ownership

| Work | Runtime | Proofbound | Auths | Capsec |
| --- | --- | --- | --- | --- |
| Credential path | Child descriptor lifecycle, service boundary, observations | Claims and exact release evidence | Credential custody, grant, profile, and provider binding | Optional detection of ambient secret access |
| Operation mediation | Deny direct paths, mediate local channel, record boundary | Evidence status and release linkage | Action schema, authorization, credential use, provider adapter | No production mediation role |
| Organization policy | Runtime plan and receipt acceptance facets | Generic evidence semantics only when demonstrated reusable | Principal, delegation, approval, revocation, and action policy | Capability-drift input |
| Profile registry | Runtime service and schema entries | Release assurance and generic artifact linkage | Auths action and identity entries | Analyzer and observation entries |
| Language analysis | Provenance import and plan comparison | Evidence meaning only if later registered | No static-analysis role | Analyzer boundary or external adapter ownership |
| Evidence discovery | Native Runtime objects and log integration | Native Proofbound receipts and status | Native Auths receipts | Native Capsec reports |
| Fleet identity | Runtime host and guest profiles | Attestation evidence meaning and assumptions | Workload and operator identity | No host-attestation role |

No candidate requires a monorepo or a shared semantic library.

## 6. Relationship to Roadmap 2

| Roadmap 2 epic | Candidate work that can be prepared | Work that remains blocked |
| --- | --- | --- |
| RT-7 compatibility | RT-17 bundle contents and independent version tuple | Signed registry operation until RT-11 |
| RT-8 drafting | RT-18 observation envelope and Capsec provenance | Analyzer claims until the diagnostic contract is accepted |
| RT-9 networking | RT-14 credential boundary and RT-15 action-to-service mapping | Credential and operation implementation until RT-5 and RT-9 ship |
| RT-10 guest profile | RT-20 identity vocabulary and threat questions | Remote attestation until a remote-host adopter exists |
| RT-11 signing | RT-14 credential-source identity and RT-17 publisher identity | Any claim of authenticated publication until the ADR is accepted |
| RT-12 receipt log | RT-19 export closure and derived-index rules | Discovery service until two log consumers exist |
| RT-13 execution service | RT-16 organization policy interviews and RT-20 fleet questions | Shared control plane and fleet implementation until measured need |

Roadmap 2 remains the delivery queue. This register cannot be used to bypass
its ordering or exit conditions.

## 7. Product validation

The candidates are evaluated against three maintained reference workloads:

1. a networked LLM coding agent;
2. a CI artifact-producing agent; and
3. an Auths-authorized consequential provider action.

The common product measurements are:

- download-to-first-verified-receipt time;
- time to complete and approve a plan;
- unexplained denial count;
- authority breadth and authority change between versions;
- repeated execution setup cost;
- time for a consumer to integrate independent verification;
- complete receipt-chain export size and verification time; and
- adopter willingness to operate or pay for each candidate capability.

A candidate that does not materially improve one named measurement remains
deferred even when it is technically feasible.

## 8. Explicitly rejected shortcuts

These candidates do not reopen Roadmap 2's rejected designs. They also reject:

- passing a reusable provider credential through an inherited environment;
- treating a provider hostname as an authorized operation;
- turning a Capsec finding into Runtime authority without human review;
- fetching mutable organization policy after child release;
- resolving a mutable profile name without binding its expanded bytes;
- treating a query index as the receipt-log trust anchor;
- treating attestation as proof that the claimed program behavior occurred;
- using one global platform version to hide incompatible native protocols; or
- making any orchestration SDK a replacement for native independent verifiers.

## 9. Review cadence

Review this register after each Roadmap 2 milestone and after each reference
workload completes a measured trial. Record one of four outcomes per candidate:

- remain deferred;
- gather more evidence;
- promote to a numbered implementation roadmap; or
- reject with the reason and the premise that could justify reconsideration.
