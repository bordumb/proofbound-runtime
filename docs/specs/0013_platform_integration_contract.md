# Specification 0013: Proof-carrying authority platform integration

**Status:** Draft cross-project integration specification; not accepted by any
project

**Applies to:** Proofbound Runtime, Proofbound, Auths, and Capsec integration
profiles

**Date:** 2026-09-13

This specification defines the common protocol boundary for four separate
products. It does not merge their implementations or make one product's result
mean another product's result. Each product keeps its own domain types,
receipts, independent verifier, release process, and trust boundary.

The integration answers one compound question without collapsing its parts:

> What capability did the source appear to require, who authorized which
> action, what authority did the operating-system boundary install for the
> identified execution, and what evidence supports the exact software releases
> that produced and verified those records?

Each clause remains independently verifiable. A valid result for one clause
does not establish another clause.

## 1. Product ownership

| Product | Repository | Owns | Does not own |
| --- | --- | --- | --- |
| Capsec | `auths-dev/capsec` | Rust source analysis, capability requirements expressed in types, and bounded audit findings | Authorization, Linux enforcement, execution receipts, or assurance status |
| Auths | `auths-dev/auths-proof` | Principal and workload identity, grants, attenuation, authorization decisions, action profiles, and signed Auths receipts | Linux boundary installation, process containment, or Proofbound claim status |
| Proofbound Runtime | `bordumb/proofbound-runtime` | Execution plans, normalized execution authority, Linux policy compilation, boundary installation, execution observations, Runtime receipts, and Runtime acceptance policy | Source-code capability correctness, principal authorization, or generic evidence semantics |
| Proofbound | `bordumb/proof-bound` | Claim registration, evidence meaning, assumption accounting, status derivation, release assurance, artifact linkage, and generic receipt composition | Agent authorization, domain policy, or the child execution security path |

Ownership follows semantics, not code reuse. A reusable structure is not a
reason to move domain meaning into Proofbound. A convenient SDK is not a reason
to move launcher behavior out of Runtime.

## 2. Shared terminology

The integration uses one term for one concept.

| Term | Meaning | Owner |
| --- | --- | --- |
| Capability requirement | An effect that source code declares or that a bounded source analysis reports | Capsec |
| Grant | Authority delegated by a principal under an Auths policy | Auths |
| Authorization decision | A verified decision that one identified action is permitted under one grant and trusted context | Auths |
| Action | The provider or domain operation described by an Auths profile | Auths |
| Execution authority | The complete authority requested in one Runtime execution plan | Proofbound Runtime |
| Enforced boundary | The exact Linux mechanisms and limits installed before one child execution | Proofbound Runtime |
| Service identity | The declared DNS service name, port, resolver policy, and transport-authentication policy used by a Runtime network profile | Proofbound Runtime |
| Claim | A reviewable statement about one identified software subject | Proofbound |
| Evidence | A typed observation, test, bounded check, theorem, refinement, or artifact relation that retains its limits | Proofbound |
| Admitted status | The status that Proofbound derives from registered claims, evidence, assumptions, and linkage | Proofbound |
| Receipt | A product-owned committed record. Its meaning is defined only by its owning protocol | Owning product |
| Receipt commitment | A digest of exact receipt bytes supplied through an independently trusted channel | Owning protocol and consumer |
| Linkage | A checked relation between exact identified objects | Integration profile |
| Acceptance decision | A consumer policy result over independently verified inputs | Consumer; Runtime provides one bounded implementation |

The public documentation MUST NOT use these terms as synonyms:

- a Capsec capability requirement is not an Auths grant;
- an Auths authorization decision is not Runtime enforcement;
- Runtime enforcement is not proof that an authorized provider effect occurred;
- a Proofbound claim status is not an execution result;
- a digest establishes identity, not behavior or publisher authenticity; and
- a signature establishes origin under a key policy, not execution truth.

## 3. Identity model

### 3.1 Typed identities

The platform recognizes these distinct identity roles:

| Identity role | Meaning |
| --- | --- |
| Principal identity | The Auths-recognized entity that grants or invokes authority |
| Workload identity | The Auths-recognized caller or workload for one invocation context |
| Authorization-decision identity | The content identity of one Auths decision receipt |
| Action identity | The canonical Auths action committed by the authorization decision |
| Capability-observation identity | The content identity of one optional Capsec report or declaration set |
| Plan identity | The Runtime plan identifier and exact canonical plan-byte identity |
| Execution identity | The Runtime identifier for one execution attempt |
| Runtime-receipt identity | The commitment to one exact Runtime receipt |
| Service identity | The Runtime-owned authenticated service-session identity |
| Artifact identity | A typed role, digest algorithm, digest bytes, and size for one artifact |
| Release identity | The project, source revision, evidence context, and exact release-artifact identity admitted by Proofbound |
| Verifier identity | The exact verifier implementation or artifact selected by the consumer |
| Signing identity | The identity and key policy that authenticates an envelope or checkpoint |
| Operator identity | The service, guest-image, registry, or log operator selected by policy |

An implementation MUST NOT store these roles as one untyped identifier string.
The same byte sequence MAY occur in two roles, but role equality does not follow
from byte equality.

### 3.2 Cross-project references

A cross-project reference names:

- one closed identity role;
- one protocol and closed schema identity;
- the exact canonical object digest;
- the digest algorithm;
- the exact byte size; and
- the owner namespace that defines the object's meaning.

The reference does not copy the foreign object's semantic fields. The owner
protocol's independent verifier decodes and validates those fields. The
integration verifier compares only the decoded values explicitly registered by
the integration profile.

Unknown roles, schema identities, algorithms, owner namespaces, and duplicate
references fail closed. A path, URL, registry coordinate, branch name, or file
name is not an object identity.

## 4. Composition protocol

### 4.1 Required verification order

The full reference flow is:

```text
optional Capsec requirement report
              |
              | provenance only
              v
human-reviewed Runtime plan
              |
Auths authorization decision -- declared Runtime input
              |
              v
Runtime execution receipt and independent commitment
              |
              v
Auths execution receipt and cross-receipt linkage record
              |
              v
Proofbound release receipt and Runtime composed receipt
              |
              v
consumer integration-profile check and acceptance policy
```

A consumer performs these steps:

1. Select an explicit integration profile.
2. Verify every native receipt with the independent verifier selected for its
   owner protocol.
3. Verify every external commitment through its registered channel.
4. Verify the typed cross-project references and the acyclic linkage graph.
5. Compare only the cross-project fields named by the integration profile.
6. Retain every assumption, exclusion, trusted role, non-reuse reason, and
   weaker status from every input.
7. Apply the consumer's acceptance policy.

A failure at any step produces no partial platform acceptance. Individual
native verification results remain reportable with their original meaning.

### 4.2 Non-upgrade rule

Composition never promotes a result. In particular:

- a Capsec observation cannot grant Runtime authority;
- an Auths grant cannot prove that Runtime installed a boundary;
- a reusable Runtime receipt cannot prove that the Auths action was authorized
  or that a remote provider performed it;
- an Auths signature cannot prove that Runtime's observations are correct;
- a Proofbound theorem cannot describe unlinked production code; and
- a log inclusion proof cannot prove that the logged execution happened.

The platform result is no stronger than the weakest applicable input for the
facet being evaluated.

### 4.3 No universal receipt

The platform MUST NOT introduce one universal receipt that re-encodes every
product's semantics. It uses native receipts plus a small linkage record and an
integration record. This keeps independent verifiers independent and lets each
protocol retain its own meaning and exact identities.

## 5. Capsec-to-Runtime drafting profile

Capsec output is an optional input to Runtime's diagnostic drafting workflow.
It has provenance `capsec-source-observation`. Runtime keeps it distinct from:

- human-authored authority;
- static ELF closure resolution;
- diagnostic runtime observation; and
- platform-required closure.

Runtime MUST NOT automatically convert a Capsec finding into accepted plan
authority. A person selects the final filesystem roots, environment names,
process authority, resource limits, and network mode. A Capsec report that is
missing, stale, built from different source bytes, or produced by an unknown
analyzer remains an untrusted drafting input.

The drafting report SHOULD show three differences:

1. a Capsec requirement with no corresponding Runtime authority;
2. Runtime authority with no Capsec requirement or runtime observation; and
3. runtime-observed behavior with no Capsec requirement.

These differences are review information. They are not violations until a
separate policy classifies them.

## 6. Auths-to-Runtime authorization profile

[Specification 0008](0008_cross_receipt_linkage.md) defines the first concrete
Auths and Runtime linkage. This specification adds these platform rules:

- Auths owns the action, principal, workload, grant, and decision meaning.
- Runtime owns the service identity, network authority, process execution, and
  boundary meaning.
- The exact Auths decision receipt is a declared Runtime input before child
  release.
- The Auths execution receipt commits to the linkage record after the Runtime
  execution exists.
- An Auths provider name does not silently become a Runtime DNS service name.
  An accepted profile defines the exact mapping and rejects ambiguity.
- Auths authorization for one action does not authorize a second Runtime
  service, redirect, proxy, executable, or execution attempt.

## 7. Proofbound release integration

Proofbound evaluates claims about each product release separately. Runtime's
composed receipt binds one Runtime execution receipt to one exact Runtime
release assurance result. A later platform profile MAY also reference Auths and
Capsec release assurances, but it MUST NOT merge their claim statuses.

Generic evidence and composition features belong in Proofbound only after the
Runtime feedback process demonstrates reuse. Linux, Auths, Capsec, and agent
domain semantics stay outside Proofbound core.

## 8. Integration selection model

The products do not share a lockstep version or release train. A platform
integration record selects an explicit tuple containing:

- the integration-profile identity;
- each participating product source and artifact identity;
- every native wire-schema identity;
- each verifier identity;
- the accepted cross-project linkage-schema identity;
- the accepted signing and digest algorithms;
- the required SDK package identities; and
- any required host or guest profile identity.

A missing tuple or unsupported combination fails closed. Product and package
labels do not imply platform support. An integration record authenticates
nothing by itself; its distribution and signing policy are trust inputs.

When signing is enabled, [ADR 0009](../adr/0009-detached-role-bound-signing.md)
defines the Runtime envelope and identity-role boundary. Native objects remain
the semantic inputs. A signature authenticates exact bytes and a role under a
consumer-pinned identity policy; it does not promote any native result.

The projects MAY publish independently. Each source change that affects an
integration surface MUST update the tested integration matrix before the tuple
is described as supported.

## 9. SDK and service boundary

A platform SDK MAY orchestrate the native SDKs and separate verifier processes.
It MUST NOT:

- embed the Runtime launcher or install the child boundary itself;
- reimplement a native verifier's semantic decisions;
- hold Auths provider credentials in application code;
- convert Capsec findings into authority without review;
- treat a service response as receipt verification; or
- hide the exact integration profile and verifier identities.

The first reference SDK can remain an example until two independent consumers
need the same orchestration surface.

## 10. Cross-project attack corpus

An accepted integration profile requires positive vectors and at least these
negative cases:

- substitute the Auths decision while retaining the Runtime execution;
- substitute the Runtime receipt while retaining the Auths execution receipt;
- reuse one Runtime execution for two authorization decisions;
- bind a Capsec report to different source bytes;
- convert a Capsec finding directly into broader Runtime authority;
- confuse an Auths provider name with a broader Runtime service identity;
- substitute one product release while retaining another product's assurance;
- downgrade one native schema while retaining the integration-profile identity;
- replace an independent verifier identity;
- omit one inherited assumption or trusted role;
- introduce a cycle in the linkage graph;
- replay an accepted service request as a second execution; and
- present signature, log inclusion, or digest equality as execution truth.

Each rejection has a stable typed reason owned by the layer that detects it.

## 11. Cross-repository change process

1. The repository that observes an integration need records the concrete case.
2. Each semantic change is proposed in the repository that owns that meaning.
3. Each affected repository reviews the shared vector and integration effect.
4. The owner publishes canonical bytes and an independent verification path.
5. The consuming repository pins the exact accepted identities and vectors.
6. The platform integration matrix changes only after every required project
   artifact is available.

Acceptance of this document in Runtime does not accept it in Proofbound, Auths,
or Capsec. Each project requires its own review record. The projects do not need
one monorepo, one release train, one cryptographic library, or one implementation
language.

## 12. Completion condition

This integration contract is complete when:

- all four projects accept the ownership and terminology tables or record an
  explicit narrower scope;
- one closed integration record identifies an accepted exact-identity tuple;
- independent verifiers validate every native receipt before linkage;
- the cross-project attack corpus fails for the expected typed reasons;
- one maintained reference workflow connects Capsec drafting, Auths
  authorization, Runtime execution, and Proofbound release assurance; and
- the workflow's documentation states what every link establishes and does not
  establish.

The [Roadmap 3 candidate register](../product-roadmap-3-candidates.md) preserves
possible credential, operation, organization-policy, profile-registry,
multi-language, discovery, and fleet extensions. Those candidates do not expand
this draft contract until their promotion and cross-repository acceptance gates
are satisfied.
