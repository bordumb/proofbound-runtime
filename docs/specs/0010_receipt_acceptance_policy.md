# Specification 0010: Receipt acceptance policy and decision

Status: accepted for implementation

## Purpose

This specification defines the first adopter-controlled decision boundary for
Proofbound Runtime. It consumes exact execution and Proofbound release inputs,
re-runs their independent verifiers, and evaluates a reviewable policy. It does
not treat a producer-authored success Boolean or a carried verification report
as authority.

The owner approved deterministic CBOR with text map keys for new Runtime wire
objects. This specification therefore fixes the bytes before implementation.

## Wire contracts

The policy schema is `proofbound-runtime-acceptance-policy/1` and its closed
CDDL is `schemas/acceptance-policy-v1.cddl`. The decision schema is
`proofbound-runtime-acceptance-decision/1` and its closed CDDL is
`schemas/acceptance-decision-v1.cddl`. Both use deterministic CBOR under RFC
8949 section 4.2.1, definite lengths, shortest integer and length encodings,
text-only map keys ordered by their encoded bytes, and no tags or floating
point values. Unknown, duplicate, or out-of-order fields fail closed.

The checked-in golden bytes and non-authoritative JSON projections are under
`schemas/vectors/v2/`. JSON is never accepted as a policy or decision input.

The policy identity is:

```text
SHA-256("proofbound-runtime-acceptance-policy/1" || 0x00 || policy_bytes)
```

The decision identity is SHA-256 over the same deterministic decision encoding
with `decision_id` omitted, prefixed by
`"proofbound-runtime-acceptance-decision/1" || 0x00`.

## Policy semantics

Version 1 requires exact equality for:

- execution-receipt schema, Runtime version, operating system, architecture,
  plan ID, executable digest/size/mode, compiled-policy digest and model,
  configured `pids.max`, `memory.max`, `memory.swap.max`,
  `memory.oom.group`, and independently derived eligibility;
- Proofbound project, project revision, release payload identity, evidence
  context, and each named claim's formal, linkage, assumption, and policy
  facets; and
- every forbidden assumption, release exclusion, open obligation, or TCB role.

Claim requirements are keyed by exact claim ID. There is no aggregate tier
comparison because Proofbound facets are partially ordered.

Freshness version 1 has the sole mode `not-required`. It makes no age claim and
does not read a clock. Adding an age-bearing mode requires a new policy schema
that names and binds a separately trusted current-time input; a producer
timestamp cannot prove its own freshness.

Lists of claim requirements and rejection values are strict ascending UTF-8
byte order with no duplicates. Receipt and release sets are compared as sets
only after their closed inputs pass validation.

## Trust inputs and verification order

`pbr-accept` receives the raw acceptance-policy bytes and their independently
expected identity; the raw execution receipt, commitment, and expected
execution ID; the exact Proofbound release directory, verifier binary, and
observation-input manifest; and the exact Runtime bundle. It performs these
steps in order:

1. strictly decode the policy and compare its domain-separated identity with
   the separately supplied expected identity;
2. invoke the independent execution verifier over the raw receipt and supplied
   commitment;
3. invoke the independent Proofbound verifier over the exact release and
   observation inputs;
4. compose the verified facts from those raw inputs, without accepting a
   caller-supplied composition or portable verification report;
5. compare typed execution and release facts with the policy; and
6. encode and publish the complete decision with no-replace semantics.

The generated verification reports are retained outputs and bound by digest in
the decision. They are never verification inputs. The raw execution receipt is
never mutated or reserialized.

## Decision semantics

An accepted decision has status `accepted` and an empty reason list. A rejected
decision has status `rejected` and every applicable typed reason in CDDL order,
without duplicates. A valid policy always yields a canonical decision even if
input verification or composition fails. A malformed policy is invalid input
and cannot define decision semantics.

The decision binds the policy identity, supplied execution commitment,
expected execution ID, optional successful composition identity, and the
digest and byte count of every raw or generated input consumed by the
decision, including the running `pbr-accept` binary. The fixed role inventory
prevents omission and role substitution.

Acceptance and execution reuse eligibility remain separate. A policy may
require reusable eligibility, but a reusable receipt can still be rejected by
any other adopter requirement.

The CLI exits zero only for `accepted`, seven for a canonical `rejected`
decision, and two for usage, malformed policy, unsafe paths, read failures, or
publication failures. It writes the decision only to a caller-selected absent
path using no-replace publication. Standard output is a JSON display projection
containing the decision identity, status, typed reasons, and output path; it is
never a verification input.

## Falsification obligations

The implementation must cover field omission and unknown fields, noncanonical
CBOR, policy substitution and stale expected identity, receipt/release/bundle
substitution, execution-ID replay, schema downgrade, claim/facet downgrade,
assumption loss, forbidden assumptions/exclusions/open obligations/TCB roles,
forged carried verification reports, decision identity mutation, output-path
replacement, and the case where a reusable receipt is rejected by policy.

## Scope and residual obligations

This specification does not authenticate artifact storage, define a receipt
database, select DSSE or Sigstore, or claim that GitHub Actions storage is a
trust anchor. A first-party Action may use content-addressed artifacts as a
carrier only. External dogfood and independent review remain release gates and
must not be represented by repository-local tests.
