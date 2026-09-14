# Specification 0008: Cross-receipt linkage with Auths

**Status:** Draft cross-project specification; not accepted in either repository

**Applies to:** `proofbound-runtime-receipt/1`,
`proofbound-runtime-composed-receipt/1`, and Auths decision and execution
receipts V1

**Date:** 2026-09-10

This specification defines how one Auths execution receipt commits to one
Runtime execution receipt and to the Proofbound release that produced the
Runtime binaries. It adds no field to any existing receipt. It uses the
Auths profile-claim roster on one side and the Runtime plan input inventory
on the other, so both closed wire contracts stay closed. It changes no
authority semantics, receipt eligibility, or claim status.

[Specification 0013](0013_platform_integration_contract.md) defines the wider
cross-project ownership, terminology, identity, compatibility, and verification
order. This specification is the narrower Auths-to-Runtime linkage profile.
Where the wider specification mentions Capsec, service networking, signing,
logs, or a platform SDK, those subjects remain out of scope here.

## Goal

The linked chain answers one bounded question:

> Was this exact provider action, authorized through this Auths decision,
> performed by a child process confined under this exact Runtime receipt,
> produced by these exact release binaries whose Proofbound assurance is
> this?

Each object is verified by its own independent verifier first. Linkage only
joins exact byte identities. It proves nothing about effect semantics and
promotes no claim facet.

## Objects and order

```text
Auths decision receipt  (t0)
   |  declared as a Runtime plan input
   v
Runtime execution receipt + commitment  (t1)
   |  committed through one Auths profile claim
   v
Auths execution receipt  (t2)
   |  optional
   v
Runtime composed receipt binding the Proofbound release
```

Every later object commits to the earlier one. No object references a later
one, so the chain is acyclic and each step is checkable offline.

## Linkage record

The Auths receipt stays commitment-only, so the details live in one retained
document, `proofbound-runtime-auths-linkage/1`. It is encoded as
deterministic CBOR under
[ADR 0003](../adr/0003-deterministic-cbor-wire-objects.md) with a closed
CDDL schema and integer map keys. The names below are the CDDL names used by
the JSON projection. Fields are exactly:

| Field | Meaning |
| --- | --- |
| `schema` | `proofbound-runtime-auths-linkage/1` |
| `auths_decision_receipt` | the Auths decision receipt content identifier |
| `auths_profile` | the Auths profile reference that executed the action |
| `runtime_execution.commitment` | `sha256:` digest of the exact Runtime receipt bytes |
| `runtime_execution.execution_id` | the Runtime execution ID from the run result |
| `runtime_execution.receipt` | artifact record: name, `sha256`, `size` |
| `proofbound_release.envelope` | artifact record of the release envelope |
| `proofbound_release.payload_sha256` | the compiled-release payload digest |
| `proofbound_release.project` | the Proofbound project name |
| `proofbound_release.project_revision` | the 40-hex source revision |
| `proofbound_release.evidence_context` | the nonempty evidence context |
| `composed_receipt` | optional artifact record of the composed receipt |

The record carries no timestamp, command bytes, result bytes, environment
value, or secret. Artifact records use the same shape as
[Specification 0003](0003_release_receipt_composition.md). Unknown or
duplicate fields are rejected.

## Auths side: one profile claim

The Auths execution receipt carries a profile-claim roster of identifier and
SHA-256 pairs. This specification registers one claim:

- identifier `proofbound-runtime.linkage.1`, in the Auths lowercase
  dotted-token grammar;
- phase `execution`; and
- digest equal to SHA-256 over the exact linkage record bytes.

The claim is added by the profile that executed the command, not by Runtime.
The Auths receipt signature therefore authenticates the linkage digest. A
profile that runs its sealed command under Runtime and omits this claim
produces an unlinked execution; that is permitted but is not linkage.

## Runtime side: one declared input

The Auths decision receipt canonical bytes are declared as a plan input of the
Runtime execution. The Runtime receipt's input inventory then records that
file's exact identity before child code starts. This binds the confined run
to the decision that authorized it without changing the plan or receipt
schema. The child may read the decision receipt; it cannot alter it.

## Independent verification

A consumer holding the two attested Auths receipts, the linkage record, the
Runtime receipt, the Runtime bundle, and any composed receipt performs, in
order:

1. Verify the Auths decision and execution receipts with the Auths offline
   verifier against verifier-local expected signers and trust anchors.
2. Find claim `proofbound-runtime.linkage.1` in the execution phase.
   Recompute SHA-256 over the retained linkage record and compare.
3. Run `pbr-verify` over the Runtime receipt with the linkage record's
   commitment as the expected commitment. The Auths signature is the channel
   that carries the commitment independently of the Runtime receipt carrier,
   which satisfies [ADR 0002](../adr/0002-external-receipt-commitment.md).
4. Check that the Runtime receipt's input inventory names the Auths decision
   receipt digest and that its execution ID equals the linkage record's.
5. If a composed receipt is present, verify it under Specification 0003 and
   require its decoded `release` values to equal the linkage record's
   decoded `proofbound_release` values. The two objects may differ in
   encoding, so the comparison is over decoded values, not bytes.

A failure at any step means linkage is not established. There is no partial
linkage result.

## Registered attacks

The following must be rejected with a typed reason before this specification
is accepted:

- a substituted Runtime receipt with an internally valid but different
  commitment;
- one Runtime receipt claimed by two Auths executions, detected because the
  decision receipt digest in the input inventory matches only one;
- an omitted or mis-phased linkage claim;
- a linkage record whose digest differs from the claimed digest;
- a composed receipt whose release identity differs from the record; and
- a Runtime receipt whose eligibility is non-reusable, including any future
  diagnostic-profile receipt.

## Trust boundary

Linkage proves that exact bytes refer to exact bytes. It does not prove that
the provider effect was correct, that the child performed only the authorized
action beyond what the Runtime boundary enforced, or that either verifier is
correct. The Auths receipt-key custody, the Runtime bundle identity, and the
Proofbound release verifier are trust inputs. All assumptions and
trusted-computing-base entries of every verified object are retained; none is
discharged by linkage.

## Ownership and acceptance

- Runtime owns the linkage record CDDL schema and golden vectors, published
  under `schemas/` when this specification is accepted.
- Auths owns the claim identifier registration inside the executing profile.
- Proofbound owns the assurance meaning of each release receipt. It does not
  interpret Auths authorization or Runtime enforcement semantics.
- Capsec has no role in this linkage profile. A later profile can reference one
  Capsec report only as typed drafting provenance under Specification 0013.
- Neither repository changes an existing receipt schema for this
  specification.
- Acceptance requires review in both repositories, a falsifier for every
  registered attack before positive code, and agreement between each
  producer and its independent verifier.
- A transparency log, Runtime receipt signing, and any new authority mode
  are out of scope and remain governed by
  [Product roadmap 2](../product-roadmap-2.md).
