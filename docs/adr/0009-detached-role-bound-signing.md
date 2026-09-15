# ADR 0009: Use detached role-bound COSE signatures

- **Status:** proposed
- **Date:** 2026-09-15
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** Runtime release, guest-image, execution, and log objects
- **Related:** [ADR 0002](0002-external-receipt-commitment.md),
  [ADR 0003](0003-deterministic-cbor-wire-objects.md), and
  [Specification 0013](../specs/0013_platform_integration_contract.md)

## Context

An external receipt commitment detects carrier substitution only when the
consumer gets the expected commitment through an independent trusted channel.
A signature can make that channel portable by binding exact bytes to a signing
key. It does not remove trust. It moves trust to the signer identity, private-key
custody, identity resolver, status evidence, algorithm implementation, and
consumer policy.

Runtime has several distinct publishers. A release publisher, execution
producer, guest-image publisher, log operator, and checkpoint witness do not
make the same statement. Reusing one signature role for another would let a
valid key authorize a statement that its owner did not intend to make.

Runtime version 2 committed objects use deterministic CBOR. The native receipt
schema defines receipt meaning. A signing or attestation format must not
reserialize that receipt, redefine its fields, or make a self-signature evidence
that the execution occurred.

This decision answers the RT-11 design questions. It does not implement
signing or a receipt log. RT-12 remains closed until two independent consumers
need retention.

## Decision

Runtime will use a deterministic-CBOR, detached, role-bound envelope around
one exact native object. Each signature entry contains one detached
`COSE_Sign1` value. The first algorithm profile is the fully specified COSE
`Ed25519` algorithm, value `-19`, from RFC 9864. The deprecated polymorphic
`EdDSA` value `-8` is not accepted.

The selected identity model is mixed:

- durable release, guest-image, log-operator, and witness objects use separate
  long-lived role identities with externally managed custody and rotation;
- execution objects may use a short-lived producer-workload identity issued
  for the exact service or CI workload;
- Auths may resolve principal control and KERI key state through an explicit
  integration profile, but Auths authorization and Runtime object signing stay
  separate decisions; and
- local CLI receipts remain valid without signatures when the consumer uses
  the independent commitment required by ADR 0002.

No Runtime command, Git hook, or Git commit-signing configuration is part of
this protocol. Source-control signatures cannot substitute for release-object
or execution-object envelopes.

## Security meaning

A valid envelope establishes only this statement:

> The key accepted for the declared role signed the exact native bytes and
> role-binding context under the consumer's identity policy.

It does not establish that:

- an execution happened;
- the producer observed the recorded effects correctly;
- the Linux host, launcher, compiler, dependency, or verifier was correct;
- an Auths action was authorized;
- a remote provider performed an effect;
- a log timestamp is fresh or correct; or
- the signed object satisfies a Runtime acceptance policy.

The fallible producer remains in the threat model. Signature validity is a
separate acceptance facet from native object validity, execution outcome,
boundary installation, release assurance, and reuse eligibility.

## Envelope architecture

```text
exact native CBOR bytes -------------------------+
        |                                        |
        v                                        v
  SHA-256 + byte size                    detached COSE payload
        |                                        |
        +--> role binding --> external AAD ------+
                              |
consumer-pinned policy ------>+--> identity resolution --> signature decision
                                                               |
                                                               v
                                  authenticated payload commitment
                                                               |
                                                               v
                                      independent native verifier
```

### Closed outer object

The implementation wave must freeze a CDDL schema equivalent to this shape:

```cddl
runtime-signed-envelope = {
  "schema": "proofbound-runtime/signed-envelope/1",
  "binding": signature-binding,
  "signatures": [+ signature-entry],
}

signature-binding = {
  "role": signing-role,
  "native_owner": tstr,
  "native_protocol": tstr,
  "native_schema": tstr,
  "payload_digest": digest,
  "payload_size": uint,
  "identity_policy": digest,
}

signature-entry = {
  "signer": typed-identity-reference,
  "key_state": typed-object-reference,
  "cose_sign1": bstr,
}
```

This is a design shape, not the shipping schema. The implementation
specification must freeze exact closed enums, field limits, object limits,
identity namespaces, and CDDL before code lands.

The `role` is one of `runtime-release`, `runtime-guest-image`,
`runtime-execution`, `runtime-log-checkpoint`, or
`runtime-checkpoint-witness`. A new role requires a new schema or an explicitly
accepted extension. Unknown roles fail closed.

`native_owner`, `native_protocol`, and `native_schema` name the protocol that
owns the payload meaning. `payload_digest` is SHA-256 over the exact detached
payload. `payload_size` is its exact byte length. `identity_policy` identifies
the exact policy bytes that define acceptable signers, thresholds, identity
evidence, status evidence, and trust roots. A policy label without an exact
digest is insufficient.

Signature entries are sorted by the deterministic encoding of their typed
signer and key-state references. Duplicate signer or key-state entries fail
closed. An empty signature list, unknown field, unknown algorithm, noncanonical
encoding, embedded payload, or nonempty unprotected COSE header fails closed.

### Signature input

Each entry contains a tagged `COSE_Sign1` object with:

- the protected `alg` header set to COSE `Ed25519` (`-19`);
- the payload field set to CBOR `nil`;
- an empty unprotected header map; and
- no ambient or unauthenticated key identifier.

The detached payload is the exact native object bytes. The COSE external
authenticated data is the deterministic CBOR encoding of:

```text
[
  "proofbound-runtime/signature-context/1",
  signature_binding,
  signer_reference,
  key_state_reference
]
```

This binds the role, native protocol, schema, payload identity, identity
policy, asserted signer, and selected key state without changing or
reserializing the native payload. An identity resolver treats the signer and
key-state references as assertions until the signature and policy both pass.

### Verification order

A verifier performs these steps in order:

1. Parse the envelope and detached payload under their independent size limits.
2. Require canonical bytes and the exact closed envelope schema.
3. Select the consumer-supplied identity policy by exact digest. Do not load a
   policy from a location controlled only by the carrier.
4. Compare the native owner, protocol, schema, role, digest, and byte size with
   the supplied payload and the consumer's expected use.
5. Resolve each asserted signer and exact key state through the resolver named
   by the policy.
6. Reconstruct the COSE signature input and verify the fully specified
   algorithm, signature, role, and policy threshold.
7. Treat the now-authenticated payload digest as the independent commitment
   input to the native verifier.
8. Verify the native object with its owner verifier.
9. Verify cross-project links and then apply consumer acceptance policy.

No partial platform acceptance survives a failure. A tool may report each
independent facet, but it must not summarize a valid signature and invalid
native object as verified.

## Identity roles

| Role | Selected identity | Custody and lifecycle | Consumer pins |
| --- | --- | --- | --- |
| Runtime release | Long-lived Runtime release identity delegated from a product trust root | External signer, KMS, HSM, or custody service; rotation and compromise cut-off are external policy inputs | Product namespace, release role, trust root, accepted key state, algorithm, and policy digest |
| Guest image | Separate long-lived guest-image publisher identity | Separate delegated key or custody policy from release signing | Guest-image role, image profile, publisher identity, key state, and policy digest |
| Execution producer | Short-lived producer-workload identity for the exact service or CI workload | Ephemeral key; issuer and subject bind the workload; validity requires a trusted time input | Issuer or resolver root, exact workload subject, execution role, validity policy, and policy digest |
| Local CLI producer | No required signing identity | ADR 0002 commitment channel remains the trust input | Expected commitment and execution identity |
| Auths principal or invoking workload | Native Auths identity and authorization evidence | Owned and verified by Auths | Native Auths profile and verifier; never accepted as a Runtime signer by implication |
| Execution service | Authenticated live endpoint identity | Owned by the service-session profile | Service identity and transport policy; not a receipt-signing identity by implication |
| Receipt-log operator | Long-lived log-specific identity | Separate log signing key and rotation policy | Log identity, operator identity, checkpoint role, key state, and policy digest |
| Checkpoint witness | Long-lived identity unique to one independently administered witness | Separate custody and persistent consistency state | Exact witness set, every witness identity, required threshold, and key state |

The same underlying organization may control more than one role, but it must
use distinct delegated identities and policy entries. Byte equality of keys or
identifiers does not imply role equality. The first maintained profile rejects
cross-role key reuse.

## Identity resolvers and candidate evaluation

### Long-lived raw or managed key

This option is simple and verifiable offline when the consumer pins the public
key. It makes rotation, revocation, custody, and compromise recovery entirely
operator-managed. It is accepted only behind a role-specific identity policy;
it is not the default platform identity model.

### Keyless workload identity

An OIDC- or SPIFFE-bound ephemeral key can bind an execution signature to one
workload. A Sigstore bundle can retain certificate and transparency material
for later verification. This option adds the issuer, CA, log, status material,
trusted time, and workload-claim mapping to the trusted inputs. It is accepted
as an optional execution-producer resolver profile. It is not required for
local CLI use and does not make the public Sigstore service a Runtime
dependency.

### Auths and KERI identity

Auths can verify principal control through raw-key, `did:key`, `did:keri`, or
another registered adapter without moving identity semantics into Runtime. A
KERI profile provides rotation-aware, delegated identity evidence that can be
verified offline from an exact retained KEL closure. That closure proves only
the selected historical state. A claim that a key is currently accepted also
needs a fresh verifier-bound checkpoint or another policy-approved status
source.

This option is accepted for durable platform roles through an explicit Auths
identity integration profile. The profile pins the exact Auths protocol,
identity descriptor, verification policy, evidence closure, verifier identity,
and selected key state. Runtime consumes only a typed resolved-identity result.
It does not interpret KERI events or convert an Auths grant into signing
authority.

### Selected combination

The platform uses long-lived, role-separated identities for durable published
objects and short-lived workload identities for execution producers. The
identity resolver is selected by the consumer profile. Auths is the first
maintained cross-project resolver integration. Keyless workload resolution is
an optional second profile. Neither is required by Runtime's unsigned local
mode.

## Custody, rotation, and revocation

- Runtime code never stores or receives a private key. It produces a bounded,
  domain-separated signing request for an external signer and validates that
  the returned signature matches that exact request.
- The child process never receives a signing handle, identity token, KEL
  update credential, witness credential, or release key.
- A signing request identifies the envelope schema, role, payload commitment,
  signer reference, key-state reference, algorithm, and identity-policy digest.
- A denied, cancelled, stale, mismatched, or ambiguous signer response fails
  closed. Runtime does not retry with another key without a new explicit
  request.
- Rotation changes the key-state identity. It never mutates the meaning of an
  older envelope.
- Revocation and compromise cut-offs are acceptance-policy inputs. A carrier's
  assertion of signing time is not trusted time.
- Offline verification retains the envelope, native payload, exact policy,
  trust roots, identity evidence, key-state evidence, status evidence, and
  verifier identities. Missing closure yields an incomplete result, not a
  fallback to a current online lookup.

## Attestation and policy-engine interoperability

COSE is the native Runtime signing envelope because it supports detached
payloads and fits the deterministic-CBOR contract. DSSE was considered because
its pre-authentication encoding binds a payload type and payload. Its standard
JSON envelope would add a second wire encoding, and its `keyid` is only an
unauthenticated hint. It is not the native Runtime envelope.

An adapter may emit an in-toto statement, DSSE envelope, Sigstore bundle, or
policy-engine input only after native envelope and payload verification. The
external statement must identify the exact native envelope and payload
commitments as typed subjects. It is a projection with its own signer and
verifier identities. It does not become a Runtime receipt and cannot change
native receipt meaning.

## Transparency-log decision

RT-12 will use a self-hosted append-only Merkle tree with SHA-256,
domain-separated leaf and internal-node hashes, operator-signed checkpoints,
inclusion proofs, and consistency proofs. A log entry is deterministic CBOR
and is keyed by the native receipt commitment. It references native objects,
linkage records, envelopes, and integration records by typed exact identity;
it does not re-encode their semantics.

A checkpoint core contains the log identity, tree size, root hash, hash-suite
identity, and checkpoint-schema identity. The operator and witnesses sign the
same exact checkpoint core under distinct signing roles. A witness verifies
the operator signature and append-only consistency from its previously
accepted checkpoint before it signs. It persists that accepted state and
refuses a conflicting root at the same tree size or a history without a valid
consistency proof.

The first maintained witness policy is all-of-N with `N >= 2` independently
administered witnesses in addition to the log operator. Threshold witness
quorums are deferred until a separate decision states a fault model and proves
that two accepted quorums intersect in at least one honest witness. A consumer
pins the log identity, operator identity, complete witness set, signature
policy, and an initial trusted checkpoint through a channel independent of the
log operator.

An offline verifier checks:

1. the pinned checkpoint or consistency chain;
2. the operator signature;
3. every required witness signature;
4. the inclusion proof for each requested object;
5. every native object with its owner verifier;
6. the typed linkage graph and integration profile; and
7. consumer acceptance policy.

A checkpoint timestamp, if present in a view, is an operator assertion. It is
not used as proof of freshness. Freshness requires a separately trusted current
time and an explicit maximum-age policy.

## User experience and API boundary

The future command surface must keep signing optional and verification
explicit:

```text
pbr run ----------------> receipt + independent commitment
   |
   +-- explicit signer -> receipt + commitment + detached envelope

pbr-verify
  payload + expected commitment ------------------> native decision
  payload + envelope + pinned identity policy ----> signature facets
                                                     + native decision
```

The library boundary uses separate operations for envelope parsing, signature
verification, native verification, and acceptance. It does not expose one
Boolean named `verified`. The machine result contains closed outcomes for at
least envelope validity, signer identity, key status, native object validity,
and policy acceptance.

Signing support must use an external-signing port. Identity resolution must use
an independent resolver port. Neither port is available to the child security
path, and neither may import Auths authorization semantics into Runtime core.

## Required falsifiers

The implementation claim wave must include at least these negative cases:

- substitute payload bytes, digest, size, native schema, role, or policy;
- replay an execution signature for another execution;
- use a release signer as a guest-image, execution, log, or witness signer;
- use an Auths action signer as a Runtime signer without explicit policy;
- accept an unknown or deprecated algorithm, including COSE `EdDSA` `-8`;
- accept an embedded payload, nonempty unprotected header, unknown field,
  duplicate signer, noncanonical CBOR, or reordered signer set;
- resolve a KERI identity at a different, stale, rotated, revoked, truncated,
  or equivocating key state;
- trust a keyless certificate without the pinned issuer, subject, chain,
  status evidence, transparency material, or trusted-time policy;
- present a producer self-signature as proof of observed effects;
- omit one required identity or status object from the offline closure;
- accept a checkpoint without the operator and complete witness set;
- accept two conflicting checkpoints, a broken consistency proof, or an old
  checkpoint as fresh; and
- project an external statement whose subject does not match both the native
  payload and envelope identities.

## Trusted roles added by implementation

When enabled, signing adds the exact signing implementation, external custody
provider, identity resolver, identity-policy distributor, trust roots, key
status source, and any trusted-time source. Keyless signing can additionally
add an identity issuer, certificate authority, and transparency service.
KERI resolution adds the retained KEL and its selected checkpoint or status
source. Logging adds the log operator, storage, witness implementations,
witness state, witness identities, and checkpoint-distribution channel.

Proofbound must retain these roles and every residual assumption. No signature
or log proof discharges the Runtime producer, operating-system, compiler,
verifier, or foreign-protocol premises.

## Consequences

### Positive

- Native receipt bytes and meaning remain unchanged.
- Role and protocol substitution are covered by the signature input.
- Runtime can support offline verification and multiple identity systems
  without owning their semantics.
- Unsigned local use stays simple and retains the existing external commitment.
- Durable publication and ephemeral execution can use different custody and
  revocation models.
- The log design detects an operator fork unless every required independent
  witness violates its consistency rule or its keys are compromised.

### Negative

- Portable authenticity adds identity, custody, status, time, and policy trust
  inputs that consumers must understand and retain.
- COSE and Ed25519 implementations join the trusted computing base.
- The first all-witness checkpoint policy favors safety over availability.
- Auths, KERI, keyless, and Sigstore integrations need separate conformance and
  attack corpora. They are not interchangeable because they provide different
  identity and lifecycle evidence.
- Existing generic policy engines consume a projection rather than the native
  Runtime object directly.

## Rejected alternatives

- **Sign the receipt digest without a role binding.** This permits
  cross-protocol and cross-role substitution.
- **Embed or reserialize the native receipt in an envelope.** This creates a
  second representation and risks signature-versus-verifier disagreement.
- **Require signed Git commits.** A commit signature is not an object envelope,
  does not cover runtime observations, and creates unrelated developer custody
  and availability dependencies.
- **Use DSSE JSON as the native envelope.** It conflicts with the
  deterministic-CBOR wire decision and does not by itself provide the required
  identity-policy and key-state binding.
- **Require public Sigstore services.** This would make hosted issuer, CA, and
  log roles mandatory for local Runtime use.
- **Make KERI the Runtime identity model.** KERI is an identity adapter with
  useful rotation evidence, not Runtime execution semantics.
- **Use the producer self-signature as execution proof.** The producer is
  fallible and can sign a false observation.
- **Trust a log operator without witnesses.** One operator can present
  inconsistent histories.
- **Use a log timestamp as freshness proof.** The operator controls that
  assertion.

## Implementation sequence

1. Accept this ADR through independent exact-head review.
2. Freeze the envelope CDDL, bounds, error taxonomy, independent verifier
   input, and canonical vectors in a new signing specification.
3. Implement the pure envelope and policy types with mutation falsifiers.
4. Implement producer and independent-verifier codecs separately.
5. Add the external-signing and identity-resolver ports without adding them to
   the child boundary.
6. Add the Auths identity integration profile and offline evidence closure.
7. Add optional keyless workload resolution only after its trust inputs and
   offline bundle are complete.
8. Add release or execution signing only as separate exact-subject claim
   waves.
9. Start RT-12 only after two independent retention consumers exist.

## Primary references

- [RFC 9052: COSE structures and detached payloads](https://www.rfc-editor.org/rfc/rfc9052.html)
- [RFC 9864: fully specified COSE algorithms](https://www.rfc-editor.org/rfc/rfc9864.html)
- [DSSE envelope specification](https://github.com/secure-systems-lab/dsse/blob/master/envelope.proto)
- [Sigstore client specification](https://github.com/sigstore/architecture-docs/blob/main/client-spec.md)
- [Sigstore bundle specification](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
- [KERI specification](https://trustoverip.github.io/kswg-keri-specification/)
