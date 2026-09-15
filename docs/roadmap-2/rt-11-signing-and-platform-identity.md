# RT-11 integration record: signing and platform identity

**Status:** proposed ADR drafted; independent review pending

**Primary owner:** Proofbound Runtime for Runtime envelopes and policy

**Integration owner:** Auths owns Auths identity and authorization semantics.

**Roadmap:** [Epic RT-11](../product-roadmap-2.md#9-epic-rt-11-signing-and-transparency-adr)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

**Decision:** [ADR 0009](../adr/0009-detached-role-bound-signing.md)

## Product result

A consumer can authenticate the origin of release, execution, and log objects
under explicit identity and key-custody policies without treating a signature
as proof that an execution happened.

## Identity questions for the ADR

The ADR must decide whether and how to use:

- an Auths principal or delegated KERI identity;
- an ephemeral workload identity;
- a long-lived Runtime product or release identity;
- a guest-image publication identity;
- an execution-service identity;
- a receipt-log operator identity; and
- checkpoint witness identities.

It must state which identity signs which exact bytes, which verifier resolves
the identity, how keys rotate or revoke, and what a consumer pins.

## Envelope boundary

- Native receipt bytes do not change.
- A detached envelope names the native protocol, schema, payload digest, and
  signing identity policy.
- Auths signatures retain Auths meaning. Runtime does not reinterpret them as
  Runtime producer correctness.
- Release signatures and execution signatures remain distinct.
- An integration record names accepted envelopes and algorithms but does not
  authenticate itself.

ADR 0009 selects a deterministic-CBOR outer envelope with exact closed,
detached `COSE_Sign1` entries. Each signature authenticates the envelope
schema, exact native payload, identity policy, signer, key state, and role
binding through COSE external authenticated data. The first algorithm is fully
specified COSE Ed25519 (`-19`). Deprecated polymorphic EdDSA (`-8`) fails
closed.

## Selected identity model

- Release, guest-image, log-operator, and witness roles use distinct durable
  identities and externally managed custody.
- Execution producers can use a short-lived workload identity.
- Unsigned local execution keeps ADR 0002's independent commitment channel.
- Auths is the first maintained identity-resolver integration. It verifies
  principal control and exact KERI state without moving Auths authorization or
  KERI event semantics into Runtime.
- The first profile invalidates all envelopes from a retired, revoked, or
  compromised key. Historical acceptance needs independently authenticated
  temporal evidence bound to the exact envelope.
- Thresholds count canonical resolved keys and controllers, not asserted
  aliases. One controller cannot occupy two witness roles.
- Source-control signing is outside the envelope contract. Git commits need
  not be signed.

## Selected log model

RT-12 will use an append-only SHA-256 Merkle tree, operator-signed checkpoints,
inclusion and consistency proofs, and at least two independently administered
witnesses. The first policy requires every configured witness. Threshold
quorums require a later fault-model decision. A checkpoint timestamp is not
freshness evidence.

## Additional falsifiers

- Use a valid Auths action signer as a Runtime release signer without policy.
- Replay an ephemeral workload signature for another execution.
- Accept a rotated or revoked KERI key outside the selected verification state.
- Substitute an envelope's protocol role while retaining the payload digest.
- Present a producer self-signature as proof of observed effects.

## Integration exit

RT-11 is platform-ready when the accepted ADR defines the complete identity
taxonomy, byte envelopes, custody and revocation rules, verifier inputs, and
consumer pinning policy for the first maintained integration profile.
