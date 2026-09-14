# RT-11 integration record: signing and platform identity

**Status:** planned ADR work

**Primary owner:** Proofbound Runtime for Runtime envelopes and policy

**Integration owner:** Auths owns Auths identity and authorization semantics.

**Roadmap:** [Epic RT-11](../product-roadmap-2.md#9-epic-rt-11-signing-and-transparency-adr)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

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
