# RT-9 integration record: authorized service execution

**Status:** blocked until RT-5 ships one production authenticated service
session

**Primary owner:** Proofbound Runtime

**Integration owner:** Auths owns authorization and action meaning.

**Roadmap:** [Epic RT-9](../product-roadmap-2.md#7-epic-rt-9-multi-service-network-allow-list)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

## Product result

One Auths-authorized action runs in one identified Runtime execution that can
reach only its declared authenticated service set. The resulting records let a
consumer verify authorization and enforcement as separate facts.

## Identity mapping

An integration profile maps these values explicitly:

- Auths principal and workload identity;
- Auths profile and canonical action identity;
- Auths authorization-decision receipt identity;
- Runtime plan and execution identity;
- Runtime service identities; and
- Runtime receipt commitment.

An Auths provider or connection alias is not a Runtime service identity. A
Runtime DNS name is not an Auths action. The mapping is profile-specific and
fails closed when it is missing or ambiguous.

## Required behavior

- The exact Auths decision receipt is a declared Runtime input.
- The Runtime plan names every permitted service before execution.
- The Auths execution receipt commits to the cross-receipt linkage record.
- Authorization for one action cannot authorize another service, redirect,
  proxy route, executable, or execution attempt.
- Runtime acceptance preserves the Auths verifier result without interpreting
  Auths grant semantics.

## Additional falsifiers

- Swap two connection aliases that resolve to the same port.
- Reuse one decision for a second Runtime execution.
- Add a second Runtime service not named by the selected Auths profile.
- Substitute an Auths action while preserving the service set.
- Substitute a Runtime service while preserving the Auths action.

## Integration exit

RT-9 is platform-ready when one maintained agent performs an authorized action
across two declared services, both native verifiers accept their own records,
the linkage verifier accepts the exact graph, and every identity-confusion case
fails with its expected typed reason.
