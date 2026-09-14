# RT-17 candidate: signed integration-profile registry

**Status:** candidate; bundle-shape planning permitted, registry operation blocked

**Primary owner:** each protocol owns its profile fields. A later ADR selects
the registry operator and publisher policy.

**Start gate:** RT-7 publishes the compatibility policy, RT-11 authenticates
publishers, and two maintained integration profiles exist.

## Product outcome

A user can select a reviewed provider or workload profile by name while the
plan and receipt chain bind the exact expanded bytes, versions, identities, and
qualification status.

## Candidate bundle

A profile bundle can contain exact references to:

- Auths action, grant, identity-method, provider-adapter, and qualification
  schemas;
- Runtime plan, service identity, transport, credential, limit, and acceptance
  profiles;
- Capsec analyzer and optional source-observation mapping;
- native SDK and verifier versions;
- Proofbound release assurance and required evidence floors;
- cross-project integration tuple;
- positive vectors and registered attacks; and
- publisher envelope and registry inclusion proof.

The bundle contains no credential value, organization grant, mutable endpoint
answer, or user-specific policy.

## Resolution rules

- A friendly name resolves before plan normalization.
- The resolved canonical bytes and content identity enter the reviewed plan.
- A mutable name such as `latest` cannot appear in a reusable plan or receipt.
- Offline use remains possible with a pinned bundle and verifier set.
- A registry result establishes publication under its identity policy. It does
  not establish that the profile is safe for a consumer's workload.

## Required attacks

- mutate a bundle behind an unchanged name;
- mix individually valid but untested product versions;
- replace a provider adapter, verifier, or qualification record;
- downgrade the attack corpus or assurance floor;
- sign the bundle with a key valid for a different role;
- omit one expanded field from the plan identity; and
- serve split registry histories without detection.

## Promotion gate

Promote RT-17 only when two independently useful profiles share the same bundle
and resolution needs and at least one external consumer uses pinned profiles.

## Rejection gate

Reject a registry that requires online lookup during child execution, cannot
export a complete offline bundle, uses a mutable name as identity, or centralizes
foreign protocol semantics in Runtime.
