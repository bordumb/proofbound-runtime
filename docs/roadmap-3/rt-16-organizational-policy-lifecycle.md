# RT-16 candidate: organizational policy lifecycle

**Status:** candidate; adopter discovery permitted, implementation blocked

**Primary owners:** Auths owns principal, delegation, approval, and revocation
policy. Proofbound Runtime owns execution-plan and receipt acceptance facets.

**Start gate:** two organizational adopters report the same policy lifecycle or
authority-drift problem.

## Product outcome

A team can review, approve, version, revoke, and audit machine authority without
placing mutable control-plane state in the child security path.

## Policy layers

Keep these decisions separate:

- Capsec requirement and authority-drift observation;
- Auths grant, delegation, action, approval, and revocation policy;
- Runtime execution plan and acceptance policy;
- Proofbound assurance floor and release-subject policy; and
- operator policy for guests, services, registries, logs, and witnesses.

One organization bundle can reference these policies. It cannot reinterpret
their native semantics.

## Candidate workflow

1. Resolve an immutable organization-policy bundle before authorization and
   execution.
2. Show the authority change from the previously approved bundle.
3. Collect the required principal approvals or record a typed rejection.
4. Bind the approved bundle identity to the Auths decision and Runtime plan.
5. Apply Runtime acceptance to independently verified receipts.
6. Retain any exception, expiry, approver, revocation snapshot, and break-glass
   reason without retaining secrets.

## Required attacks

- substitute a policy bundle after approval;
- hide added Runtime authority behind an unchanged profile name;
- use an expired exception or stale revocation snapshot;
- approve one Auths action and execute another;
- weaken a Proofbound assurance floor during composition;
- fetch mutable policy after child release; and
- treat a break-glass record as ordinary reusable authorization.

## Promotion gate

Promote RT-16 only when the same workflow appears in two organizations, the
policy owners agree on a content-addressed bundle boundary, and the measured
manual review cost or authority-drift risk justifies a new product surface.

## Rejection gate

Reject one universal policy language that reimplements Auths, Runtime, Capsec,
or Proofbound semantics. Reject a central service that must remain available in
the per-execution child boundary.
