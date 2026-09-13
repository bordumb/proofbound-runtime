# RT-13 integration record: platform execution service

**Status:** closed until one named adopter demonstrates repeated demand

**Primary owner:** Proofbound Runtime

**Roadmap:** [Epic RT-13](../product-roadmap-2.md#11-epic-rt-13-execution-service)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

## Product result

One authenticated caller can submit an authorized execution and receive the
same native receipt chain as the CLI path while the service reuses only exact
immutable setup artifacts.

## Service boundary

- Auths authenticates or authorizes the caller under the selected profile.
- Runtime owns queueing, execution-plan validation, boundary installation,
  execution, and Runtime receipt production.
- Proofbound release evidence identifies the exact service and launcher
  artifacts.
- Capsec remains an optional drafting input and never runs in the child security
  path.
- A platform SDK can orchestrate these calls but cannot replace native
  verifiers.

The service records its caller, service, Runtime release, compatibility profile,
plan, execution, receipt, and response-channel identities as separate roles.

## Required behavior

- An API request carries one challenge or idempotency identity bound to one
  authorization decision.
- Replaying it cannot create a second execution.
- The authenticated response carries the independent Runtime commitment.
- Every execution receives a fresh cgroup, Landlock ruleset, seccomp filter,
  output root, launcher state, and control channel.
- Shared caches contain only immutable artifacts verified against the plan.
- One service instance serves one tenant until RT-13.5 accepts a different
  threat model.

## Additional falsifiers

- Confuse two concurrent callers' commitments or receipts.
- Reuse one Auths decision across two queued requests.
- Substitute a cached artifact after authorization.
- Change compatibility profiles between request and result.
- Restart the service while an execution or boundary survives.

## Integration exit

RT-13 is platform-ready when the maintained SDK workflow produces the same
verified native and linked records through CLI and service paths and the
service adds no step to the per-execution child security path.
