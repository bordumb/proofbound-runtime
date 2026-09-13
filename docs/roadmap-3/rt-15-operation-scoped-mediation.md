# RT-15 candidate: operation-scoped mediation

**Status:** candidate; experiment preservation permitted, implementation blocked

**Primary owners:** Auths owns action and authorization semantics. Proofbound
Runtime owns direct-path denial, local-channel authority, and execution receipts.

**Start gate:** one consequential reference workload shows that authenticated
service-session authority is materially broader than the authorized operation.

## Product outcome

An agent receives authority for one typed provider operation instead of
arbitrary application bytes on an authenticated service session.

## Candidate claim boundary

The strongest initial claim is:

> The identified mediator accepted only one registered operation schema from
> the confined child, used only its declared credential and provider route, and
> returned one bounded response while Runtime denied undeclared direct network
> paths.

The claim does not establish that the remote provider performed the intended
real-world effect. A response is an observed provider message, not universal
effect proof.

## Architecture questions

- Reuse the explicit-broker mechanism from Experiment 0001 or place mediation
  in an Auths profile process.
- Decide whether operation parsing, canonicalization, retries, redirects,
  pagination, and provider error mapping enter the trusted computing base.
- Bind one authorization decision to one mediator request, idempotency identity,
  response, and Runtime execution.
- Deny direct DNS, TCP, proxy, Unix-socket, inherited-descriptor, and `io_uring`
  bypasses from the child.
- Keep provider-specific semantics outside Runtime core and Proofbound core.

## Required attacks

- invoke another operation through the same provider connection;
- smuggle a second operation through an allowed field or parser ambiguity;
- replay one authorized request after timeout or response loss;
- redirect credentials or payloads to another service;
- confuse two concurrent requests or idempotency identities;
- bypass the mediator with a direct or inherited network path; and
- omit the mediator release identity from the receipt chain.

## Promotion gate

Promote RT-15 only when two conditions hold: the adopter action is consequential
enough to justify a larger mediator trusted boundary, and the closed operation
reduces authority compared with the RT-5 or RT-9 session profile.

## Rejection gate

Reject a generic HTTP proxy presented as operation authority, a parser whose
accepted language is not closed and bounded, or a design that duplicates Auths
action semantics inside Runtime.
