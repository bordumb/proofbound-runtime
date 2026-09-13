# RT-14 candidate: credential custody and secret delivery

**Status:** candidate; interface discovery permitted, implementation blocked

**Primary owners:** Auths owns credential custody and provider binding.
Proofbound Runtime owns the child delivery boundary and execution observation.

**Start gate:** RT-5 ships one production authenticated-service session and one
Auths provider profile has live-provider qualification.

## Product outcome

An agent can use one declared provider authority without receiving a reusable
long-lived credential and without putting a secret value in a plan, receipt,
log, fixture, command line, or diagnostic.

## Candidate claim boundary

The strongest initial claim is:

> Before child release, the selected credential mechanism made only the
> declared credential role available to the declared service or operation for
> the bounded execution lifetime. No receipt or diagnostic retained the secret
> value.

This does not claim that the provider accepted the credential, that the child
used it correctly, or that a declared service protects data sent to it.

## Mechanisms to compare

1. A connector owns the credential and gives the child only a preauthenticated
   session.
2. An Auths operation mediator owns the credential and gives the child a closed
   local operation channel.
3. A provider issues a short-lived, narrowly scoped credential bound to the
   workload or operation.
4. A sealed descriptor exposes a bounded credential source without inherited
   environment authority.

The comparison records custody, exposure duration, child visibility, process
inheritance, rotation, revocation, provider support, cleanup, and receipt
meaning.

## Required identities

- Auths principal, workload, grant, profile, and connection alias;
- credential-source and non-secret version identity;
- Runtime service or operation identity;
- delivery mechanism and descriptor role;
- execution and Runtime receipt identity; and
- exact connector or mediator release identity.

The receipt records identities and policy only. It never records the credential
value or a reversible derivative.

## Required attacks

- inherit the credential through environment, argument, or undeclared file
  descriptor;
- read it through `/proc`, a child process, a crash report, or diagnostic;
- reuse it after execution completion or service-session expiry;
- redirect or replay it to another service or operation;
- rotate or revoke it between authorization and child release;
- confuse two concurrent executions' credential channels; and
- cause cleanup failure while retaining reusable receipt eligibility.

## Promotion gate

Promote RT-14 only when a reference workload needs a credential, Auths and
Runtime agree on the ownership boundary, the provider profile is qualified,
and one candidate gives materially less authority than long-lived environment
injection.

## Rejection gate

Reject a design that requires a reusable credential in the child environment,
cannot bind credential use to one service or operation, cannot prevent
post-execution reuse, or needs a secret value in committed evidence.
