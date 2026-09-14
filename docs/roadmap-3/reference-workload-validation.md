# Roadmap 3 reference-workload validation

**Status:** ready for design-partner discovery; no workload is qualified

**Owner:** Proofbound Runtime product planning

## Purpose

Use real workflows to decide which Roadmap 3 candidates deserve implementation.
The trials measure usability and product need. They do not produce assurance
evidence for a shipping claim unless a separate registered evidence path admits
them.

## Workload A: networked LLM coding agent

The agent reads one identified source tree, calls one declared LLM service,
writes only to one fresh output root, and returns a patch plus a verified
receipt.

Measure:

- plan completion time before and after diagnostic drafting;
- dynamic closure and unexplained denial count;
- credential exposure surface;
- service-session setup and repeated-call cost;
- output size and verification time; and
- whether one or multiple services are actually required.

This workload informs RT-14, RT-17, and RT-18. A second service informs RT-9
only when the workflow genuinely needs it.

## Workload B: CI artifact-producing agent

The agent reads an identified checkout, runs one declared toolchain, writes one
artifact tree, and retains Runtime, acceptance, and Proofbound release records.

Measure:

- install-to-first-receipt time on a clean Linux worker;
- static scaffold completeness;
- cacheable immutable setup versus per-execution boundary cost;
- output-capacity requirements;
- policy drift after one dependency update; and
- auditor export and offline verification time.

This workload informs RT-16, RT-17, RT-19, and the RT-13 service gate.

## Workload C: authorized consequential action

An Auths profile authorizes one bounded provider action. The executing process
runs under Runtime and produces the linked Auths, Runtime, and Proofbound object
closure.

Candidate actions include one repository write, deployment change, or
disposable provider mutation. The first trial must use a disposable target and
no production credential.

Measure:

- authorization-to-execution linkage effort;
- whether authenticated session authority is too broad;
- credential custody and rotation requirements;
- replay and idempotency behavior;
- time to verify the complete chain; and
- which facts an operator still has to trust.

This workload informs RT-14, RT-15, RT-16, and RT-17.

## Common success thresholds

The first discovery round records baseline values before selecting targets.
The second round can promote a candidate only when:

- a new user reaches a verified receipt without reading Runtime source;
- every manual authority choice is visible;
- no secret value enters a plan, receipt, log, fixture, or diagnostic;
- a consumer can identify every native verifier and integration profile;
- the integrated chain preserves each product's weaker results and assumptions;
- the adopter can name the operational or compliance value; and
- the adopter agrees to repeat the workflow outside a maintainer-controlled
  repository.

## Stop conditions

Stop a trial when it requires weakening a production boundary, using an
unqualified live provider, storing a secret in committed data, treating a test
as proof, or describing an unsupported platform as confined.

## Recorded result

Each trial records:

- adopter and workload identity;
- exact product and schema version tuple;
- host profile;
- inputs and non-secret configuration;
- measured values and failure reasons;
- candidate decisions affected; and
- the next experiment or rejection reason.
