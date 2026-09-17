# Single-service product proof checklist

- **Status:** active implementation
- **Created:** 2026-09-17T19:31:00+01:00 (Europe/London, BST)
- **Last updated:** 2026-09-17T21:11:30+01:00 (Europe/London, BST)
- **Current Runtime main:**
  `8513ca7e096bc762b8e7d6c3977130a1da8f31f1`; exact-main replay pending
- **Current implementation wave:** RT-5 authenticated connector engine
- **Lifecycle:** prelaunch with zero external users

This checklist is the focused path from the existing assurance foundation to
one product that an external evaluator can run. It implements the dependency
order in the [product roadmap execution order](product-roadmap-execution-order.md)
and narrows the active scope to one outcome:

> Run one identified coding or artifact-producing LLM workload with access to
> exactly one authenticated remote service, enforce its declared local and
> network authority, produce one bounded receipt, verify it independently, and
> apply an explicit consumer acceptance policy.

The normative contracts remain the specifications, threat model, ADRs, claim
manifests, and evidence units. This checklist records execution state. It does
not promote tests to proofs, source contracts to production behavior, or a
maintainer-controlled demonstration to external adoption.

## Delivery method

Use one claim-sized batch at a time.

1. Freeze the plain-language claim, exact production subject, assumptions,
   exclusions, failure classes, and evidence inventory.
2. Implement the complete coherent batch before running broad checks.
3. During implementation, run only cheap syntax or focused pure checks needed
   to avoid compounding an obvious defect.
4. After the batch is complete, run its focused static checks together.
5. Create an unsigned implementation commit and obtain an independent static
   exact-head review.
6. Correct all review blockers in separate unsigned commits. Review the final
   exact head again.
7. Add the approval-only record after `APPROVE` without changing the reviewed
   production subject.
8. Before each push, assign a CI monitor that checks every two to three minutes
   and interrupts immediately on failure or full success.
9. Push once, run the complete hosted gate, and merge only the exact reviewed
   head that passed.
10. Require a complete exact-main replay before calling changed claims
    admitted or starting a dependent production wave.

Do not run local Rust, Lean, Kani, or native builds while another local agent
owns those resources. Use hosted CI for those gates. Never weaken, skip, mock,
or relabel an unavailable enforcement mechanism.

## Phase 0: close the non-production receipt contract

- [x] Admit the first observation and launcher source-contract baseline. PR 32
  head `3c3bcd3` passed Verify run `35248987742`, merged as exact main
  `2ddb4a9`, and passed exact-main Verify run `35254613508`.
- [x] Define deterministic-CBOR reusable-success and non-reusable-failure
  receipt fragments.
- [x] Bind execution, plan, policy, service, assumptions, service-specific
  trusted-computing-base identities, observation, outcome, and cleanup.
- [x] Bind only the launcher prefix that can truthfully exist at the reported
  failure phase. Do not fabricate install, installed, or release messages.
- [x] Validate credentialed retained release state without retaining a
  credential value or value-derived digest.
- [x] Add causal cross-binding, downgrade, omission, cleanup, phase, secret,
  and trusted-computing-base mutations.
- [x] Obtain a preliminary independent `APPROVE` before restacking.
- [x] Update all exact-main admission records after the restack.
- [x] Obtain a final independent `APPROVE` for restacked receipt-contract head
  `ad2a80e`.
- [x] Add and endorse the receipt-contract approval-only review record in
  commit `c361cb1`.
- [x] Push receipt-contract commit `c361cb1` with an active CI monitor.
- [x] Pass complete exact-head hosted verification. Verify run `35262967214`
  passed every required lane and the final gate at exact head `c361cb1`.
- [x] Merge PR 33 as exact main `8513ca7`.
- [ ] Pass complete exact-main verification for `8513ca7`.

Exit: the current `PBR-NETWORK-035`, `PBR-NETWORK-036`, and
`PBR-NETWORK-037` source closures are admitted together. Production service
execution and production receipt acceptance remain disabled.

## Phase 1: implement the production connector and launcher boundary

### 1.1 Freeze the production claim

- [ ] Replace source-contract language with a claim about one exact production
  connector, supervisor path, launcher path, and child boundary.
- [ ] Register the resolver, TLS implementation, trust roots, connector
  executable and runtime closure, kernel, launcher, clock, and credential
  source as explicit assumptions or trusted-computing-base roles.
- [ ] Define the exact child-visible channel protocol and descriptor ownership.
- [ ] Define fail-closed behavior for every setup phase before any child code
  can execute.
- [ ] Keep ambient networking, reconnect, redirects, proxies, QUIC, multiple
  services, and arbitrary protocols out of scope.

### 1.2 Implement the connector

Wave status: `PBR-NETWORK-038` now registers the isolated connector-engine
candidate and its Tier 0 source tests. The initial exact-head review at
`450453d` requested changes for authority binding, exact SAN matching, absolute
deadlines, explicit TLS-provider selection, CNAME validity, source closure, and
causal falsifiers. The first correction head `cd8b16e` was rejected for one
compile defect, incomplete DNS lifetime reconciliation, terminal deadline
classification, non-causal gate tests, stale source status, and incomplete
local-dependency closure. A consolidated second correction batch is in
progress. Keep every checkbox below open until the engine runs as the exact
identified production process and the relevant behavior passes hosted and
native admission.

- [ ] Add a minimal connector executable with one purpose: establish one
  bounded authenticated TLS session for one normalized service identity.
- [ ] Resolve only the declared service name through the registered resolver
  configuration.
- [ ] Apply the closed answer, CNAME, response-byte, TTL, deadline, endpoint-
  attempt, and address-order bounds before connection.
- [ ] Verify the exact DNS service name against the TLS identity policy.
- [ ] Disable early data, session resumption, reconnect, redirects, proxy
  discovery, and ambient credential discovery.
- [ ] Create one private local stream channel before child release and retain
  no undeclared descriptor.
- [ ] Release a declared credential only after the connector is authenticated
  and the child boundary is installed. Never place the secret in a plan,
  receipt, diagnostic, fixture, log, or retained evidence.
- [ ] Enforce one authenticated session, setup and session time, directional
  application-byte, DNS-message, endpoint-attempt, and TLS-handshake bounds.
  Do not parse, count, or claim application requests or responses.
- [ ] Terminate and reap the connector on every failure and terminal path.

### 1.3 Integrate the supervisor and Linux launcher

- [ ] Use typestate so the child cannot pass `execve` until the connector is
  ready, the child boundary is installed and read back, and the exact release
  message is accepted.
- [ ] Transfer only the declared child channel descriptor.
- [ ] Deny direct child IPv4, IPv6, packet, raw, netlink, resolver, proxy,
  undeclared Unix-socket, descriptor-transfer, `io_uring`, namespace,
  privilege, and tracing paths.
- [ ] Close every undeclared inherited descriptor before acknowledgement.
- [ ] Keep all raw syscalls and `unsafe` code in
  `crates/proofbound-runtime-linux/src/sys.rs`, with complete `SAFETY:`
  preconditions.
- [ ] Preserve the existing memory, process, filesystem, wall-time, output,
  and cleanup boundaries.
- [ ] Reject unsupported kernels or missing controls before child execution.
- [ ] Keep deny-network execution byte-for-byte or semantically unchanged
  except where a reviewed shared abstraction requires a new exact admission.

Exit: a child can use only one inherited local channel to one connector-owned,
authenticated service session. Production still cannot publish a reusable
receipt until Phases 2 and 3 pass.

## Phase 2: falsify the native network boundary

- [ ] Add positive native tests for one bounded successful session on
  `x86_64` and `aarch64`.
- [ ] Attempt direct IPv4 and IPv6 sockets from the child.
- [ ] Attempt UDP DNS, raw, packet, netlink, and alternate Unix sockets.
- [ ] Attempt `sendmsg`, `recvmsg`, and `SCM_RIGHTS` descriptor transfer.
- [ ] Attempt descriptor duplication, inherited-socket reuse, and channel
  endpoint substitution.
- [ ] Attempt `io_uring` socket operations.
- [ ] Attempt descendant and helper-process bypasses inside the execution
  cgroup.
- [ ] Attempt alternate resolver, endpoint, port, SNI, certificate,
  trust-root, connector, and runtime-closure substitution.
- [ ] Attempt DNS expiry, CNAME overflow, answer overflow, response overflow,
  endpoint exhaustion, handshake overflow, and every configured deadline.
- [ ] Attempt reconnect, redirect, proxy-environment, and credential-source
  substitution.
- [ ] Kill or stall the connector and launcher in every setup and active phase.
- [ ] Verify child non-release for all pre-release failures.
- [ ] Verify bounded termination, reaping, channel closure, empty cgroup, and
  namespace cleanup for every terminal path.
- [ ] Bind the native corpus to both exact release architectures and retain the
  evidence without interpreting a passed test as universal containment.

Exit: every registered bypass or substitution fails for its intended typed
reason on both supported architectures.

## Phase 3: ship receipts, independent verification, and acceptance

### 3.1 Production receipt producer

- [ ] Integrate the admitted service fragment into the production execution
  receipt without weakening existing plan, policy, resource, output, outcome,
  assumption, or trusted-computing-base fields.
- [ ] Emit reusable success only after authenticated session completion, zero
  child exit, complete bounded observation, and successful cleanup.
- [ ] Emit a typed non-reusable failure for every incomplete, exceeded,
  inconsistent, or cleanup-failed path.
- [ ] Bind exact connector, launcher, Runtime, policy, plan, installed,
  release, observation, and release-artifact identities.
- [ ] Retain no credential value, secret-derived digest, or application
  request/response content.

### 3.2 Separate independent verifier

- [ ] Implement a separate Rust decoder and semantic verifier in
  `proofbound-runtime-verify`.
- [ ] Do not depend on another workspace crate or share producer semantic
  implementation code.
- [ ] Reject unknown schemas, fields, roles, states, failures, assumptions,
  mechanisms, and identity forms.
- [ ] Recompute every canonical identity and cross-binding independently.
- [ ] Re-run the complete omission, substitution, downgrade, cross-service,
  cleanup, prefix, and secret-retention mutation corpus against the verifier.

### 3.3 Composition and consumer acceptance

- [ ] Preserve service authority, observed service identity, bounds,
  assumptions, trusted-computing-base roles, failure state, and reuse status
  through receipt composition.
- [ ] Add an explicit single-service acceptance policy to `pbr-accept`.
- [ ] Make deny-network policy reject service-session receipts and make one-
  service policy reject any other service, port, connector, or assumption set.
- [ ] Keep diagnostic, failed, incomplete, stale, unsupported, and
  non-reusable receipts unconditionally unacceptable for reusable success.
- [ ] Add first-party Action coverage for the service-session policy without
  granting the Action network authority or credentials it does not need.

Exit: an offline consumer can independently verify and explicitly accept or
reject one production service-session execution.

## Phase 4: demonstrate one real LLM workload

- [ ] Select one exact maintained client and one API surface. The default first
  target is a minimal repository-owned Anthropic Messages API client using
  only `api.anthropic.com:443`; change this only if implementation evidence
  shows that the target cannot satisfy the one-service contract.
- [ ] Freeze the client source, dependencies, executable closure, service,
  credential-source name, input fixture, and output contract.
- [ ] Keep the test credential external and ephemeral. Never retain it or use
  it in public fixtures or routine CI.
- [ ] Use RT-8 to draft the plan, then record every human-completed authority
  choice separately from observed diagnostic provenance.
- [ ] Execute the client with a fresh output root and bounded process, memory,
  swap, time, output, and service limits.
- [ ] Verify the receipt with the standalone verifier.
- [ ] Apply the explicit consumer policy and retain the decision beside the
  exact receipt commitment.
- [ ] Demonstrate that undeclared services, redirects, proxy variables,
  alternate credentials, direct sockets, and broader write roots fail.
- [ ] Measure installation time, planning time, execution overhead, denial
  recovery, receipt verification time, and total time to first verified result.
- [ ] Publish a content-free reproducible demonstration bundle and operator
  guide.

Exit: one real networked LLM workload produces a useful artifact and an
independently accepted receipt without broader network or local authority.

## Phase 5: finish RT-7 external distribution gates

These tasks require external registry state and credentials. Source work can
prepare them, but they cannot be checked from a maintainer-controlled
simulation.

- [ ] Configure the remaining protected crates.io, PyPI, and npm publisher
  identities and the one-time npm bootstrap credential.
- [ ] Publish the selected packages from one exact reviewed and admitted main
  revision.
- [ ] Retrieve every package anonymously and compare exact retained bytes and
  manifests.
- [ ] Exercise the verifier, Runtime SDK, Python SDK, and TypeScript SDK from an
  unrelated consumer repository.
- [ ] Retain the deterministic current-integration record and exact consumer
  observations.
- [ ] Keep checksums as identity evidence only; do not describe them as
  publisher authentication until the accepted signing design is implemented.

Exit: an unrelated evaluator can install the supported packages without a path
dependency or privileged repository access.

## Phase 6: independent external review readiness

- [ ] Produce a concise review package containing the normative specification,
  threat model, accepted ADR, exact claim inventory, source closures, mutation
  corpus, formal linkage, native evidence, release identities, and residual
  assumptions.
- [ ] Include a minimal architecture map and a list of deliberately rejected
  claims.
- [ ] Include exact reproduction instructions that do not depend on a
  contributor home directory, credential, cache, or ambient network.
- [ ] Obtain review from at least one qualified human who is not the author and
  is not acting through the maintainer's AI review chain.
- [ ] Record findings without rewriting history. Correct each blocking finding
  in a distinct reviewed wave.
- [ ] Do not market the system as independently audited until that review has
  occurred and its scope is published accurately.

Exit: the product has an external security-reviewable subject and an honest
statement of what was and was not independently assessed.

## Product decision after the proof

- [ ] Interview or observe at least one evaluator attempting the complete
  workload without maintainer intervention.
- [ ] Decide whether the first buyer values consequential-action assurance,
  hostile-code containment, or both.
- [ ] If hostile-code or tenant isolation is required, open RT-10 as an outer
  microVM deployment profile while retaining Runtime as the inner per-execution
  authority and receipt layer.
- [ ] Open RT-9 only after the single-service workload succeeds and a real
  workload requires two declared services.
- [ ] Open RT-13 only after measurements show repeated setup cost dominates and
  a named adopter requires repeated invocations.
- [ ] Keep RT-12 and Roadmap 3 candidates behind their existing consumer and
  demand gates.

## Completion definition

This checklist is complete only when Phases 0 through 4 are admitted on exact
main, Phase 5 is completed or explicitly blocked by named external registry
configuration, and Phase 6 has produced the complete review package. A human
review itself and unrelated-adopter observations remain external facts and
cannot be manufactured by repository code.
