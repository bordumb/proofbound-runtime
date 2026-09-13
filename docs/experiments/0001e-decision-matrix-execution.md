# Experiment 0001E: Decision matrix execution

- **Status:** all slices and deterministic comparison complete; ADR review next
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001](0001-network-authority-mechanisms.md)
- **Roadmap:** RT-4.2 and RT-4.3
- **Production effect:** none

## Purpose

The first controls established one useful fact about each candidate:

- port-only Landlock authorizes every reachable service on the selected port;
- cgroup BPF selects a routing tuple but does not authenticate a service;
- an explicit broker can bind one closed operation to one authenticated
  service in a bounded fixture; and
- a preconnected authenticated channel binds one session while permitting
  arbitrary bounded application bytes to that service.

Those controls are not a decision. This protocol executes the complete parent
attack inventory in bounded slices, measures the surviving candidates, and
produces the exact comparison input for a separately numbered network ADR. It does not add a Runtime
network mode or treat an experiment result as assurance evidence.

## Closed result vocabulary

Every mechanism executes every registered case. A cell has exactly one
expected outcome:

- `allowed`: the declared workload completes with its exact response;
- `denied`: the attempted exchange fails at the registered enforcement point;
- `exposes-limitation`: application bytes cross a boundary broader than the
  desired service or operation authority;
- `unsupported-before-launch`: the mechanism cannot honestly provide the
  requested profile and starts no child; or
- `harness-failure`: the fixture, observation, deadline, cleanup, or recorder
  is incomplete. This is never an acceptable expected outcome.

An interface that has no target, redirect, proxy, or resolver field still runs
the case. The case must prove that the value is unrepresentable at the closed
interface or expose that transparent bytes can encode it. “Not applicable,”
“not tested,” and an absent cell are invalid.

Each observed outcome also names one exact stage:

```text
plan | prelaunch | child-boundary | resolver | routing | tls |
application-protocol | lifecycle | cleanup
```

The stage says where the observation occurred, not which component is assumed
correct. A client-side certificate failure cannot be relabeled as kernel TLS
enforcement, and a fixture timeout cannot be relabeled as a network denial.

## Slice 1: routing and transport identity

This slice runs these exact cases over IPv4 and IPv6 where the case says both:

1. exact service, endpoint, name, certificate, and response;
2. undeclared service on the allowed port;
3. literal allowed address in place of the service name;
4. literal undeclared address in place of the service name;
5. allowed endpoint with a wrong DNS name or certificate;
6. undeclared endpoint presenting the allowed fixture certificate;
7. direct TCP to an undeclared port;
8. direct UDP and QUIC-shaped UDP;
9. TCP bind/listen and UDP bind;
10. IPv4-mapped IPv6 input;
11. a nonzero IPv6 scope identifier on a non-scoped address; and
12. alternate textual address encodings that must canonicalize without
    changing the tuple or fail before launch.

The explicit broker and preconnected connector must authenticate TLS outside
the untrusted child. A and B also run a malicious raw-byte child against any
permitted routing path; client-side TLS success is recorded separately and is
not sufficient for a service-identity claim.

## Slice 2: resolution and application indirection

The disposable namespace runs an identified authoritative DNS fixture over
registered UDP and TCP channels. Its zone, query script, response sequence,
packet bytes, and observation log are exact inputs. The slice contains:

1. stable A and AAAA answers;
2. an allowed first answer followed by an undeclared answer after the frozen
   TTL;
3. a CNAME chain ending at the declared service;
4. a CNAME chain ending at an undeclared service;
5. a CNAME loop and chain above the registered depth;
6. timeout;
7. truncated UDP response with exact TCP fallback;
8. malformed response;
9. contradictory or unrequested DNSSEC flags;
10. redirect to an undeclared host;
11. redirect to cleartext or another port;
12. HTTP CONNECT and SOCKS-shaped target confusion;
13. ambient `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`; and
14. resolver configuration and environment substitution.

A mechanism that freezes an endpoint instead of resolving at execution must
return `unsupported-before-launch` for a requirement that demands TTL-based
refresh. A closed broker operation with no redirect, proxy, or target input
must prove those inputs are unrepresentable. A transparent channel must expose
any indirection bytes the service accepts; fixed routing alone does not prove
application policy.

## Slice 3: bypass, substitution, and lifecycle

This slice exercises:

1. pathname and abstract Unix sockets outside the registered control channel;
2. an inherited connected Internet descriptor;
3. `io_uring` socket creation, connect, send, and descriptor use;
4. raw and packet socket creation;
5. child fork and exec at the registered process limit;
6. a connection attempt concurrent with boundary installation and child
   release;
7. broker or connector crash before child release;
8. broker or connector crash during an exchange;
9. restart or process-identity substitution;
10. policy, program, map, rule, and configuration substitution;
11. resolver and trust-root substitution;
12. certificate and local-channel substitution;
13. executable and staged-client substitution;
14. connection reuse beyond the registered count;
15. cleanup, detach, channel-close, and namespace-teardown failure; and
16. attempted replacement of an existing result.

The stopped-launcher race case records that no child network operation occurs
before the complete boundary acknowledgement. An experiment-only wrapper that
does not use the Runtime launcher cannot pass this cell; it must run an exact
launcher-shaped control or return `unsupported-before-launch` without making a
production lifecycle claim.

## Measurement slice

Measurements run only after the functional slices reach their registered
outcomes. Each mechanism and architecture records:

- 100 cold setup and exact-request samples, reporting the sorted sample list,
  integer median, and nearest-rank p95 in nanoseconds;
- connector or broker maximum resident set size and process count;
- exact counts and byte sizes of trusted binaries, source/configuration
  objects, certificates, BPF programs/maps, Landlock rules, and channels;
- required capabilities, namespace operations, cgroup controllers, Landlock
  ABI, BPF features, and TLS implementation;
- 1,000 create/fail/remove lifecycle iterations with every iteration result
  retained as a bit set plus the first failure record; and
- a closed residual-authority list selected from the registered vocabulary.

Wall-clock samples are operational observations and need not be byte-identical
between runs. Their inventory, units, ordering, count, aggregation algorithm,
tool identities, and bounds must be deterministic. Performance never changes
a functional outcome or decision criterion.

## Machine-readable domain

Before implementing a slice, one versioned TOML manifest must enumerate its
case identifiers, fixture variant, attempted authority, expected outcome and
stage for A through D, required architectures, and maximum duration. A local
validator must prove:

- every parent row is covered by at least one case;
- every case has exactly one expectation for every mechanism;
- every referenced fixture, mechanism, stage, and outcome is in a closed enum;
- there are no duplicate identifiers or uncovered mechanisms;
- no positive decision cell depends only on untrusted-child TLS behavior;
- authority-exposure cases cannot be encoded as `allowed` or `denied`; and
- the committed manifest and generated execution inventory are identical.

Changing an expectation after observing a run requires a protocol amendment
commit that preserves the old run as a mismatch. The recorder never learns an
expected result from the implementation under test.

## Result and comparison boundary

Each slice publishes one immutable result per mechanism and architecture. Its
`RESULT.json` includes the exact source commit, manifest digest, complete case
inventory, observation-stage inventory, fixture and tool identities, raw
bounded observations, cleanup state, and residual authority. The directory is
created once and never replaced. Failed and unsupported results remain
downloadable.

One separate deterministic comparison consumes only independently verified
slice results. It rejects missing cells, mixed commits or manifest versions,
digest mismatch, architecture mismatch, unexpected outcomes, cleanup failure,
and an unregistered residual authority. It may summarize a mechanism as:

- `ineligible-service-identity`;
- `eligible-for-adr-review-with-explicit-operation-authority`;
- `eligible-for-adr-review-with-service-session-authority`; or
- `incomplete-experiment`.

The comparison cannot select a production design. The network decision ADR must name the
chosen authority granularity, adopter workload, trusted computing base,
unsupported behavior, receipt meaning, and why the operational cost is
acceptable. Independent review of the result set and ADR remains mandatory.

## Execution order

Implementation proceeds as separate historical commits:

1. machine-readable domain and completeness falsifiers;
2. deterministic DNS, dual-stack TLS, proxy, redirect, and socket fixtures;
3. routing/transport slice runners and recorders;
4. resolution/indirection slice runners and recorders;
5. bypass/lifecycle slice runners and recorders;
6. measurement runner and recorder;
7. independently verified hosted results on both architectures;
8. deterministic comparison; and
9. separately numbered network ADR for independent review.

No step waits for Proofbound PR 2 because these are observation-only
experiments. No production claim, model, schema, launcher, receipt, or release
change begins until the reviewed ADR accepts one exact boundary.

## Execution record

Steps 1 through 5 are complete. The machine-readable domain, completeness
falsifiers, deterministic fixtures, and routing/transport runner and recorder
were implemented as separate history. The routing/transport slice then ran at
exact commit `eb1c3954b44d4faf04994c861241f34e38e08e4b` in GitHub Actions run
[`34484880654`](https://github.com/bordumb/proofbound-runtime/actions/runs/34484880654).
All four mechanisms matched all 16 registered cells on both x86_64 and
aarch64, and every downloaded result inventory passed the independent
verifier. The exact result identities and interpretation are recorded in
[Experiment 0001F](0001f-routing-transport-slice.md). The resolution and
application-indirection slice then matched all 144 registered cells at
`3efbd6d` in run `34495928504`, as recorded in
[Experiment 0001G](0001g-resolution-indirection-slice.md). The bypass and
lifecycle slice matched all 144 registered cells at `7719ea2` in run
`34506078724`; every downloaded inventory passed the strengthened independent
verifier, as recorded in [Experiment 0001H](0001h-bypass-lifecycle-slice.md).

Steps 6 through 8 are complete. The measurement slice matched its frozen
completion condition at `f78fd26` in run `34539937335`. The deterministic
comparison then consumed all 32 independently verified results and was itself
independently reproduced at `085a8c8`. Its exact output and interpretation are
recorded in [Experiment 0001J](0001j-deterministic-network-comparison.md).
Step 9 remains open: a separately numbered network ADR requires independent
review. No experiment result is a mechanism decision, and none authorizes
production network behavior.
