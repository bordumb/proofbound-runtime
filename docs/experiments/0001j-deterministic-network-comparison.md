# Experiment 0001J: Deterministic network comparison

- **Status:** complete; independently reproduced
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001E](0001e-decision-matrix-execution.md)
- **Machine result:** [0001j-network-comparison.result.json](0001j-network-comparison.result.json)
- **Production effect:** none

## Comparison boundary

The deterministic producer and its separately implemented verifier consume all
32 independently verified results: four functional or measurement slices,
four candidate mechanisms, and two supported architectures. The comparison
domain freezes the result schemas, functional case counts, complete
conclusions, residual-authority rules, classifications, ordering, and required
inventory before comparison.

The producer rejects a missing or duplicate result, architecture substitution,
mixed source commits within one slice, mixed decision matrices, mixed
measurement domains, unexpected outcome, incomplete functional result,
changed residual authority, noncanonical result summary, and replacement of an
existing comparison output. The independent comparison verifier does not
import the producer or its domain parser. It reruns each slice's independent
verifier and reconstructs the complete comparison from the raw result
directories.

## Exact result

The comparison ran with producer and independent verifier source at exact
commit `085a8c8ea83e77ea5b704bb88f831f2fcce385bf`. Its exact canonical machine
result has SHA-256
`2b42d8a5dfdc617bf6324db2ad26d0d5ff27c35730e3145c9aacad409deb7c1f`.
The independent verifier reproduced that identity with `complete: true` and
`verified: true`.

| Slice | Exact source commit | Hosted run |
| --- | --- | --- |
| routing and transport | `eb1c3954b44d4faf04994c861241f34e38e08e4b` | [`34484880654`](https://github.com/bordumb/proofbound-runtime/actions/runs/34484880654) |
| resolution and application indirection | `3efbd6d0c743fa16d2f72230c57171f09df5b009` | [`34495928504`](https://github.com/bordumb/proofbound-runtime/actions/runs/34495928504) |
| bypass and lifecycle | `7719ea2cbd0a4e54b77ed2eef0ee2ed8800caa97` | [`34506078724`](https://github.com/bordumb/proofbound-runtime/actions/runs/34506078724) |
| measurement | `f78fd26338e6fe414ca5b8e5586bf8a99c804a9c` | [`34539937335`](https://github.com/bordumb/proofbound-runtime/actions/runs/34539937335) |

Every input binds decision matrix
`5e51ac2831e38c854507b232b861e2d0eddf4c0adf9f0f0b7d0d214b5fe57fa9`.
Every measurement input also binds measurement domain
`dd451c730389e864373bb69e520f8743ea1c2cf687c383099177ee740ace87e1`.
The machine result retains all 32 exact `RESULT.json` identities and the
per-architecture count, median, and p95 measurement projections.

## Derived classifications

| Mechanism | Deterministic classification | Retained authority meaning |
| --- | --- | --- |
| `landlock-port` | `ineligible-service-identity` | direct TCP to any address on the allowed port, with child-controlled resolution, TLS, and application bytes |
| `cgroup-endpoint` | `ineligible-service-identity` | direct TCP to one selected endpoint, with child-controlled TLS and application bytes |
| `explicit-broker` | `eligible-for-adr-review-with-explicit-operation-authority` | one registered operation through the mediator |
| `preconnected-channel` | `eligible-for-adr-review-with-service-session-authority` | arbitrary application bytes on one authenticated service session |

The first two candidates cannot support the roadmap's requested service-
identity language. The remaining candidates are not interchangeable. The
explicit broker provides narrower application authority at the cost of a
protocol parser and materially higher setup time. The preconnected connector
provides a broader authenticated-session authority with lower observed setup
time, but arbitrary bounded application bytes can reach the authenticated
service.

## Review gate

The machine result deliberately contains `production_selection: null`.
Selection belongs in a separately numbered network decision ADR with an
independent approving review. That ADR must choose the adopter workload and
authority granularity, enumerate the broker or connector TCB, resolution and
TLS inputs, unsupported behaviors, lifecycle and receipt observations, and
explain why the selected operational cost is acceptable.

Until that review completes, no Runtime plan, policy, launcher, receipt, or
release schema gains a network-enabled mode. This experiment result is neither
a product wire object nor a production verification input; it does not affect
the unresolved version 2 CBOR map-key decision.
