# Experiment 0001I: Network mechanism measurement slice

- **Status:** pre-registered; implementation not yet executed
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001E](0001e-decision-matrix-execution.md)
- **Roadmap:** RT-4.2 and RT-4.3
- **Production effect:** none

## Question

What is the bounded operational cost and lifecycle reliability of each network
authority candidate after it reaches every registered functional outcome?

The measurement does not change a functional cell, mechanism eligibility, or
decision criterion. A faster mechanism does not become semantically adequate.
An incomplete functional result cannot enter this slice.

## Exact workload

Each mechanism runs in a fresh loopback-only network namespace on native Linux.
The fixture serves one identified TLS response for `allowed.test` at the fixed
IPv4 endpoint `127.0.0.1:443`. The request is one complete TLS connection, one
fixed HTTP request, one exact response-body check, and clean connection close.
The certificate, trust root, request bytes, response bytes, mechanism controls,
and staged client are identified inputs.

The runner records two independent series for each mechanism and architecture:

1. 100 cold setup samples. Each sample creates the mechanism boundary and its
   required channel or attachment, confirms readiness, and tears it down.
2. 100 exact-request samples. Each sample starts from a newly created boundary,
   performs the exact request, confirms the response, and tears the boundary
   down.

Durations use `CLOCK_MONOTONIC_RAW` when the host exposes it and otherwise use
`CLOCK_MONOTONIC`. The result records the selected clock. A sample contains an
integer nanosecond count. The published list is sorted in ascending order. For
100 values, the median is the floor of the sum of positions 50 and 51 divided
by two. The nearest-rank p95 is position 95. Positions are one-based in this
description.

## Resource and inventory observations

The explicit broker and preconnected connector record their maximum resident
set size in bytes and maximum simultaneous process count during the exact
request series. Direct mechanisms record that mediator measurements do not
apply; they do not substitute the child or harness process.

Every result reports a count and total byte size for every category, including
zero-valued categories:

- trusted binaries;
- source and configuration objects;
- certificates and public trust roots;
- BPF programs;
- BPF maps;
- Landlock rules; and
- local control channels.

The inventory also retains each nonzero member's logical role, exact SHA-256
identity, and byte size. Counts and totals are derived from those members. BPF
instruction bytes and Landlock rule bytes use their canonical experiment
encoding rather than an in-memory object size.

## Platform requirements

The result records harness and mechanism requirements separately. The harness
requires root to create the disposable network namespace. It records the
effective capability mask rather than inferring individual capabilities from
the user identifier.

Each result records the exact namespace operations, cgroup v2 controller
inventory, Landlock ABI or explicit absence, BPF feature probes or explicit
absence, Python TLS implementation string, kernel release, compiler identity,
Python identity, architecture, and selected monotonic clock. An unavailable
required mechanism produces a retained incomplete result; it does not borrow a
feature observation from another mechanism.

## Lifecycle trial

Each mechanism runs 1,000 create/fail/remove iterations. An iteration creates
the selected mechanism boundary, injects a failure before a request can be
released, closes or detaches every owned resource, and confirms that the exact
created resource no longer exists. The result retains one bit per iteration in
iteration order. The least-significant bit of the first byte represents
iteration zero. A set bit means the complete iteration passed.

The result also records the first failing iteration and its closed failure code,
or `null` when all 1,000 iterations pass. A summary count is derived from the
bit set. The recorder rejects a summary that does not match the retained bits.

## Residual authority

The measurement result selects only from this closed vocabulary:

- `direct-tcp-to-any-address-on-allowed-port`;
- `direct-tcp-to-selected-endpoint`;
- `child-controlled-resolution`;
- `child-controlled-tls`;
- `arbitrary-application-bytes`;
- `registered-operation-via-mediator`; and
- `arbitrary-application-bytes-on-authenticated-session`.

The machine-readable domain fixes the exact list for every mechanism. Timing
or lifecycle observations cannot remove an authority that the functional
slices exposed.

## Publication boundary

One immutable result directory is published per mechanism and architecture.
It contains the exact measurement domain, sorted samples, lifecycle bits, raw
observations, source and evidence manifests, tool and platform identities,
inventory members, resource observations, residual authority, and one canonical
`RESULT.json`. Publication is no-replace.

The producer validates the domain and constructs the result. A separate
standard-library-only verifier does not import the producer, domain parser,
runner, or mechanism implementation. It recomputes input identities, sample
aggregation, lifecycle summaries, inventory totals, required fields, residual
authority, and the result commitment.

## Completion condition

The slice is complete only when all eight mechanism-and-architecture results
come from one exact clean source commit, pass independent verification after
download, retain 100 setup and 100 request samples, retain all 1,000 lifecycle
bits, and report no lifecycle failure. Completion authorizes deterministic
comparison only. It does not authorize production network behavior.
