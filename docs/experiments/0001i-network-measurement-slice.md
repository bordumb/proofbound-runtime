# Experiment 0001I: Network mechanism measurement slice

- **Status:** complete; all eight hosted results independently verified
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
The fixture serves the already-frozen `exact` TLS response for `allowed.test`
at the fixed IPv4 endpoint `127.0.0.1:443`. The request is one complete TLS
connection, `GET /v1/echo`, one exact 32-byte response-body check, and clean
connection close.
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
instruction bytes, BPF map configuration bytes, Landlock rule bytes, and local
channel configuration bytes use their canonical experiment encoding rather
than an in-memory kernel or language-object size.

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

## Hosted result

The slice completed at exact source
`f78fd26338e6fe414ca5b8e5586bf8a99c804a9c` in GitHub Actions run
[`34539937335`](https://github.com/bordumb/proofbound-runtime/actions/runs/34539937335).
All eight mechanism-and-architecture jobs completed. After download, the
independent standard-library-only verifier accepted each immutable result
directory. Every result retains 100 cold setup samples, 100 exact-request
samples, and 1,000 of 1,000 successful lifecycle trials with no first failure.

| Mechanism | Architecture | Setup median / p95 (ns) | Request median / p95 (ns) | `RESULT.json` SHA-256 |
| --- | --- | ---: | ---: | --- |
| `landlock-port` | aarch64 | 2,547,548 / 4,145,144 | 281,141,276 / 313,310,448 | `62abf2a8405521927e96e182bdf8127c0537eedbe4a52ad64bd688b66fd58385` |
| `landlock-port` | x86_64 | 2,579,103 / 3,380,368 | 288,431,650 / 293,031,600 | `99d527b0fcb04e8d369bec91dd92b683286f0d00df62f0dc026ce38b5350f8f7` |
| `cgroup-endpoint` | aarch64 | 6,451,516 / 18,002,296 | 278,231,640 / 279,895,480 | `d31bbb7667894c529d99b43c39dabba3efa34551045337774847060bf85d5fa3` |
| `cgroup-endpoint` | x86_64 | 5,867,338 / 13,800,283 | 288,491,790 / 301,895,344 | `f81f1943a170dded207b5b639a17c7d47ef6c25b0458318bf07655ee5cffff0a` |
| `explicit-broker` | aarch64 | 86,731,092 / 86,846,136 | 284,100,368 / 295,465,256 | `306a4f9d423471a17134e38b409ade07200813093c564802717d635fe0dd6b17` |
| `explicit-broker` | x86_64 | 96,946,069 / 97,352,809 | 291,989,294 / 294,363,119 | `2a2158f1b4917791e5e44fe29620577c485979f9a246be75f809a7a987ae1e66` |
| `preconnected-channel` | aarch64 | 22,391,804 / 22,994,776 | 270,483,508 / 278,302,904 | `4f72fc706356f61f125e3a706ada71f19fea83416d9c55800f0260411ae8313b` |
| `preconnected-channel` | x86_64 | 14,256,653 / 15,673,552 | 285,143,749 / 291,164,258 | `24dddba925fb8cb9f435af119c5948766f300d917daceb5862fce1205c1ff8b7` |

The mediator observation was one maximum simultaneous mediator process in
both mediated profiles. Maximum retained mediator RSS was 22,994,944 bytes
and 24,244,224 bytes for the aarch64 and x86_64 explicit broker, and
24,510,464 bytes and 25,886,720 bytes for the corresponding preconnected
connector. Direct profiles correctly report that mediator measurements do not
apply.

Two earlier hosted attempts remain part of the failure history. Run
`34537669699` exposed that a dropped child could not traverse the checkout and
that the mediated profiles had selected the wrong staged client. Run
`34538916842` then exposed a wrapper-dependent missing-executable exit in the
cgroup lifecycle trial. Later commits staged the exact client closure under a
traversable measurement root, replaced the ambiguous injected failure with a
fixed false result, retained bounded lifecycle diagnostics, and added a
positive falsifier before this clean run. No registered functional outcome,
measurement definition, residual authority, or decision criterion changed.

These measurements compare bounded operational observations only. In
particular, the low setup cost of port-only Landlock does not repair its broad
port authority, and the request series includes the common fresh TLS exchange.
The result authorizes the deterministic comparison step; it does not select a
mechanism or authorize production network behavior.
