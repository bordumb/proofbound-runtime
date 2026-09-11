# Experiment 0002: Runtime performance baseline

- **Status:** pre-registered; implementation not started
- **Date:** 2026-09-10
- **Roadmap:** RT-6.3
- **Production effect:** none

## Question

What time and resource cost does version 1 Runtime add to its pure decisions
and to one supported native execution, and do repeated invocations justify a
different process architecture?

This experiment measures operational cost. It is not Proofbound evidence, a
security claim, a product wire object, or permission to weaken a gate. A fast
result cannot establish correctness, and a slow result cannot invalidate an
otherwise admitted claim.

## Frozen scope

The first baseline measures only behavior already defined by the accepted
version 1 contracts. It does not define or benchmark a version 2 encoding.
Deterministic-CBOR parsing, projection, verification, and composition are added
only after ADR 0003's remaining map-key decision, closed CDDL, and golden
vectors are accepted.

### Pure operations

The pure harness measures these production entry points independently:

1. `parse_execution_plan` over the maintained minimal positive plan fixture;
2. `normalize_authority` over a validated authority containing duplicate and
   reverse-ordered path and environment entries;
3. `compile_policy` over that normalized authority;
4. `construct_execution_receipt` over one fixed reusable version 1 receipt
   input;
5. canonical version 1 receipt encoding;
6. `verify_receipt` over the exact encoded receipt and external commitment;
   and
7. `compose` over one fixed, independently valid execution and
   release fixture set.

Every fixture is checked into the repository or constructed from checked-in
typed constants. Setup, file reads, fixture parsing, cloning needed to restore
an input, and result validation are timed separately from the selected
operation. The harness consumes every result through `std::hint::black_box`
and validates the final result after each measured series.

### Native execution phases

The native harness uses the maintained static example and the existing
supported-host recipe. It records these phases without changing their order or
meaning:

- strict plan validation and normalization;
- capability and rooted-path preflight;
- executable and runtime-closure inventory;
- cgroup creation and controller readback;
- stopped launcher creation;
- Landlock, seccomp, privilege, and cgroup boundary installation;
- child release and process execution;
- bounded stream collection;
- receipt construction and publication; and
- process-tree drain and exact cgroup cleanup.

The first workload exits successfully after writing the fixed maintained
example output. A second repeated-invocation series runs the same exact plan
and executable 100 times through separate fresh executions. No daemon, shared
execution boundary, reused receipt, or reused cgroup is introduced by the
measurement.

## Measurement protocol

The pure harness is compiled with the workspace release profile. Each
operation receives at least 100 untimed warm-up iterations. It then records
1,000 independent samples. A sample batches enough identical invocations to
last at least 10 milliseconds according to a deterministic calibration pass;
the recorded value is elapsed nanoseconds divided by the batch count. The
calibrated batch count is retained with the result.

Native observations use 10 warm-up executions followed by 100 measured
executions per supported architecture. Each phase uses monotonic elapsed time.
Process-level maximum resident set size is recorded when the host exposes it;
absence is explicit rather than represented as zero.

For every series the result retains:

- sample count, calibrated batch count where applicable, median, p95, minimum,
  and maximum elapsed nanoseconds;
- source commit, clean-tree state, Rust version, target triple, release-profile
  identity, and exact benchmark executable SHA-256;
- architecture, runner image, CPU model and count, memory size, kernel release,
  cgroup version and enabled controllers for native runs;
- exact input fixture identities and output/result identity; and
- the first bounded diagnostic if setup, execution, or result validation
  fails.

The p95 is the nearest-rank 95th percentile over sorted raw samples. The median
is the midpoint for an even sample count using integer floor division. Raw
samples remain in the retained result so an independent standard-library-only
verifier can recompute every statistic and identity.

## Result boundary

Operational results use a closed JSON metadata schema because they are CI and
benchmark telemetry, not versioned Runtime product wire objects or verification
inputs. They are written outside `.proofbound`, never cited as claim evidence,
and never accepted as a substitute for a fresh assurance gate. The result
schema rejects unknown fields, non-integer durations, unsorted or incomplete
sample sets, identity mismatch, unsupported subjects, and inconsistent summary
statistics.

The producer and independent verifier are separate programs. The verifier
receives the raw result directory, recomputes file identities and statistics,
and publishes only a verification report. It never rewrites the producer
result.

## Implementation checkpoint

The version 1 pure harness is complete through `6f04b6f`. It measures all
seven pre-registered entry points, retains 1,000 raw samples per subject, and
binds the result to the exact clean source, release-profile benchmark binary,
Rust toolchain, architecture, protocol, and input fixture identities. Receipt
construction and canonical encoding use a checked-in canonical version 1
receipt. Composition uses separately identified checked-in typed constants.

The standard-library-only verifier and closed operational schema reject
subject omission or reordering, source, executable, or fixture substitution,
unknown or duplicate fields, unsorted samples, and forged summaries. The
manual hosted workflow added at `aae19a4` accepts one exact 40-character
revision, runs the complete pure domain on x86_64 and aarch64, retains producer
and verifier failures separately, and uploads the raw result and independent
report. No hosted measurement is recorded here until that workflow completes
and the downloaded artifacts verify again outside their producing jobs.

This checkpoint adds no version 2 implementation. The ADR 0003 map-key gate
continues to block version 2 CDDL, golden vectors, and both codecs.

## Hosted matrix and retention

The pure harness runs once on x86_64 and once on aarch64 Linux. Native phase
measurements run on the same two supported architectures through an explicitly
dispatched workflow at one exact source commit. All four result directories
are retained and downloaded for independent verification before this record is
marked complete.

Hosted scheduling delay, tool installation, compilation, and assurance-gate
duration remain separate CI timing metadata. They are not folded into Runtime
operation latency.

## Decision criteria

This baseline authorizes architectural investigation, not implementation:

- If median repeated native setup before child execution exceeds the median
  child execution time, document which phases dominate before proposing a
  daemon or batch interface.
- If no phase dominates or the maintained workload is too short to represent
  adopted use, retain the result and gather a second real workload rather than
  selecting an architecture from noise.
- Any daemon or shared boundary still requires a new ADR and threat model,
  regardless of the measured speedup.
- Performance changes must preserve fresh cgroups, exact boundary ordering,
  independent receipt verification, and all existing fail-closed behavior
  unless a separately reviewed contract explicitly replaces them.

## Completion condition

The experiment is complete only when both architectures publish all registered
pure and native series from one exact clean source, every retained result passes
the independent verifier, and this record cites the exact source, workflow run,
artifact identities, and derived observations. Missing platform facts or a
failed sample make the affected result incomplete; they are not silently
discarded as outliers.
