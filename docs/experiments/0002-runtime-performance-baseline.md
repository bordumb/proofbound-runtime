# Experiment 0002: Runtime performance baseline

- **Status:** in progress; pure hosted baseline complete
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

The native harness uses the maintained hello example in two frozen forms and
the existing supported-host recipe. The static workload is compiled with
`cc -O2 -static -Wall -Wextra -Werror`; the dynamic workload is compiled with
`cc -O2 -Wall -Wextra -Werror`. The harness rejects a static artifact in the
dynamic series and a dynamic artifact in the static series. For the dynamic
plan, every absolute shared-library dependency reported by the host linker
inspection is canonicalized, deduplicated, sorted, and admitted as an exact
`runtime_read` file. The ELF interpreter remains part of Runtime's independently
discovered executable closure. Both workloads record these phases without
changing their order or meaning:

- strict plan validation and normalization;
- capability and rooted-path preflight;
- executable and runtime-closure inventory;
- cgroup creation and controller readback;
- launcher-request construction and final identity revalidation;
- stopped launcher creation;
- Landlock, seccomp, privilege, and cgroup boundary installation;
- child release and process execution;
- process-tree drain and exact cgroup cleanup;
- bounded stream collection;
- output-root inventory and identity revalidation;
- receipt construction and publication; and
- run-result projection.

These are non-overlapping wall-clock intervals in the production operation's
actual dependency order. Supervisor instrumentation distinguishes stopped
launcher creation, boundary installation, child execution, cleanup, and stream
joining without changing the launcher protocol. Run orchestration
instrumentation distinguishes the surrounding pure and filesystem phases. The
timings are returned only to the benchmark harness: they do not enter an
execution receipt, run-result projection, launcher message, policy identity,
or any assurance input.

Both workloads exit successfully after writing the fixed maintained example
output. Each repeated-invocation series runs its same exact plan and executable
100 times through separate fresh executions after 10 untimed warm-ups. The
operational workload identities are exactly `hello-static-v1` and
`hello-dynamic-v1`. No daemon, shared execution boundary, reused receipt, or
reused cgroup is introduced by either measurement.

## Measurement protocol

The pure harness is compiled with the workspace release profile. Each
operation receives at least 100 untimed warm-up iterations. It then records
1,000 independent samples. A sample batches enough identical invocations to
last at least 10 milliseconds according to a deterministic calibration pass;
the recorded value is elapsed nanoseconds divided by the batch count. The
calibrated batch count is retained with the result.

Native observations use 10 warm-up executions followed by 100 measured
executions for each of the static and dynamic workloads on each supported
architecture. Each phase uses monotonic elapsed time. Process-level maximum
resident set size is recorded when the host exposes it; absence is explicit
rather than represented as zero.

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

The pure harness runs once on x86_64 and once on aarch64 Linux. Static and
dynamic native phase measurements run on the same two supported architectures
through an explicitly dispatched workflow at one exact source commit. All six
result directories are retained and downloaded for independent verification
before this record is marked complete.

Hosted scheduling delay, tool installation, compilation, and assurance-gate
duration remain separate CI timing metadata. They are not folded into Runtime
operation latency.

### Pure observation 1

At exact clean source
`2a715de2433f93b2fbe4b97be136c06118565482`, GitHub Actions run
[`34559609273`](https://github.com/bordumb/proofbound-runtime/actions/runs/34559609273)
completed the closed seven-subject pure matrix on x86_64 and aarch64 Linux
with Rust 1.94.0. Each subject retained 1,000 sorted raw samples after 100
warm-ups and deterministic calibration to a 10 millisecond target sample.

| Subject | x86_64 median / p95 (ns) | aarch64 median / p95 (ns) |
| --- | ---: | ---: |
| Plan parse | 7,625 / 7,712 | 6,430 / 6,444 |
| Authority normalization | 129 / 146 | 115 / 120 |
| Policy compilation | 107 / 109 | 122 / 128 |
| Receipt construction | 1,042 / 1,086 | 993 / 1,094 |
| Version 1 canonical JSON receipt encoding | 43,461 / 44,105 | 37,687 / 38,052 |
| Independent receipt verification | 59,525 / 60,225 | 49,543 / 49,695 |
| Release/execution composition | 58,395 / 58,989 | 47,664 / 47,842 |

The x86_64 result SHA-256 is
`d34fe97fd37fd9dce0314b263d02cceadc222b717073297a84773dbd98ea8fca`;
the retained benchmark executable SHA-256 is
`012ce60efc54fe3cd9200c7571b1c5b5c812a671b52d75698b8f02eec8cc70cc`.
The aarch64 result SHA-256 is
`b25c1e06fa6a6d51eb176f358bc76ad96a640f3cec5452bbf4d0aa3d10f4a752`;
the retained benchmark executable SHA-256 is
`9291727513b4aa8e83a9b14b615958942f7c3839e02e5874f9d5cbf99aefd84d`.

After download, both portable `SHA256SUMS` inventories verified every retained
file. The independent verifier was then rerun outside the producing jobs
against each retained executable and the exact source fixtures; it reproduced
the result identities above and accepted the complete subject domain. The
x86_64 host reported Linux `6.17.0-1022-azure` and target
`x86_64-unknown-linux-gnu`; the aarch64 host reported the same kernel build and
target `aarch64-unknown-linux-gnu`.

This observation closes only the pure half of the experiment. Native phase
and repeated-invocation measurements remain required before the completion
condition or any architectural conclusion can be evaluated.

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
