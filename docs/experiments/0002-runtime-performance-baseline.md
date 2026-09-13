# Experiment 0002: Runtime performance baseline

- **Status:** complete
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
manual hosted workflow accepts one exact 40-character revision, runs the
complete pure and native domains on x86_64 and aarch64, retains producer and
verifier failures separately, and uploads the raw results and independent
reports. The native extension retains the benchmark and all three Runtime
binaries, the exact workload and plan, 100 raw receipts, run-result
projections, outputs, and a recursive checksum inventory. Separate
architecture-matched jobs download each native artifact, verify its inventory,
rerun the independent verifier over every receipt, and require the reproduced
report to match byte for byte.

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

### Complete observation 2

At exact clean source
`774df9813371ce6476dfa182d4526669daa3d64c`, GitHub Actions run
[`34564688967`](https://github.com/bordumb/proofbound-runtime/actions/runs/34564688967)
completed all six registered series: the seven-subject pure harness on both
architectures and the static and dynamic native workloads on both
architectures. Each native producer completed 10 warm-ups and 100 fresh
measured executions. Four separate architecture-matched jobs then downloaded
the retained native artifacts, verified their recursive checksum inventories,
reran the independent verifier over all 400 raw receipts and projections, and
reproduced each original verification report byte for byte.

The downloaded pure artifacts also passed their checksum inventories. The
standard-library-only verifier was rerun outside the producing jobs against
the exact retained benchmark executable and source fixtures; both reports were
reproduced byte for byte. The six primary result and checksum-inventory
identities are:

| Series | Result SHA-256 | `SHA256SUMS` SHA-256 |
| --- | --- | --- |
| Pure x86_64 | `c147accf29874f1b0b468bc0ac0b2225d8c5f826e0c67c187908f695a44a55b2` | `68dfcd56cb5bca0a7f60a23a67ef9b83eb5aedc97695e3ca208d6a5afe637fdd` |
| Pure aarch64 | `03761f6cc570f0604ec91bdcfc8ef50076ce2674f558c9ada4b184d3b803c170` | `bac6dbf3676694b28946e6a1435d91749c4d5ee1d96b08e8e7f53066c01fef4b` |
| Static x86_64 | `975adf4f1fbcceda6644e55b5ca1309034d4af61d5c3fb31fda5adedc4b23686` | `a7d92fab51e4a00b62b67ab24afa490888ba3bfc34946f694078c9100c6f9` |
| Static aarch64 | `82f7f92d70d1fadd63e104eaf229e6b7391829e0014c9151641e70d49223339c` | `5ef7b22cdd3eb5dcf209813fdc8ef50076ce2674f558c9ada4b184d3b803c170` |
| Dynamic x86_64 | `b845d9ec9bd592a9c232b95b392fe6d70f8956a8d5d834a4f137f71f37e0e2fb` | `484a7efe6905abe8dfb1ad4fbfc3492a2d48f0c72cc49145f7c139e57c534d5e` |
| Dynamic aarch64 | `52bf59f8c615637a47c5cbef8851d5efea6a84ce44ab09c5931170e57ac3fb19` | `2163c2eeb6042b9033f1dd4223eacceb81b697d6da254bc94f37f1236abbe704` |

The headline native measurements, computed from the retained correlated raw
samples, are:

| Workload / architecture | Total median / p95 (ms) | Setup-before-child median (ms) | Child median (ms) |
| --- | ---: | ---: | ---: |
| Static x86_64 | 14.726 / 17.142 | 12.641 | 1.122 |
| Dynamic x86_64 | 14.927 / 17.964 | 11.897 | 1.102 |
| Static aarch64 | 17.267 / 29.297 | 14.625 | 1.098 |
| Dynamic aarch64 | 17.686 / 23.129 | 15.552 | 1.097 |

Setup before child execution exceeded child execution by approximately 11 to
14 times in every series. Boundary installation was the largest median phase:
4.000–5.542 ms on x86_64 and 8.451–8.585 ms on aarch64. Executable closure
inventory and launcher-request identity revalidation were the next material
setup costs. Dynamic loading did not materially change total latency for this
fixture.

This satisfies the pre-registered threshold for architectural investigation,
but it does not justify a daemon or shared execution boundary. The maintained
hello workloads are deliberately short and are not evidence of adopted-use
latency. The next performance input is a second real adopted workload; any
daemon or batch proposal still requires its own ADR and threat model. No
sample, tail, missing host fact, or failed execution was discarded.

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

The experiment completed at observation 2: both architectures published all
registered pure and native series from one exact clean source, every retained
result passed the independent verifier, and this record cites the exact source,
workflow run, artifact identities, and derived observations. Future repetitions
remain incomplete if a platform fact or sample is missing; such failures must
not be silently discarded as outliers.
