# ADR 0006: Keep CPU bandwidth separate from consumed CPU time

- **Status:** accepted
- **Date:** 2026-09-11
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** any Runtime profile after version 2 that adds CPU controls

## Context

The current Runtime bounds wall-clock duration but makes no CPU claim. Linux
cgroup v2 exposes two facts that are easy to conflate. `cpu.max` limits fair-
scheduler bandwidth by allowing a quota in each period. `cpu.stat` reports
cumulative `usage_usec` for the cgroup and its descendants. Neither interface
is a kernel-enforced total CPU-time budget; `cpu.max` is not a total CPU-time
budget.

`RLIMIT_CPU` is per process, uses coarse seconds, and is not a process-tree
total. Polling `cpu.stat` can trigger cancellation after a budget is observed,
but work continues during the polling interval and kill/drain latency. Without
an independently enforced CPU-placement bound, concurrent descendants also
make any time-only overshoot formula depend on available processors. Runtime
must not call that mechanism a hard aggregate limit.

The kernel contract is documented in the
[cgroup v2 CPU controller](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#cpu).
It defines `cpu.max` as quota per period and `cpu.stat` as cumulative
observation for the cgroup hierarchy.

## Decision

Version 2 remains unchanged and makes no CPU-bandwidth or consumed-CPU claim.
The project does not need a new CPU profile before an adopted workload shows
that wall time plus memory, swap, process, and stream bounds are insufficient.

If that evidence appears, the first CPU profile will provide bandwidth only:

- require the delegated cgroup v2 `cpu` controller;
- use `cpu.max` with a fixed 100,000 microsecond period and one explicit quota;
- set `cpu.max.burst` to zero when the host exposes it;
- read back the exact installed values before child release;
- record terminal `usage_usec`, `user_usec`, `system_usec`, `nr_periods`,
  `nr_throttled`, and `throttled_usec` as observations; and
- describe throttling only when the registered counter delta is nonzero.

That profile requires a Version 3 plan, compiled policy, launcher request,
run result, execution receipt, composed receipt, verifier, composition, and
acceptance transition. Every new committed object uses deterministic CBOR,
closed CDDL, text map keys, and golden vectors before codec code. Version 1
canonical JSON and Version 2 deterministic-CBOR semantics remain frozen.

The initial closed native corpus must include a single busy loop, a
multi-process busy loop, wall-time interaction, and a counter read race on
both architectures. It must test installation order, exact readback, cleanup,
counter monotonicity, and independent verifier rejection of mutations.

Aggregate consumed CPU time may be recorded, but it is not a total CPU-time
budget. A future hard aggregate claim needs a separate accepted ADR identifying
an enforcement mechanism and a defensible overshoot bound; supervisor polling
alone cannot satisfy it.

## Consequences

### Positive

- Public language matches the actual temporal bandwidth mechanism.
- Version 2 remains stable while adopted-workload evidence determines whether
  a Version 3 transition is worth its verification and migration cost.
- Terminal CPU counters can explain throttling without changing child outcome.

### Negative

- Wall time remains the only execution-duration enforcement in Version 2.
- A child may consume multiple processors up to host scheduling and ancestor
  controls; current receipts make no statement about that consumption.
- A future bandwidth profile needs another full cross-object claim wave.

## Rejected alternatives

- **Present `cpu.max` as total CPU time.** It is a per-period bandwidth limit.
- **Use only `cpu.weight`.** Weight is relative scheduling preference, not a
  limit and not meaningful without competing runnable groups.
- **Use `RLIMIT_CPU`.** It does not bound aggregate process-tree consumption.
- **Poll `cpu.stat` and call the result hard.** Poll and kill latency make the
  observed threshold a cancellation trigger, not a strict upper bound.

## Reopening conditions

Reopen this decision when an adopted workload demonstrates a CPU requirement,
when the supported kernel contract changes, or when a mechanism can enforce an
aggregate process-tree budget with a reviewable overshoot bound.
