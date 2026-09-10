# Specification 0007: Memory and swap execution profile

**Status:** Draft implementation specification

**Target version:** 0.2.0

**Date:** 2026-09-09

This specification defines the first resource-bound expansion after version
0.1. It adds cgroup v2 memory and swap limits, preserves exact child-process
termination, and records typed terminal resource events. It does not change the
deny-network authority profile or reinterpret a version 1 plan or receipt.

The Linux kernel documents `memory.max` as the cgroup memory hard limit and
notes that usage can temporarily exceed it. It documents `memory.swap.max` as
the swap hard limit and `memory.oom.group` as the control that treats a cgroup
as one workload for an OOM kill. The exact kernel semantics remain an explicit
Runtime assumption. See the
[cgroup v2 memory controller documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#memory-interface-files).

## Candidate claim and exact production subject

Candidate claim `PBR-RESOURCE-010`:

> For a supported version 2 execution, the Runtime installs and reads back the
> registered process, memory, swap, and OOM-group controls in the same fresh
> cgroup before child code starts. It records the cgroup's terminal memory and
> swap observations without granting a larger modeled resource bound.

The exact production subject contains:

- the version 2 plan decoder, resource newtypes, normalization, subset
  relation, and canonical plan identity;
- pure policy compilation and its policy-model identity;
- host capability probing and preflight reporting;
- fresh cgroup creation, control installation, readback, event snapshots,
  membership, drain, and removal;
- launcher sequencing and the policy/cgroup identities it binds;
- execution supervision, stream collection, terminal classification, and
  receipt construction;
- the version 2 canonical receipt projection; and
- the independent version 2 receipt decoder and eligibility derivation.

The kernel, host administrator, hardware, firmware, filesystem, compiler, and
linker remain assumptions. The claim does not assert that every Linux memory
allocation class invokes the OOM killer, that observed peak usage never
temporarily exceeds `memory.max`, or that a successful process used less
memory than its semantic workload required.

## Version transition

The version 1 plan and receipt schemas are closed. This change introduces:

- `proofbound-runtime-plan/2`;
- `proofbound-runtime-linux-policy/2`; and
- `proofbound-runtime-execution-receipt/2`.

Version 0.2 execution commands accept only plan version 2. `plan check`,
`preflight`, and `run` reject a version 1 plan with
`plan.schema.execution-obsolete`; they do not fill in implicit limits. A
reviewed migration procedure may copy a version 1 plan only after the user
chooses explicit memory and swap values.

`inspect`, `pbr-verify`, and `pbr-compose` continue to accept historical
version 1 receipts through their frozen version 1 decoder and derivation path.
They add a separate closed version 2 path. They must not convert a version 1
receipt to version 2, infer missing resource observations, or apply version 2
eligibility rules retroactively. A version 1 binary rejects version 2 inputs as
an unsupported version.

The launcher protocol may retain version 1 only if its closed message shape and
state-machine meaning do not change. The compiled-policy identity bound into
every message must select policy model version 2 and therefore the new resource
limits. Any launcher field or transition change requires a version 2 launcher
protocol in the same claim wave.

## Version 2 plan limits

The version 2 `limits` table contains exactly:

```toml
[limits]
processes = 16
wall_time_ms = 30_000
stdout_bytes = 1_048_576
stderr_bytes = 1_048_576
memory_bytes = 536_870_912
swap_bytes = 0
```

Existing version 1 limit rules remain unchanged. The new values parse into
validated types:

- `MemoryByteLimit` accepts 65,536 through 1,099,511,627,776 bytes inclusive;
- `SwapByteLimit` accepts zero through 1,099,511,627,776 bytes inclusive; and
- each value must be a multiple of 65,536 bytes.

The 64 KiB quantum gives one canonical portable input across the supported
x86_64 and aarch64 kernel page-size profiles. It is a Runtime product
restriction, not a claim that the kernel accounts every allocation in 64 KiB
units. Zero swap means `memory.swap.max = 0`; it does not disable zswap.
Compressed zswap storage remains charged through the kernel's memory-accounting
semantics and is not represented as disk swap.

The subset relation compares process, wall-time, stream, memory, and swap
limits independently. A smaller value grants no more authority. The normalizer
must preserve all six values exactly. It must not raise a memory value to a
minimum, round to a host page size, replace zero swap with `max`, or infer a
value from host capacity.

## Pure policy

Policy model version 2 contains the normalized six-limit resource record and
selects these exact cgroup controls:

- `pids.max = processes`;
- `memory.max = memory_bytes`;
- `memory.swap.max = swap_bytes`; and
- `memory.oom.group = 1`.

The canonical policy identity binds each control name and canonical decimal
value in fixed order. `memory.high`, `memory.low`, `memory.min`,
`memory.swap.high`, zswap controls, and proactive reclaim are excluded. In
particular, `memory.high` is a throttle and must not be represented as the hard
boundary in the candidate claim.

The pure claim wave must extend plan conformance, independent reference code,
the finite bounded catalog, Kani harnesses, Lean policy model, generated source
translation, and source-refinement theorem. The local bounded-domain guard from
[Specification 0006](0006_bounded_domain_consistency_guard.md) must compare the
new claim, evidence, and model-check declarations before Proofbound runs.

## Host capability and boundary installation

A supported version 2 host provides one delegated cgroup v2 root with both
`pids` and `memory` controllers available and enabled for child cgroups. The
maintained systemd profile uses `Delegate=pids memory`. The probe also requires
the configured non-root delegation to expose every control and observation
file named by this specification. The probe remains read-only: it must not
create a disposable cgroup, change a control, or leave a child behind. Fresh
child-cgroup creation validates the same file set again before execution.

For one execution, the supervisor exclusively creates the fresh cgroup and,
while it is empty:

1. verifies the retained parent mount and inode identity;
2. writes the four controls in canonical order;
3. reads each control through the retained child-cgroup descriptor;
4. requires byte-equivalent canonical values after trimming the one permitted
   line ending;
5. reads the initial event and peak files and requires zero values; and
6. revalidates freshness and identity before placing the stopped launcher.

The supervisor uses blocking control-file writes. It must not use
`O_NONBLOCK`, because the kernel gives nonblocking `memory.max` updates weaker
reclaim and OOM timing semantics. A missing controller or file, write failure,
non-canonical readback, parse error, nonzero initial observation, populated
group, or identity drift fails before child code starts.

Every terminal path reads the observations after the process tree drains but
before the cgroup is removed. Observation failure makes the execution receipt
incomplete and non-reusable. OOM, timeout, launcher failure, and supervisor
error do not skip exact-group drain and removal.

## Terminal resource observations

The version 2 receipt adds one required `resources` object. Its configured
section contains the exact readback values for `pids.max`, `memory.max`,
`memory.swap.max`, and `memory.oom.group`. Its terminal section contains:

- `memory_peak_bytes` from the fresh cgroup's `memory.peak`;
- `swap_peak_bytes` from `memory.swap.peak`;
- `memory_events`, the checked deltas for `low`, `high`, `max`, `oom`,
  `oom_kill`, and `oom_group_kill` from `memory.events.local`; and
- `swap_events`, the checked deltas for `max` and `fail` from
  `memory.swap.events`.

Each byte count and counter is a canonical decimal string so the JSON wire can
represent every `u64` value exactly. The producer retains the initial and final
snapshots until receipt construction, performs checked monotonic subtraction,
and rejects counter regression or overflow. The receipt carries the deltas,
not the mutable cgroup files or an assertion that the host reported truthfully.

The receipt also contains a canonical sorted `limit_events` set derived only
from nonzero deltas:

- `memory-high`;
- `memory-max`;
- `memory-oom`;
- `memory-oom-kill`;
- `memory-oom-group-kill`;
- `swap-max`; and
- `swap-fail`.

The independent verifier recomputes this set from the counters and rejects an
omitted, extra, reordered, or inconsistent member. A nonzero peak alone is not
a limit event.

## Outcome and reuse semantics

The child-process outcome retains its exact existing meaning: exit code,
signal, timeout, denial, launcher failure, or incomplete. Resource observations
do not overwrite that outcome. An OOM-killed process therefore remains visibly
signaled and is separately, unambiguously accompanied by
`memory-oom-kill` or `memory-oom-group-kill`.

Every nonempty `limit_events` set makes the receipt non-reusable. Version 2 adds
one non-reuse reason per limit-event kind, and the producer and independent
verifier derive the complete canonical reason set. This includes a process
that handles `ENOMEM` and exits zero when the kernel increments a registered
event. If the kernel does not increment a registered event for a failed
allocation, Runtime retains the actual process outcome and makes no inferred
memory-denial claim.

Truncated streams, timeout, signal, denial, launcher failure, incomplete
observation, and every existing version 1 condition remain non-reusable under
their current meanings. A zero exit with no limit event and complete bounded
streams is not sufficient by itself; every other version 2 eligibility
condition must also pass.

## Falsification requirements

The claim wave must start with closed attacks for:

1. missing, zero, non-quantized, or overflowing memory values;
2. missing, non-quantized, or overflowing swap values;
3. version 1 execution, unknown versions, added fields, downgrade, and
   cross-version receipt substitution;
4. normalization or policy compilation that raises either limit;
5. a missing `memory` controller or any required control/observation file;
6. write/readback mismatch for each installed control;
7. allocation beyond `memory.max` in one process and across the maximum process
   tree;
8. anonymous memory, mapped files, page cache, tmpfs/shared memory, and socket
   memory within the documented kernel accounting boundary;
9. swap disabled, zero swap, swap limit reached, and no host swap device;
10. allocation attempts before launcher release;
11. another cgroup and the supervisor remaining outside the workload OOM
    selection;
12. timeout, launcher failure, and supervisor failure concurrent with memory
    pressure;
13. malformed, missing, regressing, overflowing, or substituted event and peak
    observations;
14. mutation of each configured value, counter, derived event, outcome, and
    non-reuse reason in the independent verifier; and
15. drain and exact cgroup removal after OOM and every error path.

The complete native corpus runs on both supported architectures and retains
the exact kernel, cgroup, source, binary, and release identities. Mock files,
containers without delegated controllers, or skipped cases do not count as
native boundary evidence.

## Documentation and migration

Before release, update the threat model to enumerate the version 1 process,
wall-time, and stream boundaries separately from the version 2 memory/swap
profile. Update `doctor --explain`, preflight, plan examples, the maintained
systemd delegation recipe, receipt semantics, schema documentation, and the
release composer. The version 0.1 documentation remains available and must not
claim memory containment.

Version 0.2 publication requires reproducible native bundles on x86_64 and
aarch64, the complete native attack corpus, independent version 2 receipt
verification, exact artifact binding, and release composition. Source tests or
a digest alone do not close the release-artifact obligation.

## Review gate and residual obligations

This draft must receive explicit review before production code changes the
plan, policy, launcher, boundary, or receipt. Review must resolve at least the
64 KiB quantum and maximum values, required kernel/file baseline, event-key
compatibility, version 1 execution migration, and the exact version 2 receipt
schema.

Even after implementation, the public claim must retain Linux kernel and host
assumptions, temporary-overshoot semantics, allocation classes that do not
raise a registered event, zswap meaning, toolchain assumptions, and the exact
bounded/native evidence scope.
