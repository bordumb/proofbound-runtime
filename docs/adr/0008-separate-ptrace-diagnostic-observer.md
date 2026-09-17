# ADR 0008: Use a separate ptrace diagnostic observer

- **Status:** accepted
- **Date:** 2026-09-15
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** RT-8 diagnostic execution only

## Context

Static ELF discovery cannot show configuration searches, plugin loads, dynamic
language imports, or path-dependent behavior. A live observer can make those
effects visible, but it adds a trusted component and can change the program's
behavior. It must not weaken the production boundary or present one observed
path as complete authority.

The observer must work on the non-root Linux profile. Landlock audit records
and tracepoints describe denied operations well, but consuming the system-wide
streams requires privileged host facilities and exposes events from unrelated
processes. Seccomp user notification is unsuitable as the primary observer:
continuing a system call has documented time-of-check/time-of-use hazards and
the mechanism must not become an authorization proxy. An injected library can
be bypassed by a hostile or static executable. A general eBPF observer adds a
privileged, system-wide program and loader to the trusted computing base.

Linux `ptrace` lets a parent observe syscall entry, syscall exit, clone, and
exec events for a process tree that it creates. `PTRACE_GET_SYSCALL_INFO`
provides architecture-qualified syscall records. The observer can inspect a
successful open through the returned descriptor before the tracee resumes. It
can also see a failed operation and its error. The mechanism is detectable,
can change timing, and does not prove that an unobserved execution follows the
same path.

## Decision

RT-8 uses a separate `pbr-diagnose` executable with a ptrace-based observer.
It accepts the seed plan, absent receipt and draft targets, and one explicit
delegated cgroup root. It does not read a cgroup location from ambient
configuration.
The production `pbr` and `pbr-native-launcher` executables contain no observer
entry point and do not depend on the diagnostic crate. A source-closure check
enforces this separation.

The effectful observer has its own `proofbound-runtime-diagnose-linux` crate.
It alone enables the `diagnostic-observer` feature on the Linux boundary crate.
The production CLI uses the default empty feature set. Raw ptrace, wait, and
signal calls remain in the Linux syscall module, while the safe feature-gated
surface uses non-copy typestates. This split keeps raw Linux calls under the
existing unsafe-code boundary without adding an observer entry point to either
production executable.

The diagnostic supervisor creates and attaches to the launcher process before
the launch protocol can release target code. After it receives the launcher's
boundary acknowledgement, it stops the launcher and enables the exact trace
options before it sends the identity-bound exec release. The existing
Landlock, seccomp, cgroup, descriptor, environment, identity, and launch-order
checks remain the execution boundary. The observer may inspect tracee memory,
registers, and `/proc` state. It must not change registers, replace syscall
results, inject a descriptor, skip a syscall, or grant a path. Ptrace is an
observation mechanism and a trusted diagnostic role. It is not an enforcement
mechanism.

The safe startup session accepts an identified launcher file, revalidates it
during preparation and immediately before spawn, executes it through the
retained descriptor, and creates the launcher command and private channel
together. It retains the exact install request and
supervisor channel across every non-copy setup state. It receives and verifies
the acknowledgement internally and sends the release on that same channel. A
caller cannot supply a command, acknowledgement value, expected identity, or
different release channel to advance the session.

The trace session creates separate stdout and stderr pipes, makes both
nonblocking, and starts one bounded reader for each with shared cancellation immediately
after child creation. Each active reader retains only its independently
declared prefix but continues reading to end of file so a target cannot block
on a full pipe after the retained prefix is complete.
The session exposes both captures only after exact natural tree completion or
a successful forced tree drain. A missing pipe, reader-thread creation failure,
read failure, or join failure prevents publication. Terminal collection uses a
fixed monotonic deadline. If either reader remains unfinished, the session
cancels and joins both readers and returns a typed timeout instead of waiting
indefinitely. Once the trace retains the root pidfd for active ownership, it
disarms the standard-library numeric child cleanup guard. A raw exact wait that
reaps the root also records the guard as reaped before terminal collection.
Active-trace destruction therefore terminates only through retained pidfds, and
later cleanup cannot send a numeric-PID kill after reuse. When an earlier setup
typestate is abandoned, field ownership orders an attempted child termination
and wait before cancellation and drain-thread join. Nonblocking
reads make that cancellation bounded by the poll interval under the registered
scheduler and atomic-visibility premises. This source order does not prove Linux pipe progress or
process-tree completeness.

The same trace session owns one prepared cgroup version 2 boundary and one
private absolute execution deadline. Preparation compares the cgroup identity
and exact readbacks for `pids.max`, `memory.max`, `memory.swap.max`, and
`memory.oom.group` with the install request and seed-plan limits. Preparation
and the immediate pre-spawn transition also revalidate the zero initial
resource snapshot, empty membership, and unpopulated state. It reads the
controls again immediately before spawn and immediately before target release,
so neither transition relies only on cached setup values. The deadline starts
immediately before spawn. The spawn transition places and reads back the exact
child in that cgroup before it returns. Each later setup transition, option
installation, target release, active wait, and natural terminal collection
consults that same stored deadline; no public transition accepts a replacement
deadline. Ready stops and events are checked against the deadline before they
can become progress, and target release or resume has an immediate deadline
gate.
The deadline is checked by consuming transitions. It is not a background
watchdog. The command owner MUST drive those transitions without unbounded
delay or add an independent watchdog before it claims released wall-time
enforcement.

When the pure protocol or effectful observer requires termination, the adapter
must successfully signal all retained identity-stable process groups and starts
a separate five-second cleanup deadline before it returns the drain-only state.
The same absolute deadline covers terminal waits, cgroup drain and removal,
resource observation, stream cancellation, and both joins; no stage refreshes
it. The cleanup deadline does not extend target execution. Natural and forced
completion first establish an empty exact trace tree, then drain and remove the
cgroup, require complete version 2 resource observations, and finally join both
stream readers. Only that terminal capture can precede a pure publication
decision. A cgroup mismatch, stale freshness, placement failure, signal
failure, cleanup failure, incomplete resource observation, stream failure, or
deadline expiry prevents all diagnostic publication. Dropping an unfinished
session orders best-effort root-child, cgroup, and stream-reader cleanup. These
are source-order properties; native kernel, clock, scheduler, cgroup, and pipe
behavior still requires the RT-8 attack corpus.

The separate diagnostic Linux crate presents one coupled adapter instead of
re-exporting the raw trace typestates. It validates observation bounds before
spawn. After the exact initial trace stop, every consuming adapter transition
moves one private trace typestate and one pure protocol. The pure protocol is
seeded from the exact spawned process only after that process reaches the stop.
Effectful boundary success precedes its pure record. The Linux option operation
returns the exact installed bits through the trace state, and the adapter passes
those bits through the closed pure validator before it records option readiness.
Pure release authorization precedes the effectful release. The public surface
provides process identity and read-only protocol status, but no raw trace state,
public owner field, or mutable protocol handle.
The future event loop extends the active coupled state rather than splitting
these owners.

The observer follows the complete child tree with the closed clone, fork,
vfork, and exec options. It records only the syscall families defined by the
diagnostic specification. Every count, string read, process, event, and output
byte is bounded. An unknown architecture, unsupported syscall form, missed
child, observer overflow, tracee-memory read failure, identity drift, or
unexpected stop marks the diagnostic result incomplete. It never causes the
production receipt path to accept weaker evidence.

The initial decoder recognizes only Linux x86_64 audit architecture
`0xc000003e` and aarch64 audit architecture `0xc00000b7`. It uses separate
number tables for those architectures and rejects x32. It reads a registered
path or socket address at the syscall-entry stop under independent string,
path, and socket-address bounds. It reads `open_how` only in its registered
24-byte form and reads only the first flags word from a registered `clone3`
form. A `clone` or `clone3` request with `CLONE_UNTRACED` fails closed while
the tracee remains stopped at entry, because resuming it could create a child
outside the registered event tree. It records the `sendto` payload length but
never reads payload bytes.
All raw tracee-memory access stays in the Linux syscall module and is read-only.

The traced thread is stopped during an operand read, but another thread in the
same address space can still mutate shared bytes before kernel consumption.
The operand is an observation of supplied bytes at one stop, not proof of the
kernel-selected object. Descriptor-producing and image-replacing success need
a later identity-resolution wave before they can use `kernel-selected`.

A pure protocol owns release order, lifetime process and event accounting,
gap accumulation, drain ordering, and publication eligibility. It requires a
closed tree-empty acknowledgement after it directs termination. The Linux
adapter owns ptrace, wait, memory-read, signal, process-cleanup, and the truth
of that acknowledgement. It sets a permanent unreconciled-tree condition before
child registration and cannot acknowledge an empty tree after a message,
identity, capacity, thread-group, or handle failure.
This separation lets the ordered decisions receive bounded source evidence
without presenting effectful Linux behavior as proved.

For a successful descriptor-producing file open, the observer records the
kernel-selected target through `/proc/<pid>/fd/<fd>` while the tracee is still
stopped. For a denied operation, it records the supplied path and an explicit
resolution state. A best-effort supervisor resolution is advisory and carries
the before and after object identities used to detect drift. It is not called
the kernel-selected target. A stable symlink fixture may produce a resolved
candidate; a race or inaccessible component remains unresolved.

The first successful-object resolver deliberately accepts fewer cases than
Linux can express. A returned descriptor is resolved only when the stopped
tracee is the sole retained tracee, so no observed peer can share and replace
its descriptor table during inspection. The resolver retains the procfs object
handle before it reads the link and obtains device, inode, mode, and mount
identity from that retained handle. A successful exec is resolved from the
stopped post-exec image only after trace identity reconciliation removes
superseded threads. A non-UTF-8, non-absolute, deleted, non-filesystem procfs
link form, over-bound, or otherwise ambiguous procfs target remains unresolved.
This wave does not infer a symlink-hop count from a kernel-selected descriptor
or executable. The separate denied-path candidate resolver owns bounded
symlink walking and drift checks.

The denied-path resolver runs only while the exact caller is stopped and is the
sole retained tracee. It anchors absolute paths below `/proc/<pid>/root` and
relative paths below the retained root plus either `/proc/<pid>/cwd` or the
nonnegative directory descriptor. It clamps parent traversal at the tracee
root, follows no more than the declared symlink-hop bound, retains the final
object, and repeats the complete resolution pass. Only equal normalized paths,
hop counts, and complete object identities become `stable-candidate`.
Differences become `identity-drift`; hop exhaustion becomes `symlink-limit`;
other unsupported cases remain unresolved. A non-UTF-8 version 1 path fails
event mapping and produces no candidate artifact. None of these outcomes names
the object selected by the failed system call.

The observer emits two separate closed JSON artifacts:

1. a diagnostic receipt that identifies the execution, seed plan, observer,
   mechanism, inputs, bounds, events, gaps, and completion state; and
2. a plan draft that keeps human, static-closure, runtime-observation, Capsec,
   and platform-required provenance separate.

Both artifacts state `safe_policy: false`. The diagnostic receipt states
`reusable: false` and uses its own schema. `pbr-verify`, `pbr-compose`, and
`pbr-accept` reject that schema with the stable reason
`profile.diagnostic.not-reusable`. A user must make every authority choice and
produce a normal plan before `pbr plan check` can succeed.

## Security properties

- Diagnostic observation cannot add execution authority.
- The diagnostic profile cannot produce a production execution receipt.
- A consumer cannot relabel a diagnostic receipt as production evidence.
- The observer never runs in the production launcher process or child domain.
- Missing observer coverage is retained as an explicit gap.
- A retained stream limit cannot stop the observer from draining later bytes.
- A stream collection failure cannot produce a diagnostic publication.
- A caller cannot refresh the plan wall-time deadline between trace states.
- A drain-only state is returned only after process-group termination starts.
- Terminal publication requires complete version 2 resource observations.
- Network attempts remain open decisions and never become network authority.
- Environment names, write roots, resource limits, and network mode remain
  human choices.

## Consequences

- The diagnostic path has a larger trusted computing base and higher overhead
  than production execution.
- A traced program can detect the observer or follow another path later.
- A diagnostic execution that requests `CLONE_UNTRACED` is terminated and can
  produce only an incomplete, non-reusable result.
- Some denied paths cannot be resolved exactly. The draft must preserve that
  uncertainty instead of inventing a target.
- Ptrace policy on a host can make the diagnostic profile unsupported while
  the production profile remains supported.
- The initial observer is Linux and architecture specific. Each supported
  architecture needs its own syscall decoder and native attack corpus.

## Rejected alternatives

- **Landlock audit or tracepoints as the required observer.** They are useful
  optional diagnostics, but the supported consumption paths are privileged and
  system-wide.
- **Seccomp user notification as the required observer.** It is a mediation
  protocol with tracee-memory race hazards and would blur observation with
  policy.
- **Injected interposition library.** A target can bypass it and it changes the
  dynamic closure.
- **Automatic broad diagnostic authority.** It would expose data merely to
  make the program progress and would turn observation into an implicit grant.
- **Observer code in `pbr-native-launcher`.** It enlarges the production
  security path and makes the no-observer production claim harder to inspect.

## Reopening conditions

Reopen this decision if an unprivileged, per-domain Landlock event channel
becomes available; if ptrace cannot follow a required maintained workload; or
if native evidence shows that the observer cannot preserve the existing
pre-release boundary order.

## Primary references

- [Linux ptrace manual](https://man7.org/linux/man-pages/man2/ptrace.2.html)
- [Linux seccomp filter documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux Landlock system-wide management](https://docs.kernel.org/admin-guide/LSM/landlock.html)
