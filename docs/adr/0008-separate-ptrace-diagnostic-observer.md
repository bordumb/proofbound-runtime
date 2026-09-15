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
The production `pbr` and `pbr-native-launcher` executables contain no observer
entry point and do not depend on the diagnostic crate. A source-closure check
enforces this separation.

The diagnostic supervisor creates and attaches to the launcher process before
the launch protocol can release target code. The existing Landlock, seccomp,
cgroup, descriptor, environment, identity, and launch-order checks remain the
execution boundary. The observer may inspect tracee memory, registers, and
`/proc` state. It must not change registers, replace syscall results, inject a
descriptor, skip a syscall, or grant a path. Ptrace is an observation
mechanism and a trusted diagnostic role. It is not an enforcement mechanism.

The observer follows the complete child tree with the closed clone, fork,
vfork, and exec options. It records only the syscall families defined by the
diagnostic specification. Every count, string read, process, event, and output
byte is bounded. An unknown architecture, unsupported syscall form, missed
child, observer overflow, tracee-memory read failure, identity drift, or
unexpected stop marks the diagnostic result incomplete. It never causes the
production receipt path to accept weaker evidence.

A pure protocol owns release order, lifetime process and event accounting,
gap accumulation, drain eligibility, and publication eligibility. The Linux
adapter owns ptrace, wait, memory-read, signal, and process-cleanup effects.
This separation lets the ordered decisions receive bounded source evidence
without presenting effectful Linux behavior as proved.

For a successful descriptor-producing file open, the observer records the
kernel-selected target through `/proc/<pid>/fd/<fd>` while the tracee is still
stopped. For a denied operation, it records the supplied path and an explicit
resolution state. A best-effort supervisor resolution is advisory and carries
the before and after object identities used to detect drift. It is not called
the kernel-selected target. A stable symlink fixture may produce a resolved
candidate; a race or inaccessible component remains unresolved.

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
- Network attempts remain open decisions and never become network authority.
- Environment names, write roots, resource limits, and network mode remain
  human choices.

## Consequences

- The diagnostic path has a larger trusted computing base and higher overhead
  than production execution.
- A traced program can detect the observer or follow another path later.
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
