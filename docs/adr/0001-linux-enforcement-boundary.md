# ADR 0001: Native Linux enforcement boundary

- **Status:** accepted
- **Date:** 2026-09-04
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** version 1 execution profile

## Context

Proofbound Runtime must execute an untrusted child with less authority than the
developer account that starts it. The product also needs an exact, reviewable
account of the mechanism used for each execution.

A cross-platform abstraction chosen before any native boundary exists would
hide meaningful differences between operating systems. A container alone would
also add a large runtime and configuration surface without proving that the
requested child policy was installed.

The first product slice needs a small boundary that can support explicit
filesystem, executable, environment, process, network, and resource rules. It
must fail closed when the host cannot provide the requested mechanism.

## Decision

Version 1 targets native Linux on `x86_64` and `aarch64`.

The supported boundary uses:

- Landlock for filesystem read, write, and execute authority;
- seccomp for the closed syscall restrictions required by the selected profile;
- `PR_SET_NO_NEW_PRIVS` before child execution;
- a fresh delegated cgroup v2 boundary for process and resource limits;
- a new allow-listed environment;
- closure of undeclared file descriptors;
- exact executable, ELF interpreter, runtime, and loader identities; and
- a supervisor-to-launcher acknowledgement bound to the compiled policy.

The runtime consumes an explicitly identified cgroup v2 delegation root. That
root is an empty inner node with the required controllers already enabled, and
the supervisor runs in a strict descendant leaf. This follows cgroup v2's
no-internal-process and delegation-containment rules: the runtime never creates
workload cgroups under its populated current cgroup and never writes into a
hierarchy owned by an unrelated manager.

The supervisor creates the fresh output root and an execution cgroup below the
delegation root. It starts the launcher in a paused state, places it in the
execution cgroup, and supplies the validated compiled policy through a private
channel. The launcher installs every remaining restriction before it calls
`execve`.

An unsupported Landlock ABI, seccomp feature, cgroup controller, architecture,
or sequencing step stops the operation. The runtime emits no reusable execution
receipt and does not fall back.

## Assurance meaning

Native positive and denial tests provide bounded evidence about the identified
Linux mechanism, platform, policy, runtime closure, and attack corpus. They do
not prove that Linux is correct or that all forms of exfiltration are absent.

The planned policy theorem concerns the compiler relation:

> Compiling a supported normalized authority plan does not grant an authority
> absent from the formal policy model.

The theorem retains assumptions about Linux mediation and its correspondence
with the formal model. Artifact linkage is required before a model theorem can
describe shipping Runtime bytes.

## Consequences

### Positive

- The first security boundary is explicit and small enough to inspect.
- Filesystem and syscall authority use native kernel enforcement.
- Child processes inherit restrictions across the supported process tree.
- Unsupported hosts remain visibly unsupported.
- Platform-specific premises stay in receipts and Proofbound claims.

### Negative

- Version 1 is not cross-platform.
- Native Linux CI needs identified host capabilities and cgroup delegation.
- The host launcher must place the supervisor in a leaf below an empty
  delegation root before invoking Runtime.
- Dynamic runtimes need explicit read-only runtime closures.
- The kernel and enforcement mechanisms remain in the trusted computing base.
- A later macOS or Windows profile needs a separate semantic contract and ADR.

## Alternatives considered

### Containers as the primary boundary

Rejected for version 1. Container configuration and the host runtime add a
large authority surface. A container can transport native tests, but container
confinement does not count as evidence for this boundary.

### MicroVMs

Deferred. MicroVMs provide a stronger isolation boundary for some threats but
add image construction, boot, orchestration, and attestation complexity. They
do not remove the need for explicit in-guest authority or honest receipts.

### User-space syscall mediation

Rejected as the primary boundary. A broad user-space broker would expand the
trusted runtime and make complete mediation difficult to establish.

### Cross-platform version 1

Rejected. One product label must not imply equivalent assurance from different
mechanisms before each platform has an explicit model and native evidence.

## Revisit conditions

Revisit this decision when:

- the native Linux mechanism cannot satisfy the registered agent workloads;
- a stronger boundary materially reduces the trusted computing base;
- a second platform has an independently specified and tested profile;
- network allow-list semantics become necessary; or
- remote execution or multi-tenancy changes the attacker model.
