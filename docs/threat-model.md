# Threat model

- **Status:** implemented version 1 boundary; release-artifact linkage pending
- **Version:** 0.1.0
- **Date:** 2026-09-07
- **Applies to:** the Proofbound Runtime version 1 execution profile

## Purpose

Proofbound Runtime runs a command that the caller does not fully trust. It gives
the command declared authority and records the installed boundary and observed
outcome in an execution receipt.

This threat model defines what the initial product protects, which attacks it
rejects, what it trusts, and what remains outside its claims. The boundary is
implemented and has bounded native evidence on identified `x86_64` and
`aarch64` Linux runners. Until release binding is complete, these statements do
not apply to a published 0.1.0 artifact.

## Protected assets

The initial boundary protects:

- files outside registered read roots;
- files outside the fresh registered write root;
- executables outside the registered executable closure;
- environment values whose names are not registered;
- inherited file descriptors that are not part of the child contract;
- network authority, which is denied by the initial profile;
- host process and resource capacity above registered limits;
- reviewed source trees from modification by the child;
- execution outputs from substitution before receipt construction; and
- receipt meaning from omission, substitution, downgrade, and forged reuse.

The assurance metadata itself is also an asset. A consumer must be able to
distinguish boundary installation, child outcome, output validation, receipt
validity, and reuse eligibility.

## Adversaries

### Untrusted child

The child command and its descendants can be malicious. They can attempt to:

- traverse paths or follow links outside registered roots;
- read host credentials, adjacent repositories, or user configuration;
- modify source, tools, inputs, or other undeclared paths;
- execute an undeclared binary or dynamic loader;
- open sockets or use an inherited communication channel;
- inspect undeclared environment values;
- fork or allocate beyond registered limits;
- forge launcher control messages;
- terminate abnormally after producing partial output; or
- exploit races between identity checks and use.

The child can know the complete policy. Security does not depend on hiding it.

### Fallible producer

The runtime receipt producer can contain defects. It can accidentally omit a
field, accept an unknown version, misclassify an outcome, retain stale input,
or mark a failed execution reusable. The independent verifier is a separate
trust boundary and must re-derive portable decisions without importing producer
semantics.

### Malicious receipt carrier

A party transporting or storing a receipt can alter, truncate, reorder,
substitute, replay, or remove fields. Canonical encoding, typed identities, and
independent validation detect locally decidable defects. An exact SHA-256
commitment delivered through a channel independent of the carrier detects
canonical substitutions that retain all internal relationships. A receipt and
commitment controlled by the same carrier do not establish integrity.

## Trusted computing base

Initial execution claims depend on:

- host hardware and firmware;
- the Linux kernel and selected system-call behavior;
- Landlock filesystem mediation;
- seccomp syscall mediation;
- cgroup v2 resource and process accounting;
- `PR_SET_NO_NEW_PRIVS` behavior;
- filesystem identity and descriptor behavior;
- the exact launcher and supervisor artifacts;
- the Rust compiler, linker, standard library, and relevant dependencies;
- the cryptographic digest implementation used for identities; and
- each exact executable, loader, runtime, and runtime library root granted to
  the child.

Proofbound must retain these roles and any narrower claim-specific premises. A
receipt signature or digest does not discharge them.

Release interpretation additionally trusts the independently supplied release
artifact, its recorded digest, the reproducible-build environment, and the
Proofbound release-receipt verifier. Reproducibility establishes agreement of
bytes under the registered build recipe; it does not establish compiler or
kernel correctness.

## Initial enforced boundary

The initial supported profile requires:

1. A strict plan that declares command, inputs, environment names, read roots,
   write roots, executable closure, network mode, and resource limits.
2. Validation and deterministic normalization without authority amplification.
3. Exact resolution and identity of security-relevant files before execution.
4. A fresh cgroup v2 boundary with the registered limits.
5. Closure of undeclared file descriptors.
6. Rejection of root or mismatched saved identities, removal of ambient and
   active capability sets, and verified installation of `no_new_privs`.
7. Installation of the complete Landlock filesystem ruleset.
8. Installation of the complete seccomp filter.
9. A typed acknowledgement bound to the compiled policy identity.
10. `execve` only after every required step succeeds.

Failure or unsupported capability stops the execution. The runtime does not
fall back to an unconfined or weaker mode.

## Authority surfaces

### Filesystem

Landlock mediates the supported filesystem access classes. The runtime must
resolve paths under explicit roots, retain requested and resolved identities,
control symlink traversal, and prefer descriptor-relative operations where the
platform supports them.

Version 1 accepts the explicitly reviewed Landlock ABI range 3 through 11; an
older or newer ABI is unsupported until its guarantees are reviewed. The
ruleset handles truncation from ABI 3, device `ioctl` from ABI 5, and pathname
Unix-socket resolution from ABI 9. Read and write rules may cover registered
directory trees; execute rules are accepted only for exact regular-file
descriptors, never directories. Because the closed ruleset also handles
`READ_FILE`, Linux's internal executable reopen requires each exact executable
rule to grant both `READ_FILE` and `EXECUTE`. This platform closure exposes only
the already identified executable bytes; it does not grant directory-wide read
or execute authority.

### Executables and runtime closure

The plan must identify allowed executables. Dynamically linked programs also
need the exact ELF interpreter and registered runtime libraries. Dynamic
language runtimes can require larger read-only library roots. These roots are
authority and must remain visible. Directory-wide execute authority must not
replace exact executable roles.

### Network

Version 1 denies socket-related authority through a closed seccomp profile and
closes inherited file descriptors. It does not provide hostname, address, or
service allow-lists.

The filter validates the kernel audit architecture, kills x32-numbered calls on
`x86_64`, returns `EPERM` for the complete registered socket syscall family,
and denies all `io_uring` entry points because asynchronous socket operations
would bypass a direct-syscall-only network policy. Unknown non-network syscalls
remain allowed and are constrained by the other installed boundaries.

The supervisor and launcher exchange deterministic CBOR messages through a
private Unix sequence-packet channel. Every message binds the execution,
compiled-policy, and cgroup identities. The launcher stops itself before it
receives policy data. Its state machine permits the exec handoff only after all
boundary witnesses exist and the bound acknowledgement is sent.

### Environment

The supervisor builds a new child environment from registered names. The child
does not inherit the complete parent environment. Version 1 does not support
secret providers.

### Processes and resources

A fresh cgroup v2 boundary enforces registered process limits. The supervisor
enforces wall-time and stream-size limits. Every limit and observed termination
state appears in the receipt.

The supervisor starts a new launcher image and observes its `SIGSTOP` before it
places and verifies the process in the fresh cgroup. A child-only pre-exec hook
passes only registered close-on-exec descriptors. Separate drain threads retain
bounded stream prefixes while continuing to drain discarded bytes. A monotonic
deadline kills the process tree, and every terminal path drains and removes the
fresh cgroup before it returns positive execution evidence.

The supervisor classifies `SIGSYS` as a denied outcome. It does not infer a
denial from a child exit code. A child that observes and handles `EACCES` or
`EPERM` retains its actual exit or signal outcome in the receipt.

## Required attack corpus

Before a platform profile can be described as supported, native Linux evidence
must cover at least:

- path escape, link substitution, and identity drift;
- undeclared file read and write;
- undeclared executable and loader substitution;
- directory-wide execute amplification;
- socket creation and connection;
- inherited socket and file-descriptor use;
- undeclared environment access;
- process, time, and stream limit exhaustion;
- boundary-installation reordering and acknowledgement forgery;
- partial output and abnormal child termination;
- receipt omission, duplicate fields, truncation, and unknown versions;
- policy, runtime, input, output, and platform identity substitution;
- forged reuse eligibility; and
- assumption or trusted-computing-base removal.

Passing this corpus is bounded enforcement evidence. It is not a universal
theorem about every Linux behavior or attack.

## Out of scope

The initial product does not protect against:

- a malicious host administrator or host root;
- a compromised kernel, hypervisor, firmware, or hardware;
- kernel vulnerabilities or an incorrect enforcement implementation;
- microarchitectural, timing, power, electromagnetic, or other side channels;
- denial of service within a permitted resource bound;
- authorized reads being copied into authorized outputs;
- covert channels through resources that the policy deliberately permits;
- physical attacks;
- remote workload identity or confidential-computing attestation;
- macOS or Windows behavior; or
- semantic defects in the untrusted command's intended work.

## Receipt interpretation

A valid execution receipt can establish that the producer recorded an exact
plan, boundary identity, execution outcome, and output inventory in the
registered format and that the verifier accepted the derived relationships.
This interpretation requires the independently supplied receipt commitment;
without it, the receipt is inspectable data rather than a verified statement.

It cannot by itself establish that:

- the host kernel was correct;
- the declared policy matched the caller's real intent;
- the child had no side channel;
- output content was semantically correct;
- every unregistered attack was impossible; or
- the Runtime release possessed a stronger Proofbound status than its release
  receipt admits.

## Review triggers

Review and version this threat model when a change:

- adds an authority class or network mode;
- changes path or executable resolution;
- changes boundary-installation order;
- changes the trusted computing base;
- changes receipt meaning or reuse eligibility;
- adds a platform or enforcement mechanism;
- permits a fallback;
- introduces remote execution, a daemon, or multi-tenancy; or
- changes an explicit exclusion into a product claim.
