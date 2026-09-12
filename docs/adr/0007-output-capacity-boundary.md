# ADR 0007: Require a host-managed project quota for output capacity

- **Status:** accepted
- **Date:** 2026-09-11
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** any Runtime profile that claims an adversarial output-root capacity

## Context

The current Runtime grants one exact write root, bounds captured stdout and
stderr, and inventories outputs after execution. It does not bound storage
consumed inside that write root. Post-run inventory is observation, not
enforcement: a hostile child can exhaust blocks or inodes before Runtime can
inspect the directory. Cgroup `io.max` limits throughput or operations, not
capacity.

The governing rule is: post-run inventory is observation, not enforcement.

The product needs persistent ordinary files after execution, a hard failure
before host-wide exhaustion, and accounting that remains valid for process
descendants. Linux quotas natively enforce space and inode hard limits; the
[kernel quota documentation](https://www.kernel.org/doc/html/latest/filesystems/quota.html)
defines those separately. XFS project quota associates a directory tree with a
project identifier and supports enforced block and inode limits; the
[XFS documentation](https://www.kernel.org/doc/html/latest/admin-guide/xfs.html)
documents the `pquota`/`prjquota` mode.

## Decision

Version 2 remains unchanged and makes no adversarial output-capacity claim.
Any future capacity profile must use a privileged host storage manager to
prepare one fresh XFS project-quota root per execution before child release.
The manager, filesystem identity, mount identity, quota configuration, project
identifier allocation, and cleanup protocol join the trusted computing base.

The capacity contract covers allocated blocks and inodes, not logical file
length. It has these explicit edge meanings:

- sparse files consume quota only for allocated blocks plus their inode;
- metadata and extended attributes follow the selected XFS quota accounting
  behavior and are not silently redefined as logical bytes;
- deleted-open files remain charged until the last reference is closed;
- memory-mapped writes allocate charged blocks through the same filesystem;
- nested mounts are forbidden and must fail before child code; and
- hard links, reflinks, renames, project-ID inheritance, and cross-project
  movement require native substitution cases before admission.

The Runtime must identify the prepared root without path-only trust, verify the
hard block and inode limits, verify project inheritance, prohibit mount and
namespace bypasses, and obtain a bound manager acknowledgement before launcher
release. Terminal quota usage is observation. The receipt must distinguish the
configured hard limits, pre-release readback, terminal usage, and any quota
denial signal that the mechanism can identify without interpreting arbitrary
child behavior.

This profile requires a new versioned plan, compiled policy, launcher protocol,
run result, receipt, independent verifier, composition, and acceptance wave
under ADR 0003. It is not part of Version 2 and is not authorized for production
until a separate manager specification, threat-model update, and native attack
corpus are reviewed.

## Mechanism comparison

### Isolated tmpfs

An isolated mount can cap blocks and inodes, but it consumes memory/swap,
requires privileged mount lifecycle, and disappears on unmount. Persisting
outputs requires a second bounded export path. It is unsuitable as the first
persistent-output profile.

### Filesystem project quota

Selected. It preserves normal file APIs and persistent outputs while enforcing
hard block and inode limits for a directory project. It requires an explicitly
managed supporting filesystem and privileged project allocation.

### Loop or image filesystem

It supplies an obvious capacity ceiling but adds image allocation, formatting,
mount, recovery, and copy-out lifecycle to the trusted path. The operational
surface is larger than project quota for the same persistent-file goal.

### Privileged storage broker

A broker can implement logical-byte or object-count semantics, but ordinary
filesystem syscalls would need mediation or replacement. It becomes a large
protocol and content TCB and is not selected for the first profile.

## Consequences

- Existing users keep the Version 2 write-root and post-run inventory meaning.
- Documentation must state that current output roots are not safe against host
  storage exhaustion by a malicious child.
- A capacity feature cannot be shipped as a small `io.max`, inventory, or
  `RLIMIT_FSIZE` patch.
- The host manager and XFS project-quota requirement reduce portability but
  make the eventual claim precise and enforceable.

## Rejected alternatives

- **Use `io.max`.** Throughput and IOPS are not storage capacity.
- **Reject after inventory.** The host can already be exhausted.
- **Use `RLIMIT_FSIZE`.** A per-file process limit does not bound a directory,
  inode count, descendants, or many small files.
- **Call logical byte length capacity.** Sparse files and filesystem allocation
  make that different from the selected enforcement subject.

## Reopening conditions

Reopen this decision if the product adopts ephemeral-only outputs, supports a
host filesystem other than XFS with equivalent evidenced project semantics, or
selects a brokered object API instead of ordinary filesystem access.
