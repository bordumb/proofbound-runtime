# Specification 0005: Read-only execution preflight

**Status:** Accepted implementation specification

**Version:** 0.2.0

**Date:** 2026-09-09

This specification adds a read-only execution preflight to the CLI defined by
[Specification 0002](0002_cli_surface.md). It joins plan validation, host
capability probing, confined path resolution, and exact artifact observation
without installing an execution boundary or starting child code. It does not
change plan, run-result, receipt, verification, or reuse semantics.

## Command grammar

The CLI accepts exactly this additional form:

```text
pbr preflight --plan <path> --receipt <path> --cgroup-root <path>
```

Option order is fixed and mirrors `pbr run`. Missing, repeated, reordered, or
additional options are invalid CLI usage and exit `2`. The command reads the
plan through an identified descriptor, probes the supplied cgroup root, and
inspects the proposed receipt and output targets. It never creates either
target.

## Read-only boundary

Preflight may perform only observations that the execution path must repeat:

1. canonicalize, open, identify, and read the plan exactly once;
2. strictly decode and normalize the plan and compile its pure policy;
3. open the canonical plan parent as the confined resolution root;
4. probe the exact versioned host capabilities and delegated cgroup root;
5. validate that the requested receipt target has a resolvable parent and does
   not exist;
6. validate that the plan's output-root parent resolves beneath the plan root
   and that its leaf does not exist;
7. resolve and identify the working directory, executable, optional ELF
   interpreter, project inputs, and external runtime-library roots; and
8. revalidate every retained identity before returning success.

The command must not create or remove a file or directory, write a cgroup
control, create an execution cgroup, generate an execution identifier, spawn a
launcher, install Landlock or seccomp, read environment values, or write a
receipt. Checking whether a target could actually be created would itself
mutate the observed namespace, so preflight reports only the non-existence and
resolved-parent facts. `run` remains responsible for exclusive creation.

## Output

Every syntactically valid preflight invocation emits one closed JSON object
with schema `proofbound-runtime-preflight/1`. Invalid command grammar and an
output-write failure retain the existing stderr-only CLI behavior.

A failed preflight contains exactly:

```json
{
  "schema": "proofbound-runtime-preflight/1",
  "ready": false,
  "phase": "<closed phase>",
  "code": "<stable machine code>"
}
```

Phases are closed and ordered: `plan-input`, `plan-validation`,
`authority-normalization`, `plan-root`, `host-capabilities`, `receipt-target`,
`output-root`, `working-directory`, `executable-closure`, `read-authority`, and
`identity-revalidation`. The first failed dependency terminates the preflight;
later phases are not reported as successful or failed when their inputs were
not established. The same code is also written as `pbr: <code>` on standard
error. Exit classification uses the existing command classes: invalid input
`2`, unsupported boundary `3`, and identity drift `4`.

A successful preflight contains exactly:

- `schema`, fixed to `proofbound-runtime-preflight/1`;
- `ready`, fixed to `true`;
- `caveat`, fixed to `preflight.point-in-time`;
- `plan_id`;
- `plan_source`, the exact execution-plan artifact and its requested and
  resolved paths;
- `platform`, containing the architecture, kernel release, Landlock ABI,
  available seccomp actions, cgroup directory, cgroup mount and inode
  identities, and available controllers;
- `command`, containing the identified executable, optional identified ELF
  interpreter, and identified working-directory inventory;
- `inputs`, containing each identified project input or runtime-library root in
  canonical artifact-identity order;
- `output_root`, containing its requested path, resolved parent, and resolved
  absent target; and
- `receipt`, containing its resolved absent target.

Each identified artifact contains exactly `role`, `sha256`, `size`, and `mode`,
using the same field meaning as an execution receipt. Each path observation
contains `requested`, `resolved`, and `artifact`. The optional interpreter is
JSON `null` for a static executable. All paths must be representable as UTF-8;
an unrepresentable diagnostic path fails closed with a typed code rather than
being lossily converted.

No success field authorizes later execution. In particular, the observed
identity of a directory is a point-in-time recursive inventory, the output and
receipt targets may appear after inspection, and the host capability state may
change. `run` must repeat every security-relevant check, retain descriptors,
install the boundary, and reject drift independently.

## Ownership and implementation boundary

The pure core continues to own strict plan parsing, normalization, and policy
compilation. The Linux crate owns capability meaning, confined resolution,
ELF discovery, identity observation, and a new read-only output-root target
inspection primitive. The CLI owns phase ordering, JSON projection, file-path
presentation, exit mapping, and receipt-target inspection.

Preflight must reuse the production parser, resolver, capability probe, and
identity implementations. A second permissive parser, path walker, ELF parser,
or host-support decision is prohibited. The new output-root primitive may
share validation with `FreshOutputRoot::create`, but it must stop before the
creation syscall.

## Acceptance and falsification

Implementation is complete only when:

1. invalid plan bytes, every registered plan error, and normalization failure
   map to their exact phase and existing machine code;
2. unsupported hosts preserve the exact `ProbeError` code and exit `3`;
3. root escapes, symlinks, forbidden file kinds, missing execute mode, malformed
   ELF, architecture mismatch, and unavailable interpreter fail in the exact
   resolution phase;
4. existing or invalid receipt and output targets fail without changing them;
5. success reports the same artifact identities that the production run path
   observes for an unchanged fixture;
6. a mutation between initial observation and final revalidation produces
   `identity-revalidation` and exit `4`;
7. filesystem and cgroup snapshots are byte-for-byte unchanged by success and
   failure cases, and no child process is created;
8. output JSON validates against the checked-in closed schema; and
9. the complete native preflight corpus runs on both supported architectures.

## Compatibility

This is an additive command and a new diagnostic schema. Version 0.1 binaries
do not implement it. A preflight report is neither an execution receipt nor
portable evidence and must not be accepted by `pbr-verify`, `pbr-compose`, or a
future receipt-acceptance policy as proof that an execution occurred.
