# Specification 0002: Version 1 CLI surface

**Status:** Accepted implementation specification

**Version:** 0.1.0

**Date:** 2026-09-07

This specification refines the product-surface requirements in
[`0001_initial_spec.md`](0001_initial_spec.md). It fixes the command grammar,
outputs, and component boundaries for Wave 4 without changing the plan or
receipt schemas.

## UX

The public executable is `pbr`. It accepts exactly one of these command forms:

```text
pbr doctor --cgroup-root <path>
pbr plan check --plan <path>
pbr run --plan <path> --receipt <path> --cgroup-root <path>
pbr inspect <receipt>
pbr --help
pbr --version
```

Arguments not shown above are rejected. In particular, `run` never accepts a
command override. The reviewed plan remains the sole source of the executable,
arguments, environment allow-list, authority, and limits.

The command flow is deliberately explicit:

```text
+----------------------+     +----------------------+     +------------------+
| plan.toml            | --> | pbr plan check       | --> | normalized JSON  |
| reviewed declaration |     | no host mutation     |     | or typed error   |
+----------------------+     +----------------------+     +------------------+
           |
           v
+----------------------+     +----------------------+     +------------------+
| pbr run              | --> | receipt.json         | --> | pbr-verify       |
| supported Linux only |     | canonical bytes      |     | committed bytes  |
+----------------------+     +----------------------+     +------------------+
           |
           +----------> stdout: receipt commitment and execution summary
```

- `doctor` probes every required version 1 host capability without running a
  workload or mutating the cgroup hierarchy. It always emits one JSON report.
  It exits `0` only when all required capabilities are available and `3`
  otherwise.
- `plan check` strictly decodes, validates, and normalizes a plan. It performs
  no path resolution, capability probing, or host mutation. Success emits one
  JSON explanation of the normalized plan.
- `run` resolves paths relative to the plan file's canonical parent, requires a
  supported host, installs the full boundary, captures the outcome, and creates
  the receipt with exclusive creation. It emits one JSON summary containing
  the receipt path and an independently transportable `sha256:` commitment.
  A child failure is recorded in the receipt and does not change the command's
  `0` exit status when runtime orchestration and receipt construction succeed.
- `inspect` reads a receipt and pretty-prints its JSON structure. It does not
  check canonical bytes, commitments, identities, derivation, or reuse
  eligibility, and it never prints words such as valid, verified, or reusable
  as its own judgment.

Machine results go to standard output. Typed diagnostics use
`pbr: <machine-code>` on standard error. The stable exit classes remain `0`,
`2`, `3`, `4`, `5`, and `6` as defined by Specification 0001. Output-write
failure is invalid input (`2`) because the requested control-channel operation
did not complete.

## Architecture

The CLI owns syntax, file I/O orchestration, and exit mapping. It does not own
policy semantics, Linux enforcement, or receipt eligibility.

```text
+-----------+      +------------------+      +-----------------------+
| pbr CLI   | ---> | pure core        | ---> | Linux runtime         |
| grammar   |      | plan + policy    |      | probe/resolve/execute |
| file I/O  |      | receipt builder  |      | output inventory      |
+-----------+      +------------------+      +-----------------------+
      |                       |
      |                       v
      |                +------------------+
      +--------------> | canonical receipt|
                       +------------------+
                                |
                                v
                       +------------------+
                       | pbr-verify       |
                       | independent      |
                       +------------------+
```

The crate layout follows Specification 0001:

- `main.rs` parses the closed grammar and maps typed failures to exit classes.
- `doctor.rs` translates `CapabilityReport` into stable JSON.
- `plan.rs` translates validated and normalized core types into stable JSON.
- `run.rs` composes existing core and Linux APIs and atomically completes one
  receipt attempt without duplicating their decisions.
- `inspect.rs` contains presentation only. It must not depend on the independent
  verifier or call producer validation as a substitute for verification.

Every command exposes an injected, side-effect-light entry point for unit tests.
Native execution remains covered by the identified Linux corpus and an
end-to-end CLI test on each supported architecture.

## APIs

### `doctor`

Input: an explicit delegated cgroup v2 root. Output is a closed JSON object with
`schema`, `supported`, and one entry for operating system, architecture, kernel
release, Landlock, `no_new_privs`, seccomp, and cgroup v2. Each entry is either
`{"status":"available", ...}` or
`{"status":"unavailable","code":"<machine-code>"}`. Values are observations,
not claims about future availability.

### `plan check`

Input: UTF-8 TOML at `--plan`. Output is a closed JSON object with schema
`proofbound-runtime-plan-check/1`, the plan identifier, exact command, and
canonical normalized authority. Paths and environment names are sorted and
deduplicated by the pure core. No filesystem identity appears because this
command does not resolve artifacts.

### `run`

Inputs: a plan path, a new receipt path, and a delegated cgroup v2 root. The
receipt path must not exist and must be outside the child's writable authority.
The API returns a summary with schema `proofbound-runtime-run-result/1`, the
receipt path, receipt commitment, and recorded child outcome. Receipt bytes use
the existing canonical producer and are never reserialized by the CLI.

### `inspect`

Input: one UTF-8 JSON file. Output is deterministic pretty JSON with the same
data model and no added fields. Parsing is limited to generic JSON syntax and
resource bounds; versioned receipt meaning belongs exclusively to
`pbr-verify`.
