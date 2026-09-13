# Specification 0004: Host-readiness explanations

**Status:** Accepted implementation specification

**Version:** 0.1.0

**Date:** 2026-09-09

This specification adds an explanatory projection to the version 1 `doctor`
command defined by [Specification 0002](0002_cli_surface.md). It does not
change capability probing, supported-host semantics, boundary installation,
receipts, or the existing `proofbound-runtime-doctor/1` output.

## Command grammar

The CLI accepts one new exact form:

```text
pbr doctor --cgroup-root <path> --explain
```

The option order is fixed. Missing, repeated, reordered, or additional options
are invalid CLI usage and exit `2`. The existing form remains valid and keeps
its existing output:

```text
pbr doctor --cgroup-root <path>
```

Both forms perform the same read-only `CapabilityReport` probe exactly once.
Neither form installs a boundary, changes a cgroup, starts child code, or tests
a weaker fallback.

## Output

The explanatory form emits one closed JSON object with schema
`proofbound-runtime-doctor-explanation/1`. The top-level fields are exactly:

- `schema`;
- `supported`; and
- `capabilities`.

`capabilities` contains exactly the same seven named entries as the existing
doctor report: `operating_system`, `architecture`, `kernel_release`,
`landlock`, `no_new_privileges`, `seccomp`, and `cgroup_v2`.

An available entry is identical to the corresponding entry in
`proofbound-runtime-doctor/1`. An unavailable entry contains exactly:

```json
{
  "status": "unavailable",
  "code": "<stable ProbeError code>",
  "requirement": "<one stable missing requirement>",
  "remediation": "<one stable non-mutating next action>"
}
```

The requirement states the capability needed by the closed version 1 profile.
The remediation can identify a supported host property or direct the user to a
maintained procedure. It must not mutate the host, run privileged commands,
claim that a future run will succeed, suggest a weaker boundary, or convert an
unavailable capability into an available one.

Every `ProbeError` variant has one exhaustive explanation. Multiple capability
entries may carry the same operating-system explanation when the host cannot
perform Linux-specific probes. Text is presentation owned by the CLI; the
Linux crate continues to own capability semantics and stable error codes.

## Exit and trust semantics

The explanatory form exits `0` only when the underlying report is supported
and `3` otherwise. Output failure remains exit `2`. Explanation text is a
diagnostic projection of one observation. It is not evidence that a capability
will remain available, a host mutation occurred, or an execution boundary was
installed.

The existing machine report remains stable so current consumers do not receive
new fields. Consumers that need remediation must request and validate the new
schema explicitly.

## Acceptance and falsification

Implementation is complete only when:

1. the same injected `CapabilityReport` produces the same support decision in
   both doctor forms;
2. the existing form retains its exact schema and unavailable-entry shape;
3. every `ProbeError` produces one exact code, requirement, and remediation in
   the explanatory schema;
4. an unknown, missing, repeated, reordered, or trailing option is rejected
   before the probe runs;
5. unavailable output still exits `3` and cannot be presented as supported;
6. output-write failure remains a typed CLI failure; and
7. native tests confirm the command performs no additional host mutation or
   child execution.

## Compatibility

This is an additive CLI form and a new schema. It does not reinterpret an
existing doctor result, execution plan, run result, receipt, verification
report, or release receipt. Version 0.1 binaries do not implement the new form;
documentation must not show it as part of the `v0.1.0` archive.
