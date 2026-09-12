# Specification 0009: Run denial diagnostics

**Status:** Draft implementation specification

**Target version:** 0.2.0

**Date:** 2026-09-10

This specification defines stable human diagnostics for failures that
`pbr run` already detects. It does not add a live observer, infer a denial
from child behavior, change an execution outcome, change receipt eligibility,
or define a committed wire object. Version 1 plan, run-result, and receipt
bytes remain unchanged.

## Claim and exact production subject

Candidate claim `PBR-DIAGNOSTIC-011`:

> When `pbr run` fails at a Runtime-owned boundary, its diagnostic identifies
> the closed execution phase, the invariant that failed, and the existing
> exact machine code without changing the recorded child outcome or creating a
> receipt from an incomplete execution.

The exact production subject is the `pbr run` orchestration error type, every
mapping from core and Linux errors into that type, and the CLI stderr renderer.
The low-level error enumerations remain owned by their current crates. Child
stderr, arbitrary exit codes, kernel audit text, and host log messages are not
part of the subject.

## Diagnostic form

A failed syntactically valid `pbr run` invocation writes exactly one line:

```text
pbr: phase=<phase> rule=<rule> code=<machine-code>
```

The phase and rule tokens use lowercase ASCII letters, digits, and hyphens.
The machine code is the existing stable code from the exact failed operation.
Exit classes remain `2` for invalid input, `3` for an unsupported boundary,
`4` for identity drift, `5` for launcher or supervision failure, and `6` for
receipt construction or publication failure.

This form supersedes only the `pbr: <machine-code>` rendering specified for
`pbr run` in Specification 0002. Other commands retain their existing stderr
contracts. Historical binaries are unchanged.

## Closed phases and rules

The phase vocabulary is:

1. `receipt-target`;
2. `plan-input`;
3. `plan-validation`;
4. `authority-normalization`;
5. `plan-root`;
6. `host-capabilities`;
7. `output-root`;
8. `working-directory`;
9. `executable-closure`;
10. `read-authority`;
11. `runtime-identity`;
12. `launcher-identity`;
13. `environment`;
14. `policy-compilation`;
15. `execution-identity`;
16. `cgroup`;
17. `launcher-request`;
18. `identity-revalidation`;
19. `launcher-protocol`;
20. `output-inventory`;
21. `receipt-construction`;
22. `receipt-publication`; and
23. `result-projection`.

The rule vocabulary is:

- `receipt-target-valid`;
- `plan-source-readable`;
- `plan-valid`;
- `authority-normalized`;
- `plan-root-confined`;
- `host-supported`;
- `output-root-fresh`;
- `working-directory-resolved`;
- `executable-closure-resolved`;
- `read-authority-resolved`;
- `runtime-identity-observed`;
- `launcher-identity-observed`;
- `environment-representable`;
- `policy-identity-constructed`;
- `execution-identity-created`;
- `cgroup-boundary-prepared`;
- `launcher-request-constructed`;
- `artifact-identities-stable`;
- `launcher-boundary-complete`;
- `output-inventory-stable`;
- `receipt-constructed`;
- `receipt-published`; and
- `run-result-representable`.

One phase and one rule are assigned at the call site that owns the failed
invariant. A shared low-level error can therefore retain one machine code while
appearing under different phases. Identity drift keeps exit class `4` and the
phase whose retained identity failed; it is not collapsed into one generic
identity phase.

## Assurance boundary

The diagnostic reports where Runtime stopped and which Runtime invariant was
not established. It does not claim that the kernel denied a child operation.
A completed child that exits with `EPERM`, `EACCES`, a signal, or an arbitrary
nonzero code keeps its existing receipt outcome. Runtime does not translate
that behavior into one of these orchestration diagnostics.

No diagnostic field is a verification input. The receipt producer and
independent verifier remain unchanged by this slice. If a later machine-result
schema carries diagnostics, that object must follow the version and encoding
rules in ADR 0003. A live trace profile requires a separate specification and
trusted-computing-base analysis.

## Falsification requirements

Before implementation is admitted:

1. a closed catalog must cover capability, resolution, identity drift,
   output-root, launcher protocol, cgroup, receipt construction, receipt
   publication, and result-projection failures;
2. every catalog entry must assert the exact exit class, phase, rule, and
   machine code;
3. changing only a low-level error source must not silently change its owning
   phase or rule;
4. no constructor may accept arbitrary phase or rule strings;
5. the renderer must emit one bounded line with no path, environment value,
   child output, or secret-bearing context;
6. completed child outcomes must retain their existing receipt and run-result
   meaning; and
7. native orchestration tests must preserve no-child and no-receipt behavior
   for failures that occur before launcher release.

## Review gate and residual obligations

This draft requires explicit review before it is published as the version 0.2
CLI contract. Review must confirm the closed vocabulary, compatibility impact
of the stderr change, and the boundary between an orchestration failure and a
completed child outcome.

Even after implementation, diagnostics retain the assumptions of the
underlying capability probes, resolution boundary, launcher protocol, cgroup
lifecycle, and receipt producer. Stable identifiers improve explanation; they
do not strengthen those underlying claims.

## Implementation checkpoint

As of 2026-09-11, the source implementation is complete on the roadmap branch.
The production error type closes over all 23 phases and 23 rules, each
registered diagnostic case asserts its exact exit class and machine code, and
the CLI emits the bounded one-line form without changing child outcomes or
receipt meaning. The exact native `pbr` corpus additionally runs five
deterministic failures before launcher release on both supported
architectures: occupied receipt target, missing plan input, unavailable host
capability, occupied output root, and executable-resolution failure. Every
case asserts empty stdout, the exact diagnostic, no child marker, and no new
receipt; the resulting closed inventory is retained for release observation.

This checkpoint does not approve this specification. The vocabulary and
compatibility change remain draft until explicit owner review. It also does
not describe diagnostics as released: that statement requires both exact
native release contexts to reproduce and observe the `pbr` artifact at the
approved mainline release revision.
