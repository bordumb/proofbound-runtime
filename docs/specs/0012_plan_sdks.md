# Specification 0012: Plan-construction SDKs

- **Status:** accepted for implementation
- **Applies to:** Runtime 0.2 Rust, Python, and TypeScript SDK packages
- **Roadmap:** RT-3.5

## Boundary

The SDKs are convenience producers for the settled version 2 execution-plan
wire object and strict consumers of the JSON projection printed by `pbr run`.
They do not execute workloads in-process, compile Linux policy, install a
boundary, construct receipts, verify receipts, compose releases, or make
acceptance decisions.

Python and TypeScript invoke an explicitly selected `pbr` executable as a
separate child process with an explicit argument vector and environment. The
Rust package constructs plans and decodes machine-result projections; callers
that execute use the same separate-process product boundary. The independently
distributed `pbr-verify`, `pbr-compose`, and `pbr-accept` binaries remain
separate and are never reimplemented by an SDK.

## Plan construction

All three SDKs fix network authority to deny and accept the same remaining
closed logical fields:

- plan identifier;
- executable, arguments, and working directory;
- read, runtime-read, write, and execute path arrays;
- inherited environment-name array;
- process, wall-time, stdout, stderr, memory, and swap limits.

They reject unknown fields, non-integer or out-of-range integers, invalid plan
identifiers, null-containing arguments, duplicate environment or path entries,
anything except exactly one write root and one execute path, an execute path
different from the command executable, and limits outside the version 2
quantization and size bounds.

Successful construction returns the exact deterministic-CBOR bytes defined by
`schemas/execution-plan-v2.cddl` and ADR 0003. Rust reuses the production core
parser for semantic validation after encoding. Python and TypeScript use
separate small encoders and must match the checked-in golden vector byte for
byte. They do not accept or emit the JSON projection as plan input.

## Run-result projection

The SDK result type accepts only a closed JSON object with schema
`proofbound-runtime-run-result/2`, a nonempty receipt path, a 32-byte lowercase
hex commitment with the `hex:` display prefix, a version-4 16-byte lowercase
hex execution ID with the `hex:` display prefix, and one closed outcome:

- `exited` with a code from 0 through 255;
- `signaled` with a signal from 1 through 255;
- `timed-out`;
- `denied`;
- `launcher-failed`; or
- `incomplete`.

This value is a control-channel projection. It transports the independently
selected commitment and execution ID but is never receipt-verification input.

## Process invocation

Python and TypeScript expose a `run` helper that:

1. requires explicit `pbr`, plan, receipt, and cgroup-root paths;
2. invokes exactly `pbr run --plan PLAN --receipt RECEIPT --cgroup-root ROOT`;
3. supplies only the caller's explicit environment map;
4. places no shell between the SDK and `pbr`;
5. bounds stdout and stderr capture;
6. accepts exit zero only; and
7. strictly decodes the one-line JSON result projection.

The helper returns typed process and result errors. It does not retry, mutate a
plan, infer policy from a failure, inspect a receipt, or weaken `pbr` errors.

## Packaging and evidence

The Rust crate is `proofbound-runtime-sdk`. The Python distribution is
`proofbound-runtime-sdk`; its import package is `proofbound_runtime`. The npm
package is `@proofbound/runtime-sdk`. Each package carries version 0.2.0,
repository and license metadata, no runtime dependency on producer/verifier
internals, and a release-package smoke check.

Cross-language golden tests, malformed-plan cases, closed result-projection
tests, shell-bypass invocation tests, oversized-output tests, and package-file
inventories form the initial evidence. Publication to an external registry is
a distribution event and remains gated on exact tag/release approval; the
repository claim covers the package sources and reproducible package checks,
not registry authenticity.
