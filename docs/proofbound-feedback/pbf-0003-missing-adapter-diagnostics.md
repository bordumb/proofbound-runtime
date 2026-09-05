# PBF-0003: Missing adapter diagnostics

- **Status:** `proposed`
- **Priority:** `near-term`
- **Kind:** `workflow`
- **Created:** 2026-09-05
- **Last updated:** 2026-09-05
- **Runtime claim:** `PBR-AUTH-001`
- **Runtime milestone:** Milestone 1
- **Proofbound target:** CLI reporting
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

When a required adapter executable is absent, `proofbound check --json` reports
the cited evidence as missing but omits the adapter execution failure that
caused the evidence to be absent. A clean installation can therefore look like
a claim-registration error instead of an incomplete Proofbound installation.

## Runtime observation

GitHub Actions run `33848780621` installed `proofbound-cli` at revision
`0a5c6b6dcf7e3b59cdf71ec5f8d50082c5f3a3e0` but did not install
`proofbound-adapter-test`, `proofbound-adapter-kani`, or
`proofbound-adapter-lean`. The Rust tests, independent conformance runner, Kani
installation, and Lean build completed successfully.

`proofbound check --root . --json` then returned exit code 3 and made
`PBR-AUTH-001` invalid. Its claim errors only said that these records were
missing:

- `example-test:authority-conformance`;
- `bounded-check:authority-normalization-bounds`; and
- `theorem:authority-normalization-model`.

The JSON report did not include the unit-run diagnostics that identified the
missing adapter executables. The resulting remediation, "run the registered
evidence unit," did not explain that the units could not start.

## Ownership test

Every Proofbound consumer uses external adapter processes. The distinction
between an absent adapter, a failed evidence run, and a stale citation is
generic Proofbound behavior and is independent of Runtime and Linux policy.

## Assurance risk

The current behavior fails closed, which is correct, but it obscures the reason.
Users may delete valid evidence citations or weaken a claim policy to make the
board green when the actual defect is an incomplete tool installation.

## Proposed upstream behavior

Include every selected unit-run outcome and its structured adapter diagnostic
in the JSON check report. A claim error caused by an unavailable adapter should
identify the unit, expected executable, stable adapter error code, and exact
installation or configuration remediation. It must remain distinct from a
unit that ran and failed and from a citation with no registered unit.

## Evidence meaning

### Establishes

- The report explains why a registered evidence record was not produced.
- Automation can distinguish unavailable tooling from failed or stale evidence.

### Does not establish

- That installing an adapter makes its evidence pass.
- That an adapter result is policy-admitted.
- Any proof, bounded-check, source-refinement, or artifact-binding status.

## Acceptance criteria

1. A fixture with an absent registered adapter returns a JSON unit-run
   diagnostic naming the unit and executable.
2. A missing adapter cannot be rendered only as a missing evidence citation.
3. Substituting an executable with the wrong adapter identity is reported as an
   identity or protocol failure, not as stale evidence.
4. Human and JSON reports classify the same unit outcome and claim failure.
5. The report retains the claim's assumptions, bounds, linkage, policy
   blockers, and trusted-computing-base roles.

## Compatibility and migration

Adding unit-run diagnostics requires a versioned extension to the JSON report
schema. Existing status derivation and exit codes do not need reinterpretation.

## Local treatment

Runtime CI installs the orchestrator and every adapter required by its Tier 2
manifests at one exact Proofbound revision. It checks that each executable is
available before running the offline assurance gate. Missing adapters continue
to fail CI.

## Upstream handoff

- **Destination:** not upstreamed
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Unresolved.
