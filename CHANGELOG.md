# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A read-only `pbr preflight` command that validates a plan, probes the
  supported host boundary, resolves exact command and input identities, and
  inspects fresh output and receipt targets without starting child code or
  mutating the host.
- A deterministic, checksummed source bundle for the maintained static hello
  execution and independent receipt-verification example.
- A fail-closed exact-release installer with closed archive/member validation
  and embedded reviewed digests for both version 0.1 architectures.
- A separate read-only `pbr doctor --cgroup-root <path> --explain` projection
  with stable missing requirements and non-mutating remediation.

## [0.1.0] - 2026-09-09

### Added

- Strict execution-plan validation and normalized authority explanation through
  `pbr plan check`.
- Native `x86_64` and `aarch64` Linux enforcement with Landlock, seccomp,
  `no_new_privs`, cgroup v2, bounded streams, and fail-closed capability probes.
- Canonical execution receipts, external receipt commitments, and the
  independently implemented `pbr-verify` verifier.
- Proofbound claim, falsifier, bounded-check, Lean refinement, native boundary,
  orchestration, and release-reproduction evidence.
- A fail-closed Proofbound release-envelope gate that retains the independent
  verifier's canonical report.
- The `pbr-compose` typed plugin, closed cross-receipt attack corpus, and native
  release workflow that joins exact Proofbound release assurance to one exact
  independently verified Runtime execution without upgrading claim facets.
- Independent transport of the expected execution ID in the `pbr run` result,
  preventing composition from deriving its replay expectation from the receipt
  carrier.
- Lean 4.33 source refinement for the production receipt-binding constructor
  and canonical wire projection.
- Contextual theorem-derived binding of the four Tier 3 claims to the exact
  native `pbr` artifacts, with independent verification and no promotion of
  observation-only claims.

## [0.0.0] - 2026-09-04

### Added

- Initial product specification and assurance wavefront.
- Contributor guidance and the Proofbound feedback loop.
- Tier 0 claims, assumptions, repository checks, and CI bootstrap.

[Unreleased]: https://github.com/bordumb/proofbound-runtime/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bordumb/proofbound-runtime/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/bordumb/proofbound-runtime/releases/tag/v0.0.0
