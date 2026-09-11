# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-11

### Added

- Explicit, validated Version 2 memory and swap limits with cgroup v2 control
  installation, canonical readback, terminal peak and event observations, and
  exact cleanup across every terminal path.
- Closed CDDL schemas and deterministic-CBOR golden vectors for Version 2
  execution plans, compiled policies, run results, execution receipts, and
  composed receipts, using text map keys under RFC 8949 section 4.2.1.
- Independent Version 2 receipt decoding, canonicality checks, resource-event
  derivation, mutation attacks, and historical Version 1 verification.
- A registered `PBR-RESOURCE-010` effectful boundary claim with bounded cgroup
  tests and exact native release-observation wiring, without presenting Linux
  behavior as theorem-derived artifact soundness.
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
- A complete two-architecture native memory workload and attack catalog,
  retained native context, and a measured Runtime performance baseline.
- A deterministic-CBOR adopter acceptance policy and decision format,
  independently reverified `pbr-accept` CLI, closed acceptance attack corpus,
  reproducible standalone acceptor artifact, and pinned first-party GitHub
  Action with opt-in exact-artifact retention.
- A read-only `pbr plan scaffold` command that inventories bounded static ELF
  interpreter and transitive dependency metadata under explicit glibc or musl
  host profiles, records resolution provenance, and emits only an explicitly
  unsafe JSON review aid with all human policy choices left open.
- Rust, Python, and TypeScript plan SDKs that match the deterministic-CBOR
  Version 2 golden vector, strictly decode non-verifying run results, preserve
  the separate-process boundary, and carry closed reproducible-package checks.

### Changed

- New execution commands require Version 2 plans with explicit memory and swap
  values; inspection and verification retain separate frozen Version 1 paths.
- `pbr-compose` composes Version 2 execution receipts into deterministic-CBOR
  Version 2 composed receipts while preserving historical Version 1 behavior.
- Authority, policy, receipt eligibility, and receipt binding source
  refinements now build only with Lean 4.33 and cover the Version 2 resource
  domain without weakening their visible toolchain assumption.
- Required CI runs cheap preflight first, executes Rust, formal, and both native
  architecture lanes in parallel, retains timing and native context artifacts,
  and admits only the exact successful aggregate.

### Security

- A nonzero memory or swap peak is never inferred to be a limit event. Version
  2 eligibility derives canonical non-reuse reasons only from registered
  nonzero kernel counter deltas and preserves the independent child outcome.
- Producer and verifier CBOR codecs remain separate, and every JSON rendering
  of a Version 2 object is explicitly non-authoritative and never a
  verification input.

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

[Unreleased]: https://github.com/bordumb/proofbound-runtime/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/bordumb/proofbound-runtime/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/bordumb/proofbound-runtime/compare/v0.0.0...v0.1.0
[0.0.0]: https://github.com/bordumb/proofbound-runtime/releases/tag/v0.0.0
