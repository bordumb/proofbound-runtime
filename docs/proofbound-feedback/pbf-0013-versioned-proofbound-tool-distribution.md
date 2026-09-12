# PBF-0013: Versioned Proofbound tool distribution

- **Status:** `upstream-ready`
- **Priority:** `near-term`
- **Kind:** `workflow`
- **Created:** 2026-09-09
- **Last updated:** 2026-09-09
- **Runtime claim:** `none`
- **Runtime milestone:** Milestone A: sustainable assurance development
- **Proofbound target:** release workflow, tool bundle manifest, and installer
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound has no versioned distribution containing the CLI, independent
verifier, and adapters that a consumer can pin as one tool identity. Runtime
therefore compiles five or six executables from an exact Git revision in every
clean hosted job.

## Runtime observation

Runtime workflows pin Proofbound commit
`70af5e61110fc09704076a6d8b00fd8ff011b1c8`. The Verify workflow installs
`proofbound`, the Aeneas, test, Kani, and Lean adapters with `cargo install`.
The release workflow also installs `proofbound-verify`. Representative Verify
run `34345620529` spent 4 minutes 36 seconds compiling the pinned Proofbound
tools after spending 20 minutes 51 seconds building the translation tools.

Exact source pinning prevents a floating branch from selecting different
source, but each consumer rebuild still depends on the Rust toolchain,
dependency resolution, build host, and installation procedure. Runtime also
consumes a commit that is not yet on Proofbound `main` or identified by a
Proofbound release.

## Ownership test

Proofbound owns the set of executables that jointly implement compilation,
independent verification, and adapter protocols. Any CI consumer needs a
complete compatible set. Runtime should pin and verify that set, but it should
not define Proofbound's generic release contents or compatibility contract.

## Assurance risk

Installing tools independently can mix incompatible revisions or omit the
independent verifier or one required adapter. A mutable installer or tag could
change the selected bytes. A checksum downloaded from the same untrusted
location as its artifact proves only internal agreement, not publisher
authenticity.

A distributed bundle establishes tool identity and provenance under declared
distribution and build assumptions. It must not be treated as evidence that
the tools are correct or that their outputs are admitted.

## Proposed upstream behavior

Publish one immutable Proofbound tool bundle for each supported platform. The
bundle must contain the CLI, independent verifier, every first-party adapter,
and a canonical manifest with:

- the exact Proofbound source revision and release identity;
- platform and architecture;
- every executable name, protocol version, size, and digest;
- Rust toolchain and locked dependency identities;
- build workflow and builder identities; and
- the bundle's own schema and digest procedure.

Publish the expected bundle digest through a reviewed, immutable release
record. Provide a small installer or maintained action that requires an exact
release and expected digest, verifies the manifest and every member, rejects
extra executable members, and installs to an explicit destination. State the
release channel and builder as TCB roles. Do not provide a mutable `latest`
mode for protected use.

## Evidence meaning

### Establishes

- A consumer selected one exact, complete, platform-specific Proofbound tool
  set.
- Installed executable bytes match the reviewed bundle manifest.
- Source, toolchain, builder, platform, and distribution identities remain
  available for TCB accounting.

### Does not establish

- Correctness of Proofbound, an adapter, Rust, the builder, or the host.
- Publisher authenticity unless a separately trusted release identity or
  signature policy supplies it.
- Freshness or validity of evidence produced by the tools.
- Compatibility with an unlisted platform or consumer schema.

## Acceptance criteria

1. Clean `x86_64` and `aarch64` Linux workers install the exact complete tool
   set from one release identity and independently match every member digest.
2. A missing executable, extra executable, wrong architecture, unsupported
   platform, unavailable immutable release, or absent expected digest fails
   closed before any evidence unit runs.
3. A changed member, substituted manifest, mixed-release executable, mutable
   tag, or adjacent checksum without the pinned expected identity is rejected.
4. The bundle producer and independent installation verifier derive the same
   canonical member inventory, bundle identity, and source/toolchain metadata.
5. Every distribution, build-host, compiler, and platform assumption and TCB
   role remains visible to the consuming project.
6. Runtime can replace per-job source compilation with the bundle without
   changing evidence receipts, claim status, or `--fresh` behavior.

## Compatibility and migration

This adds a distribution contract. Existing source builds remain supported
under their current source, toolchain, and host identities. Runtime migrates
only after the published bundle contains every executable its workflows use
and pins the exact bundle digest; no existing receipt is reinterpreted.

## Local treatment

Runtime compiles all required tools from exact Proofbound revision `70af5e6`
in every clean protected and release job, verifies that each executable is on
the path, and retains Proofbound and toolchain identities in assurance
metadata. It accepts the latency and does not use a mutable prebuilt tool or
claim that an adjacent checksum authenticates a publisher.

## Upstream handoff

- **Destination:** `proof-bound` release workflow, distribution manifest, and
  installation verifier
- **Issue:** none
- **Specification or ADR:** not yet upstreamed
- **Commit or pull request:** none

## Resolution

Unresolved.
