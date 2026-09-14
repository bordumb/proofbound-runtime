# PBF-0013: Exact-identity Proofbound tool distribution

- **Status:** `upstreamed`
- **Priority:** `near-term`
- **Kind:** `workflow`
- **Created:** 2026-09-09
- **Last updated:** 2026-09-14
- **Runtime claim:** `none`
- **Runtime milestone:** Milestone A: sustainable assurance development
- **Proofbound target:** tool-bundle workflow, manifest schema, and installer
- **Upstream record:** Proofbound PR 10 head `693976f` independently approved
  and merged as `dd481a3`; Proofbound PR 12 reviewed subject `6072127` and
  approval envelope `5f190e0` merged as `9512469`; exact-main Verify run
  `34899222179` and immutable publication run `34900896450` passed
- **Supersedes:** none
- **Superseded by:** none

## Summary

Proofbound has no complete distribution containing the CLI, independent
verifier, and adapters that a consumer can pin as one exact tool-set identity.
Runtime therefore compiles five or six executables from an exact Git revision
in every clean hosted job.

## Runtime observation

Runtime workflows pin Proofbound commit
`1084e0d1dc5685933b705d8844af5b123399e0b9`. The Verify workflow installs
`proofbound`, the Aeneas, test, Kani, and Lean adapters with `cargo install`.
The release workflow also installs `proofbound-verify`. Representative Verify
and release-candidate jobs continue to spend several minutes compiling the
pinned Proofbound tools after building the translation tools.

Exact source pinning prevents a floating branch from selecting different
source, but each consumer rebuild still depends on the Rust toolchain,
dependency resolution, build host, and installation procedure.

## Ownership test

Proofbound owns the set of executables that jointly implement compilation,
independent verification, and adapter protocols. Any CI consumer needs a
complete compatible set. Runtime should pin and verify that set, but it should
not define Proofbound's generic bundle contents or tool-set identity contract.

## Assurance risk

Installing tools independently can mix different source revisions or omit the
independent verifier or one required adapter. A mutable installer or selector
could change the selected bytes. A checksum downloaded from the same untrusted
location as its artifact proves only internal agreement, not publisher
authenticity.

A distributed bundle establishes tool identity and provenance under declared
distribution and build assumptions. It must not be treated as evidence that
the tools are correct or that their outputs are admitted.

## Proposed upstream behavior

Produce one deterministic Proofbound tool-bundle candidate for each supported
platform. The bundle must contain the CLI, independent verifier, every
first-party adapter, public schemas, and a canonical manifest with:

- the exact Proofbound source revision and successful mainline Verify run;
- a product label that is metadata, not a compatibility promise;
- platform and architecture;
- every payload name, mode, size, and digest;
- Rust toolchain and locked dependency identities;
- build workflow and builder identities; and
- the bundle's own schema and digest procedure.

Retain the candidate archive, manifest, and SHA-256 record as exact workflow
artifacts. Provide a standalone installer that requires the expected archive
digest, verifies the manifest and every member, rejects unknown or extra
members, and installs to an explicit destination without implicit replacement.
State the workflow, builder, compiler, linker, platform, archive implementation,
and installer runtime as trusted-computing-base roles. Do not provide a mutable
`latest` selector for protected use.

## Evidence meaning

### Establishes

- A consumer selected one exact, complete, platform-specific Proofbound tool
  set.
- Installed executable bytes match the reviewed bundle manifest.
- Source, successful mainline verification run, toolchain, builder, platform,
  and distribution identities remain available for TCB accounting.

### Does not establish

- Correctness of Proofbound, an adapter, Rust, the builder, or the host.
- Publisher authenticity unless a separately trusted publisher identity or
  signature policy supplies it.
- Freshness or validity of evidence produced by the tools.
- Compatibility with an unlisted platform or consumer schema.

## Acceptance criteria

1. Clean `x86_64` and `aarch64` Linux workers install the exact complete tool
   set for one source revision and successful Verify run, and independently
   match every member digest.
2. A missing executable, extra executable, wrong architecture, unsupported
   platform, unavailable exact candidate, or absent expected digest fails closed
   before any evidence unit runs.
3. A changed member, substituted manifest, mixed-revision executable, mutable
   selector, or adjacent checksum without the pinned expected identity is
   rejected.
4. The bundle producer and independent installation verifier derive the same
   canonical member inventory, bundle identity, and source/toolchain metadata.
5. Every distribution, build-host, compiler, and platform assumption and TCB
   role remains visible to the consuming project.
6. Runtime can replace per-job source compilation with the bundle without
   changing evidence receipts, claim status, or `--fresh` behavior.

## Prelaunch adoption

This adds a current distribution contract. It does not create a compatibility
or support obligation. Runtime switches from source builds only after the
candidate contains every executable its workflows use and Runtime pins the
exact source revision, workflow run, archive digest, and manifest identity. No
existing receipt is reinterpreted.

## Local treatment

Runtime's admitted evidence path still compiles all required tools from exact
Proofbound revision `1084e0d`. The current dogfood wave separately pins public
immutable release `388736918`, resolves its tag to the pinned source, validates
its seven exact asset identities, binds its embedded and detached manifests,
and installs it only in an isolated required CI job. The public bytes do not
yet run evidence units. The source-build cutover remains a separate reviewed
wave. Claim-specific assumptions retain GitHub, repository controls, DNS, TLS,
Python, digest, installer, runner, process, and filesystem roles. Runtime does
not claim that the release channel or an adjacent checksum independently
authenticates a publisher.

## Upstream handoff

- **Destination:** `proof-bound` tool-bundle workflow, manifest schema, and
  standalone installer
- **Issue:** none
- **Specification or ADR:** `docs/specs/0004_tool_bundle_distribution.md`
- **Commit or pull request:** Proofbound PR 10, approved head
  `693976fea7e169fc84a3919113fd0a1e6a132544`, merged to `main` as
  `dd481a381913f7df1e7d89c261a0098a3f747995`; Proofbound PR 12,
  reviewed subject `607212759756acf6857ffe2072c2c05773f95adb`, approval
  envelope `5f190e01cd6e9b1189d4c8538e7af2d09b4a1143`, merged as
  `95124692b6b9383a265c8024f21bb964737f8b6b`

## Resolution

Proofbound PR 10 implements the proposed prelaunch bundle, manifest, installer,
two Tier-0 claims, deterministic production checks, and hosted workflow. Its
complete local 12-stage gate passed at the initial implementation head. After
review fixes, 33 focused tests and both registered claims passed at exact clean
head `693976f`, and an independent exact-head review recorded `APPROVE` with no
findings. The pull-request gate passed, the approved head merged as unsigned
main commit `dd481a3`, and exact-main Verify run `34887427661` passed. Both jobs
in tool-bundle run `34889426459` passed. The retained archive digests are
`c76795b24937f9091e9103bea7dcb4e0dd9369187e9f81d1bfe686a5bafda256`
for `linux-x86_64` and
`56ef5c8aebbbde488102b8d2bac6e3e712bba76e3dbf261187aedd83729528fe`
for `linux-aarch64`; their manifest digests are respectively
`895f07f68380f151ebed3533b464160dab545f8751f5dc1a9eeb21e7fe803783`
and `cb8479bea4509c02b1318f2f671472e4292b9cf398bdc7e7098dfb6c0d8740f3`.
Proofbound PR 12 added the draft-first public publication path, exact-source
tag, closed seven-asset publication manifest, immutable-release gate, and
anonymous retrieval check. Exact-main Verify run `34899222179` and
bundle/publication run `34900896450` passed. Immutable public release
`388736918` binds source `9512469`, verification run `34899222179`, and bundle
run `34900896450`. Resolution remains open until Runtime's isolated dogfood and
later source-build cutover pass without changing evidence meaning or `--fresh`
behavior.
