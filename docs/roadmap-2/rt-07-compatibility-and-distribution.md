# RT-7 integration record: prelaunch packaging and distribution

**Status:** RT-7.1 prelaunch distribution contract drafted; Proofbound bundle
prerequisite upstreamed in PR 10; RT-7.2 verifier-package implementation
locally validated; exact-head review and distribution remain blocked

**Primary owner:** Proofbound Runtime

**Roadmap:** [Epic RT-7](../product-roadmap-2.md#5-epic-rt-7-prelaunch-packaging-and-published-crates)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

**Native distribution contract:**
[Specification 0014](../specs/0014_public_compatibility_and_distribution.md)

**Delivery order:**
[Product roadmap execution order](../product-roadmap-execution-order.md)

## Product result

A consumer can install the Runtime verifier and SDKs, select a tested
cross-project identity tuple, and reproduce each package from its exact source
revision.

## Current source audit

The 2026-09-13 source audit found:

- `proofbound-runtime-sdk` explicitly permits publication, has no unpublished
  Runtime dependency, and is already built twice and byte-compared by the
  release workflow;
- the Python wheel and npm tarball have complete package metadata and the same
  reproducible package check;
- `proofbound-runtime-verify` now has explicit public metadata, a closed package
  payload, and no workspace-crate dependency;
- `proofbound-runtime-core` inherits `publish = false` and depends on the
  unpublished binding and receipt crates through workspace paths;
- the release workflow now retains SDK and verifier packages in aggregate
  provenance but contains no registry publication or registry-byte retrieval
  step; and
- no machine-readable Runtime current-integration manifest exists.

These are source facts, not package-registry observations or publication
approval.

## Proofbound prerequisite checkpoint

[PBF-0013](../proofbound-feedback/pbf-0013-versioned-proofbound-tool-distribution.md)
is upstreamed as Proofbound PR 10 at exact head
`1ceb40f6bf426bff55960ec14de244b25978d8c2`. That head adds deterministic
platform tool bundles, a closed manifest schema, a standalone fail-closed
installer, and exact source and mainline-Verify identities. Its complete local
12-stage Proofbound gate passed with zero assurance regressions.

The prerequisite is not resolved until PR 10 merges and the exact merged
revision produces successful `x86_64` and `aarch64` bundle candidates. Runtime
continues to compile its pinned Proofbound revision until it can pin the exact
upstream source revision, successful workflow run, archive digest, and manifest
identity. A product label does not participate in that decision.

## RT-7.2 implementation checkpoint

The first verifier-distribution slice now includes:

- the registered `PBR-DISTRIBUTION-015` claim and package-toolchain premise;
- a dependency-free, semantic-TOML package preflight with stable failure codes;
- mutations for publication, metadata, workspace, path, target-specific, Git,
  alternate-registry, and workspace-patch dependencies; source inventory;
  version; revision; archive inventory; packaged-source substitution; and byte
  reproduction;
- two isolated `cargo package` productions and exact byte comparison;
- safe archive extraction, an unrelated temporary `cargo install`, and an
  executed version check;
- a closed package manifest that records package, binary, supported receipt
  schemas, source revision, digest, and size; and
- an exact-revision release job whose retained bytes join aggregate release
  provenance.

The full preflight and Rust gates, the isolated package build, and the
`PBR-DISTRIBUTION-015` fresh evidence unit pass in the working tree. The
package check includes exact packaged-source comparison. These results are not
an exact-head hosted observation. Specification 0014 still needs independent
acceptance. A successful local package build is not registry dogfood, and the
workflow contains no publication credentials or registry write step.

## Repository work

- Proofbound Runtime owns its current public crate set, Python and npm
  packages, package-byte reproduction, and current-integration manifest.
- Proofbound owns its tool-bundle identity and distribution contract. Runtime
  consumes the result of feedback item PBF-0013 when it is available.
- Auths and Capsec own their own package and wire identities. They are peers in
  a tested platform tuple, not Runtime dependencies unless
  a selected integration profile requires them.
- Runtime-only publication does not wait for an optional Auths or Capsec
  profile. Each integration profile becomes supported only after its complete
  exact identity tuple passes the shared conformance corpus.

## Required contract

The Runtime current-integration document must distinguish:

- product source and artifact identity;
- native plan and receipt schema identities;
- SDK package identity;
- verifier package and executable identity;
- integration-profile identity; and
- tested platform integration tuples.

No package registry, adjacent checksum, tag name, or integration record
authenticates a publisher before RT-11 selects an identity policy.

## Additional falsifiers

- A platform tuple containing an unavailable package fails.
- A supported native schema paired with an untested integration profile fails.
- A package rebuilt from the selected source revision with different bytes
  fails release comparison.
- A consumer cannot silently replace one project's verifier with another
  executable identity.

## First implementation slice

The first RT-7 code pull request is limited to the independent verifier package:

1. accept Specification 0014 through independent review;
2. add a package preflight that rejects workspace-crate dependencies,
   incomplete metadata, undeclared files, and source/package inventory
   mismatch;
3. make `proofbound-runtime-verify` independently packageable without changing
   verifier semantics;
4. build it twice and compare exact package bytes;
5. retain its package identity in release artifacts; and
6. dogfood the local package from an unrelated temporary consumer before any
   registry publication is authorized.

Items 2 through 6 are implemented and locally exercised. Item 1, clean
exact-head hosted evidence, and registry evidence remain open. Registry
publication stays blocked until they close.

The slice does not publish to crates.io, change a receipt schema, modify the
launcher, or select the pure producer crate surface. Any later distribution
event is bound to an approved exact mainline source and package identity;
package labels are metadata only.

## Integration exit

RT-7 is platform-ready when all published Runtime packages identify their
native schema support, the maintained current-integration manifest names tested
cross-project combinations, and no product is forced into coordinated releases.
Support for older interfaces is intentionally deferred until a launch-readiness
decision identifies real external consumers.
