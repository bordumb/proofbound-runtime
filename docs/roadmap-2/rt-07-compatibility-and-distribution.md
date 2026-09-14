# RT-7 integration record: prelaunch packaging and distribution

**Status:** RT-7.2 verifier package merged and admitted; the first public
immutable Proofbound exact-source bundle is published; Runtime bundle dogfood
is in progress; registry publication and the current-integration record remain
open

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
was independently approved at Proofbound PR 10 head
`693976fea7e169fc84a3919113fd0a1e6a132544` and merged as
`dd481a381913f7df1e7d89c261a0098a3f747995`. That source adds deterministic
platform tool bundles, a closed manifest schema, a standalone fail-closed
installer, and exact source and mainline-Verify identities. Exact-main Verify
run `34887427661` passed.

Proofbound PR 12 then added the public immutable delivery boundary. Its exact
reviewed subject is `6072127`, its approval-only envelope is `5f190e0`, and its
unsigned merge is `9512469`. Exact-main Verify run `34899222179` passed.
Tool-bundle run `34900896450` reproduced and dogfooded both Linux bundles,
published release `388736918`, and anonymously re-downloaded and checked its
closed seven-asset inventory. The release tag identifies the full source
commit as `proofbound-tools-95124692b6b9383a265c8024f21bb964737f8b6b` and
the release reports `immutable=true`.

Runtime's canonical pin records the exact release, source, verification,
workflow, asset digest, and byte-size identities in
`proofbound/toolchains/proofbound-tool-bundle-pin.json`. The first consumer
wave installs those public bytes only in an isolated required dogfood job. It
does not give the new path authority over evidence. Replacing the existing
source-build path follows only after this wave passes independent review and
exact-main hosted verification. The product label does not participate in
selection.

## RT-7.2 implementation checkpoint

The first verifier-distribution slice now includes:

- the registered `PBR-DISTRIBUTION-015` claim and package-toolchain premise;
- a dependency-free, semantic-TOML package preflight that admits one exact
  package, target, dependency, and metadata surface with stable failure codes;
- mutations for publication, metadata, workspace, path, target-specific, Git,
  alternate-registry, and workspace-patch dependencies; source inventory;
  product label; revision; archive inventory; packaged-source, original
  manifest, and VCS-identity substitution; and byte reproduction;
- two isolated `cargo package` productions and exact byte comparison;
- safe archive extraction, an unrelated temporary `cargo install`, and an
  executed version check;
- a closed deterministic-CBOR package manifest that records package, binary,
  supported receipt schemas, source revision, digest, and size, with JSON only
  as a diagnostic projection; and
- an exact-revision release job whose retained bytes join aggregate release
  provenance, with that join included in the registered evidence checker.

The slice passed independent exact-head review and its hosted gate, then merged
as unsigned Runtime main commit `7f989d3`. Exact-main Verify run `34896209689`
passed all lanes. Specification 0014 was included in that exact review. A
successful local or hosted package build is not registry dogfood, and the
workflow contains no registry publication credential or write step.

## Public Proofbound bundle dogfood checkpoint

The next claim-sized Runtime wave adds:

- a canonical Runtime-owned pin with one exact public immutable release and
  seven exact asset identities;
- closed validation of source, workflow, release, tag, target commit,
  immutability, inventory, roles, digests, and byte sizes;
- independent parsing of the publication and selected platform manifests;
- verification of the checksum set, archive, installer, and every installed
  executable before a tool is used;
- mutation cases for noncanonical pins, mutable releases, identity and
  inventory substitution, every selected downloaded asset, and installed
  executable substitution; and
- an isolated required Linux CI job that installs and executes the public
  bundle while the admitted source-build evidence path stays unchanged.

This staged parity wave is not a compatibility period. It limits the
supply-chain blast radius before a separate reviewed cutover removes the Git
source build from protected CI and release production.

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

Items 1 through 6 passed exact-head review, hosted evidence, merge, and
exact-main verification. Registry evidence remains open. Registry publication
stays blocked until its explicit later gate closes.

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
