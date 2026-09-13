# Specification 0014: Public compatibility and distribution

- **Status:** draft for RT-7.1 review; no registry publication is authorized
- **Date:** 2026-09-13
- **Applies to:** Proofbound Runtime product releases, public Rust crates,
  Python packages, npm packages, machine-readable CLI results, and Runtime wire
  schemas
- **Roadmap:** RT-7

This specification defines what a Proofbound Runtime version promises and how a
public package relates to exact tagged source. It does not authenticate a
publisher. RT-11 owns publisher and signing identity.

## 1. Compatibility surfaces

The product maintains separate compatibility surfaces:

| Surface | Compatibility unit | Consumer |
| --- | --- | --- |
| Runtime product | Product semantic version and release tag | Operator |
| Execution plan | Closed schema identifier and canonical bytes | Plan producer and Runtime |
| Execution receipt | Closed schema identifier and canonical bytes | Independent verifier |
| Composed receipt | Closed schema identifier and canonical bytes | Composer and consumer |
| Acceptance policy and decision | Closed schema identifiers and canonical bytes | Policy author and acceptor |
| Machine CLI result | Closed schema identifier and typed error or outcome vocabulary | SDK and automation |
| Rust crate API | Crate name and semantic version | Rust compiler and downstream crate |
| Python SDK API | Distribution name, import name, and semantic version | Python application |
| TypeScript SDK API | npm package name, exported declarations, and semantic version | Node.js application |
| Platform integration | Explicit tested version tuple under Specification 0013 | Integrated consumer |

Compatibility on one surface does not imply compatibility on another. A valid
Runtime plan does not imply that a particular SDK API is source-compatible. A
compatible package set does not imply that an unlisted platform tuple is
supported.

## 2. Version policy

Every public package uses Semantic Versioning. Before product version 1.0, the
project still treats these changes as breaking:

- removing or renaming a public type, function, field, command, flag, machine
  code, or supported wire schema;
- changing the meaning of an existing closed value;
- accepting a broader authority for the same valid plan bytes;
- changing canonical bytes for an existing valid wire object;
- weakening verification, receipt eligibility, assumption retention, or
  acceptance behavior; and
- raising a required language or toolchain version outside the policy below.

A breaking change requires a new minor version while the affected package is
below 1.0 and a new major version after it reaches 1.0. The changelog and
compatibility matrix must name every pre-1.0 breaking change explicitly. A
patch release is never a breaking release. No released wire schema changes in
place under any package version transition.

A minor package version MAY:

- add a new public API without changing existing behavior;
- add support for a new, separately identified wire schema;
- add a new optional feature whose disabled state preserves existing behavior;
  or
- raise the minimum supported language or toolchain version as specified in
  section 5.

Before 1.0, a minor package version MAY also carry an explicitly documented
breaking API change. Prefer a new API or schema beside the old one when that
keeps the public surface small and unambiguous.

A patch package version MAY correct behavior that violates the existing
contract, strengthen rejection of input that the existing closed schema already
forbids, improve diagnostics without changing stable machine codes, or repair
packaging without changing the public API.

A security correction MAY reject behavior accepted by an earlier
implementation when that behavior contradicted the existing specification. The
release notes must identify the correction and affected versions. It must not
be described as a new breaking contract.

## 3. Wire compatibility

- Every wire object has a closed schema identifier.
- Released schema meaning and canonical bytes are immutable.
- A new field, variant, algorithm, role, outcome, or error that changes the
  accepted closed domain requires a new schema identifier.
- Producers emit only the current schema selected by their product release.
- Verifiers identify each supported historical schema explicitly.
- A verifier must not reinterpret an unknown schema as the newest known schema.
- Removal of historical receipt verification requires a breaking verifier
  release and an explicit retention-impact decision.
- An executor may stop accepting an older plan schema only through a documented
  product compatibility transition. Receipt verification and plan execution
  support are separate promises.

JSON projections are views unless their specification explicitly makes them a
wire authority. They do not replace deterministic CBOR inputs.

## 4. Public package selection

### 4.1 Initial publication order

The first candidates are:

1. `proofbound-runtime-verify`, because the independent verifier is the first
   consumer boundary and must have no workspace dependency;
2. `proofbound-runtime-sdk`, because it already has an independently packageable
   plan-construction and run-result surface;
3. the Python distribution `proofbound-runtime-sdk`;
4. the npm package `@proofbound/runtime-sdk`; and
5. selected pure producer crates only after their complete public dependency
   closure and API surface pass review.

The candidates do not become public merely because this draft names them.
Package publication requires the selection record, package preflight, release
approval, exact tag, and registry action.

The first verifier slice selects the existing
`proofbound-runtime-verify` Cargo package. That package contains both the
`pbr-verify` binary and its independent Rust library. Every exported library
item is therefore part of the public Rust compatibility surface; publication
does not treat the library as an internal implementation detail. The package
does not expose producer, launcher, composer, or acceptance code. Its Cargo
manifest admits only the `crates-io` registry. This selection constrains a
future Cargo publication target; it does not authorize publication.

### 4.2 Pure producer selection gate

Before publishing `proofbound-runtime-core`, the review must decide whether its
public contract should expose the binding and receipt crates. Every selected
path dependency must become a published dependency with an explicit compatible
version. A registry package cannot depend on an unpublished workspace path.

The selection review must prefer the smallest durable public surface. It can
publish a narrower facade instead of the internal core when that avoids making
implementation structure a permanent compatibility promise.

### 4.3 Components that are not libraries

The Linux launcher, supervisor, syscall module, host orchestration tool, log
writer, and execution service are not published as embeddable libraries. They
remain separate processes or release artifacts. No SDK duplicates boundary
installation, receipt verification, composition, or acceptance semantics.

## 5. Language and toolchain support

- Each Rust crate declares `rust-version` and its enabled feature set.
- Raising the Rust minimum supported version requires at least a minor crate
  release and a changelog entry.
- Python and Node.js minimum versions are public package metadata.
- Raising a Python or Node.js minimum requires at least a minor package release
  and a changelog entry.
- A required platform, kernel, or architecture change is a Runtime product
  compatibility decision, not only a package metadata edit.
- The release workflow uses pinned build tools. A build-tool change does not
  change the consumer minimum unless the public package metadata changes.

All first-party Runtime packages produced for one Runtime release use the same
product version until a later accepted policy permits independent package
versions. This rule does not impose lockstep versions on Proofbound, Auths, or
Capsec.

## 6. Distribution trust

GitHub Releases, crates.io, PyPI, and npm are separate distribution trust
inputs. Before RT-11:

- a digest names exact bytes;
- a tag names repository state under the current repository controls;
- a registry checksum shows registry byte consistency; and
- none of these facts authenticates a publisher by itself.

Public documentation must state this limit. After RT-11, the compatibility
policy can reference an accepted signing envelope and identity policy without
changing the native package bytes.

## 7. Release production

Public packages are produced only by the release workflow for one exact
approved commit on `main`.

The first verifier slice uses the closed
`proofbound-runtime-package-preflight/1` result and the closed
`proofbound-runtime-verifier-package-manifest/1` artifact manifest. The
manifest records the exact `.crate` identity and the two receipt schemas the
verifier accepts. Stable `package.*` failure codes reject the registered
preflight and production attacks before release retention.

The verifier preflight parses the package and workspace manifests as TOML. It
checks the semantic values instead of source-line spelling. It rejects path,
Git, alternate-registry, package-patch, workspace-patch, and replacement
sources. It also rejects a direct, aliased, workspace, or target-specific
dependency on another Runtime crate. The admitted dependency source is the
default `crates.io` registry only.

The workflow must:

1. verify the exact requested revision and release state;
2. build each package twice in clean independent directories;
3. require byte equality;
4. compare the package file inventory and retained source bytes with the exact
   tag;
5. reject undeclared generated, credential, local configuration, build output,
   or version-control files;
6. record package name, version, digest, size, source revision, and schema
   support in one closed manifest;
7. upload the packages for release review;
8. publish only after all required release and independent review gates pass;
   and
9. retrieve the registry packages and compare them with the approved package
   identities.

Publication from a developer machine or a non-release workflow is unsupported.
The workflow must not reuse a package version after a failed or partial
publication.

## 8. Yank and correction policy

- Do not delete a released version when the registry supports yanking.
- Yank only for a security defect, unusable package, legal requirement, or
  incorrect immutable metadata that prevents safe use.
- Record the reason, affected packages, affected schemas, safe replacement,
  and date in the changelog or a linked advisory.
- A yank does not erase historical receipt or artifact identity.
- A fixed release uses a new version and new package bytes.
- Never move or recreate a release tag to match a replacement package.

## 9. Compatibility matrix

Each Runtime release publishes a machine-readable compatibility record and a
human rendering. The record names:

- Runtime product and release revision;
- public package versions and identities;
- emitted and accepted plan schemas;
- emitted and verified receipt schemas;
- composed-receipt, acceptance-policy, and decision schemas;
- machine-result schema and stable error vocabulary version;
- supported Rust, Python, Node.js, Linux, and architecture profiles;
- required Proofbound tool and receipt versions; and
- accepted optional platform integration tuples.

An absent tuple is unsupported, not implicitly compatible. The record is a
distribution artifact and does not authenticate itself.

## 10. Consumer support

- Provide one minimal consumer for each published package.
- Test consumers from registry downloads, not workspace paths.
- Keep verifier and producer examples separate.
- Retain the exact dependency lock and compatibility record used by each
  consumer test.
- An unrelated repository must dogfood each package before RT-7 closes.

Download count is not compatibility evidence. A passing consumer test is one
bounded observation for the tested version tuple.

## 11. Required falsifiers

- Add a workspace-only dependency to a public crate.
- Change canonical bytes without changing the wire schema.
- Change a public API without the required version transition.
- Raise a language minimum in a patch release.
- Build package bytes whose inventory differs from the exact tag.
- Attempt publication from a non-release context.
- Publish one package from an incomplete first-party version set.
- Substitute registry bytes after release approval.
- Select an unlisted platform compatibility tuple.
- Replace the independent verifier with an unrecorded version.
- Yank a package without a recorded reason and replacement.

Each case fails with a stable release or compatibility reason before any
consumer describes the combination as supported.

## 12. Acceptance and completion

This draft requires independent review before acceptance. Acceptance must
confirm:

- the selected public package surface is smaller than the child security path;
- verifier independence remains intact;
- historical wire meaning cannot change in place;
- the release workflow, tag, package, and registry identities are distinct;
- no checksum is presented as publisher authentication; and
- Proofbound, Auths, and Capsec remain independently versioned products.

RT-7 is complete only when the selected packages are available from their
registries, registry bytes match the approved exact-tag packages, unrelated
consumers pass, and the published compatibility policy and matrix describe the
result.
