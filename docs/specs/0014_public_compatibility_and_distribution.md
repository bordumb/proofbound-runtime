# Specification 0014: Prelaunch packaging and distribution

- **Status:** draft for RT-7.1 review; no registry publication is authorized
- **Date:** 2026-09-14
- **Applies to:** Proofbound Runtime product releases, public Rust crates,
  Python packages, npm packages, machine-readable CLI results, and Runtime wire
  schemas
- **Roadmap:** RT-7

This specification defines how a current Proofbound Runtime package relates to
exact source. The product is prelaunch and has no external users. It makes no
backward-compatibility promise. It does not authenticate a publisher. RT-11
owns publisher and signing identity.

## 1. Current contract surfaces

The product identifies these separate current surfaces:

| Surface | Exact unit | Consumer |
| --- | --- | --- |
| Runtime product | Product label, source revision, and release tag | Operator |
| Execution plan | Closed schema identifier and canonical bytes | Plan producer and Runtime |
| Execution receipt | Closed schema identifier and canonical bytes | Independent verifier |
| Composed receipt | Closed schema identifier and canonical bytes | Composer and consumer |
| Acceptance policy and decision | Closed schema identifiers and canonical bytes | Policy author and acceptor |
| Machine CLI result | Closed schema identifier and typed error or outcome vocabulary | SDK and automation |
| Rust crate API | Crate name, source revision, and package digest | Rust compiler and downstream crate |
| Python SDK API | Distribution name, source revision, and package digest | Python application |
| TypeScript SDK API | npm package name, source revision, and package digest | Node.js application |
| Platform integration | Explicit tested identity tuple under Specification 0013 | Integrated consumer |

Identity on one surface does not imply support on another. A valid Runtime plan
does not imply that a particular SDK package belongs to the current tested
tuple. An available package set does not imply that an unlisted platform tuple
is supported.

## 2. Prelaunch change policy

The repository uses its existing version fields because package registries and
build tools require them. Before launch, those fields do not promise semantic
versioning or support for older interfaces. The exact source revision, schema
identifier, package digest, and tested integration tuple are authoritative.

The project may replace an API, command, machine code, toolchain minimum, wire
schema, or canonical encoding between prelaunch candidates. Each replacement
must still:

- use a new schema identifier when old bytes could otherwise acquire new
  security meaning;
- update every producer, independent verifier, composer, policy consumer, SDK,
  fixture, and conformance vector in one explicit migration;
- invalidate stale evidence and tested integration tuples;
- preserve the exact historical identity of any retained artifact; and
- run the complete current-contract and adversarial corpus before publication.

The project supports only the current published candidate unless one document
explicitly lists another tuple. Support promises, transition periods, and
long-term support start only after a launch-readiness decision records that
external consumers exist.

## 3. Wire identity

- Every wire object has a closed schema identifier.
- One schema identifier never acquires a different security meaning.
- A new field, variant, algorithm, role, outcome, or error that changes the
  accepted closed domain requires a new schema identifier.
- Producers emit only the current schema selected by their product release.
- Verifiers identify each currently supported schema explicitly.
- A verifier must not reinterpret an unknown schema as the newest known schema.
- A prelaunch migration may remove an older schema immediately. The migration
  must update the complete current tuple and must not
  reinterpret old bytes.
- Receipt verification and plan execution support remain separate current
  capabilities.

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
item is therefore part of the current public Rust surface; publication does
not treat the library as an internal implementation detail. The package
does not expose producer, launcher, composer, or acceptance code. Its Cargo
manifest admits only the `crates-io` registry. This selection constrains a
future Cargo publication target; it does not authorize publication.

### 4.2 Pure producer selection gate

Before publishing `proofbound-runtime-core`, the review must decide whether its
public contract should expose the binding and receipt crates. Every selected
path dependency must become a published dependency in the exact current
package set. A registry package cannot depend on an unpublished workspace path.

The selection review must prefer the smallest durable public surface. It can
publish a narrower facade instead of the internal core when that avoids making
implementation structure an unnecessary public dependency.

### 4.3 Components that are not libraries

The Linux launcher, supervisor, syscall module, host orchestration tool, log
writer, and execution service are not published as embeddable libraries. They
remain separate processes or release artifacts. No SDK duplicates boundary
installation, receipt verification, composition, or acceptance semantics.

## 5. Language and toolchain support

- Each Rust crate declares `rust-version` and its enabled feature set.
- Python and Node.js minimum versions are explicit package metadata.
- A prelaunch candidate may change a minimum immediately. The
  current package metadata, tested tuple, and setup diagnostics change together.
- The release workflow uses pinned build tools. Build-tool and consumer-tool
  identities remain separate.

All first-party Runtime packages produced for one Runtime release use the same
product label. Exact source and package digests remain authoritative. Runtime,
Proofbound, Auths, and Capsec do not coordinate release numbers.

## 6. Distribution trust

GitHub Releases, crates.io, PyPI, and npm are separate distribution trust
inputs. Before RT-11:

- a digest names exact bytes;
- a tag names repository state under the current repository controls;
- a registry checksum shows registry byte consistency; and
- none of these facts authenticates a publisher by itself.

Public documentation must state this limit. After RT-11, the distribution
contract can reference an accepted signing envelope and identity policy without
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

## 9. Current integration manifest

Each Runtime release publishes a machine-readable current-integration record
and a human rendering. The record names:

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
- Retain the exact dependency lock and current-integration record used by each
  consumer test.
- An unrelated repository must dogfood each package before RT-7 closes.

Download count is not integration evidence. A passing consumer test is one
bounded observation for the tested identity tuple.

## 11. Required falsifiers

- Add a workspace-only dependency to a public crate.
- Change canonical bytes without changing the wire schema.
- Change a public API without updating the exact current package tuple.
- Raise a language minimum without updating package metadata and host checks.
- Build package bytes whose inventory differs from the exact tag.
- Attempt publication from a non-release context.
- Publish one package from an incomplete first-party version set.
- Substitute registry bytes after release approval.
- Select an unlisted platform integration tuple.
- Replace the independent verifier with an unrecorded version.
- Yank a package without a recorded reason and replacement.

Each case fails with a stable release or integration reason before any
consumer describes the combination as supported.

## 12. Acceptance and completion

This draft requires independent review before acceptance. Acceptance must
confirm:

- the selected public package surface is smaller than the child security path;
- verifier independence remains intact;
- one schema identity cannot acquire different security meaning;
- the release workflow, tag, package, and registry identities are distinct;
- no checksum is presented as publisher authentication; and
- Proofbound, Auths, and Capsec remain independently identified products.

RT-7 is complete only when the selected packages are available from their
registries, registry bytes match the approved exact-tag packages, unrelated
consumers pass, and the published current-integration manifest describes the
result. Support for older interfaces is not an RT-7 exit condition before
launch.
