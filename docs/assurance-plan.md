# Assurance plan

This document records the completed evidence path for each current load-bearing
claim. Claim manifests remain the source of truth for admitted
status, assumptions, exclusions, and exact evidence identities.

## Assurance summary

| Claim | Last admitted result or current candidate | Meaning |
| --- | --- | --- |
| `PBR-AUTH-001` | Tier 3, source-refined with contextual artifact binding | The theorem-derived closed set binds the refined normalization claim to the exact native `pbr` member in each reviewed release context. |
| `PBR-POLICY-002` | Tier 3, source-refined with contextual artifact binding | The pure policy compiler is source-refined and its theorem-derived closed set selects the exact native `pbr` members. |
| `PBR-SEQUENCE-003` | Tested/model-only with exact native artifact observation | Launcher sequencing is effectful Linux behavior. Exact execution observations do not prove kernel effects generally. |
| `PBR-RECEIPT-004` | Tier 3, source-refined with contextual artifact binding | The receipt decision is source-refined and its theorem-derived closed set selects the exact native `pbr` members. |
| `PBR-BINDING-005` | Tier 3 current lifecycle closure admitted on exact Runtime main `1da65a5` | The production constructor and wire projection remain source-refined. PR 31 run `35236845497` and exact-main run `35241672716` admitted the changed shared-core closure without changing receipt behavior. |
| `PBR-VERIFY-006` | Tested/model-only with exact native artifact observation | The evidence remains bounded to the registered mutations and exact rejection reasons exercised by each native `pbr-verify`. |
| `PBR-RUN-007` | Current tested/model-only closure admitted on exact Runtime main `da52925` | PR 34 run `35276015624` and exact-main run `35280257983` replayed the complete closure without turning native observation into a theorem. |
| `PBR-COMPOSE-008` | Tested/model-only with exact native artifact observation | Each exact native composer joins verified receipts without upgrading any inherited facet. |
| `PBR-PREFLIGHT-009` | Current tested/model-only closure admitted on exact Runtime main `da52925` | The current point-in-time preflight closure passed PR 34 and its exact-main replay; exact released-artifact observation remains open. |
| `PBR-RESOURCE-010` | Current tested/model-only closure admitted on exact Runtime main `da52925` | The current memory and swap closure passed PR 34 and its exact-main replay without claiming theorem-derived kernel or artifact soundness. |
| `PBR-DIAGNOSTIC-011` | Current tested/model-only closure admitted on exact Runtime main `da52925` | The closed run phase and rule mapping remains tested without inferring a kernel denial or changing receipt meaning. |
| `PBR-ACCEPT-012` | Current tested/model-only closure admitted on exact Runtime main `da52925` | Adopter policy decisions bind independently verified inputs; exact released acceptor observation and external Action dogfood remain open. |
| `PBR-SCAFFOLD-013` | Current tested/model-only closure admitted on exact Runtime main `da52925` | Static ELF scaffolding remains bounded diagnostic evidence, not a safe policy or a complete dynamic-load inventory. |
| `PBR-SDK-014` | Current source closure admitted on exact Runtime main `da52925` | The current SDK and Specification 0016 closure passed PR 34 and its exact-main replay. Registry publication and consumer dogfood remain open. |
| `PBR-DISTRIBUTION-015` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current deterministic-CBOR helper closure passed PR 34 and its exact-main replay; registry publication remains external. |
| `PBR-DISTRIBUTION-016` | Tier 1 credential-scoped consumer admitted on exact Runtime main `a8df83d` | Runtime pins one immutable public Proofbound release, confines its read-only workflow credential to canonical GitHub API metadata, keeps release assets anonymous, and rejects identity, inventory, manifest, checksum, archive, installer, and installed-byte substitution. Exact-head PR 23 run `35034962830` and exact-main run `35038304369` passed. |
| `PBR-DISTRIBUTION-018` | Tier 1 current protected-route closure admitted on exact Runtime main `da52925` | The current source retains explicit, protected, ordered, credential-isolated publication. External registry configuration, publication, and observations remain open. |
| `PBR-DISTRIBUTION-025` | Tier 1 current integration source admitted on exact Runtime main `da52925` | PR 34 and its exact-main replay admitted the current SDK and integration closure. The tuple remains unpublished until an exact protected publication retains it. |
| `PBR-DRAFT-017` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | Closed diagnostic vocabulary and non-reuse remain intact. |
| `PBR-DRAFT-019` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | The admitted producer preserves non-reuse and mandatory human authority choices. |
| `PBR-OBSERVER-020` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | PR 34 and its exact-main replay admitted the current shared-core closure. |
| `PBR-OBSERVER-021` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current shared trace closure passed PR 34 and its exact-main replay. |
| `PBR-OBSERVER-022` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current adapter closure passed PR 34 and its exact-main replay. |
| `PBR-OBSERVER-023` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current entry-time operand closure passed PR 34 and its exact-main replay. |
| `PBR-OBSERVER-024` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current shared trace, adapter, and observer closure passed PR 34 and its exact-main replay. |
| `PBR-OBSERVER-025` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current syscall-decoder closure passed PR 34 and its exact-main replay; kernel ABI truth and memory stability remain open. |
| `PBR-OBSERVER-026` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | Event mapping remains closed. |
| `PBR-OBSERVER-027` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | Bounded stream handling remains intact. |
| `PBR-OBSERVER-028` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | Diagnostic lifecycle gating remains intact. |
| `PBR-OBSERVER-029` | Tier 1 current contract closure admitted on exact Runtime main `da52925` | The current object-resolution closure passed PR 34 and its exact-main replay; Linux pathname completeness remains open. |
| `PBR-OBSERVER-030` | Tier 1 candidate-resolution source admitted on exact Runtime main `d60d1f3` | Failed path operations produce only advisory stable candidates after two bounded root-confined observations agree; drift and hop exhaustion remain explicit gaps. Independently approved PR 26 head `2fc82ff` passed run `35172227506`, including both native architectures. Exact-main run `35175269953` passed. Linux pathname completeness remains pending. |
| `PBR-OBSERVER-031` | Tier 1 current lifecycle closure admitted on exact Runtime main `da52925` | PR 34 and its exact-main replay admitted the current shared-core closure without reopening RT-8 product behavior. |
| `PBR-NETWORK-032` | Tier 0 current contract closure admitted on exact Runtime main `da52925` | PR 34 and its exact-main replay admitted the current service-session contract closure. |
| `PBR-NETWORK-033` | Tier 0 current policy closure admitted on exact Runtime main `da52925` | The compiler closure separately binds child denial, the channel-only profile, and complete connector authority. |
| `PBR-NETWORK-034` | Tier 0 current pure lifecycle admitted on exact Runtime main `da52925` | Source tests cover the closed forward path and typed terminal failure. The Lean theorem remains an unregistered candidate. Every effectful child wave remains open. |
| `PBR-NETWORK-035` | Tier 1 current observation contract admitted on exact Runtime main `da52925` | PR 34 exact-head run `35276015624` and exact-main run `35280257983` admitted the exact CNAME and effective-expiry observation closure. |
| `PBR-NETWORK-036` | Tier 1 current launcher contract admitted on exact Runtime main `da52925` | PR 34 and its exact-main replay admitted the complete current launcher source contract. Production launcher behavior remains disabled. |
| `PBR-NETWORK-037` | Tier 1 current receipt contract admitted on exact Runtime main `da52925` | PR 34 and its exact-main replay admitted the current success and failure source contract. Production receipt integration remains open. |
| `PBR-NETWORK-038` | Tier 1 connector engine admitted on exact Runtime main `da52925` | Independently approved source `b9ad56a` plus approval envelope `2d6cf97` passed exact-head run `35276015624`; exact-main run `35280257983` admitted the isolated engine. Process supervision, launcher binding, native evidence, receipts, and release artifacts remain open. |
| `PBR-NETWORK-039` | Tier 1 supervised connector-process candidate pending first exact admission | The candidate identifies declared artifacts, creates private channels, starts one exact retained connector, validates complete readiness binding, and bounds terminal reaping. Connector confinement, child release, credentials, native evidence, receipts, and release artifacts remain open. |

### Current changed subjects pending exact admission

The connector-process candidate changes the Linux crate manifest, public module
surface, raw channel wrapper, and new process executable. `PBR-NETWORK-039` and
every existing claim whose registered closure intersects those exact files are
pending until an independent exact-head approval, complete hosted verification,
merge, and exact-main replay. No status from `da52925` transfers to this
candidate.

The RT-5 contract wave passed exact-head run `35216056050`, merged as exact
Runtime main `d48122b06c4880aeba45291a107c51ad381067a4`, and passed exact-main
run `35220098639`. That exact subject admits every claim previously listed as
changed by the contract wave, including the first Tier 0 admission of
`PBR-NETWORK-032`.

The pure-policy wave passed exact-head run `35226379485` and merged as exact
Runtime main `a94c21a9d1b399f9eff8771e06ce253fe9a6c4ca`. Exact-main run
`35231003515` passed. That exact subject admits `PBR-NETWORK-033` and the
intersecting pure-policy closure without transferring status to later source.

The lifecycle wave passed PR 31 run `35236845497`, merged as exact main
`1da65a5c53f27b97a15f95ed1a9fb01170121444`, and passed exact-main run
`35241672716`. That exact source admits the intersecting existing claims and
the new Tier 0 `PBR-NETWORK-034` subject. The Lean theorem remains a compiled
candidate, not registered theorem evidence.

The non-production receipt integration passed PR 33 exact-head run
`35262967214` at `c361cb1`, merged as exact main `8513ca7`, and passed
exact-main run `35267321804`. That exact receipt-contract source is admitted.
The later isolated connector-engine wave was independently approved through
source head `b9ad56a`; approval-only commit `2d6cf97` passed PR 34 exact-head
run `35276015624`, merged as exact main `da52925`, and passed exact-main run
`35280257983`. That exact source admits `PBR-NETWORK-038` and every replayed
intersecting closure. It still does not implement the supervised connector,
production producer, separate Rust verifier, composition, acceptance, native
attacks, or release-artifact linkage. The new `PBR-NETWORK-039` candidate is a
later exact source and starts with no inherited admission.

This pending ledger does not weaken or retract an admission for an older exact
source. It prevents a source-identity change from silently inheriting that
admission.

The contextual theorem bindings do not change the four Tier 3 claims' selected
`REFINED` primary linkage or remove their toolchain assumptions. Exact artifact
observations do not promote the four test-based claims to `ARTIFACT_BOUND`.

## PBR-DISTRIBUTION-015

The production subject is the independently installable
`proofbound-runtime-verify` package. Its intended closure contains:

- one exact public package, target, dependency, metadata, and source surface;
- no path, Git, alternate-registry, workspace-patch, or Runtime workspace
  dependency;
- a stable preflight failure vocabulary for metadata, dependency, inventory,
  dependency source, version, revision, archive inventory, archive payload,
  reproduction, and consumer failures;
- two isolated package builds compared by exact bytes;
- safe extraction and installation into an unrelated temporary consumer;
- exact comparison of retained source bytes, the original Cargo manifest, and
  Cargo VCS identity;
- one retained deterministic-CBOR package manifest with exact source revision,
  artifact identity, binary name, and supported receipt schemas;
- independent validation of the closed manifest, canonical carrier, selected
  identities, and retained archive digest and size; and
- checked inclusion of the verifier namespace in aggregate release provenance.

The evidence path is:

1. mutate explicit publication, manifest surfaces, dependencies, source files,
   product label, selected revision, archive members, retained Cargo metadata,
   and reproduction bytes;
2. inspect the exact archive member inventory and compare retained package
   source bytes with the registered repository source;
3. compare two independently produced `.crate` byte strings;
4. install the extracted package outside the workspace and execute
   `pbr-verify --version`;
5. decode and independently validate the canonical package manifest against
   the selected source, package label, CDDL, and retained archive; and
6. retain the package manifest and checksum in the exact-revision release
   workflow and aggregate release provenance.

This claim does not establish verifier semantics. `PBR-VERIFY-006` owns that
behavior. It does not authenticate a publisher or assert registry-byte
identity. The exact reviewed package source merged as Runtime commit `7f989d3`,
and exact-main Verify run `34896209689` passed. Registry publication remains
blocked.

## PBR-DISTRIBUTION-016

The production subject is Runtime's consumer for one exact public immutable
Proofbound tool bundle. Its intended closure contains:

- one canonical Runtime-owned pin for the exact upstream source, successful
  verification run, producing bundle run, release ID, tag, and seven assets;
- a closed pin parser that rejects duplicate keys, unknown fields,
  noncanonical bytes, invalid roles, and non-exact inventories;
- workflow-credential-scoped re-reading of the hosted release ID, tag, target commit,
  publication state, immutability state, and asset identities, plus independent
  resolution of the tag object to the pinned source commit, with anonymous
  release-asset downloads;
- exact checks of the checksum set, publication manifest, selected platform
  manifest, archive, and installer before installer execution, including
  byte-for-byte equality of the detached and embedded platform manifests;
- an independent comparison between the selected detached manifest and every
  installed executable's name, size, digest, type, and executable mode; and
- one admitted isolated required Linux CI job that dogfoods the public bytes;
  and
- a separate cutover configuration that makes each protected evidence shard
  and release architecture independently install the same verified public
  bytes before Proofbound runs.

The evidence path mutates the pin form, release state, source and tag identity,
asset inventory, manifest carrier, metadata, payload, platform, and modes,
checksum order and contents, each selected downloaded byte string, and one
installed executable. The
upstream public release is Proofbound release `388736918`, source `9512469`,
Verify run `34899222179`, and bundle run `34900896450`.

The isolated dogfood wave passed exact-head review and merged as Runtime
commit `f2a06de`. Exact-main Verify run `34908515545` passed. The protected
cutover passed independent review and exact-head Verify run `34915891330`,
then merged unsigned as `4a0cfdb`. Exact-main Verify run `34918706960` passed.
That admission remains historical and applies only to the anonymous metadata
consumer at that exact identity. The credential-scoping correction changed the
claim and `PBR-BUNDLE-DISTRIBUTION-AX-012`, passed independent review and PR 23
Verify run `35034962830`, and merged unsigned as `a8df83d`. Exact-main run
`35038304369` passed. That exact evidence admits the credential-scoped subject
at `a8df83d`; it does not transfer the historical `4a0cfdb` admission to any
other source identity.
This does not prove Proofbound correctness or independently
authenticate GitHub or a publisher. `PBR-BUNDLE-DISTRIBUTION-AX-012` retains
the GitHub, repository control, DNS, and TLS premises.
`PBR-BUNDLE-TOOLCHAIN-AX-013` retains the Python, digest, installer, runner,
process, and filesystem premises.

## PBR-DISTRIBUTION-018

The subject is the opt-in selected-package route in the exact-source release
workflow and its registry-credential-free observer. Its current closure
contains:

- a default-off Boolean publication input;
- one exact mainline revision admitted by the complete release-provenance job;
- a protected `package-publish` environment on every publisher;
- ordered verifier, Rust SDK, Python SDK, and TypeScript SDK publishers;
- a crates.io token exposed only to each Rust publisher step;
- a PyPI pending trusted publisher;
- an independently selected, default-off npm first-publication input that is
  selected only after an immediate anonymous `404` observation;
- a one-time npm bootstrap token exposed only to that initial publish step;
- an exact selected npm script inventory with no publish lifecycle hook and
  `--ignore-scripts` on both publication routes;
- a normal npm OIDC route that requires the package endpoint to return exactly
  `200` immediately before publication and has no bootstrap-token reference;
- exact reproduction of each Rust upload input against its approved retained
  artifact; and
- anonymous retrieval and exact byte comparison of all four registry
  artifacts before one canonical observation record is retained.

The bounded evidence mutates the approved source revision, package manifests,
downloaded bytes, metadata hosts, package inventory, and workflow gates. It
does not publish a package or test external configuration. Registry ownership,
protected-environment rules, the scoped crates.io token, the PyPI pending
publisher, npm scope control, the bootstrap token and its revocation, and the
post-bootstrap npm OIDC record remain explicit external obligations. Partial
publication can occur because the registries do not provide one atomic
transaction; the current-integration manifest must remain absent until the
complete selected set passes anonymous observation. The npm status probe does
not prove package absence, reveal a private package, or lock registry state.

## PBR-DISTRIBUTION-025

The subject is the current-integration producer, independently owned verifier,
and their placement after the anonymous registry observer in the exact-source
release workflow. Its current closure contains:

- one deterministic-CBOR record with a closed CDDL and no unknown-member or
  noncanonical fallback;
- exact identity of one Runtime source revision, both supported Linux release
  bundles, both separate acceptor artifacts, and all eight embedded executable
  identities;
- all four registry package observations for that same source revision;
- separate emitted and accepted schema profiles for plans, receipts,
  composition, acceptance, and machine results;
- source-checked Rust, Python, and Node.js minimums and closed SDK error-code
  inventories;
- both explicit Linux target profiles;
- the complete exact Proofbound source, public tool-bundle, and composed-release
  schema identities; and
- an empty optional-integration inventory that implies no Auths, Capsec, guest,
  service, or other support.

The independent verifier shares no decoder or semantic table with the producer.
It re-derives the complete expected record from the registry observation,
Runtime artifact files, and canonical Proofbound pin before it emits the JSON
and Markdown views. The bounded evidence substitutes artifacts and record
members and an embedded verifier, removes a registry observation, injects an
unknown member, supplies a noncanonical carrier, compares every SDK error
vocabulary with source, and checks workflow ordering.

This source wave does not publish a package or current tuple. External registry
configuration and behavior, package and SDK tools, Proofbound distribution,
Python, hashing, filesystems, and hosted workflow behavior remain explicit
premises. RT-7 still requires one successful protected publication and
anonymous observation plus unrelated consumer dogfood.

## PBR-POLICY-002

The production subject is the pure policy compiler. Its intended source closure
is:

- closed normalized-authority and platform-capability inputs;
- platform-neutral policy types;
- deterministic Landlock, seccomp, and cgroup policy compilation; and
- no filesystem, process, clock, environment, or syscall effects.

The evidence path is:

1. negative cases for omitted, substituted, and amplified authority;
2. positive and boundary conformance vectors;
3. a finite Kani catalog over every supported policy state;
4. a Lean subset theorem for the closed supported policy model;
5. Charon/Aeneas translation of the smallest production function;
6. a byte-pinned handwritten refinement bridge; and
7. exact release-artifact binding.

The claim retains `PBR-LINUX-AX-001` because the theorem models policy meaning;
it does not prove that the kernel implements the model.

## PBR-SEQUENCE-003

The production subject is the launcher and supervisor protocol that gates
`execve`. Its intended source closure is:

- fresh cgroup creation and membership checks;
- the private typed launcher protocol;
- privilege removal and `no_new_privs` installation;
- Landlock and seccomp installation;
- boundary acknowledgement and supervisor exec release bound to the
  compiled-policy identity; and
- the final `execve` handoff.

The evidence path is:

1. protocol-state tests that reject every invalid transition;
2. acknowledgement and exec-release omission, truncation, forgery, and
   substitution attacks;
3. native Linux tests that observe each required boundary before child code;
4. denial tests for undeclared filesystem, network, environment, descriptor,
   and process authority;
5. unsupported-host tests that produce no positive enforcement evidence; and
6. exact native release-artifact observation of the launcher bundle role.

This claim must not be presented as a pure refinement theorem. It keeps the
Linux and host assumptions visible. The typed protocol transition test is
registered as Proofbound example evidence. The production-path native corpus
is additionally required on both `x86_64` and `aarch64` Linux CI hosts; it is
bounded platform evidence and does not discharge the kernel, host, or toolchain
premises.

## PBR-BINDING-005

The production subject is pure execution-receipt construction from validated
inputs and observations. Its intended source closure is:

- the closed version 1 receipt domain;
- typed artifact and trusted-computing-base roles;
- deterministic canonical receipt construction; and
- completeness validation before reuse eligibility is derived.

The evidence path is:

1. one omission and one substitution mutation for every required role;
2. replay, downgrade, truncation, duplicate-key, and premise-loss attacks;
3. finite checks over role-presence and outcome combinations;
4. a Lean theorem that reusable construction contains every required role;
5. source refinement for the pure constructor; and
6. exact release-artifact binding.

Digest equality establishes identity only. It does not establish artifact
behavior.

## PBR-VERIFY-006

The production subject is the standalone `pbr-verify` implementation. Its
intended source closure is independent from all other workspace crates and
contains:

- strict receipt decoding;
- canonical-byte validation;
- validation of an independently supplied exact-byte commitment;
- identity and artifact-role validation;
- independent reuse-eligibility derivation;
- typed errors and stable exit behavior; and
- the verifier executable entry point.

The evidence path is:

1. shared normative positive and negative vectors;
2. the complete registered receipt attack corpus;
3. exact typed rejection reasons from the independent implementation;
4. producer/verifier differential conformance; and
5. exact native release-artifact observation of the `pbr-verify` bundle role.

The claim stays bounded to registered attacks and retains
`PBR-COMMITMENT-AX-007`. Acceptance of a finite corpus is not proof that an
unrepresented receipt property is correct or that a carrier-independent
commitment was supplied correctly.

## PBR-RUN-007

The production subject is the `pbr run` orchestrator. Its source closure joins
the independently assessed pure core to the effectful Linux boundary without
moving either component's decisions into the CLI.

The evidence path is:

1. closed CLI grammar tests that forbid command overrides;
2. negative orchestration cases for capability, path, environment, identity,
   output-root, outcome, and receipt-carrier substitution;
3. one native end-to-end execution on each supported architecture;
4. independent verification of the emitted canonical receipt bytes; and
5. exact native release-artifact observation of the runtime, launcher, and
   verifier bundle roles.

This claim remains effectful and assumption-bearing. Pure core proofs do not
prove that the CLI selected the corresponding observations or that Linux
installed the boundary.

## PBR-COMPOSE-008

The production subject is the pure typed composition boundary, with the
`pbr-compose` executable responsible only for closed input acquisition,
independent verifier execution, and no-replace publication. Its source closure
contains:

- strict decoders for the Proofbound release, Runtime bundle, execution
  receipt, and both verifier reports;
- exact artifact identity and bundle-role validation;
- equality between verified and compiled claim-status inventories;
- union-with-origin for assumptions and trusted-computing-base entries;
- a domain-separated composition identity over canonical bytes; and
- an independent complete-byte recomputation path for mutation tests.

The evidence path is:

1. the frozen omission, substitution, downgrade, replay, and premise-loss
   attack catalog;
2. closed CLI grammar, verifier-failure propagation, and no-replace output
   tests;
3. one native release-workflow observation on each supported architecture;
4. retention of every inherited claim facet, assumption, and trusted component;
5. exact native release-artifact observation of the composer plus retention of
   both verified inputs' exact identities.

Composition does not increase any inherited claim's formal or linkage facet.
It retains `PBR-COMMITMENT-AX-007`: placing a receipt and its expected
commitment into the same replaceable carrier is still not authentication.

## PBR-PREFLIGHT-009

The production subject is the read-only `pbr preflight` orchestration path. It
reuses the strict plan parser, pure normalizer and policy compiler, Linux host
probe, confined resolver, ELF interpreter discovery, and artifact identity
implementation used by `pbr run`. It stops before execution identifiers,
output-root creation, cgroup creation, launcher startup, or boundary
installation.

The current bounded evidence path is:

1. closed command grammar and typed failure-report tests;
2. a frozen attack inventory for invalid plans, unsupported hosts, occupied
   targets, path escape, symlink, executable, interpreter, and identity drift;
3. unit tests for the exact identity projection and the read-only output-target
   inspection primitive; and
4. a required native workflow step that checks point-in-time identities and
   snapshots the cgroup and absent targets on both supported architectures.

The claim remains `TESTED` and `MODEL_ONLY`. Until a release head executes the
native workflow and binds the resulting exact `pbr` members, the command is a
development capability rather than a released artifact claim. A successful
report is never evidence that a later run will observe the same identities or
install a boundary.

## PBR-DIAGNOSTIC-011

The production subject is the typed `pbr run` error boundary and its stderr
renderer. Each call site assigns one closed execution phase and one closed
failed-invariant rule while retaining the low-level machine code and existing
exit class.

The current bounded evidence path is:

1. a frozen catalog for capability, resolution, identity drift, output-root,
   launcher-protocol, cgroup, receipt, and result-projection failures;
2. typed phase and rule enums with unique bounded identifiers;
3. direct tests that the producer mappings match the frozen catalog; and
4. an exact one-line renderer test that contains no dynamic failure context.

The claim remains `TESTED` and `MODEL_ONLY`. It does not infer a denial from a
child exit code, child stderr, host logs, or kernel audit text. Specification
0009 and an exact release artifact remain open review and publication
obligations.

## PBR-DRAFT-017

The current subject is the closed diagnostic vocabulary and the production
consumer non-reuse boundary. It fixes exactly two execution profiles, one
observer mechanism, five provenance classes, four resolution classes, and two
completion states. Separate closed JSON schemas describe a diagnostic receipt
and a non-policy draft.

The bounded evidence path checks that:

1. the independent schema contract validates canonical vectors against closed
   nested objects, typed path, process, and socket operands, drift identities,
   event result states, completion and gap consistency, exact Capsec input
   identities, the three comparison classes, retained draft context, and each
   mandatory human choice;
2. unknown profile, mechanism, provenance, resolution, and completion values
   fail closed;
3. the independent verifier recognizes a canonical diagnostic receipt only to
   reject it with `profile.diagnostic.not-reusable` before commitment or
   production receipt decoding;
4. an isolated composer adapter test maps the same verifier reason to its
   closed command error;
5. an isolated acceptance adapter test maps that verifier result to the closed
   `diagnostic-profile-not-reusable` reason; and
6. the production CLI and native launcher manifests contain no diagnostic
   observer dependency.

This claim does not say that `pbr-diagnose` exists or that the composer and
acceptance tests exercise their complete command and publication paths. The
pure artifact producer and Capsec identity comparison are registered under
`PBR-DRAFT-019`. The end-to-end command falsifiers, ptrace observer, native
attack corpus, and exact released-artifact binding remain explicit
obligations.

## PBR-DRAFT-019

The production subject is the pure aggregate constructor that turns already
validated, bounded diagnostic observations into the two distinct RT-8
artifacts. Both objects stream through one fixed byte limit during encoding;
the producer does not first materialize an unbounded complete JSON tree. The
constructor cannot install a boundary, observe a process, or grant plan
authority. Its diagnostic receipt is always non-reusable. Its plan draft keeps
network attempts and unresolved observations open, restricts candidates to
explicit normalized project or runtime roots, excludes system, home, and
temporary roots, and requires a person to choose write roots, environment
names, resource limits, and network mode. Capsec comparison requires the exact
schema, source, analyzer, and report identities. Exact static and
platform-required closure entries remain non-authoritative, retain content and
role identity, and stay separate from scoped authority candidates. The public
constructor rejects diagnostic, human, or Capsec provenance for closure entries.
A closure-tagged candidate must bind to an exact entry with a compatible role,
kind, path, and provenance before the draft producer emits it.

The initial evidence path must falsify event and per-process bounds, sequence
ordering, result and error exclusivity, resolution and identity consistency,
completion and one-way gap consistency, natural exact-capacity completion,
path and symlink evidence and bounds, redacted target leakage, non-normalized
or out-of-scope paths, streaming output overflow, all four Capsec identities
and incomplete reports, network-to-authority conversion, missing human
choices, provenance relabeling, noncanonical JSON, and drift from both
registered schema vectors. The independent checker must also confirm that
neither the production CLI nor the native launcher depends on the diagnostic
producer.

This claim starts at Tier 1 because its independent checker has a Tier 1
minimum. It does not establish that a ptrace observer sees
all effects, that a suggested path is safe or complete, or that a diagnostic
artifact can be accepted as production evidence.

## PBR-OBSERVER-020

The current subject is the pure diagnostic observer protocol. It owns no
process, filesystem, clock, environment, network, or raw system-call effect.
It permits target release only after the caller records ptrace ownership, the
production boundary acknowledgement, and the exact closed process-tree trace
options in order.

The bounded evidence path checks that:

1. missing, extra, or out-of-order setup state cannot release target code;
2. total event, per-process event, and lifetime process bounds cause explicit
   gaps only when another item arrives after the bound is full;
3. natural completion at each exact capacity remains complete;
4. draining never resumes collection, retains newly discovered children only
   within the process bound, and cannot finish before all retained processes
   have terminal wait results and the adapter confirms an empty child tree;
5. duplicate processes, unknown children, unexpected stops, observer failure,
   invalid identifiers, invalid bounds, and terminal-state reuse fail closed;
   and
6. the production CLI and Linux launcher do not depend on the diagnostic
   crate.

The setup-failure directive requires termination of the stopped child tree and
publishes no artifact. A post-release failure requires termination and may
publish only an incomplete diagnostic result after drain. This claim does not
establish correctness of ptrace, wait handling, syscall decoding, tracee-memory
reads, process termination, the tree-empty acknowledgement, or the future Linux
adapter.

## PBR-OBSERVER-021

The current subject is the feature-gated Linux trace-startup API. The
production CLI does not enable the feature or depend on the separate Linux
diagnostic crate. Raw ptrace, wait, and signal calls remain confined to the
existing Linux syscall module. The public safe layer exposes non-copy
typestates for the prepared child, exact initial exec stop, trusted launcher
self-stop, boundary-running state, identity-checked acknowledgement stop,
installed exact options, and active syscall-stop trace. Preparation accepts an
identified launcher file, revalidates its exact identity during preparation
and again immediately before spawn, and creates the private launcher channel
and command together. It executes through the retained
launcher descriptor and retains both channel ends, the exact install request,
and every borrowed inherited descriptor through one consuming spawn. Safe
callers cannot substitute a command or channel or deliberately close and reuse
a descriptor number between preparation and spawn. Every later
state moves one private session that owns the same child, process identity,
supervisor channel, and identity-bound request. The session receives the
acknowledgement internally and sends the release through that same channel. Its
public states expose the process identity but no mutable child handle, so safe
callers cannot replace the child retained by the session. Its child guard
attempts to kill and reap that child when a transition fails or the caller
abandons a state.

The bounded evidence path checks that:

1. only the separate diagnostic Linux crate selects the observer feature;
2. raw calls and `unsafe` blocks remain confined to the Linux syscall module;
3. one internally created channel carries the install request, matching
   acknowledgement, and identity-bound release without a caller-supplied
   protocol value or channel;
4. acknowledgement identity is checked before the launcher is stopped;
5. the exact closed option set is installed before a release can be sent;
6. syscall-stop observation is requested before `ActiveTrace` is constructed;
   and
7. the prepared command has one consuming spawn and retains the lifetime of
   every inherited descriptor through it; and
8. every spawned state contains the same private session type, every transition
   moves that session, no public API exposes mutable child replacement, and its
   child guard contains the only setup-state kill and wait operations; and
9. invalid descriptors, process identifiers, deadlines, channel operations,
   launcher responses, stops, exits, identities, and operating-system results
   map to closed errors.

The Rust test checks only closed value validation and distinct error codes. The
independent checker inspects the declared ownership and transition structure.
Neither executes the Linux trace lifecycle. This is a source-level startup
claim. It does not establish Linux ptrace correctness, tracer-death behavior,
successful process cleanup, process-tree coverage, syscall decoding,
tracee-memory reads, or a complete diagnostic execution. Those properties
require the next adapter, native attack, and release-binding waves.

## PBR-OBSERVER-022

The current subject is the separate diagnostic Linux adapter's setup surface.
It replaces the crate's raw trace-typestate re-exports with one consuming set of
adapter states. Observation bounds are validated before trace preparation and
child creation. The exact spawned process identity seeds the pure protocol only
after that process reaches its initial trace stop. Every later state owns one
private effectful trace typestate and the same private pure observer protocol.
The option-install operation returns the exact installed bits through the trace
typestate; the adapter parses those bits through the closed pure type before it
records option readiness. Public access is limited to process identity and
immutable protocol status.

The bounded evidence path checks that:

1. bounds are validated before the exact trace session is prepared;
2. the exact spawned process reaches its initial stop before that same process
   identity seeds the pure protocol and attachment is recorded;
3. every post-attachment adapter state privately owns the matching trace state
   and one pure protocol without copy or clone derivation;
4. acknowledgement completes before its pure state advances, and the exact
   option bits returned after Linux installation pass the closed pure validator
   before option readiness advances;
5. pure release authorization precedes effectful target release in one
   consuming transition;
6. exact private field declarations, return types, and re-export checks prevent
   public raw trace ownership or mutable protocol access; and
7. neither production executable depends on the diagnostic adapter or pure
   diagnostic crate.

The independent checker inspects source and manifest structure. It does not
execute the setup path. Hosted compilation can reject type or lint defects but
does not establish Linux effect correctness. This claim does not implement or
prove process-tree waits, child discovery, syscall entry and exit pairing,
architecture decoding, tracee-memory reads, termination, tree-drain truth, or a
complete diagnostic execution.

## PBR-OBSERVER-023

The current subject is the feature-gated Linux `ActiveTrace` source API and
its raw-call wrappers. One private map starts with the exact released root.
Every wait names an identifier in that map. The implementation never asks the
kernel for an arbitrary child from the tracer process. Process-creation events
yield a child identity. Before the parent can resume, the trace records the
child's procfs thread-group identity, obtains one pidfd for that group, and
adds the child to the exact wait set.

System-call entry information is retained privately and paired with its exit
information before the API returns one complete event. The stopped tracee is
held until the caller asks for another event. An exec event requires the exact
wait result to name the requested retained thread-group leader. The kernel
event message can name the former non-leader thread. Both identities must
belong to the retained surviving thread group. The trace transfers the former
thread state to the surviving leader, preserves its pending syscall entry for
the following exit stop, and removes superseded thread state in that group.
Exact terminal wait results remove tracees and unused process handles.

The bounded evidence path checks that:

1. active waits are selected only from the private tracee map and never use a
   global `waitpid` target;
2. child identity and its thread-group pidfd are retained before the parent
   resumes;
3. system-call entry and exit information is paired, with missing or duplicate
   phases rejected;
4. leader and non-leader exec identity replacement updates the retained set,
   preserves syscall pairing across the exec event, rejects foreign identities,
   and removes superseded thread state;
5. unexpected stops, event errors, and timeouts make further collection require
   drain; and
6. active-trace drop and explicit drain address thread groups only through
   retained pidfds, so PID reuse cannot redirect a termination signal.

The Rust tests check the closed error vocabulary and strict bounded procfs
`Tgid` parser. The independent checker inspects the registered source
structure. Hosted compilation can reject type and lint defects. None of these
establishes the Linux effects. `PBR-DIAGNOSTIC-TRACE-AX-016` retains ptrace,
wait, procfs, pidfd, signal, scheduler, and terminal-reporting premises. Native
attack evidence, architecture-specific syscall decoding, and bounded
tracee-memory reads remain open. PBR-OBSERVER-024 separately registers the
effectful process-map bound, adapter coupling, and source-level tree-drain
acknowledgement order.

## PBR-OBSERVER-024

The current subject is the separate Linux adapter's consuming active-observer
API. Before release, the adapter converts the already validated lifetime
process bound into the effectful trace's closed process-limit type. Each active
step then consumes one complete event while the same non-copy state privately
owns the trace and pure protocol. Process creation, exec identity replacement,
terminal status, unexpected stops, and reserved event counts advance the pure
protocol before the adapter returns the next state.

A trace failure or pure termination directive returns only a drain typestate.
The trace retains at most the declared process capacity plus one stopped child
per retained creator, which bounds its closed drain capacity at twice the
declared value. The pure protocol never admits an attempted lifetime overflow.
The adapter privately retains those overflow identities so they cannot be
mistaken for entries in the bounded ledger.

A process-creation message, identity, capacity, thread-group, or handle failure
sets a permanent unreconciled-tree condition before the risky registration
step. Even if every already registered process later reaches a terminal wait,
that condition prevents the trace from returning a successful drain report and
therefore prevents either complete or incomplete publication.

The effectful drain continues exact waits and reports pending child creation,
exec replacement, and terminal observations. The adapter reconciles those
reports with the pure protocol and its private overflow set. It can record the
pure tree-empty acknowledgement and select incomplete publication only after
the trace returned a successful empty-tree report and no overflow identity
remains. Natural completion similarly requires the effectful trace and pure
process map to be empty before complete publication.

The registered Rust tests cover atomic pure exec reconciliation and the closed
process-limit values. The independent checker byte-pins the load-bearing event
and drain bodies and executes mutation witnesses for omitted registration,
false empty reporting, premature overflow clearing, omitted drain reporting,
and replay bypass. It also fixes the public typestates, dependency separation,
and source selection. This is a source contract. It does not establish Linux event
completeness, correct syscall meaning, tracee-memory reads, exact native cleanup,
or a released diagnostic executable. Those obligations remain explicit under
PBR-DIAGNOSTIC-TRACE-AX-016 and the RT-8 native evidence wave.

## PBR-OBSERVER-025

The current aggregate subject joins the pure observer bound accessors, the
Linux adapter's bound derivation and irreversible failure-to-drain transition,
the active trace's pre-resume entry capture, architecture router, closed
tables, argument helpers, and bounded readers, and the raw read-only process
memory operation. It selects one closed table from the Linux audit architecture
before it interprets a syscall number. The table contains only the filesystem,
socket, process-creation, and execution families registered by Specification
0015 for x86_64 and aarch64. It rejects x32, unknown architectures, and
unsupported `openat2` or `clone3` structure forms.

The process-creation decoder also treats `CLONE_UNTRACED` as an unsupported
registered form. It detects the flag for both `clone` and `clone3` while the
tracee is stopped at system-call entry. The trace does not resume that request;
the coupled adapter terminates and drains instead of allowing an intentionally
unreported child.

The raw syscall-information parser names the current Linux reserved and flags
fields. Both must be zero. It rejects a return larger than its supplied buffer
and accepts only the exact operation-specific byte count for none, entry, exit,
or seccomp data. A future extension therefore becomes a typed diagnostic
failure and drain obligation until Runtime registers its meaning.

The trace captures a registered operand before it resumes the stopped tracee.
Path strings must terminate within the tracee-string read bound and fit the
independent retained-path bound. Socket addresses must fit their independent
bound. The raw module performs only `process_vm_readv`; the safe trace module
completes a partial read or returns a typed failure. `sendto` retains a payload
length but never reads the payload pointer or bytes. Other unregistered syscall
numbers resume without producing a retained event.

The Rust tests cover architecture-qualified table selection, unknown
architecture rejection, x32 rejection, bound constructors, the closed error
vocabulary, and compilation of the selected adapter release and drain paths.
The independent checker byte-pins the compiler and crate-selection closure;
the adapter prepare, spawn, release, and drain transitions; the trace startup
release, event loop, wait-observation router, entry handler,
bound constructor, router, both architecture tables, width and byte-order
helpers, supported-family decoder, syscall-information fetch and exact parser,
bounded readers, and raw read operation. Its mutation witnesses cover the
router, architecture numbers, x32 rejection, `CLONE_UNTRACED` rejection,
argument width, byte order,
reserved and flags fields, truncated and extended operation sizes, each operand
bound, adapter limit wiring, payload pointer selection, and raw read-only
operation. These source checks do not prove the Linux ABI, `process_vm_readv`,
memory stability, or event completeness.
`PBR-DIAGNOSTIC-DECODE-AX-017` retains those premises. Native decoder fixtures,
object resolution, command integration, and release binding remain open. The
following `PBR-OBSERVER-026` wave owns artifact mapping.

Replacement hosted run `34988148920` passed preflight, formal, both native,
and every fresh-evidence lane except the receipt lane, whose anonymous
Proofbound release request hit GitHub's rate limit before evidence execution.
The Rust lane exposed a distinct large-enum lint in the adapter's public drain
observation. The current correction uses one boxed event only when an event
selects terminal drain. It adds no boxing allocation to normal continue,
natural-completion, or trace-wait events. The affected exact-body checks are
refreshed. Independent re-review approved exact head `fbd2d66`. Approval-only
head `db95947` passed complete exact-head run `34992273744` and merged unsigned
as `4783896`. Exact-main Verify run `34997195939` passed.

## PBR-OBSERVER-026

The current subject is the separate Linux trace-to-artifact mapper. Each
complete registered syscall event becomes one diagnostic event with the exact
trace process identity, closed audit architecture, syscall class, bounded
entry operands, and either a consistent nonnegative result or positive Linux
error. A successful image replacement produces an event only when the trace
retained a matching `execve` or `execveat` entry. Process creation, image
replacement without an entry, exit, and unexpected-stop lifecycle records do
not become duplicate syscall events.

The mapper owns a monotonic sequence counter and advances it only after a
successful artifact construction. It keeps every filesystem and socket object
resolution `unresolved`. It never invents a resolved path or object identity,
and it retains only the `sendto` payload length supplied by the decoder. An
unknown audit architecture, inconsistent result marker, invalid exec entry,
non-UTF-8 version 1 path, artifact inconsistency, or sequence overflow returns
a closed error.

The Rust tests cover both architectures, all closed syscall classes, result
validation, bounded operand preservation, invalid path encoding, and socket
family classification. The independent checker byte-pins every load-bearing
mapping body and exact source file. Its causal mutations attempt a resolution
upgrade, wrapping sequence arithmetic, lossy path conversion, wider error
range, missing class, discarded socket bytes, and weakened exec validation.
This evidence does not prove the Linux event, operand, or result; it does not
resolve an object; and it does not yet connect mapping failure or artifact
publication to a released `pbr-diagnose` command.

## PBR-OBSERVER-027

The current subject is the standard-stream owner inside the separate Linux
diagnostic trace. The spawn transition takes both configured child pipes, makes
them nonblocking, and starts two independently bounded drains with one shared
cancellation signal before it returns the spawned trace state. Each active drain retains no
more than its declared prefix and continues reading after truncation until end
of file. The exact stdout and stderr limits remain distinct.

Natural completion collects both streams only after the retained trace tree is
exactly empty. Forced termination adds them to its report only after the exact
tree drain succeeds. The coupled adapter obtains the captures before the pure
protocol selects publication. A missing pipe, reader-thread creation failure,
read failure, or join failure is typed and prevents publication. On abandoned
early setup states, declaration and drop order makes the child guard attempt
termination and wait before cancellation and join of the outstanding drain handles. Nonblocking
polling makes the cancellation path independent of pipe closure. Terminal
collection has a fixed monotonic deadline. An unfinished reader causes shared
cancellation, joins both handles, and returns a typed timeout without publishing
captures. Retaining the root pidfd for active-trace ownership and an exact raw
terminal wait that reaps the root each disarm its retained numeric child cleanup
guard. Active-trace destruction consequently terminates only through pidfds.
Early setup destruction attempts child termination and wait; it does not claim
that infallible drop cleanup is observable.

The Rust tests cover independent limits plus exact, truncated, zero-limit, and
terminal-timeout capture. The independent checker byte-pins the load-bearing
spawn, reader, deadline, cancellation, raw-wait cleanup ownership, completion, drain, and adapter
transitions. Its mutations remove one pipe, cross-wire a limit, stop reading at
truncation, remove the terminal deadline, remove timeout cancellation, remove
root-reap disarming, remove startup rollback, reverse drop order, weaken exact-tree completion, and move
pure publication selection ahead of output collection. This is source evidence. Linux pipe behavior,
scheduler progress, trace-tree truth, cgroup placement, wall-time enforcement,
native pipe-saturation attacks, command integration, and release binding remain
open. `PBR-DIAGNOSTIC-STREAM-AX-022` retains the ptrace terminal-reporting,
Linux pipe, scheduler, memory-ordering, and thread-runtime premises separately
from the compiler and checker premises in
`PBR-DIAGNOSTIC-STREAM-CHECK-AX-020`.

## PBR-OBSERVER-028

The current subject is the terminal capture owner inside the separate Linux
diagnostic trace. Preparation accepts the exact fresh cgroup version 2 owner
and full seed-plan resource limits. It compares the request cgroup identity and
the read-back process, memory, swap, and OOM-group controls during preparation,
then revalidates the zero resource snapshot, empty membership, and unpopulated
state during preparation and immediately before spawn. It reads the controls
again immediately before spawn and immediately before target release. The
execution deadline is created immediately before spawn, stored privately in the
trace session, and used by setup, option installation, release, active
observation, and natural terminal collection. A ready stop or event cannot win
after expiry, and target release or resume has an immediate deadline check. No
public transition accepts a replacement deadline. Spawn places and reads back
the exact child in the cgroup before returning the spawned typestate.

An observer failure or pure termination directive consumes the active trace,
successfully signals every retained identity-stable process group, and starts a
separate five-second cleanup deadline before it returns a drain-only owner.
Natural and forced completion establish an empty exact trace tree before they
consume the cgroup owner. One absolute cleanup deadline covers those waits,
cgroup drain and removal, complete version 2 resource observations, stream
cancellation, and both joins. The adapter obtains this combined terminal
capture before it selects either publication result. Identity, freshness,
control, placement, signalling, cleanup, resource-observation, read, join, or
deadline failure is typed and prevents publication. Field ownership orders
best-effort abandoned-session cleanup through root child, cgroup, and stream
readers.

The Rust evidence fixes the no-refresh public method signatures. The
independent checker byte-pins preparation, spawn, freshness, exact-stop,
deadline, resume, termination, cgroup, terminal, and adapter transitions. Its
causal mutations remove a memory-control comparison or freshness check, replace
the execution deadline, reverse cleanup owners, accept a late stop or event,
discard process-group signal failure, refresh the stream deadline, accept
incomplete resources, or move publication before terminal capture. This
remains source evidence.
Linux cgroup membership and counters, monotonic-clock progress, scheduler and
ptrace behavior, termination, pipe progress, native attacks, command
integration, and release binding remain open.
`PBR-DIAGNOSTIC-LIFECYCLE-AX-023` retains those native runtime premises.
`PBR-DIAGNOSTIC-LIFECYCLE-CHECK-AX-021` separately retains only compiler,
standard-library, and independent-checker premises.

## PBR-OBSERVER-029

The current subject is the successful-filesystem-object resolver shared by the
separate Linux trace and diagnostic mapper. It operates while the exact tracee
is stopped. Returned descriptors are eligible only for a successful registered
open operation, a Linux-width nonnegative descriptor, and one retained tracee.
Post-exec identity is eligible only after exact exec reconciliation. The
resolver retains an `O_PATH` object before it reads the procfs link and complete
`statx` identity. Deleted, non-UTF-8, over-bound, non-filesystem procfs-link,
incomplete, or
ambiguous results remain unresolved.

Rust tests exercise the closed eligibility and mapping decisions. The
independent checker requires the retained-handle, stopped-tracee, sole-tracee,
complete-identity, normalized-path, and artifact-consistency guards. Its
mutations remove the sole-tracee guard, normalized-path check, or retained
`O_PATH` open. This is source evidence. Linux ptrace, procfs, `statx`, mount,
descriptor-table, pathname, scheduler, command, native, and released-artifact
behavior remain assumptions or open obligations.

## PBR-OBSERVER-030

The current subject is the advisory denied-path candidate resolver. A failed
registered path operation is eligible only for one stopped retained tracee. A
manual walk anchors absolute paths at the tracee root and relative paths at the
tracee cwd or exact directory descriptor, confines parent traversal to that
root, and stops at the declared symlink-hop limit. Two complete observations
must agree on path, symlink count, and complete object identity. Drift and
symlink exhaustion remain typed gaps and unresolved artifact events.

Rust tests cover root confinement, hop exhaustion, stable mapping, and identity
requirements. The independent checker requires two resolution passes, equality,
root confinement, a closed hop bound, advisory-only mapping, and propagation of
the two typed gaps. Its mutations bypass equality, root confinement, or the
advisory resolution class. This evidence does not prove Linux pathname or
filesystem behavior and does not identify the object selected by a failed
syscall.

## PBR-OBSERVER-031

The current subject is the separate `pbr-diagnose` command plus its release
inventory construction. The command strictly parses one seed plan, reuses its
normalized production authority, installs the same Landlock, seccomp, cgroup,
descriptor, environment-name, executable, and resource boundary, and adds only
the separate observer. It requires an explicit delegated cgroup root and absent
receipt and draft targets outside child write authority. Terminal protocol
eligibility precedes bounded artifact construction and create-new, durable,
no-replace publication. The production command and launcher do not depend on
diagnostic crates. The active exit extension may read one static scaffold only
through a retained regular-file descriptor that the seed plan already declares
as a project input. It requires an exact target, loader, dependency, platform,
and content-identity match before it adds non-authoritative static or
platform-required identified-closure entries. It does not add filesystem
authority.

Rust tests cover the closed command arguments and observation bounds. The
independent checker requires seed-authority reuse, boundary constructors,
terminal gating, absent targets, durable no-replace publication, production
dependency separation, release inventory inclusion, declared scaffold access,
strict scaffold parsing, exact closure identity checks, and provenance
separation. Its mutations weaken create-new publication, terminal eligibility,
child-write exclusion, identity matching, or provenance integrity. Native
stale-target, symlink-input, unexpected-stop, and `CLONE_UNTRACED` evasion
cases run on both supported architectures without making diagnostic output
reusable. The product-exit extension passed PR 27 exact-head run `35194713490`,
merged as `275e6e7`, and passed exact-main run `35198698472`. The final
adversarial wave passed PR 28 exact-head run `35203053015`, merged as
`da8c96b`, and passed exact-main run `35207382756`. This closes RT-8 at that
exact identity. A later source-closure change still requires its own fresh
admission and does not inherit this status.

## PBR-NETWORK-032

The current subject is the separate parser for the proposed
authenticated-service-session plan. It validates one canonical DNS service,
one numeric DNS-over-TCP resolver endpoint, closed TLS rules, bounded resolver
and session limits, canonical connector support paths, one inherited local
channel descriptor, and an optional service-bound credential-source descriptor.
The parsed base child authority still contains `NetworkMode::Deny`.

The production execution parser explicitly rejects the same plan until the
connector, native launcher profile, receipt, independent verifier, composition,
acceptance, attack corpus, and release waves are admitted. Rust tests cover the
positive closed contract, service-name substitution, credential-environment
omission, credential-service substitution, resolver address-width
substitution, limit ordering, and production-parser rejection. The tests do not
establish DNS, TLS, connector, kernel, credential, or remote-service behavior.
`PBR-SDK-014` separately owns cross-language construction of these bytes.
The contract subject passed PR 29 exact-head run `35216056050`, merged as exact
Runtime main `d48122b06c4880aeba45291a107c51ad381067a4`, and passed exact-main
run `35220098639`. The pure-policy schema and Specification 0016 clarification
passed PR 30 run `35226379485` and exact-main run `35231003515` at
`a94c21a9d1b399f9eff8771e06ce253fe9a6c4ca`. The later lifecycle closure
passed PR 31 run `35236845497`, merged as exact main
`1da65a5c53f27b97a15f95ed1a9fb01170121444`, and passed exact-main run
`35241672716`.

## PBR-NETWORK-033

The current subject is the pure compiler for the proposed single-service
policy. It compiles the validated base authority through the existing
deny-network policy and emits one frozen deterministic-CBOR policy vector. The
bytes separately bind `network = deny-network-v1`,
`child_network = channel-only-v1`, and the complete connector-owned
`service_session`. The maintained independent Python generator reproduces the
same vector from the frozen service plan.

The compiler does not install a connector, create or transfer a channel,
change the production execution parser, or establish DNS, TLS, kernel, or
credential behavior. Formal non-amplification and Rust-refinement evidence are
still open. The shipping network claim remains unavailable until the complete
effectful, receipt, verifier, composition, acceptance, native-corpus, and
release waves are admitted.

The pure-policy subject passed PR 30 exact-head run `35226379485` and merged as
exact Runtime main `a94c21a9d1b399f9eff8771e06ce253fe9a6c4ca`. Exact-main run
`35231003515` passed. The later lifecycle closure passed PR 31 and exact-main
run `35241672716` at `1da65a5` without changing the compiler's behavior.

## PBR-NETWORK-034

The current subject is a pure service-session lifecycle decision. It admits
only the ordered phases `created`, `resolving`, `connecting`, `authenticating`,
`ready`, `active`, `closing`, and `closed`. Each nonterminal phase can instead
enter one typed `failed` terminal state. Backward, skipped, reconnect,
repeated-release, and post-terminal transitions are errors. Exhaustive Rust
tests cover every phase and non-failure event pair plus typed failure from
every phase.

The accompanying Lean model defines the same closed phases, events, terminal
failures, and transition relation. Its candidate theorem states that the model
transition succeeds exactly for the registered relation. The theorem is not
yet registered or admitted as Proofbound evidence and does not establish a
Rust refinement. Neither subject runs DNS, a connector, TLS, a launcher, a
child, or cleanup. Effectful linkage and receipt verification remain open. The
pure lifecycle subject passed PR 31 run `35236845497` and exact-main run
`35241672716` at exact main `1da65a5`.

## PBR-NETWORK-035

The current subject is a proposed deterministic-CBOR service-session
observation fragment plus an independent Python semantic checker. The closed
success vector binds one declared service and policy to the exact connector
closure, canonical DNS answer and attempt prefix, authenticated TLS result,
registered local channel, bounded traffic counters, complete forward
lifecycle, terminal cleanup, and optional credential-source name. The type and
checker exclude credential values and application request or response bytes.

The mutation corpus rejects unknown fields; invalid authority limits; invalid
resolution, attempt, endpoint, TTL, and expiry timing; an endpoint outside the
answer set; invalid TLS identity or resumption; excess traffic; a skipped
lifecycle transition; incomplete cleanup; cross-service or malformed
credential identity; and retained secret content. This source contract does
not establish
that a producer observed those facts, that the shipping verifier checks them,
or that a connector or Linux boundary enforced them. Production receipt,
failure, verifier, composition, acceptance, native, and artifact-binding waves
remain open.

## PBR-NETWORK-036

The current subject is a proposed deterministic-CBOR service-session launcher
handshake and an independent semantic checker. The install and installed
messages start one closed ordered transcript within the existing one-mebibyte
whole-frame bound. Each later message binds the complete canonical install
request. The transcript binds the execution, policy, cgroup, child executable, connector
identity and generation, DNS and TLS observation identities, selected endpoint,
channel endpoint identities and descriptor, limits, child-filter bytes, and
retained descriptor inventory. The release message binds the canonical service
map by SHA-256. The mutation corpus rejects identity, cgroup, connector,
endpoint, channel, descriptor, filter, release-binding, and retained-secret
substitutions.

The production launcher message union is unchanged and does not accept this
handshake. This source contract does not establish that any boundary was
installed or that a child was released. The failure handshake, effectful
supervisor and launcher implementation, native attacks, receipt integration,
shipping verifier, composition, acceptance, and artifact binding remain open.

## PBR-NETWORK-037

The current subject is a proposed deterministic-CBOR service-session receipt
fragment and an independent Python semantic checker. Both success and failure
bind the expected execution, plan, compiled policy, service, complete
registered assumption identifiers, and the closed
service-specific trusted-computing-base projection with fixed-size identity
digests. Failures before launcher start bind no fabricated install identity;
later failures bind the exact retained launcher prefix appropriate to their
reported boundary and release state. Reusable success
also binds the exact installed acknowledgement, release message, canonical
successful observation, and zero child exit.

Every failed form is non-reusable and retains exactly one phase-consistent
reason. It records whether the boundary was installed, requires the exact
installed acknowledgement when present, requires the exact release only after
child release, prohibits a release before that transition, and retains the
terminal child, channel, cgroup, connector, and namespace cleanup states. The
mutation corpus rejects execution, plan, policy, service, launcher,
observation, eligibility, assumption, trusted-computing-base, boundary,
release, failure, and cleanup substitutions, including nested observation
changes with a refreshed digest.

The production receipt producer and independent Rust verifier remain
unchanged and reject this fragment. The Python checker is contract evidence,
not the shipping verifier. Production integration, separate decoding and
verification, composition, acceptance, network effects, native attacks, and
release-artifact binding remain open.

## PBR-NETWORK-038

The proposed connector engine is isolated in
`crates/proofbound-runtime-connector`. Its only setup input is one complete
validated service authority, which remains attached to the resolution and TLS
path. Its resolver sends length-prefixed DNS queries only to that authority's
numeric TCP resolver under refreshed absolute deadlines. The parser rejects
transaction, question, truncation, status, compression-loop, name,
address-length, zero-TTL, CNAME-and-address conflict, and trailing-data
violations. It retains response and CNAME identities instead of packet
contents, propagates the shortest CNAME lifetime to endpoint eligibility, and
sorts unique endpoints as canonical IPv4 followed by IPv6.

The TLS path loads only caller-supplied PEM trust-root bytes, selects rustls's
ring provider explicitly, configures the declared minimum version, disables
resumption and early data, and requires an exact non-wildcard leaf DNS SAN after
ordinary chain and name validation. It rejects expired answers, absolute setup
deadline expiry, and excess handshake bytes, and retains a length-delimited
peer-chain identity. The
channel path treats application bytes as opaque, applies independent
directional plaintext limits and one session deadline, uses no reconnect, and
does not interpret requests or responses.

This is Tier 1 bounded source evidence. Registered tests and the independent
source-mutation check cover complete-authority
retention, DNS transaction and TTL substitution, CNAME conflict and lifetime,
wildcard-name rejection, explicit provider selection, deadline error typing,
trust-root failure, address ordering, and closed error classes. They do not
establish behavior of an external resolver or TLS peer, trust-root artifact
binding, a connector process, launcher, child filter, cleanup path, receipt
producer, verifier, or release artifact. The production CLI still rejects the
service-session authority. Those obligations remain explicit and block product
availability.

## PBR-NETWORK-039

The proposed connector-process layer is isolated in
`crates/proofbound-runtime-linux/src/connector_process.rs` and the
`pbr-service-connector` binary. The supervisor side retains and revalidates the
exact plan, connector executable, trust-root set, resolver configuration, and
ordered connector runtime artifacts. It creates one unnamed Unix stream pair
for application bytes and one unnamed packet pair for control reports before
process creation. Apart from standard descriptors connected to null devices,
only the exact retained plan, trust-root, connector-side stream, and
connector-side control descriptors survive exec. The connector executable
descriptor exists only until the kernel completes the exact descriptor-relative
exec and remains close-on-exec.

Preparation also parses the complete bounded connector image as a supported
64-bit little-endian ELF for the selected architecture. A dynamic image is
rejected unless its exact absolute interpreter path names one identified,
executable artifact in the registered connector runtime closure. This closes
script and undeclared-interpreter substitution; discovery of every transitive
dynamic library remains a later native preflight and confinement obligation.

The child parses a closed bootstrap, rejects duplicate inherited descriptors,
recomputes plan and trust-root identities before parsing or network effects,
resolves and authenticates through the admitted connector engine, and reports
authenticated readiness before starting the opaque proxy. The fixed control
report binds execution, policy, process generation, channel, plan, trust-root,
connector, runtime-closure, and resolver-configuration identities. Terminal
traffic and closed typed failures use separate fixed forms. The supervisor
bounds setup and terminal waits, rejects out-of-order or malformed reports, and
kills and reaps an unfinished connector when ownership ends.

This is Tier 1 bounded source evidence. It does not establish connector
filesystem or network confinement, the child launcher boundary, credential
release, native bypass resistance, production CLI reachability, production
receipts, independent receipt verification, or release-artifact behavior. The
runtime-closure paths are identified inputs in this wave; native enforcement
of that closure remains an explicit obligation before production release.

## Bounded-domain declaration guard

The workspace test stage checks every Runtime claim that cites bounded-check
evidence before Proofbound manifest compilation. The local guard requires the
claim, cited evidence unit, and referenced model-check manifest to declare the
same identifier, description, cardinality, and ordering key. It also rejects
cross-claim evidence substitution and non-confined model-manifest paths.

This is a repository declaration invariant, not claim evidence. It does not
prove that an adapter visited the finite domain or make the same check inside
Proofbound's portable compiled bundle. PBF-0007 remains open until a reviewed
Proofbound compiler and independent verifier enforce the relation.

## Promotion rule

A claim changes tier, profile, public language, or primary linkage only in the
same commit that registers the evidence that justifies the change. A source
closure change invalidates stale generated output and requires every affected
evidence path to run again.
