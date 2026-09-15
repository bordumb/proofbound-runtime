# Assurance plan

This document records the completed evidence path for each current load-bearing
claim. Claim manifests remain the source of truth for admitted
status, assumptions, exclusions, and exact evidence identities.

## Assurance summary

| Claim | Admitted result | Meaning |
| --- | --- | --- |
| `PBR-AUTH-001` | Tier 3, source-refined with contextual artifact binding | The theorem-derived closed set binds the refined normalization claim to the exact native `pbr` member in each reviewed release context. |
| `PBR-POLICY-002` | Tier 3, source-refined with contextual artifact binding | The pure policy compiler is source-refined and its theorem-derived closed set selects the exact native `pbr` members. |
| `PBR-SEQUENCE-003` | Tested/model-only with exact native artifact observation | Launcher sequencing is effectful Linux behavior. Exact execution observations do not prove kernel effects generally. |
| `PBR-RECEIPT-004` | Tier 3, source-refined with contextual artifact binding | The receipt decision is source-refined and its theorem-derived closed set selects the exact native `pbr` members. |
| `PBR-BINDING-005` | Tier 3, source-refined with contextual artifact binding | The production constructor and wire projection are source-refined and bound to the exact native `pbr` members. |
| `PBR-VERIFY-006` | Tested/model-only with exact native artifact observation | The evidence remains bounded to the registered mutations and exact rejection reasons exercised by each native `pbr-verify`. |
| `PBR-RUN-007` | Tested/model-only with exact native artifact observation | Each native release executes the exact `pbr` bundle role end to end without turning that observation into a theorem. |
| `PBR-COMPOSE-008` | Tested/model-only with exact native artifact observation | Each exact native composer joins verified receipts without upgrading any inherited facet. |
| `PBR-PREFLIGHT-009` | Tested/model-only on the development branch | The point-in-time preflight projection and registered failure surface are tested; exact native release observation remains an explicit obligation. |
| `PBR-RESOURCE-010` | Tested/model-only pending exact 0.2 release observation | The version 2 memory and swap controls, observations, and attack corpus are tested without claiming theorem-derived kernel or artifact soundness. |
| `PBR-DIAGNOSTIC-011` | Tested/model-only on the development branch | The closed run phase and rule mapping is tested without inferring a kernel denial or changing receipt meaning. |
| `PBR-ACCEPT-012` | Tested/model-only on the development branch | Adopter policy decisions bind independently verified inputs; exact released acceptor observation and external Action dogfood remain open. |
| `PBR-SCAFFOLD-013` | Tested/model-only on the development branch | Static ELF scaffolding is bounded diagnostic evidence, not a safe policy or a complete dynamic-load inventory. |
| `PBR-SDK-014` | Tier 1, independently checked source and package contract | Rust, Python, and TypeScript SDKs preserve the separate-process boundary; registry publication and consumer dogfood remain open. |
| `PBR-DISTRIBUTION-015` | Tier 1 independently reviewed and admitted on exact Runtime main | The verifier package has a closed preflight, source-payload comparison, byte reproduction, local consumer, and release-retention path; no registry or publisher claim is admitted. |
| `PBR-DISTRIBUTION-016` | Tier 1 public-bundle consumer independently reviewed and admitted on exact Runtime main | Runtime pins one immutable public Proofbound release and rejects identity, inventory, manifest, checksum, archive, installer, and installed-byte substitution. Every protected evidence and release job installs that exact bundle independently. |
| `PBR-DISTRIBUTION-018` | Tier 1 npm-bootstrap correction pending exact review | Publication is explicit, exact-source, protected, ordered, and credential-isolated. The active correction adds the missing one-time npm bootstrap gate; external configuration and observations remain open. |
| `PBR-DISTRIBUTION-025` | Tier 1 implementation previously approved at `a81e259`; registry-route dependency changed and exact re-review is required | A deterministic-CBOR producer and independent verifier close one Runtime-only integration tuple after complete registry observation. No tuple is published until an exact protected run retains it. |
| `PBR-DRAFT-017` | Tier 1 bounded contract and source-level non-reuse checks | Closed diagnostic vocabulary and schemas are registered, and verifier, composer, and acceptor paths reject diagnostic receipt reuse. The live observer remains open. |
| `PBR-DRAFT-019` | Tier 1 bounded producer contract independently reviewed and admitted on exact Runtime main | The pure diagnostic artifact producer preserves non-reuse, provenance, explicit gaps, and mandatory human authority choices. It does not claim live observer coverage. |
| `PBR-OBSERVER-020` | Tier 1 decoder identity admitted on exact Runtime main `4783896` | The complete decoder subject passed exact-head run `34992273744` and exact-main run `34997195939`. |
| `PBR-OBSERVER-021` | Tier 1 decoder identity admitted on exact Runtime main `4783896` | The shared trace source passed exact-head run `34992273744` and exact-main run `34997195939`. |
| `PBR-OBSERVER-022` | Tier 1 decoder identity admitted on exact Runtime main `4783896` | The adapter derives capture limits from the same validated protocol and passed exact-head run `34992273744` and exact-main run `34997195939`. |
| `PBR-OBSERVER-023` | Tier 1 decoder identity admitted on exact Runtime main `4783896` | Entry-time operand capture passed exact-head run `34992273744` and exact-main run `34997195939`. |
| `PBR-OBSERVER-024` | Tier 1 decoder identity admitted on exact Runtime main `4783896` | The shared trace, adapter, and observer sources passed exact-head run `34992273744` and exact-main run `34997195939`. |
| `PBR-OBSERVER-025` | Tier 1 syscall-decoder source admitted on exact Runtime main `4783896` | Approval-only head `db95947` passed complete exact-head run `34992273744`; exact-main run `34997195939` also passed. Kernel ABI truth, memory stability, and native attacks remain open. |
| `PBR-OBSERVER-026` | Tier 1 event-mapping source admitted on exact Runtime main `a89b92d` | The mapper preserves the closed trace identity, operands, and outcome fields, assigns contiguous sequence values, and keeps object resolution unresolved. Exact-head Verify run `35018691928` passed; exact-main run `35025687602` was started. Linux truth, object resolution, command integration, native attacks, and release binding remain open. |
| `PBR-OBSERVER-027` | Tier 1 bounded-stream source pending independent review and hosted admission | The trace starts independent stdout and stderr drains after spawn, retains bounded prefixes while reading to EOF, and exposes captures only after terminal tree handling. Linux pipe progress, cgroup placement, wall time, command integration, native attacks, and release binding remain open. |

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
- anonymous re-reading of the hosted release ID, tag, target commit,
  publication state, immutability state, and asset identities, plus independent
  resolution of the tag object to the pinned source commit;
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
schema, source, analyzer, and report identities.

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
router, architecture numbers, x32 rejection, argument width, byte order,
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
states, declaration and drop order makes the child guard terminate and wait
before cancellation and join of the outstanding drain handles. Nonblocking
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
