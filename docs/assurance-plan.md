# Assurance plan

This document records the completed evidence path for each load-bearing version
0.1 claim. Claim manifests remain the source of truth for current admitted
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

The contextual theorem bindings do not change the four Tier 3 claims' selected
`REFINED` primary linkage or remove their toolchain assumptions. Exact artifact
observations do not promote the four test-based claims to `ARTIFACT_BOUND`.

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
- boundary acknowledgement bound to the compiled-policy identity; and
- the final `execve` handoff.

The evidence path is:

1. protocol-state tests that reject every invalid transition;
2. acknowledgement omission, truncation, forgery, and substitution attacks;
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

## Promotion rule

A claim changes tier, profile, public language, or primary linkage only in the
same commit that registers the evidence that justifies the change. A source
closure change invalidates stale generated output and requires every affected
evidence path to run again.
