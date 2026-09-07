# Assurance plan

This document records the intended evidence path for each load-bearing version
0.1 claim. Claim manifests remain the source of truth for current admitted
status. A target below is a work commitment, not present evidence.

## Target summary

| Claim | Target | Reason |
| --- | --- | --- |
| `PBR-AUTH-001` | Tier 3, artifact-bound | The deterministic normalization core is source-refined. Only release binding remains. |
| `PBR-POLICY-002` | Tier 3, artifact-bound | Policy compilation is a pure total function over closed authority and platform types. |
| `PBR-SEQUENCE-003` | Native bounded evidence, artifact-bound | Launcher sequencing is effectful Linux behavior. A pure model cannot prove kernel effects occurred. |
| `PBR-RECEIPT-004` | Tier 3, artifact-bound | The receipt-eligibility decision is source-refined. Only release binding remains. |
| `PBR-BINDING-005` | Tier 3, artifact-bound | Receipt construction and role completeness can be isolated as a pure deterministic core. |
| `PBR-VERIFY-006` | Registered attack-corpus evidence, artifact-bound | The statement is intentionally bounded to registered mutations and exact rejection reasons. |

Artifact binding does not upgrade the behavioral evidence by itself. It only
connects admitted evidence to exact release bytes.

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
6. exact release-artifact binding.

This claim must not be presented as a pure refinement theorem. It keeps the
Linux and host assumptions visible.

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
- identity and artifact-role validation;
- independent reuse-eligibility derivation;
- typed errors and stable exit behavior; and
- the verifier executable entry point.

The evidence path is:

1. shared normative positive and negative vectors;
2. the complete registered receipt attack corpus;
3. exact typed rejection reasons from the independent implementation;
4. producer/verifier differential conformance; and
5. exact release-artifact binding.

The claim stays bounded to registered attacks. Acceptance of a finite corpus is
not proof that an unrepresented receipt property is correct.

## Promotion rule

A claim changes tier, profile, public language, or primary linkage only in the
same commit that registers the evidence that justifies the change. A source
closure change invalidates stale generated output and requires every affected
evidence path to run again.
