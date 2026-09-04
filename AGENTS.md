# Proofbound Runtime contributor guide

The normative product contract is
`docs/specs/0001_initial_spec.md`. Read it before changing architecture,
security behavior, public schemas, receipt meaning, or repository structure.

Proofbound Runtime is a Linux-first execution-assurance gateway. It is not an
operating-system kernel. It uses kernel-enforced mechanisms to give one child
execution declared authority and to produce a bounded execution receipt.

## Assurance boundaries

- Proofbound Runtime owns execution plans, authority semantics, Linux policy
  compilation, boundary installation, run observations, and execution receipts.
- Proofbound owns claim status, evidence meaning, assumption accounting, release
  assurance, artifact linkage, and generic receipt composition.
- Proofbound does not run in the child security path.
- A runtime receipt describes one identified execution. It is not a universal
  proof of containment or absence of exfiltration.
- Tests are never proofs. Bounded checks are never unbounded theorems. Model
  theorems are not shipping claims without registered linkage.
- Digests establish identity. They do not establish behavior.
- Missing or unsupported enforcement MUST fail closed. Do not add an
  unconfined, weaker, or best-effort fallback.

## Development process

Use Proof-Driven Development for every security-relevant change:

1. State the claim in plain English.
2. Identify the exact production subject.
3. Register assumptions, exclusions, and the intended evidence.
4. Add a falsifier, negative case, or adversarial mutation.
5. Implement the smallest typed behavior that can satisfy the claim.
6. Run the applicable evidence producers.
7. Inspect residual assumptions and open obligations.
8. Publish only the language admitted by the compiled evidence.

Plain English is the accountability boundary. It is not itself a proof. A claim
becomes stronger only when Proofbound admits the required evidence and linkage.

Use the Proofbound tiers progressively:

- Tier 0 registers claims, assumptions, exclusions, source closures, and tests.
- Tier 1 adds bounded checks, mutation witnesses, and independent conformance.
- Tier 2 adds Lean theorems about the formal model.
- Tier 3 links selected Rust behavior and release artifacts to admitted
  propositions.

Develop assurance as a wavefront:

1. Map the complete intended product at Tier 0.
2. Take one small foundational claim through Tier 3 before expanding the
   architecture.
3. Develop later behavior in claim-sized waves toward each claim's declared
   target tier.
4. Refactor when stronger evidence exposes a weak abstraction, invalid state,
   incomplete proposition, effectful dependency, or linkage gap.
5. Re-run or rebuild all affected evidence after each refactor.

The tiers apply to individual claims, not to the repository as global phases.
Do not force every claim to Tier 3. Do not transfer status across changed source
or artifact identities. Historical receipts remain bound to their original
subjects.

`proofbound check` is verify-only and may write only below `.proofbound/`.
Change committed assurance artifacts only with `proofbound update`.

## Proofbound feedback loop

Read `docs/proofbound-feedback/README.md` before recording or upstreaming a
Proofbound requirement.

When runtime development exposes a generic assurance need:

1. Confirm that the need comes from a concrete runtime behavior, failing case,
   or blocked claim.
2. Confirm that the behavior is generic to Proofbound rather than a Linux or
   agent-domain rule.
3. Copy `docs/proofbound-feedback/TEMPLATE.md` to the next stable feedback ID.
4. Record the observation, current evidence, assurance risk, proposed generic
   behavior, and acceptance criteria.
5. Add the item to the index in `docs/proofbound-feedback/README.md`.
6. Keep any local workaround explicit and assurance-weakening.
7. Do not change the sibling `proof-bound` repository unless the current user
   request explicitly includes upstream work.
8. After upstream work occurs, record the exact Proofbound issue, specification,
   ADR, commit, or pull request and update the feedback status.

Do not use the feedback directory for runtime feature requests, Linux
implementation details, informal brainstorming, or duplicate Proofbound
documentation. Runtime decisions belong in this repository's specifications or
ADRs. The feedback record is a handoff contract, not a second source of truth.

## Architecture boundaries

- Keep authority normalization, policy meaning, identity rules, and receipt
  eligibility in the pure core.
- Keep filesystem, process, clock, environment, cgroup, Landlock, and seccomp
  effects outside the pure core.
- Keep the Linux launcher minimal. It installs the complete boundary before it
  starts child code.
- Put raw syscalls and `unsafe` code only in
  `crates/proofbound-runtime-linux/src/sys.rs`.
- Give the independent verifier no dependency on another workspace crate.
- Do not share semantic implementation code between the receipt producer and
  independent verifier.
- Keep generated Lean only below `formal/generated/`.
- Keep handwritten refinement modules outside generated directories and
  byte-pin them through Proofbound.
- Put domain semantics in Proofbound Runtime. Do not add them to Proofbound
  framework core.

## Type-Driven Development

- Parse wire data into validated domain types at the boundary.
- Use newtypes for identities, digests, paths, durations, and resource limits.
- Use closed enums for versions, roles, mechanisms, outcomes, and errors.
- Use typestate where security depends on ordering.
- Use non-empty collection types when an empty inventory is invalid.
- Do not use Boolean fields when the state has more than two meanings.
- Do not use arbitrary strings for security-relevant categories.
- Keep authority-subset checks explicit, deterministic, and total.
- Return typed errors. Do not panic in library or runtime paths.

## Code and documentation style

- Prefer small modules with one clear owner and purpose.
- Minimize dependencies and enabled dependency features.
- Avoid global mutable state and ambient configuration.
- Write comments only for a non-obvious reason, invariant, proof
  correspondence, security boundary, or platform constraint.
- Do not write comments that repeat the code.
- Add a `SAFETY:` comment to every `unsafe` block. State each precondition and
  why it holds.
- Write public Rust doc comments in ASD-STE100 Simplified Technical English.
- Use short declarative sentences, active voice, and one term for one concept.
- State units, preconditions, errors, and security effects explicitly.
- Do not use vague words, idioms, unexplained abbreviations, or promotional
  claims in technical documentation.

## Security and data handling

- Do not put secret values in plans, receipts, logs, fixtures, or tests.
- Pass only registered environment names to a child.
- Close undeclared file descriptors before child execution.
- Use temporary roots for tests. Do not depend on the contributor's home
  directory, credentials, user configuration, or network access.
- Record unsupported platform capabilities as unsupported. Do not count mocks,
  containers, or skipped tests as native Linux enforcement evidence.
- Preserve every assumption and trusted-computing-base role across receipt
  composition.

## Validation

Run `just ci` before submitting a change after that command exists. Until the
repository skeleton provides it, run every available check that applies to the
files you changed and state which gates are not yet implemented.

Before finishing work:

- inspect the working tree and preserve unrelated user changes;
- check Markdown and generated artifacts for drift;
- confirm producer and verifier agreement when their contracts change;
- confirm that negative and adversarial cases fail for the expected reason;
- inspect Proofbound for weakened, missing, or stale evidence; and
- do not commit or push unless the user asks.
