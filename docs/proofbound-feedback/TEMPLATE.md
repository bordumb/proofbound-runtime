# PBF-NNNN: Short title

- **Status:** `observed`
- **Priority:** `near-term`
- **Kind:** `subject-model`
- **Created:** YYYY-MM-DD
- **Last updated:** YYYY-MM-DD
- **Runtime claim:** `PBR-...` or `none`
- **Runtime milestone:** Milestone N
- **Proofbound target:** note, specification, ADR, plugin, verifier, or unknown
- **Upstream record:** not upstreamed
- **Supersedes:** none
- **Superseded by:** none

## Summary

State the missing generic Proofbound capability in two or three sentences.

## Runtime observation

Describe the exact runtime behavior, failing case, or blocked claim that exposed
the gap.

Include exact paths, schema versions, claim IDs, receipt identities, test names,
and commands when they exist. Separate observed facts from inferences.

## Ownership test

Explain why Proofbound should own this behavior.

Name at least one plausible non-runtime consumer when the proposal adds generic
framework semantics. If the need is specific to agents, Linux, Landlock,
seccomp, cgroups, or Runtime policy, keep it in Proofbound Runtime instead.

## Assurance risk

Explain what can become overstated, omitted, downgraded, stale, or
unverifiable if the gap remains.

State which evidence distinction or fail-closed rule is at risk.

## Proposed upstream behavior

Describe the smallest generic behavior that Proofbound needs.

Do not prescribe internal implementation unless the trust boundary requires
it. Do not introduce runtime-domain semantics into Proofbound core.

## Evidence meaning

### Establishes

- State only what valid evidence can establish.

### Does not establish

- State the bounds, assumptions, and stronger claims that remain unavailable.

## Acceptance criteria

1. State one exact positive behavior.
2. State one missing-data or unsupported-capability rejection.
3. State one omission, substitution, downgrade, or replay rejection.
4. Require equivalent derivation by the producer and independent verifier when
   the result is portable.
5. Require every inherited assumption, bound, and trusted-computing-base role
   to remain visible.

## Compatibility and migration

Describe schema versioning, existing receipt behavior, migration, and downgrade
handling. Write `None` when the item has no compatibility effect.

## Local treatment

Describe the current fail-closed workaround. If there is no sound workaround,
name the Runtime claim or milestone that remains blocked.

Do not make the local workaround appear stronger than it is.

## Upstream handoff

Add exact Proofbound repository paths and links after upstream work begins.

- **Destination:** not upstreamed
- **Issue:** none
- **Specification or ADR:** none
- **Commit or pull request:** none

## Resolution

Record the upstream decision and the Runtime change that consumed it. Leave this
section as `Unresolved` until Proofbound makes a decision.

Unresolved.
