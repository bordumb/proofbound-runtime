# ADR 0005: Cache exact formal tools without caching assurance conclusions

- **Status:** accepted by the maintainer on Claude's independent model review;
  retention measurement open
- **Date:** 2026-09-10
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** required pull-request and mainline verification workflows

## Context

The last successful serial Verify run before CI partitioning spent about 21
minutes building the pinned Charon and Aeneas closure and about 23 minutes in
the repository gate. The proof tools were rebuilt for every superseding commit,
including commits that changed only documentation or workflow mechanics.

RT-0.3 now records stage and unit duration as operational build metadata and
keeps the fresh Proofbound run separate from those records. The first measured
bottleneck is therefore the exact Nix closure used for source translation, not
the assurance conclusions produced from Runtime source.

A restored cache is not evidence. The cache action, GitHub cache service, Nix
store database, and restored bytes can affect which tool executes. Version
output alone cannot prove that a hostile replacement implements the named
tool. Any required workflow that consumes a cache must retain that premise
explicitly.

## Proposed decision

Cache only the Nix store used to obtain the exact registered Charon and Aeneas
toolchain in the required formal lane.

- Pin the cache action by its full commit identity.
- Use one exact primary key containing the runner operating system and
  architecture, the complete Aeneas source revision, and the registered
  translation-toolchain lock identity.
- Do not use prefix or fallback restore keys. A changed toolchain produces a
  miss and a new isolated cache.
- Run the same `nix build` command on hits and misses, then verify the registered
  Charon and Aeneas version outputs before any refinement or evidence command.
- Keep `proofbound check --fresh` in every protected full gate. Never restore
  `.proofbound`, Rust or Lean compiled project outputs, release artifacts, or
  prior verification results.
- Do not use the cache in release reproduction. Both release architectures
  retain clean double builds and exact artifact observation.
- Upload timing as operational metadata so a cache hit can change duration but
  cannot change evidence kind, freshness, bounds, status, or public language.
- Register the pinned cache action and GitHub Actions cache service under the
  existing toolchain assumption and trusted-computing-base description.

The initial implementation uses `nix-community/cache-nix-action` at commit
`7df957e333c1e5da7721f60227dbba6d06080569`. Changing that identity, cache
scope, key construction, restored paths, or downstream identity checks reopens
this decision.

## Initial operational observation

The first miss and hit establish that the exact-key mechanism functions; they
do not satisfy the two-week retention gate below. Seed run
[`34551042525`](https://github.com/bordumb/proofbound-runtime/actions/runs/34551042525)
at exact source `ccfa7f3bbfe1e4e38bc9ea1af4d03f2e943e23bb` built the translation-tool
closure in 20 minutes 22 seconds and saved cache entry `7571759207` under key
`formal-nix-v1-Linux-X64-3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0-2c46b140b0b35c42621384abf2ff0cef460cff5186c5ff59733b6abdd77af205`.

Follow-up run
[`34554553968`](https://github.com/bordumb/proofbound-runtime/actions/runs/34554553968)
at exact source `2232851973b8fabc873a056b87d25442b4d2ddc4` restored that closure in 2
minutes 7 seconds, installed the pinned Charon and Aeneas outputs in 15 seconds,
and then completed the unchanged fresh evidence gate successfully. Its retained
formal timing artifact records a complete 1,096,887 ms formal stage, including
734,720 ms for fresh evidence. The cache therefore removed about 18 minutes
from this observed tool-install slice without reusing an assurance conclusion.
One hit is not a latency distribution, reliability result, or independent
review.

## Consequences

### Positive

- The dominant repeated tool build can be reused without reusing a Runtime
  proof, test result, receipt, compiled object, or release artifact.
- Exact keys make toolchain changes fail toward recomputation rather than a
  partial cache match.
- A cache outage or eviction degrades to a normal clean tool build.
- Timing artifacts show whether the cache meets the roadmap target in practice.

### Negative

- The pinned cache action and GitHub cache service become explicit required-CI
  dependencies and TCB roles.
- Post-restore version checks detect accidental mismatch but do not prove the
  behavior of hostile replacement bytes. The toolchain assumption remains.
- Saving and restoring a Nix store may cost more than rebuilding on some runs;
  the timing record must justify retaining the mechanism.
- The cache does not accelerate Rust, Kani, Proofbound, or Lean installation in
  this first slice.

## Alternatives

### Restore prior Proofbound output

Rejected. A prior compiled manifest or evidence receipt is an assurance
conclusion, not a tool. Restoring it would undermine the protected fresh gate.

### Use fallback cache prefixes

Rejected. A partial match can silently select a closure produced under a
different toolchain identity.

### Cache release build outputs

Rejected. Release evidence requires two clean reproductions and observation of
the final exact artifacts.

### Cache every compiler output

Deferred. Broad Rust, Lean, Kani, or project-target caches enlarge the mutable
input surface before timing demonstrates that they are needed.

## Independent review and open obligation

Claude independently reviewed this decision on 2026-09-11 against the workflow,
registered toolchain assumption, threat model, and runs `34551042525` and
`34554553968`. The review confirmed that the key is closed over the selected
toolchain, restored paths exclude assurance and release outputs, post-restore
checks run before evidence, and the added trusted-computing-base premise remains
registered. The verdict was **approve** with no required change.

The mechanism decision is accepted. The retention decision remains open until
2026-09-25 02:25 UTC, two weeks after the first green cache hit began. At that
gate, retain the cache only if the timing records show lower formal-lane latency
without any changed evidence outcome or freshness label.
