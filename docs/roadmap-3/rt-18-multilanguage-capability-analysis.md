# RT-18 candidate: multi-language capability analysis

**Status:** candidate; adapter-boundary planning permitted, analyzer claims blocked

**Primary owners:** each analyzer owns its language semantics. Runtime owns
provenance import and comparison. Capsec owns Capsec report meaning.

**Start gate:** RT-8 accepts the diagnostic profile and one maintained Python
and one maintained TypeScript workload require better drafting.

## Product outcome

A developer can combine language-specific source observations with static
executable closure and diagnostic runtime observations without presenting any
analysis as complete authority inference.

## Language-neutral observation envelope

An observation envelope should identify:

- language and runtime profile;
- analyzer source and artifact identity;
- exact source closure and dependency-lock identity;
- configuration and enabled analysis depth;
- bounded finding inventory with source locations;
- unsupported syntax, dynamic-loading, macro, FFI, native-extension, and
  reflection cases;
- completeness state and residual assumptions; and
- canonical report bytes and content identity.

The envelope carries findings. It does not define each language's analysis
semantics.

## Runtime use

- Import the report outside the pure authority core.
- Render findings only as `source-observation` provenance.
- Compare them with human-authored authority and diagnostic observations.
- Require human selection of all final authority and limits.
- Preserve missing or incomplete analysis as visible open items.

## Required attacks

- bind a report to different source or lockfile bytes;
- omit dynamically imported modules or native extensions;
- hide network access behind reflection, subprocesses, macros, or FFI;
- relabel incomplete analysis as complete;
- mix analyzer artifacts under one report identity; and
- broaden a Runtime draft automatically from a finding.

## Promotion gate

Promote RT-18 only when RT-8 proves the shared provenance boundary useful and
the Python and TypeScript reference workloads show a material reduction in plan
completion time or unexplained denials.

## Rejection gate

Reject a language-neutral analyzer that hides language-specific limits, a
completeness claim without a closed source and dependency model, or any path
that turns findings into accepted authority.
