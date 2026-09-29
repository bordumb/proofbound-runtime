# Proofbound Runtime TypeScript SDK

This package constructs validated version 2 and version 3 plan bytes, invokes an explicitly
selected pbr process without a shell, and strictly decodes its JSON control
result. It requires Node.js 22.6 or newer and has no runtime dependencies.

Use `buildPlanV3` for an exact declared-egress authority and
`parseRunResultV3` (or `run({ resultVersion: 3, ... })`) for its control result.
Version 3 execution remains unavailable until the release's
`network_modes` inventory admits `declared-egress` under Specification 0017.

It does not execute Runtime policy in-process or verify receipts. See
docs/specs/0012_plan_sdks.md in the source repository for the complete boundary.
