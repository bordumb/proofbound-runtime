# Specification 0003: Release and execution receipt composition

**Status:** Accepted implementation specification

**Version:** 0.1.0

**Date:** 2026-09-07

This specification defines the first typed Proofbound plugin for Proofbound
Runtime. The plugin lives in this repository, outside Proofbound core. It
composes independently verified release assurance with one independently
verified Runtime execution without promoting either receipt beyond its own
evidence.

## Goal

The composition answers one bounded question:

> Did these exact Runtime release binaries produce and verify this exact
> execution receipt, and what assurance, assumptions, exclusions, and open
> obligations did the independently verified Proofbound release report for the
> registered source revision retain?

It does not prove that the source produced the binaries, that the binaries
implement the source semantics, that either verifier is correct, or that the
host observations are honest. Those remain represented by the release report,
the Runtime receipt, explicit tool identities, and inherited assumptions.

## Command

The public executable is `pbr-compose`:

```text
pbr-compose \
  --release <proofbound-release-directory> \
  --proofbound-verifier <path> \
  --runtime-bundle <extracted-runtime-bundle-directory> \
  --execution-receipt <path> \
  --execution-commitment sha256:<digest> \
  --expected-execution-id <uuid> \
  --output <absent-path>
pbr-compose --help
pbr-compose --version
```

Arguments not shown above are rejected. Every path is explicit. The output
path must not exist and is published with the same temporary-file plus
no-replace-link pattern used by `pbr run`.

The plugin executes the supplied `proofbound-verifier` with
`--release <directory> --json`. It executes the exact `pbr-verify` found in the
Runtime bundle with the supplied execution commitment and receipt. A nonzero
status, stderr output, non-UTF-8 output, oversized output, duplicate or unknown
JSON field, unexpected schema, or noncanonical execution receipt fails closed.

## Inputs

### Proofbound release

The Proofbound release directory must contain a valid contextual exact-
observation release: `proofbound-release-envelope/5` with a
`proofbound-compiled-release/5` payload. The independent verifier result must
be a closed `proofbound-verification-report/3` with verdict `bytes-observed`.
The report and payload must name the same nonempty evidence context. The plugin
binds that context, the exact envelope bytes, its payload identity, the exact
verification-report bytes, the verifier executable identity, project name,
and project revision.

Every claim row is retained with its formal, linkage, assumption, and policy
facets and its complete exact-artifact observation inventory. Every assumption
and every entry in `not_proved_out_of_scope` is retained. The plugin never
removes a claim because its status is weak or its publication policy is
blocked. It rejects a version 3 or version 4 release because those carriers do
not bind Runtime's required release evidence context.

### Runtime bundle

The extracted directory must contain exactly these regular files:

- `pbr`;
- `pbr-native-launcher`;
- `pbr-verify`;
- `pbr-compose`; and
- `RELEASE-MANIFEST.json`.

The manifest uses `proofbound-runtime-release-manifest/1`. Its architecture,
target, toolchain, and version are nonempty closed values. Its artifact list
must contain the four binary logical names exactly once in the order above.
The plugin recomputes every binary's SHA-256 and byte size and rejects
symlinks, non-regular files, missing executable bits, extra manifest roles,
duplicates, substitutions, and size drift.

The running `pbr-compose` executable must have the same bytes as the bundled
`pbr-compose` entry. This makes the exact composition tool identity visible; it
does not prove that the tool is correct.

### Runtime execution

The execution receipt must be canonical `proofbound-runtime-receipt/1` bytes.
The bundled `pbr-verify` must accept those exact bytes against the independently
supplied commitment. The plugin then strictly reads only the fields required
for the cross-receipt join:

- `execution_id`;
- `runtime.runtime`;
- `runtime.launcher`;
- `producer`;
- `assumptions`;
- `trusted_computing_base`; and
- `eligibility`.

The execution ID must equal the separately supplied expected ID. The runtime
and producer identities must both equal the bundled `pbr` identity. The
launcher identity must equal the bundled `pbr-native-launcher` identity. The
receipt's trusted-computing-base inventory must contain exact entries for the
same runtime and launcher identities. Reusable composition additionally
requires the independent execution-verification report to say reusable with
an empty reason inventory.

## Output

The plugin emits canonical compact JSON with schema
`proofbound-runtime-composed-receipt/1`. The closed top-level fields are:

- `schema`;
- `composition_id`;
- `release`;
- `runtime_bundle`;
- `execution`;
- `claims`;
- `assumptions`;
- `not_proved_out_of_scope`;
- `trusted_computing_base`; and
- `eligibility`.

`composition_id` is the domain-separated SHA-256 of all other canonical fields
using `proofbound-runtime-composed-receipt/1\n` as the domain. Artifact
identities contain a logical role, `sha256:<64 lowercase hex>`, and decimal
string byte size. The output carries exact input commitments and verifier
identities rather than only their reported verdicts.

Assumptions and trusted-computing-base entries are strict sorted sets. The
output union must contain every entry inherited from either input. An entry is
tagged with `release`, `execution`, or both origins; same-name entries with
different meanings remain distinct. Open obligations and exclusions are
retained under their originating claim.

Eligibility is derived, never caller supplied:

- `composed` means both independent verifications succeeded, all exact-byte
  joins succeeded, the expected execution ID matched, and execution
  eligibility was reusable;
- `non-composed` is not emitted as a successful artifact; every failed premise
  returns a typed error and creates no output.

The plugin records Proofbound's exact claim facets but derives no new
Proofbound facet. In particular, this receipt does not turn `MODEL_ONLY` into
`ARTIFACT_BOUND`. The `bytes-observed` verdict records complete independent
byte observation; it does not establish theorem-to-artifact linkage.

## Attack inventory

The version 1 implementation must freeze and reject at least these cases:

| ID | Mutation | Required result |
| --- | --- | --- |
| `PBR-COMP-001` | Omit one Proofbound claim row | `composition.release.claim-omitted` |
| `PBR-COMP-002` | Substitute the Proofbound payload digest | `composition.release.substituted` |
| `PBR-COMP-003` | Change a claim facet or policy bit | `composition.release.downgraded` |
| `PBR-COMP-004` | Substitute one Runtime binary | `composition.bundle.substituted` |
| `PBR-COMP-005` | Swap runtime and launcher roles | `composition.bundle.role-mismatch` |
| `PBR-COMP-006` | Replay a receipt under another expected execution ID | `composition.execution.replayed` |
| `PBR-COMP-007` | Remove one inherited assumption | `composition.assumption.omitted` |
| `PBR-COMP-008` | Remove one trusted-computing-base entry | `composition.tcb.omitted` |
| `PBR-COMP-009` | Supply a noncanonical execution receipt | propagate the exact verifier rejection |
| `PBR-COMP-010` | Supply an unknown schema or field | `composition.schema.invalid` |
| `PBR-COMP-011` | Replace an existing output path | `composition.output.exists` |
| `PBR-COMP-012` | Present `MODEL_ONLY` as `ARTIFACT_BOUND` | `composition.release.downgraded` |
| `PBR-COMP-013` | Downgrade the contextual release to a pre-context schema or verdict | `composition.release.downgraded` |
| `PBR-COMP-014` | Omit or substitute the evidence context across the release and report | `composition.release.context-mismatch` |
| `PBR-COMP-015` | Omit or change an exact-artifact observation retained by a claim | `composition.release.downgraded` |

The test corpus must include one valid chain plus every registered mutation.
Producer and a separately implemented verification path must agree on the
canonical composition identity before the receipt is release evidence.

## Trust boundary

The plugin trusts the explicitly supplied verifier executables to perform
their domain checks, but records their exact identities. It independently
checks the narrow joins between their outputs and the byte identities it can
observe. It does not trust a caller-authored success Boolean, status facet,
artifact digest, assumption union, or TCB union.

The caller remains responsible for transporting the execution commitment and
expected execution ID independently of the receipt. The release operator
remains responsible for the source-to-binary build relationship under
`PBR-TOOLCHAIN-AX-003`. Exact-artifact observation records show which bytes the
registered procedures exercised. They do not prove that the source produced
those bytes or that the bytes implement the source model.
