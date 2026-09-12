# Independent review records for upstream Proofbound changes

- **Reviewer:** Claude, an agent independent of the authoring agent
- **Date:** 2026-09-11
- **Status of these records:** review findings, not approvals. The
  maintainer decides whether an AI review satisfies the UP-0.1 requirement
  for a reviewer other than the change author.
- **Scope:** `bordumb/proof-bound` pull requests 2, 6, 7, 8, and 9

Each record lists the exact diff reviewed, the findings with file and line,
and a verdict. A checkbox in
[product-roadmap-feedback.md](product-roadmap-feedback.md) closes only when
the listed required changes have landed and a re-review records a verdict of
approve.

## PR 2: Add Python and TypeScript assurance support

- **Head:** `dev-languageAgnosticism` into `main`, merge base `0a5c6b6`
- **Reviewed diff:** `git diff main...dev-languageAgnosticism`
- **Note:** the reviewed head is an ancestor of `70af5e6`, the commit Runtime
  pins, so Runtime already consumes this work. Merging changes nothing for
  Runtime's composer.
- **Verdict:** REQUEST CHANGES. Five blocking items.
- **Update 2026-09-11:** the authoring agent reports item 1 fixed in
  `e4d67f3`. That fix has not been re-reviewed.
- **Update 2026-09-12:** all five blocking-item fixes are pushed at exact
  head `21ab780127193422219254d31077952475094908`. The implementation commits
  are `e4d67f3` and `78022a3` for items 1 and 2, `c36ea65` for item 3,
  `e049463` for item 4, and `b033df1` for item 5. Two subsequent test-only
  commits, `424e0c7` and `21ab780`, make repository fixtures safe under a
  reused build cache. `cargo xtask ci` completed all 12 stages locally at
  that exact clean head, including fresh Python and TypeScript reference
  verticals and standalone verification of both portable releases. This is
  an implementation report, not a review verdict; PR 2 remains REQUEST
  CHANGES until an independent re-review records approval.

### Blocking items

1. **Status derivation weakened for every subject, not only Python and
   Node.** `mutation_witness_valid` dropped the two-independent-shadow
   requirement. `baseline.program != mutant.program` became
   `baseline.program != mutant.program || baseline.args != mutant.args` at
   `crates/proofbound-core/src/evidence.rs:1810`, mirrored at
   `crates/proofbound-verify/src/verifier.rs:2143`.
   `command_runs_exact_check` gained an unguarded pytest branch that accepts
   any command containing `-m pytest` whose last argument merely ends with
   the check id, at `evidence.rs:1866-1875`. `witness.subject` is only
   length-checked at `evidence.rs:1828`, so branch selection is
   attacker-controlled. Failure scenario: a hand-authored receipt with a
   subject that is not `python:` or `npm:`, two pytest-shaped commands that
   differ only in a path argument, and exit code 101 validates as a mutation
   witness in both engines. It was previously rejected. This moves `INVALID`
   or `OPEN` to `TESTED`. Required: restore the two-shadow rule for
   non-Python and non-Node subjects, gate the pytest and vitest branches on
   a validated subject grammar rather than an unvalidated prefix, and add
   the attack case to the shared corpus. Related: `verifier.rs:2251`.

2. **Node mutation receipts cannot distinguish the two shadows.**
   `logicalize_value` maps both shadow roots to `$PROJECT` at
   `crates/proofbound-adapter-node/src/lib.rs:2608`, and core and verify
   then require baseline and mutant commands to be byte-identical at
   `evidence.rs:1797`. The Node receipt therefore contains nothing that
   distinguishes the two shadows. Rust uses distinct programs; Python uses
   `$BASELINE` and `$MUTANT` rootdirs. Required: give Node mutation receipts
   a shadow-distinguishing command form, or state in Specification 0003 why
   identical commands are acceptable for the Node route.

3. **Silent schema relaxations inside existing schema versions.**
   `allowed_exit_codes` changed from `const [101]` to `oneOf [1] | [101]`
   inside the unversioned `proofbound-adapter-observation/2`,
   `proofbound-evidence/3`, and receipt schemas.
   `schemas/mutation-registry.schema.json` widened `symbol` from a
   structured pattern to `^[ -~]+$` with no version bump. Required: bump the
   affected schema versions instead of editing version 2 and version 3 in
   place.

4. **The Node execution route ships CI-unverified.**
   `.github/workflows/ci.yml` is not in the diff and installs no Node
   toolchain. `cargo xtask ci` stage 10 runs only `demo allowance` and
   `demo artifact-certificate` at `crates/xtask/src/main.rs:929-943`, and
   `demo.rs` has exactly two runners. Neither `demo/python-inventory-service`
   nor `demo/typescript-codec` is referenced by any crate, workflow, or
   justfile. The whole Node path, `npm ci`, vitest, tsc, `npm pack`, and
   mutation replay, is covered only by mocked unit tests. The external
   trials in the PR body (Click, ItsDangerous, attrs, HTTPX, Vitest Coverage
   Report Action, Node TypeScript Boilerplate) are local-only and not
   reproducible from the repository. Required: wire both new demos into
   `xtask ci` stage 10 with a Node setup step, or state in the PR that the
   Node route ships CI-unverified.

5. **`node_modules` is missing from `TRANSLATION_RESERVED_PATH_COMPONENTS`**
   at `crates/proofbound-manifest/src/model.rs:506-516`. The list still
   names `.venv` and `__pycache__` but not `node_modules`, which
   contradicts commit `c7abf2f` "align generated-state boundaries". Required:
   add `node_modules`. Also note that no exclusion list covers `dist/`,
   `build/`, or `coverage/`.

### Non-blocking findings

- No adapter-level negative tests exist for the Hypothesis property route or
  the Python distribution route, and none for timeout or truncation on the
  Node side.
- `vitest`, `tsc`, `mypy`, and `pytest` are bound only by self-reported
  version strings (`adapter-node/src/lib.rs:658-665`,
  `adapter-test/src/lib.rs:1751`) plus lockfile integrity. `node`, `npm`,
  and `python3` are digested. Specification 0003 section 5.1 permits the
  version-string binding, so this is conformant but not sufficient. Consider
  digesting the resolved entry points.
- Zero-mutant claims still reach `TESTED` by design, because there is no
  coverage metric. State this explicitly in the specification.
- The PR's assurance-regression gate is discharged by
  `proofbound/reviews/pr-0002-language-support.toml`, a self-review envelope
  signed by the authoring agent. That is the self-review-as-independent-
  review pattern UP-0.1 forbids. A non-author envelope is required at merge.

### Findings that pass

- New adapters fail closed. All error variants route through `failed()` or
  `failed_response()`, which null the evidence
  (`adapter-node/src/lib.rs:408`, `adapter-test/src/lib.rs:654`). Timeouts
  become `NodeError::Budget` (`adapter-node/src/lib.rs:268`) or
  `AdapterError::Timeout`. The compiler refuses any `!response.success` at
  `crates/proofbound-cli/src/compile.rs:1896`, pinned by
  `failed_protocol_response_never_admits_attached_evidence`. Negative tests
  cited: `mypy_requires_agreeing_exit_and_empty_json_diagnostics`,
  `pyright_count_only_output_is_not_an_authoritative_inventory`
  (`adapter-test/src/lib.rs:5488`, `:5510`),
  `vitest_report_requires_exactly_the_registered_assertion`,
  `tsc_configuration_requires_literal_strict_json`,
  `lockfile_validation_requires_integrity_and_rejects_local_dependencies`,
  `tarball_members_must_be_regular_reviewed_source_bytes`,
  `installation_never_enables_lifecycle_scripts`
  (`adapter-node/src/lib.rs:2789-3014`).
- `node_modules` is excluded from five closure sets
  (`crates/proofbound-evidence/src/closure.rs:243`, `cli/compile.rs:960`,
  `cli/scaffold.rs:1215`, `adapter-test/src/lib.rs:5046`, `.gitignore`)
  with tests at `adapter-test/src/lib.rs:5605` and `compile.rs:6705`.
- The verifier is in lockstep. Every new record type, the `python_plugins`
  inventory, and the reshaped mutation predicate land in `proofbound-verify`
  with agreement tests in `crates/proofbound-verify/tests/conformance.rs`:
  `distribution_reproduction_is_recomputed_from_portable_candidate_identities`,
  `node_mutation_receipt_requires_exact_vitest_abi_and_package_inputs`,
  `python_mutation_receipt_requires_exact_pytest_shadow_abi`.
- A mutation survivor is not merely reported: the adapter errors and
  `proofbound check` aborts (`compile.rs:1896`).
- `RELEASE_ENVELOPE_SCHEMA_V3` and `COMPILED_RELEASE_SCHEMA_V3` are
  untouched.
- The `StaticCheck` facet is added only as an empirical `Ledger` kind
  (`crates/proofbound-core/src/types.rs:116`, `:134`, `:151`,
  `status.rs:1097`), and the shared corpus gains the `PROVED`-upgrade attack
  case in `proofbound/conformance/v1/status-graphs.json`.

## PR 6: Promote the verified Proofbound integration line

- **Head:** `codex/exact-artifact-observations` at `a6964f6` into `main`
  at `0a5c6b6`
- **Reviewed:** topology, envelopes, regression set, PR 2 dependency, CI,
  schema versions. Not a line-by-line read of the 618 changed files.
- **Verdict:** BLOCKING. Not a merge candidate.

### Findings

1. **Topology passes.** 249 commits. PRs 3, 4, and 5 are present as real
   merge commits (`802a5a5`, `c16d497`, `70af5e6`), not cherry-picks. The
   merge base equals `origin/main` exactly. Runtime's pinned `70af5e6` is on
   the line, one commit behind the head. The only later commit is `a6964f6`
   "review: retire superseded integration approval".
2. **No approval envelope covers this promotion.** Envelope history on the
   line: `ed4fab9`, `1deb41f`, `d6b4592`, `8149a95`, `d5d9aab`, `c4ad13b`,
   `788e359`, `a6964f6`. The envelope `788e359` was followed by later byte
   changes and was correctly retired at the head. `proofbound/reviews/` at
   the head contains only `pr-0001-assurance-regressions.toml`, the same as
   on `main`.
3. **The regression set fails closed.** `proofbound diff
   main..codex/exact-artifact-observations --json` exits 2 with
   `PB-DIFF-0002`: 618 changes, 43 regressions, every one
   `approved_by: null`. Breakdown: 27 `enlarged-tcb` (toolchain corpus bytes
   in `docs/experiments/0016-native-canonical-parser/corpus/toolchain.json`
   and others, across PB-SELF, PY, and TS claims); 12 `formal-downgrade`
   (`demo/allowance/proofbound/evidence/rust-kernel-tests.toml` flips
   `kind = "property-test"` to `"example-test"`, so DEMO-TRANSFER-001
   through 006 each lose a property-test citation); 4 `new-assumption`
   (PY-RUNTIME-001 and TS-RUNTIME-001 newly constrain PY-RESERVATION-001,
   PY-WHEEL-001, TS-CODEC-001, TS-PACKAGE-001). Schemas moved:
   `receipt.schema.json` +146, `evidence-unit.schema.json` +294, new
   `observation-inputs.schema.json`.
4. **PR 2 is embedded and unreviewed.** `dev-languageAgnosticism` is an
   ancestor of the head; all six PR 2 commits are inside PR 6. Merging PR 6
   would land PR 2 without review.
5. **CI fails for the right reason.** Both "Verify only" runs fail on
   `PB-DIFF-0002`. `isDraft: true`, `mergeStateStatus: UNSTABLE`,
   `reviewDecision` empty.
6. **Schema versions match Runtime.** The head emits
   `proofbound-release-envelope/6`, `proofbound-compiled-release/6`
   (`crates/proofbound-verify/src/format.rs`, `compile.rs:439`), and
   `proofbound-verification-report/3` (`verifier.rs:555`), which is exactly
   what Runtime Specification 0003 requires. `main` is still at envelope/3
   and report/1, so Runtime cannot compose against `main` today.

### Required before merge

1. Review and merge PR 2 first, then recompute the promotion diff against
   the new `main`.
2. Adjudicate all 43 regressions by hand. The 12 property-test to
   example-test downgrades need restoration or a written rationale; an
   approval envelope must not bless them silently.
3. Review the schema deltas and the envelope 3 to 6 and report 1 to 3 jumps
   as status-derivation and release-composition surfaces.
4. Add the approval-only envelope commit as the new head with zero bytes
   after it, then re-run the verify-only gate at that exact head.
5. Re-point Runtime's pin in `ci.yml`, `release.yml`, `lakefile.toml`, and
   `lake-manifest.json` to the resulting mainline identity.

## PR 7: Reject claim/evidence bounded-domain drift

- **Head:** `codex/pbf-0007-domain-consistency` into
  `codex/exact-artifact-observations`, 10 files
- **CI:** the `pull_request` run passes; the `push` run on the same head
  fails with `PB-DIFF-0002`, inherited from the base line.
- **Verdict:** APPROVE WITH REQUIRED CHANGES.

### Findings

- Claim-side (`compile.rs:3858-3877`) and evidence-side
  (`compile.rs:1785-1796`) `BoundedDomain` derive from the same
  `BoundedDomainManifest` through identical code, so the digest comparison
  is meaningful and ordering-key drift is bound through
  `registration_sha256`. Status derivation changes for bounded and
  exhaustive evidence: claims lacking `bounded_domain` move from admitted to
  INVALID. That is fail-closed and intended, but it is a migration event.

1. **HIGH, unversioned compatibility break.** `ClaimReceipt.bounded_domain`
   is added at `crates/proofbound-verify/src/format.rs:261` and
   `schemas/receipt.schema.json:91` with no compiled-release schema bump;
   `format.rs:14-17` still tops out at `COMPILED_RELEASE_SCHEMA_V6`. Every
   already-issued v3 to v6 release with a bounded claim deserializes
   `bounded_domain: None` and hard-fails at `verifier.rs:4437`. Required:
   introduce `proofbound-compiled-release/7` and gate the new requirement on
   it. Runtime note: Specification 0003 requires envelope/6 and payload/6,
   so Runtime's composer must move in the same wave.
2. **MEDIUM, `registered_domain_language` silently repurposed.**
   `status.rs:802` and `verifier.rs:4413` require the public language to
   equal `bounded_domain.description` exactly. PBF-0007 asks that it never
   be formed from disagreeing data; exact equality makes the field
   redundant. Required: document the deprecation or relax to a derivation
   rule.
3. **MEDIUM, over-enforcement versus the feedback record.** `status.rs:812`
   iterates all `valid_evidence`, not only primary bounded evidence. A
   legitimately cited corroborating bounded receipt over a narrower domain
   now invalidates the claim. Required: scope the loop to primary bounded
   evidence.
4. **LOW, verifier coverage is indirect.** The verifier's `BoundedDomain` in
   `format.rs` has no `constraints` field, so it cannot check the ordering
   key field-wise; `conformance.rs:1843` simulates it by mutating
   `registration_sha256`. The core test at `status/tests.rs:962-987` has a
   mixed-domain multi-evidence case; the verifier conformance suite does
   not. Required: add one.

## PR 8: Retain adapter failures in status reports

- **Head:** `codex/pbf-0003-unit-diagnostics` into the PR 7 branch, 6 files
- **CI:** as PR 7.
- **Verdict:** REQUEST CHANGES. Items 1 and 2 are stated acceptance
  criteria in PBF-0003 and UP-0.3.

### Findings

- Schema versioning is done correctly: `schemas/report.schema.json:9` moves
  to `proofbound-report/2`, `unit_runs` is required, `report.rs:38`. The
  `!response.success` restructure at `compile.rs:1911-1922` returning
  `Ok(None, run)` is a genuine improvement. Diagnostics never admit
  evidence; claim assumptions, bounds, and TCB roles are untouched.

1. **HIGH, the claim explanation is unchanged.** `render_unit_runs` is
   called only from `render_status` at `report.rs:72`. `render_claim` at
   `report.rs:101-175`, and its `proofbound-claim-report/1` JSON, still show
   only missing-evidence citations, which is the exact symptom PBF-0003 was
   filed against. Required: render the same unit-run cause in the claim
   report and claim explanation.
2. **HIGH, timeout is not distinguished.** The `outcome` enum at
   `report.schema.json:26` has no timeout value; `compile.rs:1963-1967` maps
   everything unmatched to `"failed"`; no `PB-ADAPTER-*` timeout code exists
   in `adapter.rs`. PBF-0003's second occurrence is the 900 second Kani
   budget. Required: add a timeout outcome and code.
3. **MEDIUM, stable code recovered by string scraping.**
   `adapter_execution_diagnostic` at `compile.rs:1957-1984` regex-scans the
   flattened `anyhow` display text for the first `PB-ADAPTER-####` token. A
   nested or quoted code wins over the real one, and an un-coded failure
   collapses to `PB-ADAPTER-0900`. Required: carry a typed error.
4. **MEDIUM, adapter identity is three different things.**
   `unit.adapter.executable()` on the error path (`compile.rs:1969`),
   `format!("{:?}", unit.adapter)` on the cache path (`compile.rs:1893`),
   `response.adapter` on success. PBF-0003 asks for the executable
   identity. Required: one identity form.
5. **MEDIUM, adapter protocol tightened without a version bump.**
   `adapter.rs:192-197` now rejects `success: false` responses carrying no
   diagnostics, while `adapter.rs:44` and `:126` still declare
   `proofbound-adapter-protocol/1`. Existing third-party adapters break as
   protocol failures. Required: version the protocol.
6. **LOW, no end-to-end fixture.** PBF-0003 asks for a fixture with an
   absent registered adapter; coverage is unit-level only at
   `report.rs:508` and `compile.rs:8907`.

## PR 9: Prepare reviewed Lean identity updates

- **Head:** `codex/pbf-0002-lean-identity-update` into the PR 8 branch,
  27 files
- **CI:** runs still pending at review time.
- **Verdict:** REQUEST CHANGES. The core update path is approvable once
  items 1 to 3 are addressed and CI is green.

### Findings

- The update path is well constructed: single-claim ownership, sole-output
  boundary, and declaration and inventory checks in
  `lean_identity_update_target` (`compile.rs:963-1017`); a double re-parse
  guard confirming only the four fields changed (`compile.rs:1108-1128`,
  `:1148-1165`); policy axiom admission before any write
  (`compile.rs:1098-1118`).

1. **HIGH, ADR 0025 misstates compatibility.** It says no manifest or
   receipt schema changes and unchanged verify-only behavior. In fact
   `model.rs:10` bumps the adapter unit schema to `/2`, and `receipt.rs:30`
   and `:132` bump `proofbound-lean-unit-configuration` to `/2` including
   its digest domain separator. Every existing Lean receipt's
   `unit_configuration_sha256` changes, invalidating all cached Lean
   evidence. Required: correct the ADR and state the migration.
2. **HIGH, an unrelated `lake build` was added to the check path.**
   `runtime.rs:63-115` inserts a build command into the sealed audit, the
   captured execution, and the run indices. This addresses PBF-0003's third
   occurrence, not PBF-0002, and changes every Lean receipt's execution
   capture. Required: split it into its own PR with its own falsifiers.
3. **MEDIUM, provenance observation moved into the orchestrator's TCB.**
   `receipt.rs:119-134` deletes the adapter's own `git_identity` call and
   echoes `unit.project_revision` and `unit.tree_state` from the request.
   PBF-0002 sanctions the binding, but the adapter no longer independently
   observes tree state, so a wrong or hostile caller can assert `Clean`.
   Required: record this TCB shift in ADR 0025.
4. **MEDIUM, claim manifests become generated artifacts of their own
   proofs.** Adding `outputs = [".../DEMO-TRANSFER-00X.toml"]` to five demo
   units feeds `exact_artifacts(root, &evidence_unit.outputs)` at
   `receipt.rs:117` on the check path too. Not load-bearing for status
   today, but the claim manifest's bytes now enter its own evidence
   provenance, and any edit invalidates the receipt. State this or remove
   the outputs.
5. **LOW, no test for an out-of-boundary adapter write** in the new Lean
   path, although ADR 0025 lists it as a required falsifier.
