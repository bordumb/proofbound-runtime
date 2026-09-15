# Independent review records for upstream Proofbound changes

- **Reviewer:** Claude, an agent independent of the authoring agent
- **Date:** 2026-09-11
- **Status of these records:** the initial records are review findings, not
  approvals. A later section is an approval only when it names an exact
  re-reviewed head and explicitly records an APPROVE verdict. The maintainer
  decides whether an AI review satisfies the UP-0.1 requirement for a
  reviewer other than the change author.
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

### Independent re-review at exact head `21ab780127193422219254d31077952475094908`

- **Reviewer:** Codex, independent of the authoring agent
- **Review date:** 2026-09-12
- **Reviewed base:** `main` at
  `0a5c6b6dcf7e3b59cdf71ec5f8d50082c5f3a3e0`
- **Reviewed head:**
  `21ab780127193422219254d31077952475094908`
- **Reviewed range:**
  `0a5c6b6dcf7e3b59cdf71ec5f8d50082c5f3a3e0...21ab780127193422219254d31077952475094908`,
  with focused regression review of the fixes after `ed4fab9`
- **Method:** source and diff inspection, review of the committed negative
  tests and workflow wiring, and read-only inspection of both exact-head
  GitHub Actions failures. No build or test command was run during this
  review, to avoid interfering with the concurrent authoring work.
- **Verdict:** **APPROVE**. All five blocking findings are closed at the
  reviewed head. The fixes introduce no new blocking finding. This verdict
  is byte-specific and does not apply after any head change.
- **Maintainer endorsement:** **ENDORSED** for preparation of the required
  non-author approval envelope and continuation of the merge sequence. This
  endorsement is not the Proofbound approval envelope and does not bypass
  the fail-closed approval gate.

#### Disposition of the five blocking findings

1. **Closed: mutation status derivation is again subject-specific and
   fail-closed.** Core and the independent verifier now parse the witness
   subject into a closed Rust, Python, or Node form before they select a
   command grammar. Rust requires distinct `$BASELINE` and `$MUTANT`
   executable roots and its exact test ABI. Python requires the exact
   `python3 -m pytest -p no:cacheprovider --rootdir` shadow ABI. Node
   requires the exact Vitest shadow ABI. The expected mutation exit is 101
   for Rust and 1 for Python and Node. Malformed subjects, a pytest-shaped
   command for a Rust subject, and reuse of the baseline command as the
   mutant command have negative coverage in both the core status tests and
   independent-verifier conformance tests. The original cross-subject
   acceptance path is no longer present.

2. **Closed: Node receipts distinguish the two mutation shadows.** The Node
   adapter records mutation commands through a mutation-specific
   observation path. It maps the two execution roots to distinct
   `$BASELINE` and `$MUTANT` logical roots instead of mapping both to
   `$PROJECT`. Core and the independent verifier require those distinct
   roots and equal command tails. Adapter tests pin both logical command
   identities, and conformance tests reject a receipt that replays the
   baseline command as the mutant command.

3. **Closed: the relaxed wire rules have new schema versions.** The adapter
   observation schema is now version 3, the evidence schema is version 4,
   the mutation registry and witness schemas are version 3, and the release
   envelope and compiled release schemas are version 4. Producer, public
   JSON schemas, fixtures, and independent verifier agree on the new
   versions. The old constants remain only where needed to identify and
   reject superseded input; legacy-version rejection is covered by tests.
   The change is an explicit pre-release cutover, not a silent edit to an
   accepted wire version.

4. **Closed: both new language reference verticals are part of CI.** Stage
   10 now runs fresh check, release, and standalone-verifier flows for the
   Python inventory and TypeScript codec demos. The workflow installs a
   pinned Node 24.3.0 toolchain and uses the repository lockfile cache. The
   Node adapter installs each isolated shadow with `npm ci`, lifecycle
   scripts disabled, audit disabled, and the lockfile enforced. Xtask tests
   pin all three commands for both demos. The author-reported clean local
   run reached all 12 stages; that report was not rerun by this reviewer.

5. **Closed: `node_modules` is a reserved translation path component.** It
   is present in the typed manifest validator and in the public translation
   unit schema. Runtime and schema tests reject paths that contain it. The
   earlier note about `dist`, `build`, and `coverage` does not create a
   blocker: those names can identify reviewed source or build inputs, so a
   universal name-only exclusion would require a separate semantic claim.

#### Regression and gate review

- The fix range also removes the obsolete self-approval envelope. It does
  not replace it with another self-review artifact.
- The two final fixture commits bind the test inputs with `include_bytes!`
  so a reused build cache cannot redirect the tests to unreviewed runtime
  paths. They do not relax producer or verifier behavior.
- No new schema, status-derivation, subject-grammar, shadow-identity,
  translation-boundary, verifier-independence, or CI-coverage blocker was
  found in the fix range.
- Both GitHub Actions runs for this exact head currently fail at the same
  intended `PB-DIFF-0002` approval check. The reported regressions are the
  four new assumptions for `PY-RESERVATION-001`, `PY-WHEEL-001`,
  `TS-CODEC-001`, and `TS-PACKAGE-001`, each with `approved_by: null`.
  Earlier stages in the inspected logs pass. This is the expected
  fail-closed state before the required non-author approval envelope is
  added; it is not evidence of a new implementation blocker. The envelope
  must remain a separate commit and the full exact-head evidence must run
  again after it lands.

### Superseding independent re-review at exact head `21ab780127193422219254d31077952475094908`

- **Reviewer:** Codex, independent of the authoring agent
- **Review date:** 2026-09-12
- **Reviewed base:** `main` at
  `0a5c6b6dcf7e3b59cdf71ec5f8d50082c5f3a3e0`
- **Reviewed head:**
  `21ab780127193422219254d31077952475094908`
- **Reviewed range:**
  `0a5c6b6dcf7e3b59cdf71ec5f8d50082c5f3a3e0...21ab780127193422219254d31077952475094908`,
  with focused inspection of the seven commits after `ed4fab9`
- **Method:** inspected the exact-head tree from an immutable `git archive`,
  the complete fix-range diff, the producer, pure core, independent verifier,
  public schemas, negative tests, reference manifests, and CI plan. No branch
  was checked out and no build or test command was run, to avoid interfering
  with concurrent authoring work.
- **Verdict:** **REQUEST CHANGES**. All five previously reported blockers are
  closed, but the exact head contains one newly identified blocking
  producer/schema contradiction. This verdict supersedes the earlier
  same-head `APPROVE` record above.
- **Maintainer endorsement:** **NOT ENDORSED**. The earlier same-head
  endorsement is withdrawn. Do not prepare a non-author approval envelope or
  continue the merge sequence from this subject.

#### Recheck of the five original blockers

1. **Closed: mutation validation is subject-specific and fail-closed.** Core
   and the independent verifier parse a closed Rust, Python, or Node subject
   grammar before selecting a command grammar. Rust requires programs below
   distinct `$BASELINE/target` and `$MUTANT/target` roots plus the exact
   libtest selector and `--exact`. Python requires the exact pytest shadow
   command. Node requires the same Vitest tool tail below distinct
   `$BASELINE/node_modules` and `$MUTANT/node_modules` roots and the exact
   selected-test arguments. The expected exit remains 101 for Rust and 1 for
   Python and Node. Negative tests cover malformed subjects, cross-subject
   pytest selection, injected arguments, and baseline-command replay.

2. **Closed: Node mutation commands preserve shadow identity.** The Node
   adapter now uses a mutation-specific observation path and emits distinct
   `$BASELINE` and `$MUTANT` logical roots. Core and verifier reject replay of
   the baseline program as the mutant program. Adapter and conformance tests
   pin this distinction.

3. **Closed: the relaxed wire contracts use new versions.** The adapter
   observation, evidence, mutation registry, mutation witness, release
   envelope, and compiled release contracts moved to versions 3, 4, 3, 3, 4,
   and 4 respectively. Producers and the independent verifier select the new
   versions, and public-schema tests reject the superseded versions.

4. **Closed: both new language verticals are in CI.** Stage 10 performs fresh
   check, release, and standalone verification for the Python inventory and
   TypeScript codec demos. The workflow installs Node 24.3.0. Node shadows use
   lockfile-enforced `npm ci` with lifecycle scripts, audit, and funding
   requests disabled.

5. **Closed: `node_modules` is reserved from translation.** The typed
   manifest validator and public translation-unit schema both reject the path
   component, with direct negative coverage.

#### New blocking finding

1. **BLOCKER: the public evidence and receipt schemas reject every valid Node
   mutation receipt.** A Node mutation unit registers exactly six input
   artifacts: the registry, target preimage, mutant artifact, witness source,
   `package-lock.json`, and `package.json`
   (`demo/typescript-codec/evidence/reject-padding-mutant.toml:8`). Core
   requires those six at `crates/proofbound-core/src/evidence.rs:1760-1781`,
   and the independent verifier mirrors that rule at
   `crates/proofbound-verify/src/verifier.rs:2088-2103`. However,
   `schemas/evidence.schema.json:100` and
   `schemas/receipt.schema.json:190` both constrain every mutation witness to
   exactly four input artifacts. A producer/verifier-valid Node mutation
   receipt therefore cannot validate against either published v4 schema. The
   Stage 10 vertical does not expose this because it does not validate the
   generated evidence and release against the public JSON schemas.

   Required change: make both schemas encode the same subject-specific
   cardinality as core and verifier (six for a validated `npm:` subject and
   four for Rust or Python), then add public-schema tests that validate a
   complete Node mutation evidence record and compiled release and reject
   wrong cardinalities for all three subject kinds. Re-run the independent
   re-review at the resulting exact head.

#### Fix-range regression review

- The obsolete self-approval envelope is absent.
- The final two fixture commits only bind existing test inputs at compile
  time; they do not relax production or verifier behavior.
- No additional blocker was found in subject parsing, exact command
  selection, shadow identity, schema-version selection, translation path
  handling, adapter failure behavior, or CI wiring.

### Post-review hosted-gate finding

- **Envelope head:** `bcd2d46925375e1d3d243ddeab116b08672611bd`
- **Hosted result:** the approval envelope resolved all four exact assurance
  regressions, and the full gate progressed through the formal stages and the
  Python reference vertical. The TypeScript package claim then became INVALID
  on Linux because its registered npm archive digest had been generated with
  npm 10.9.8 rather than the workflow's pinned npm 11.4.2.
- **Root cause and fix:** Node 24.3.0's npm 11.4.2 produces SHA-256
  `6315de8611c4f8f2133ddf8fca9b4577128b8665b3d9b1af11db85d36c717446`
  for the registered archive; Node 22.23.1's npm 10.9.8 produces the former
  `931e913bdcdcd3f22d7d3ed324f8f3546fce3b0482a58770af0c5c86079043ea`
  compressed byte stream. The author reports that the full TypeScript
  reference vertical passed locally with the corrected registration.
- **New subject:** `f7744290176e01496079d5c7a2415598d67e2757` restores
  the Node-24 digest and retires the now-stale approval manifest. This
  post-review change invalidates the approval at `21ab780`; PR 2 therefore
  requires a narrow independent re-review of `21ab780..f774429` and a new
  approval-only envelope before merge.

### Narrow independent re-review at exact head `f7744290176e01496079d5c7a2415598d67e2757`

- **Reviewer:** Codex, independent of the authoring agent
- **Review date:** 2026-09-12
- **PR base:** `main` at
  `0a5c6b6dcf7e3b59cdf71ec5f8d50082c5f3a3e0`
- **Previously reviewed head:**
  `21ab780127193422219254d31077952475094908`
- **Reviewed delta:**
  `21ab780127193422219254d31077952475094908..f7744290176e01496079d5c7a2415598d67e2757`
- **Reviewed head:**
  `f7744290176e01496079d5c7a2415598d67e2757`
- **Method:** inspected both commits and their combined diff, inspected the
  intermediate and final review-envelope trees, reproduced `npm pack` twice
  with the workflow's exact Node 24.3.0 and npm 11.4.2 executables, reproduced
  the old digest with Node 22.23.1 and npm 10.9.8, and inspected the completed
  exact-head GitHub Actions regression output. The reproductions wrote only to
  a temporary directory. No repository build or broad test was run.
- **Verdict:** **APPROVE**. The corrected digest is exact for the workflow
  toolchain, the stale approval envelope is absent, the four adjudicated
  new-assumption regressions are unchanged, and the delta introduces no new
  blocking finding. This verdict is byte-specific and does not apply after a
  head change.
- **Maintainer endorsement:** **ENDORSED**. The maintainer authorized the
  agent to use its best judgment to complete the roadmap, then explicitly
  authorized the independent review to inspect the repository contents. This
  endorsement permits the new exact-head non-author approval envelope; it
  does not replace that envelope or bypass the fail-closed gate.

#### Narrow re-review findings

1. **The npm package digest is correct.** Two independent `npm pack` runs
   against the reviewed TypeScript demo, using Node 24.3.0 and npm 11.4.2 with
   lifecycle scripts disabled, produced byte-identical 1,300-byte archives.
   Both archives have SHA-256
   `6315de8611c4f8f2133ddf8fca9b4577128b8665b3d9b1af11db85d36c717446`,
   exactly the value registered at the reviewed head. The same source packed
   with Node 22.23.1 and npm 10.9.8 reproduces the previous
   `931e913bdcdcd3f22d7d3ed324f8f3546fce3b0482a58770af0c5c86079043ea`
   digest. This confirms npm packer version drift as the failure's root cause;
   it does not indicate source or inventory drift.

2. **The stale approval envelope was correctly retired.** Commit `bcd2d469`
   added `proofbound/reviews/pr-0002-language-support.toml` for the prior
   reviewed subject. Commit `f774429` changes a reviewed evidence byte, so the
   prior base/head-bound envelope cannot authorize the new subject. The same
   commit deletes that envelope. At the reviewed head, `proofbound/reviews/`
   contains only the pre-existing PR 1 envelope.

3. **The assurance regressions are unchanged.** The completed exact-head
   GitHub Actions diff reports the same four `new-assumption` regressions, with
   the same IDs and claim bindings, for `PY-RESERVATION-001`, `PY-WHEEL-001`,
   `TS-CODEC-001`, and `TS-PACKAGE-001`. Each correctly has
   `approved_by: null`, and the run stops with `PB-DIFF-0002`. No fifth
   regression appears. A new exact-head envelope may therefore adjudicate the
   same four findings, but it must bind the new head revision.

4. **No new blocker is introduced.** Across the reviewed delta, the envelope
   add and delete cancel. The only net repository change is the one-line
   registered digest correction. No production code, schema, specification,
   workflow, source input, assumption, exclusion, claim, or verifier behavior
   changes. The exact-head hosted workflow is red only because the corrected
   subject intentionally has no approval envelope yet; it stops before the
   TypeScript reference vertical and must be rerun after the new envelope
   lands.

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

## PR 6 independent re-review: exact artifact observations

- **Reviewer:** Independent Codex task `01a09849-d631-7971-8b29-e6112f51d58d`
- **Reviewed base:** `0268b2918395f4f2901ef4e982546332a3b6715a`
- **Reviewed head:** `f87315f19d722bc3493d9f36837556cd400aea7b`
- **Working tree:** Clean; the reviewer made no changes.
- **Verdict:** **REQUEST CHANGES**

### Blocking findings

1. **Bounded exact observations disagree between producer and verifier.**
   `EvidenceRecord::validate` uses `EvidenceKind::is_empirical`, which excludes
   `BoundedCheck`, while the independent verifier and ADR 0020 explicitly
   admit bounded checks as exact-observation evidence. The status predicate
   must remain unchanged. Add a separate observation-support predicate and
   producer/verifier parity coverage for all seven admitted kinds.
2. **The normative version transition is incomplete.** Specification 0001
   remains at version 0.13.0 and Section 11.5 ends with the coordinated `/4`
   transition, while the implementation emits and verifies compiled releases
   and envelopes `/5` and `/6`. The specification must define exact
   observations, reviewed evidence contexts, contextual artifact bindings,
   the related evidence/report fields, and the distinction between
   `record-consistent` and `bytes-observed`.
3. **The normative graph vocabulary contradicts the implementation.** The
   closed endpoint table omits the new test-suite/model-check dependency
   pairs and `(translation-unit, premise)`. Its cycle rule also says that only
   declared mutual theorem cycles are valid, although Section 8.1 and both
   implementations admit the exact typed premise-discharge cycle. Reconcile
   the closed table and cycle rule without broadening either implementation.

### Rechecked prior blockers and requested areas

- The earlier PR 2 blocking findings and ancestry issue are closed at this
  head.
- The Node mutation schema cardinalities are aligned across Rust, Python, and
  Node.
- The 12 `property-test` to `example-test` changes are justified
  reclassifications. The 27 enlarged-TCB findings all trace to the one frozen
  toolchain-corpus artifact and are acceptable false-positive classifications
  for the reviewed research path.
- EXP0005 revision immutability is restored with new revisions in new files.
- Evidence contexts and contextual binding sets otherwise fail closed.
- Python plugin identity now binds the compiler-owned plugin distribution
  closure and distinguishes materially different pytest environments.
- Producer/verifier independence remains intact.
- The reviewer found no other release blocker, but requested removal of
  trailing blank lines in four EXP0022 research documents as review hygiene.

No approval envelope may cover this reviewed head. A fresh exact-head review
is required after the three blockers are fixed.

## PR 6 independent re-review: reviewed-context enforcement

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `0268b2918395f4f2901ef4e982546332a3b6715a`
- **Reviewed head:** `dcd7d4fbcfd79850f57d44a7fd99209146a9ea65`
- **Method:** Static inspection only; no builds, tests, edits, commits, or pushes.
- **Working tree:** Clean.
- **Verdict:** **REQUEST CHANGES**

### Blocking findings

1. **HIGH — `project/2` can bypass its required reviewed release context.**
   ADR 0021 requires a nonempty `required_release_contexts` subset, but the
   public project schema does not require either context field for `project/2`
   or give the sets a nonzero lower bound. Semantic validation accepts empty
   sets, and release validation enforces membership and omission only after
   the required set is nonempty. A `project/2` manifest can therefore produce
   a base release or select any registered context contrary to the documented
   fail-closed contract.
2. **MEDIUM — the normative version-4/version-5 transition overstates
   contextual ownership.** Specification 0001 says every
   `proofbound-evidence-unit/5` is owned by one context. The schema and semantic
   validator intentionally permit `/5` without a context as the registration
   route for a noncontextual exact observation, which produces a version-4
   release. The specification must distinguish the observation-manifest
   version from optional contextual activation.

The reviewer confirmed that the earlier observation-kind, graph-table, and
cycle-rule blockers are closed. The PR 2 fixes, EXP0005 frozen history, Python
plugin identity, assurance-regression explanations, independent-verifier
separation, and EXP0022 hygiene changes remain acceptable. The reviewed diff
was whitespace-clean, and no approval envelope existed.

No approval envelope may cover this reviewed head. A fresh exact-head review
is required after the two findings are fixed.

## PR 6 final independent approval

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `0268b2918395f4f2901ef4e982546332a3b6715a`
- **Reviewed head:** `3da584e4046cbe024be9649ff3dd65cd19e49880`
- **Branch:** `codex/exact-artifact-observations`
- **Method:** Static inspection only; no builds, tests, edits, commits, or pushes.
- **Working tree:** Clean.
- **Findings:** None.
- **Verdict:** **APPROVE**

The reviewer confirmed that the final context-enforcement commit requires both
nonempty context sets in the public `project/2` schema, independently rejects
empty sets in semantic validation, and adds positive, missing, and empty
falsifiers. Specification 0001 now correctly distinguishes a noncontextual
evidence-unit `/5` that contributes to a version-4 release from a context-owned
`/5` unit that contributes to the version-5 release route.

The previously closed exact-observation kind parity, graph endpoint and cycle
contracts, Node mutation receipts, EXP0005 frozen history, Python plugin
identity, verifier independence, 39 assurance-regression adjudications, and
EXP0022 hygiene remain intact. The final fix is limited to four relevant files,
the exact diff is whitespace-clean, and the reviewed head contains no approval
envelope.

As maintainer, I endorse this independent `APPROVE` verdict for the exact base
and reviewed head above. The approval-only envelope may bind this reviewed
parent; no later production, schema, specification, or evidence bytes may be
included in that approval commit.

## PR 7 independent re-review: bounded-domain release semantics

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `354d6f853082b8b8b348efe460725e4dc90558a1`
- **Reviewed head:** `c269cfefe627ad97393acb919765a073ad890761`
- **Branch:** `codex/pbf-0007-domain-consistency`
- **Method:** Static inspection only; no builds, tests, edits, envelopes, or
  GitHub review submission.
- **Working tree:** Clean; `git diff --check` passed.
- **Verdict:** **REQUEST CHANGES**

### Blocking findings

1. **HIGH — the public schema rejects valid contextual version-7 releases.**
   The producer emits compiled-release `/7` for every release shape and keeps
   a selected `evidence_context`, but `schemas/receipt.schema.json` requires a
   context only for versions 5 and 6 and forbids it for every other version.
   Contextual observation and contextual artifact-binding releases produced
   under version 7 therefore fail the shipped public schema. Version 7 must
   permit the optional context; semantic verification remains responsible for
   requiring it when a contextual record is present.
2. **MEDIUM — producer and verifier disagree when theorem and exhaustive
   evidence coexist.** The producer gives an admitted theorem precedence and
   treats exhaustive evidence as proof only when no theorem earned `PROVED`.
   The independent verifier activates exhaustive-as-proof whenever the policy
   flag and an exhaustive record exist, even after theorem proof. It can then
   require a claim-owned exhaustive domain that the producer correctly treats
   as corroborating. The verifier must mirror theorem precedence, with a
   mixed theorem-plus-exhaustive parity case.
3. **LOW — standalone format documentation stops its byte-verdict semantics at
   version 6.** `crates/proofbound-verify/FORMAT.md` must include version 7 and
   state how its noncontextual, contextual-observation, and contextual-binding
   shapes inherit byte and context rules.

The reviewer confirmed that the original version-7 migration,
`registered_domain_language` derivation, primary-family bounded/exhaustive
scoping, mixed-domain verifier coverage, and version-4-through-version-6
historical behavior are otherwise corrected. The final formatting-only commit
did not alter semantics.

No approval envelope may cover this reviewed head. A fresh exact-head review
is required after all three findings are fixed.

## PR 7 second independent re-review: structural domain projection

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `354d6f853082b8b8b348efe460725e4dc90558a1`
- **Reviewed head:** `df974548c2b132c52bfba831614372c73deca3fa`
- **Branch:** `codex/pbf-0007-domain-consistency`
- **Method:** Static inspection only; no builds, tests, edits, envelopes, or
  GitHub review submission.
- **Working tree:** Clean; the full-range `git diff --check` passed.
- **Verdict:** **REQUEST CHANGES**

### Blocking finding

1. **MEDIUM — the derived domain-language invariant remains
   standing-dependent.** Specification 0001 and ADR 0023 define version-7
   `registered_domain_language` solely as the exact projection of
   `bounded_domain.description`. The producer and verifier enforce the pair
   only after `BOUNDED_CHECKED` or exhaustive-derived `PROVED` standing. A
   version-7 `OPEN` or `TESTED` claim can therefore retain a missing or
   contradictory pair. The pair must be structurally equal for every
   version-7 claim, with non-standing negative cases and historical-version
   gating in the independent verifier.

The reviewer confirmed that all three findings from the prior review are
closed. Version 7 now permits an optional public-schema context while versions
4 through 6 keep their historical rules; theorem precedence is aligned between
producer and verifier with parity coverage; and the byte-verdict documentation
includes every version-7 release shape. The final `f8607d7..df97454` change is
formatting-only and has no semantic effect.

No approval envelope may cover this reviewed head. A fresh exact-head review
is required after the structural projection rule is fixed.

## PR 7 final independent approval

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `354d6f853082b8b8b348efe460725e4dc90558a1`
- **Reviewed head:** `073689ee5382356ca921a4b9baf0ca4ccbba3dad`
- **Branch:** `codex/pbf-0007-domain-consistency`
- **Method:** Static inspection only; no builds, tests, edits, envelopes, or
  GitHub review submission.
- **Working tree:** Clean; the full-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

The reviewer confirmed that the structural domain projection applies before
standing selection in the producer and to every version-7 claim in the
independent verifier. Positive, missing-domain, missing-language, and
mismatched-language cases cover non-standing claims, while versions 4 through
6 retain their historical behavior. The version-7 context schema, theorem
precedence, primary evidence-family scoping, mixed-domain coverage, and
byte-verdict documentation remain aligned. The final
`699d119..073689e` delta changes formatter layout in two test files only.

As maintainer, I endorse this independent `APPROVE` verdict for the exact base
and reviewed head above. An approval-only envelope may bind this reviewed
parent; no later production, schema, specification, documentation, or evidence
bytes may be included in that approval commit.

## PR 7 final independent approval after hosted lint

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `354d6f853082b8b8b348efe460725e4dc90558a1`
- **Reviewed head:** `567e9e67d44d575dedbfb8256d0ba5aed9ffbbc2`
- **Branch:** `codex/pbf-0007-domain-consistency`
- **Method:** Static inspection only; no builds, tests, edits, envelopes, or
  GitHub review submission.
- **Working tree:** Clean; the full-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

The prior exact-head approval was superseded by one unsigned lint-only commit.
The reviewer confirmed that `073689e..567e9e6` only combines adjacent branches
that return `PROVED`. The guarded `exhaustive_as_proof` predicate still requires
an empty admitted-theorem set, so theorem precedence and primary-family
selection are logically unchanged. Every earlier PR 7 finding remains closed.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`567e9e67d44d575dedbfb8256d0ba5aed9ffbbc2`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 7 final independent approval after release-smoke repair

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `354d6f853082b8b8b348efe460725e4dc90558a1`
- **Reviewed head:** `60674c5e40a718780e87b64a43f2482ee27be391`
- **Branch:** `codex/pbf-0007-domain-consistency`
- **Method:** Static inspection only; no builds or tests.
- **Working tree:** Clean; the full-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted release construction exposed that the smoke path emitted a version-7
payload while retaining a version-4 envelope and digest domain. The reviewer
confirmed that `567e9e67..60674c5e` closes that defect with one exact shared
mapping for payload and envelope versions 4 through 7, rejects unknown payload
schemas, leaves the normal release path's payload-domain hashing correct, and
makes the smoke path hash the actual emitted payload schema. The regression
case binds the payload schema, envelope schema, and domain-separated digest.
All previously approved PR 7 domain-consistency, compatibility, context,
precedence, scoping, documentation, and verifier-independence fixes remain
unchanged.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`60674c5e40a718780e87b64a43f2482ee27be391`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 8 independent re-review: retained adapter failure diagnostics

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `32e44f08cd5b6ef36822d4881aaeccf54532de6c`
- **Reviewed head:** `4fe933e0d8603e423f024c5c30199ecc5cd73c05`
- **Branch:** `codex/pbf-0003-unit-diagnostics`
- **Method:** Static inspection only; no builds, tests, edits, or envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Verdict:** **REQUEST CHANGES**

### Blocking findings

1. **HIGH — Lean timeout paths still emit `PB-LEAN-0011`.** The orchestrator
   classifies only the new protocol-wide `PB-ADAPTER-0010` code as `timeout`,
   so an actual Lean timeout remains an ordinary `failed` run.
2. **MEDIUM — the Python protocol-v2 helper does not implement the version-2
   operation contract.** It equates success with evidence presence, accepts
   failed responses with inventory and no diagnostic, can serialize those
   invalid failures, and rejects valid successful `doctor` and `inventory`
   responses that correctly have null evidence.
3. **LOW — `PB-ADAPTER-0010` retains a second non-timeout meaning.** A
   defensive compiler guard uses the reserved timeout code for generic adapter
   rejection. The path is not normally reachable, but the code must be removed
   or renumbered.

The reviewer confirmed that claim reports and explanations retain unit runs,
invocation errors are typed without display-text scraping, every run path uses
the registered executable identity, and the absent-executable falsifier
actually attempts to spawn the missing registered program. Protocol and report
version adoption is otherwise consistent, evidence remains fail-closed, and
the approved PR 7 merge adds no blocker. The later `c6d096d` commit changes
formatter layout only and does not resolve these findings.

No approval envelope may cover either head. A fresh exact-head independent
review is required after all three findings are fixed.

## PR 8 second independent re-review: timeout and protocol falsifiers

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `32e44f08cd5b6ef36822d4881aaeccf54532de6c`
- **Reviewed head:** `a93716965b8b221e070f5836ad985a6050d0b87c`
- **Branch:** `codex/pbf-0003-unit-diagnostics`
- **Method:** Static inspection only; no builds, tests, edits, or envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Verdict:** **REQUEST CHANGES**

### Blocking findings

1. **MEDIUM — Python still permits whitespace-only inventory.** The helper
   rejects empty, oversized, controlled, unsorted, and duplicate strings but
   accepts a value such as `" "`. It can therefore serialize a version-2
   response that the public schema and Rust boundary reject.
2. **LOW — Lean timeout falsification is narrower than the implementation.**
   Static tracing confirms that all request-reachable deadline paths now emit
   `PB-ADAPTER-0010` and non-time resource failures keep `PB-LEAN-0011`, but
   the new runtime unit test covers only an already-exhausted deadline. Direct
   captured-execution and child-process deadline cases must retain the new
   code.

The earlier Lean-code, Python failure-invariant, null-evidence success, and
defensive-code findings are closed in production behavior. The hosted suite at
this head compiled, formatted, and linted the workspace; its only Rust-test
failure was the existing captured-execution falsifier still expecting
`PB-LEAN-0011`. The later one-line `f2e0e6b` commit updates that direct case to
the protocol-wide timeout code but does not address the Python lexical boundary
or add a child-process deadline falsifier.

No approval envelope may cover these reviewed heads. A fresh exact-head review
is required after both remaining findings are fixed.

## PR 8 final independent approval

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `32e44f08cd5b6ef36822d4881aaeccf54532de6c`
- **Reviewed head:** `440eafa59c4b19245177d9a9d12f007c4e09c264`
- **Branch:** `codex/pbf-0003-unit-diagnostics`
- **Method:** Static inspection only; no builds, tests, edits, or envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

The reviewer confirmed that all original and subsequent PR 8 findings are
closed. Claim reports and explanations retain relevant unit diagnostics;
invocation errors are typed without display-text scraping; every cache,
success, adapter-failure, and invocation-failure path uses the registered
executable identity; the actual absent-executable fixture performs a failed
spawn; and version-2 reports and protocol envelopes remain fail-closed.

Every Lean deadline, elapsed-time, captured-time, child-process, and redundant
receipt-level time overrun now maps to `PB-ADAPTER-0010`. Disk, memory, budget
arithmetic, platform-limit, and oversized-output failures retain the distinct
Lean resource code. Python accepts valid successful null-evidence envelopes,
rejects whitespace-only inventory, and enforces failure evidence, inventory,
and diagnostic invariants during parsing and serialization. The final
`fea5be6..440eafa` delta changes only the redundant receipt-level budget guard,
with timeout taking precedence if time and another resource both exceed their
limits. The approved PR 7 integration adds no blocker.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`440eafa59c4b19245177d9a9d12f007c4e09c264`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 8 final independent approval after hosted compile

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `32e44f08cd5b6ef36822d4881aaeccf54532de6c`
- **Reviewed head:** `b8a5fc16d0d14b0e12df25670f3583f8ebf85734`
- **Branch:** `codex/pbf-0003-unit-diagnostics`
- **Method:** Static inspection only; no builds, tests, edits, or envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted compilation showed that the child-timeout test's `unwrap_err()` imposed
an unintended `Debug` bound on the successful output type. The reviewer
confirmed that `440eafa..b8a5fc1` changes only that test harness: an explicit
`Ok(_)` arm still fails the falsifier, while `Err(error)` preserves the exact
timeout code and message assertions. No production behavior changed, and all
prior PR 8 conclusions remain valid.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`b8a5fc16d0d14b0e12df25670f3583f8ebf85734`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 9 final independent approval: reviewed Lean identity updates

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `7137a576c064d62e66b6d97659325c835ef53411`
- **Reviewed head:** `f061b00611b9fdb3e713a305603e3ab7cb4c5c73`
- **Branch:** `codex/pbf-0002-lean-identity-update`
- **Method:** Static inspection only; no builds, tests, formatters, edits, or
  envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

The reviewer confirmed that all five PR 9 findings are closed. ADR 0025 states
the fail-closed request and configuration identity migration; the unrelated
`lake build` behavior is absent; and the orchestrator-supplied Git provenance
shift is explicit as a trusted-computing-base change. A Lean unit's `outputs`
field is now only an update allowlist: check, update, and reproduce receipts do
not report the owning claim manifest as a generated proof artifact, while the
complete unit configuration remains identity-bound. The Lean-specific escaped
write falsifier exercises the production validate-before-import helper and
confirms that neither the intended manifest rewrite nor the foreign adapter
write reaches the real tree after rejection.

Hosted preflight required one formatter-only adjustment after the behavioral
fixes. The reviewer confirmed that `1b957c9661595335146a1162026e1a3883f5bd9d`
to `f061b00611b9fdb3e713a305603e3ab7cb4c5c73` changes formatting only, that the
final head is an unsigned direct child of the behaviorally reviewed head, and
that every earlier conclusion remains valid. The approved PR 8 integration
introduces no new blocker.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`f061b00611b9fdb3e713a305603e3ab7cb4c5c73`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 9 final independent approval after hosted compile

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `7137a576c064d62e66b6d97659325c835ef53411`
- **Reviewed head:** `7d3b0bb1b96e4b39a03f435d7fd4a6a5c17cf6d5`
- **Branch:** `codex/pbf-0002-lean-identity-update`
- **Method:** Static inspection only; no builds, tests, formatters, edits, or
  envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted compilation showed that `std::fs` remained necessary for the existing
`fs::symlink_metadata` call in `validate_exact_paths`. The reviewer confirmed
that `f061b00611b9fdb3e713a305603e3ab7cb4c5c73` to
`7d3b0bb1b96e4b39a03f435d7fd4a6a5c17cf6d5` restores only that import in the
Lean receipt module. No runtime logic, receipt meaning, or earlier review
conclusion changes, and the final unsigned head is a direct child of the prior
approved head.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`7d3b0bb1b96e4b39a03f435d7fd4a6a5c17cf6d5`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 9 final independent approval after corpus migration

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `7137a576c064d62e66b6d97659325c835ef53411`
- **Reviewed head:** `38b4124cd251b335f1d8e1eb770a551a028f4a25`
- **Branch:** `codex/pbf-0002-lean-identity-update`
- **Method:** Static inspection only; no builds, tests, formatters, edits, or
  envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted tests exposed that PR 9 changed the exact bytes of the
`accept-conserves` evidence unit after merged-main conformance had frozen
corpus revision 4. The reviewer confirmed that the repair preserves
`corpus/cases.json`, `cases-r3.json`, and `cases-r4.json` byte-for-byte; adds a
revision-5 corpus whose only semantic-input change is the exact current
`accept-conserves.toml` SHA-256; and makes Rust and independent Python
conformance select revision 5. Every path and digest registered by revision 5
matches the reviewed tree. Historical result references retain their original
corpus, and the documentation does not reopen or strengthen the concluded
experiment.

The unsigned final head is a direct child of the prior approved head. This
closes the stale-corpus failure without changing the registered experiment
cases, projection meaning, or any earlier PR 9 behavior. No new blocker was
found.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`38b4124cd251b335f1d8e1eb770a551a028f4a25`. An approval-only envelope may bind
this reviewed parent; no later production, schema, specification,
documentation, or evidence bytes may be included in that approval commit.

## PR 9 final independent approval after corpus-header correction

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `7137a576c064d62e66b6d97659325c835ef53411`
- **Reviewed head:** `918ec9821b3010dcfcb964b476351deac63df751`
- **Branch:** `codex/pbf-0002-lean-identity-update`
- **Method:** Static inspection only; no builds, tests, formatters, edits, or
  envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted preflight showed that the immutable revision-5 corpus was selected by
all seven current IR prototype tests while the shared header validator still
required revision 4 and its prior frozen status. The reviewer confirmed that
the final unsigned direct-child commit changes only those two expectations to
the exact revision and status already carried by `cases-r5.json`.

The commit does not change a corpus, source or digest registration, projection
rule, experiment identifier, schema, baseline, source-identity contract, case,
profile, or conclusion. Historical corpus files remain byte-unchanged, and the
remaining revision-4 references describe history rather than current test
selectors. No new blocker was found.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`918ec9821b3010dcfcb964b476351deac63df751`. No later production, schema,
specification, documentation, or evidence byte may be included without a new
exact-head review.

## PR 9 final independent approval after checker parity correction

- **Reviewer:** Independent Codex task `01a09863-e2fc-71c3-832b-4f5ba5e2f61c`
- **Reviewed base:** `7137a576c064d62e66b6d97659325c835ef53411`
- **Reviewed head:** `1084e0d1dc5685933b705d8844af5b123399e0b9`
- **Branch:** `codex/pbf-0002-lean-identity-update`
- **Method:** Static inspection only; no builds, tests, formatters, edits, or
  envelopes.
- **Working tree:** Clean; the exact-range `git diff --check` passed.
- **Findings:** None.
- **Verdict:** **APPROVE**

The revision-5 Rust prototype tests passed at the preceding hosted head. The
two Python failures then showed that the independent checker retained the same
stale revision-4 header guard. The reviewer confirmed that the final unsigned
direct-child commit changes only the Python checker's accepted revision and
frozen status to the exact values in immutable `cases-r5.json` and the Rust
producer.

The Python tests already select revision 5. No live revision-4 guard remains in
either implementation. The change does not modify corpus bytes, registrations,
projection cases, baseline, schema, experiment identity, hashing, or any
conclusion. Producer and independent checker continue to recompute identities
and semantics separately. No new blocker was found.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`1084e0d1dc5685933b705d8844af5b123399e0b9`. No later production, schema,
specification, documentation, or evidence byte may be included without a new
exact-head review.

## RT-7 registry-publication independent approval

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `4a0cfdb19d436f05b1c0391e0d5050b9eb0fd584`
- **Reviewed head:** `cf55085378d5d71ec12b1ec4b471217cc7331900`
- **Branch:** `codex/rt7-registry-publication`
- **Method:** Complete exact-range static review only. No files were modified
  and no builds or tests were run by the reviewer.
- **Findings:** No P0, P1, or P2 findings.
- **Verdict:** **APPROVE**

The reviewer confirmed that the workflow is default-off, validates one exact
mainline revision, waits for aggregate provenance, and serializes the four
protected publishers before observation. Cargo and npm publication explicitly
select their intended registries. Static Cargo credentials exist only in the
two Rust publish steps. PyPI and npm receive only job-scoped OIDC authority.
Checkout credentials are not persisted into Rust publication or registry
observation.

The observer rejects an invalid initial endpoint before opening it and rejects
every redirect before a follow-up request can occur. It closes local manifest
roots and entries, validates the version and selected file names, prevents path
selection, requires positive sizes and exact digests, and compares all four
downloaded byte strings with the approved artifacts. The regression corpus
covers substitution, duplicate JSON members, unopened redirect targets,
endpoint credentials, ports, fragments, revision drift, and manifest-surface
and version mutations. The observation schema closes the object and ordered
four-entry inventory.

`PBR-DISTRIBUTION-018` limits the result to a protected workflow and bounded
evidence. It does not claim that publication, external configuration,
publisher authentication, or RT-7 completion has occurred. Cargo, SDK,
registry, GitHub, transport, runtime, and filesystem premises are explicit and
bound into the sole evidence closure, including `rust-toolchain.toml`.

Residual non-blocking assumptions and obligations remain explicit. The
protected environment, scoped crates.io token, and exact PyPI and npm trusted
publisher records require external configuration. GitHub, registries, DNS,
TLS, package clients, runtimes, and filesystem behavior remain trusted
premises. Publication is not atomic, and registry availability or propagation
can make observation fail after partial publication. The hosted exact-head
gate, protected publication run, retained observations, unrelated-consumer
checks, and current-integration manifest remain open. Rust publication
repackages after the compared reproduction step; the Cargo premise and later
anonymous exact-byte comparison state that boundary honestly.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`cf55085378d5d71ec12b1ec4b471217cc7331900`. This approval-only envelope adds
no reviewed production, schema, specification, claim, or evidence bytes. Any
later change to those bytes requires a new exact-head review.

## RT-7 registry-publication approval after workflow-count correction

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `4a0cfdb19d436f05b1c0391e0d5050b9eb0fd584`
- **Reviewed head:** `9422165568fae0349a3d086fdfab8545d7f3b18a`
- **Branch:** `codex/rt7-registry-publication`
- **Method:** Static inspection only; no builds, preflight wrapper, or tests
  were run by the reviewer.
- **Findings:** No P0, P1, or P2 findings.
- **Verdict:** **APPROVE**

Hosted preflight showed that the two new registry Rust publisher jobs added two
uses of the pinned Rust toolchain action while the global workflow invariant
still expected nine. The reviewer confirmed that the direct child of the prior
approval envelope changes only `tools/ci/test_required_workflow.py`, increasing
that exact count from 9 to 11. The exact branch range contains precisely two
new uses, and all 11 uses retain the same exact 40-character action pin.

The only other post-subject change is the accurate approval record above. No
production, workflow, schema, specification, claim, assumption, or evidence
bytes changed after `cf55085378d5d71ec12b1ec4b471217cc7331900`.
All prior conclusions about default-off publication, exact-source and
provenance ordering, protected environments, registry selection, credential
isolation, redirect and endpoint closure, manifest and schema closure,
exact-byte observation, and residual assumptions remain valid.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`9422165568fae0349a3d086fdfab8545d7f3b18a`. This approval-only envelope adds
no reviewed production, workflow, schema, specification, claim, assumption,
evidence, or test bytes.

## RT-8 diagnostic-contract foundation approval after RT-7 rebase

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `acf8f24730857a6e7906336b570c61bec7213ab1`
- **Reviewed head:** `d242b87b0b4b10fe3a86807a141e4c40a0470efc`
- **Branch:** `codex/rt8-diagnostic-profile`
- **Method:** Complete exact-range static re-review. The reviewer changed no
  files and ran no builds or tests.
- **Findings:** No blocking findings.
- **Verdict:** **APPROVE**

The reviewer confirmed that the rebase preserves the previously approved RT-8
implementation and introduces no new assurance or product-claim blocker. Every
prior blocking finding remains resolved: the acceptance-decision v2 transition
inventory and UTF-8 wire ordering; event operands and drift identities; exact
Capsec identity binding and all three difference classes; narrowed composer and
acceptance evidence language; complete dependency-free nested schema and vector
validation; consistent completion spelling; and Unicode canonicalization
agreement, including literal non-ASCII fixture bytes and lone-surrogate
rejection.

The status refresh accurately leaves final hosted admission, the live observer,
and the plan-draft producer open. The approval applies only to the exact subject
above. It does not claim that source-level tests prove kernel observation or
that the RT-8 epic is complete.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`d242b87b0b4b10fe3a86807a141e4c40a0470efc`. This approval-only envelope adds
no reviewed production, schema, specification, claim, assumption, evidence, or
test bytes. Any later change to those bytes requires a new exact-head review.

## RT-8 diagnostic-contract approval after hosted-gate corrections

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `acf8f24730857a6e7906336b570c61bec7213ab1`
- **Reviewed head:** `253b33d64ca3d812f5d2b1a347edb64ba0ac8075`
- **Branch:** `codex/rt8-diagnostic-profile`
- **Method:** Narrow exact-head static re-review. The reviewer changed no files
  and ran no builds or tests.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted verification found two declaration-only defects at the preceding
approval envelope. The reviewer confirmed that the correction changes exactly
three subject files. `PBR-DRAFT-017` now has the Tier 1 ceiling required by its
independent-check evidence kind. The assurance summary records the same bounded
Tier 1 meaning without claiming a released observer or producer. The acceptance
test assertion changes only to canonical Rust formatting and keeps identical
ordering semantics.

The intervening `35ebd79fc132d802299af9f206320beb1294d366` commit records only
the prior exact-head approval. No security behavior, schema, diagnostic
contract, or evidence meaning changed beyond the required claim-ceiling
correction. No new blocker was found.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`253b33d64ca3d812f5d2b1a347edb64ba0ac8075`. This approval-only envelope adds
no reviewed production, schema, specification, claim, assumption, evidence, or
test bytes. Any later subject change requires a new exact-head review.

## RT-8 verifier error-precedence corrective approval

- **Reviewer:** Independent Codex task `/root/review_runtime_pr4`
- **Reviewed base:** `acf8f24730857a6e7906336b570c61bec7213ab1`
- **Reviewed head:** `f40c1681a66a2877ce7bb68256c1297879c3e168`
- **Branch:** `codex/rt8-diagnostic-profile`
- **Method:** Exact-head static corrective review. The reviewer changed no
  files and ran no builds or tests.
- **Findings:** None.
- **Verdict:** **APPROVE**

Hosted Verify run `34926427870` showed that the initial diagnostic precheck
changed the failure precedence for an unrelated JSON projection. The reviewed
correction limits the new duplicate-key and canonical-byte checks to objects
whose top-level schema is exactly
`proofbound-runtime-diagnostic-receipt/1`. Other JSON inputs return to the
unchanged production canonical, commitment, and semantic-verification path.
Canonical diagnostic receipts still fail before commitment and production
receipt decoding with `profile.diagnostic.not-reusable`; duplicate or
noncanonical diagnostic objects still fail closed first.

The reviewer also confirmed that the preceding schema, Unicode, Capsec,
event-operand, acceptance-decision, evidence-language, and claim-tier
corrections remain intact and that no live observer, released producer, or
completed RT-8 claim is asserted.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`f40c1681a66a2877ce7bb68256c1297879c3e168`. The following approval-only commit
adds no reviewed production, schema, specification, claim, assumption,
evidence, or test bytes. Any later subject change requires a new exact-head
review.

## RT-8 diagnostic artifact producer initial review

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `cb52c5115d73c72aebad51c4c0f4a301068d8479`
- **Reviewed head:** `ed9c6ca105748b409fe85a243975c51c80ccdb51`
- **Branch:** `codex/rt8-observer`
- **Method:** Exact-head static review. The reviewer changed no files and ran
  no builds or tests.
- **Verdict:** **REQUEST CHANGES**

The review found seven blocking clusters:

1. the registered Rust evidence imported private re-exports and one broad-root
   fixture constructed an invalid outcome and resolution pair;
2. Capsec usability did not bind the selected report identity;
3. a redacted socket event could retain raw address bytes;
4. absolute-path validation admitted traversal-shaped values and candidate
   selection did not require an explicit project or runtime scope or exclude
   nested system, home, and configured temporary roots;
5. tracee-string, symlink, count-gap, and draft-output bounds were incomplete;
6. the claim named the wrong Rust subject and omitted imported core sources,
   Specification 0013, and the Python/JSON/filesystem checker assumption; and
7. public evidence language described negative coverage that the registered
   falsifiers did not yet contain.

Architecture separation, fixed `safe_policy: false` and `reusable: false`,
mandatory human authority choices, network non-grant, and production-consumer
non-reuse remained intact. The producer cannot proceed until each blocker is
corrected in a separate subject and re-reviewed at its exact head.

## RT-8 diagnostic artifact producer first correction re-review

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `cb52c5115d73c72aebad51c4c0f4a301068d8479`
- **Reviewed head:** `2c0d86aea8386358c9694a381d5ac94885c9e297`
- **Branch:** `codex/rt8-observer`
- **Method:** Complete exact-range static re-review. The reviewer changed no
  files and ran no builds or tests.
- **Verdict:** **REQUEST CHANGES**

The re-review confirmed closure of the private-import and invalid-fixture
failures, exact Capsec report identity, redacted socket and path payloads in
both producer and schema, and normalized explicitly scoped candidate
selection. It found six remaining blocking clusters:

1. exact event or process capacity incorrectly forced a coverage gap even when
   the run ended naturally without omission;
2. a stable candidate could omit both its supplied path and symlink-hop
   evidence;
3. output bounds were checked after construction of potentially enormous
   complete JSON values instead of during encoding;
4. direct `str.as_bytes().len()` expressions would fail the required Clippy
   warnings-as-errors gate;
5. the claim subject named only plan-draft construction while claiming both
   receipt and draft production; and
6. registered falsifiers did not yet cover process and per-process bounds, all
   four Capsec identities and incomplete reports, or nested system, home, and
   configured temporary roots.

This verdict is not endorsed. The findings require another separate correction
subject and exact-head review before the producer branch can proceed.

## RT-8 diagnostic artifact producer second correction re-review

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `cb52c5115d73c72aebad51c4c0f4a301068d8479`
- **Reviewed head:** `75b3f62d115cb01b7c7e8fac1842a76b128dc24d`
- **Branch:** `codex/rt8-observer`
- **Method:** Complete exact-range static re-review. The reviewer changed no
  files and ran no builds or tests.
- **Verdict:** **REQUEST CHANGES**

The re-review confirmed that the count-gap meaning is now one-way, reusable
path resolutions require complete path and symlink evidence, redacted targets
remain closed, bounded encoding is incremental, the aggregate producer is the
exact claim subject, Capsec mutations cover all registered identities and
incomplete reports, and the new source and evidence files are registered.

It found three remaining blocking boundaries:

1. the diagnose manifest's direct `serde` dependency was absent from its
   `Cargo.lock` package entry;
2. natural exact-capacity completion was not isolated for the per-process and
   process-count branches; and
3. the missing path and symlink evidence mutation covered only stable
   candidates, while the configured-home test used a path already excluded by
   the independent system-root rule.

This verdict is not endorsed. A separate correction must synchronize the
locked graph and add discriminating falsifiers for all three boundaries before
another exact-head review.

## RT-8 diagnostic artifact producer third correction re-review

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `cb52c5115d73c72aebad51c4c0f4a301068d8479`
- **Reviewed head:** `99ee74cde4dde465119cd255be95d1ef898f19e1`
- **Branch:** `codex/rt8-observer`
- **Method:** Exact-range static re-review. The reviewer changed no files and
  ran no builds or tests.
- **Verdict:** **REQUEST CHANGES**

The re-review confirmed that the locked `serde` dependency, all three natural
exact-capacity cases, both Rust reusable-path resolution branches, both schema
structures, and the nested configured-home exclusion are corrected.

One falsifier remained non-discriminating. The new kernel-selected schema
mutation added an unknown `outcome` field and retained the stable-candidate
`error` and `result` values. It therefore failed for unrelated closed-schema
and outcome reasons before testing the missing path or symlink evidence. The
mutation must use the declared wire fields for a successful kernel outcome
before removing each target field independently.

This verdict is not endorsed. The falsifier correction requires a separate
commit and exact-head re-review.

## RT-8 diagnostic artifact producer final approval

- **Reviewer:** Independent Codex task `/root/review_runtime_pr6`
- **Reviewed base:** `cb52c5115d73c72aebad51c4c0f4a301068d8479`
- **Reviewed head:** `07c1b13e89560a9e0df95cdc0da7e1404f62531e`
- **Branch:** `codex/rt8-observer`
- **Method:** Exact-range static re-review. The reviewer changed no files and
  ran no builds or tests.
- **Findings:** None.
- **Verdict:** **APPROVE**

The reviewer confirmed that each kernel-selected schema mutation now uses the
declared successful-outcome wire fields and independently removes either path
or symlink evidence. Each rejection is therefore caused by the intended rule.
All earlier blockers remain closed: locked dependency synchronization,
one-way count-gap semantics, natural-capacity and overflow cases for all count
bounds, complete reusable-path evidence in Rust and schema, bounded streaming
encoding, aggregate claim identity, exact Capsec identities, redaction,
normalized scoped paths, and discriminating system, home, and temporary-root
exclusions.

As maintainer, I endorse this independent `APPROVE` verdict for exact head
`07c1b13e89560a9e0df95cdc0da7e1404f62531e`. The following approval-only
commit adds no reviewed production, schema, specification, claim, assumption,
evidence, or test bytes. Any later subject change requires a new exact-head
review.

## RT-8 diagnostic artifact producer hosted correction

Hosted Verify run `34930489605` tested approval envelope
`7154acd69cc95ffabd8fcace3ac2de216fe00023`. Both native boundary lanes passed,
but the Rust and ledger lanes found three source defects:

1. `DiagnosticGap` was imported into non-test draft code but used only by the
   test module, which failed the warnings-as-errors gate;
2. adjacent Capsec report-identity and structural-validity branches returned
   the same result and failed the Clippy identical-branch gate; and
3. the broad-root Rust evidence fixture used bytes that were not a valid typed
   execution identifier, so the registered test failed before reaching its
   path-scope assertion.

Clippy also required the path-containment Boolean expression to use its direct
equivalent form. These corrections do not change the reviewed authority,
schema, producer, or receipt meaning, but they change the exact subject and
therefore require a new independent exact-head review.
