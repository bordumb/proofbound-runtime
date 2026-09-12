Checking the remaining exit conditions I have not verified yet, then I'll build the list.

Verified against the branch head, the four reviews, and the roadmap's own exit conditions. Done and not listed: Order 0, RT-0.2, RT-0.3, RT-3.1 install path, RT-3.2 preflight, RT-3.4 diagnostics, RT-6.3 benchmarks, the network experiments, and ADRs 0003 through 0007.

## Do first: get the gate green

- [x] **Root-cause the receipt shard.** The long-running unit is `receipt-eligibility-bounds`, the v2 receipt Kani bounded check in `proofbound/model-checks/receipt-eligibility.toml`. The proof is partitioned into seven outcome-class harnesses without changing its registered 8,796,093,032,448-state domain or its 8 GiB memory and 2 GiB disk bounds. The 2,400-second host-measured envelope passed at exact source `3186d62434fe79b1ee7a59c527a38c1fb42148ef` in GitHub Actions run `34667606741`, together with every other required job and the final assurance gate.
- [x] **Add `--fresh` to the release evidence run** in `tools/release/proofbound-release.sh:67`. RT-0.4 requires it in release contexts.
- [x] **Replace the self-referential tool-bundle checksum** in `ci.yml:255` with a pinned expected digest so restored tools are verified against something the job did not just produce.

## Memory profile, Order 4

- [x] **Retain cgroup readback values and put them in the receipt.** `crates/proofbound-runtime-linux/src/cgroup.rs:459` compares and discards; `crates/proofbound-runtime-cli/src/run.rs:828` fills the receipt from the plan. Spec 0007 line 177 requires exact readback values.
- [x] **Make the verifier compare configured and peak values** to the normalized plan limits. `crates/proofbound-runtime-verify/src/identity.rs:222` currently discards them. Add attack cases that expect a semantic reason, not a commitment mismatch. The verifier preserves Specification 0007's overshoot semantics: a peak beyond a configured limit is valid when the corresponding terminal max event is present.
- [x] **Turn observation failure into a non-reusable receipt, not an aborted run.** `supervisor.rs:314` maps any `cgroup.finish()` error to a hard error. Spec 0007 line 169. Drain or removal failure still aborts; a terminal counter/read failure retains configured readbacks and emits a verified non-reusable receipt with a null terminal observation.
- [x] **Add the missing native assertions:** group-OOM kill count in the max-process-tree case, exact `swap.events` max/fail projection in the bounded-swap-pressure case, and a real sibling-cgroup case. Bind each catalog id in `memory-v2.toml` to an executed case instead of substring matching. The accepted memory profile permits allocation failure without either swap event, so the native oracle records both counters without claiming that one must be nonzero.
- [x] **Guard the two silent-skip sites** in `cgroup.rs:1093` and `probe.rs:539` with the `PROOFBOUND_NATIVE_REQUIRED` check the rest of the native suite uses.

## Acceptance, Order 5

- [x] **Decouple acceptance from reuse eligibility.** `compose/src/lib.rs:832` refuses non-reusable receipts, so policy's `eligibility: non-reusable` option is unsatisfiable. Let a non-reusable receipt reach `evaluate` and be rejected by policy with `eligibility-mismatch`.
- [x] **Derive rejection reasons instead of emitting both.** `accept/src/lib.rs:490` always pushes `input-verification-failed` and `composition-missing`. Route the three failure sources in `main.rs:166` to distinct reasons and add a replay reason.
- [x] **Make the assumption-loss attack real.** `lib.rs:957` calls the rejection helper directly and cannot fail. Mutate inherited assumptions and assert the derived reason.
- [x] **Let policy and the Action pin the Proofbound verifier and release directory by digest.** Today only the archive, acceptor, and policy are pinned.
- [x] **Bound CBOR pre-allocation** in `accept/src/cbor.rs:112` and `compose/src/cbor_decode.rs:108`. Do not call `with_capacity` from a header count before reading elements.

## CBOR wire contract, cross-cutting

- [x] **Anchor the golden vectors independently.** The README credits cbor2 but it is not in the repo. Either add cbor2 as a pinned dev dependency that regenerates and compares, or remove the claim and add a second independent encoder.
- [x] **Pin the execution receipt producer to its golden.** `core/src/receipt.rs:814` has no byte-level test; policy, run result, composed receipt, and SDK all do.
- [x] **Add v2 carrier attacks through the public entry point:** duplicate key, reordered key, trailing bytes, and invalid UTF-8 fed to `verify_receipt`, plus a test that each JSON projection is rejected by `pbr-verify`, `pbr-compose`, and `pbr-accept`.
- [x] **Decide what "separate codec" means.** The verifier's decoder is a verbatim copy of the producer's. Either accept that with a divergence-guard test or write the verifier's from the CDDL without reference to the producer. Align `MAX_BYTES`, which is 16 MiB in two decoders and 64 MiB in the composer.

## Claim ledger honesty

- [x] **Restore open obligations** on PBR-RUN-007, SEQUENCE-003, VERIFY-006, and COMPOSE-008. Their release-observation units run only in the manual release workflow, which has not run at any 0.2 head. Match the wording PBR-PREFLIGHT-009 uses.
- [x] **Add the four missing claims** to the summary table in `docs/assurance-plan.md`, and add a doc check that fails when a claim has no row.
- [ ] **Run the 0.2.0 release workflow on the exact merge head** and only then close the observation obligations. RT-1.5 and the Order 3 exit condition both wait on this. This is a maintainer action.

## Upstream, Order 1

- [ ] **Resolve Proofbound PR 2's independent review,** then obtain the maintainer-endorsed non-author envelope, merge, recompute the promotion diff against upstream main, and seal it with a new approval envelope. Claude's 2026-09-11 model review requested changes on five blockers; item 1 identifies a cross-project mutation-witness status weakening caused by lost two-shadow validation and argument-prefix language dispatch. Runtime is still pinned to `70af5e6`, which is not on upstream main. The separate PR 6 review confirmed that PR 2 is embedded and found 43 regressions; those must be recomputed and adjudicated only after PR 2 merges.
- [ ] **Protect upstream main and tag a Proofbound release,** then move `ci.yml:235` and `release.yml:147` to that identity. Protection and tagging are maintainer actions.
- [ ] **Upstream PBF-0007, then PBF-0003, then PBF-0002 and PBF-0001.** PR 7 is approved with required changes, led by a compiled-release/7 transition that must move Runtime's composer in the same wave. PRs 8 and 9 requested changes (two and three items respectively). PBF-0001 remains last. PBF-0007 gates any new bounded resource claim beyond the local guard.
- [ ] **Decide the Proofbound envelope encoding upstream** per UP-0.8 and make the composer accept exactly what the pinned release declares.

## Review process, RT-0.1

- [ ] **Add `CODEOWNERS`** for specs, ADRs, schemas, claims, formal bridges, `sys.rs`, launcher and supervisor code, the verifier, and release workflows. Name a real reviewer per entry.
- [ ] **Require one approving review on main.** Branch protection currently requires zero. This review-count decision is a maintainer action; until it changes, leave PRs visibly unapproved rather than self-approving.
- [ ] **Split future work into claim-wave PRs** under ten hand-written commits. PR 3 is 372 commits and cannot be reviewed as a unit.

## Network decision, Order 7

- [x] **Get ADR 0004 an independent review** and record acceptance or rejection. Claude independently reviewed the frozen comparison and registered attack domain on 2026-09-11; the accepted ADR records the four required changes and retains the implementation gates.

## Deferred by the roadmap's own rules, not incomplete

CPU and output-capacity implementation wait on adopted-workload evidence under ADRs 0006 and 0007. SDK registry publication moved to roadmap 2 RT-7. Order 8 is blocked on Order 7. The two-week RT-0.4 latency measurement cannot start until the gate is green.

Next: paste the first group to the other agent. Nothing else on this list can be verified until the gate passes.
