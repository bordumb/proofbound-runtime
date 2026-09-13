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

- [x] **Promote the reviewed Proofbound integration line.** PR 2 merged as `0268b2918395f4f2901ef4e982546332a3b6715a`; the recomputed PR 6 promotion merged as `354d6f853082b8b8b348efe460725e4dc90558a1`. Their replacement approval envelopes bind the final reviewed parents, and their exact hosted gates passed before merge.
- [ ] **Protect upstream main and tag a Proofbound release.** Runtime CI, release, and Lake metadata now pin independently approved schema-v7 subject `1084e0d1dc5685933b705d8844af5b123399e0b9`, merged by Proofbound PR 9 as `3a78873634dbfeccfac1624b09d19a8afbe1b52a`. Move those pins to the protected release identity after tagging. Protection and tagging are maintainer actions.
- [ ] **Finish the upstream PBF sequence.** PBF-0007 landed through PR 7 at `32e44f08cd5b6ef36822d4881aaeccf54532de6c`; PBF-0003 landed through PR 8 at `7137a576c064d62e66b6d97659325c835ef53411`; and PBF-0002 landed through PR 9 at `3a78873634dbfeccfac1624b09d19a8afbe1b52a` from independently approved subject `1084e0d1dc5685933b705d8844af5b123399e0b9`. PBF-0001 remains last.
- [x] **Retain Proofbound release envelopes as canonical JSON.** Proofbound Specification 0001 keeps the version-7 envelope and compiled payload in the canonical JSON release contract. Runtime Specification 0003 and the composer now accept exactly envelope/payload version 7 and reject versions 3 through 6 as downgrades.

## Review process, RT-0.1

- [ ] **Add `CODEOWNERS`** for specs, ADRs, schemas, claims, formal bridges, `sys.rs`, launcher and supervisor code, the verifier, and release workflows. Name a real reviewer per entry.
- [ ] **Require one approving review on main.** Branch protection currently requires zero. This review-count decision is a maintainer action; until it changes, leave PRs visibly unapproved rather than self-approving.
- [ ] **Split future work into claim-wave PRs** under ten hand-written commits. PR 3 is 372 commits and cannot be reviewed as a unit.

## Network decision, Order 7

- [x] **Get ADR 0004 an independent review** and record acceptance or rejection. Acceptance rests on Claude's independent model review of the frozen comparison and registered attack domain on 2026-09-11, endorsed by the maintainer; it does not imply a human reviewer under UP-0.1. The accepted ADR records the four required changes and retains the implementation gates.

## Deferred by the roadmap's own rules, not incomplete

CPU and output-capacity implementation wait on adopted-workload evidence under ADRs 0006 and 0007. SDK registry publication moved to roadmap 2 RT-7. Order 8 is blocked on Order 7. The two-week RT-0.4 latency measurement cannot start until the gate is green.

Next: paste the first group to the other agent. Nothing else on this list can be verified until the gate passes.
