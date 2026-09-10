# Experiment 0001H: Bypass and lifecycle slice

- **Status:** pre-registered; implementation not yet measured
- **Parent protocol:** [0001E](0001e-decision-matrix-execution.md)
- **Decision domain:** `bypass-lifecycle` in `decision-matrix.toml`

## Question and boundary

Do mechanisms A through D preserve their registered authority boundary across
every bypass, identity-substitution, crash, reuse, cleanup, and publication
case, on x86_64 and aarch64 Linux? This experiment may classify a candidate;
it cannot authorize production network support or select the ADR.

The immutable matrix contains exactly 18 ordered cases: six socket/process
bypasses, six lifecycle/crash/reuse cases, four identity substitutions, one
cleanup failure, and one no-replace publication case. Each case has exactly
one expectation per mechanism. Execution code must not read that expectation.

## Required observations

Every case freezes a prelaunch plan containing the matrix digest, source
commit, mechanism, action, subject identities, inherited descriptor inventory,
maximum connection/process counts, and cleanup obligations. Raw evidence must
retain the attempted operation, the first denying boundary, process and
descriptor identities before and after release, mediator state transitions,
native control acknowledgement, fixture contacts, teardown inventory, and
runner exit.

The install-race cell requires a launcher-shaped stopped child: no network
operation may precede the complete native-boundary acknowledgement. Unix,
raw/packet, and `io_uring` attempts must be real syscalls with their native
errno retained. Inherited Internet descriptors are rejected before release.
Crash and restart cases bind mediator PID, executable digest, channel peer,
and generation. Substitution cases mutate exactly one committed object after
planning. Reuse attempts perform the registered exchange and then one excess
exchange. Cleanup success requires no surviving child, mediator, cgroup,
attachment, namespace, or open control channel. Existing output bytes must
remain byte-identical.

## Result and verification

One no-replace result contains 18 closed cells plus exact evidence, source,
tool, and decision-matrix inventories. An independent verifier reconstructs
the case vocabulary and expected plan parameters without importing the
producer, orchestrator, or classifier. It derives every observed outcome from
raw evidence and accepts only 18/18 matches.

Implementation proceeds in historical commits: close the case vocabulary;
add syscall and lifecycle fixtures; add immutable plans and raw classifier;
add mechanism orchestrators; add recorder and independent verifier; compose
the clean-subject runner; add the eight-job hosted matrix; then download,
independently verify, and record all eight results. Any mismatch is preserved
and fixed in a later commit; registered expectations are never rewritten from
observed output.
