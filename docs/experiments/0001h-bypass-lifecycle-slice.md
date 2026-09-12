# Experiment 0001H: Bypass and lifecycle slice

- **Status:** complete; all eight hosted results independently verified
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

## Hosted result

The slice completed at exact source
`7719ea2cbd0a4e54b77ed2eef0ee2ed8800caa97` in GitHub Actions run
[`34506078724`](https://github.com/bordumb/proofbound-runtime/actions/runs/34506078724).
All 18 cases matched for all four mechanisms on x86_64 and aarch64 Linux: 144
of 144 registered cells. Both hosted decision-fixture jobs passed. After
download, the independent verifier reconstructed every plan and raw outcome,
checked every manifest and digest, and validated the retained syscall,
stopped-release, inherited-descriptor, mediator, substitution, reuse, cleanup,
runner, and no-replace evidence in all eight results.

| Mechanism | aarch64 `RESULT.json` SHA-256 | x86_64 `RESULT.json` SHA-256 |
| --- | --- | --- |
| `landlock-port` | `2c66b7090a0977ae81b57f3128bf90696260a525f025b3d61fd1c53fabb88413` | `5d3778fc3ec5818993e2650e2bf23d9a25ee36d77b08a06233089ce8f21aba7c` |
| `cgroup-endpoint` | `58062ada4a41c9b3b42ba7390defd80b7bce6fa807748ac051fcb6ca349e34f7` | `0ec07c985950b3e88bb5504749ce03bc2cb8bb38203031724645bba12e82c005` |
| `explicit-broker` | `35702acccb3e0a670c3d5f8df35bf5c183660650fb423ebb9cc07575f2bee499` | `26550fcefb12b9c95f45db30654ee518d4f998ef8271fb0c5bd6305505d801f9` |
| `preconnected-channel` | `24cebfd98d87b3c6fcd558f6b745a88ef968990ab050ee4c2cf8920c90d26ada` | `c0210e5bf3045dff8aa6d74805170d7382712e00ccdf4d5f77bf3706ec4495df` |

The first hosted run retained a staged-inventory failure caused by Python bytecode
and an architecture-sensitive executable bound. The second retained Landlock's
native `EACCES` connect denial where the harness had required `EPERM`. Both
failures were corrected in later commits without changing an expectation. A
downloaded-result recheck then exposed host-dependent `EAGAIN` numbering in the
portable verifier; the verifier now freezes Linux ABI errno values. This result
closes only the bypass/lifecycle functional slice. It does not select a
mechanism or authorize production network behavior. The later measurement and
deterministic comparison are recorded separately; an independently reviewed
network decision ADR remains required.
