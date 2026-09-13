# Experiment 0001F: Routing and transport slice

- **Status:** native results recorded and independently verified
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001](0001-network-authority-mechanisms.md)
- **Decision protocol:** [Experiment 0001E](0001e-decision-matrix-execution.md)
- **Machine domain:** [`decision-matrix.toml`](../../experiments/network_authority/decision-matrix.toml)
- **Production effect:** none

## Question

For every routing-and-transport case registered before implementation, where
does each candidate actually enforce authority: plan validation, child syscall
boundary, routing selection, TLS authentication, application protocol, or not
at all?

This slice compares mechanisms; it does not repeat the first-control
conclusions as if they were new evidence. A result is complete only when all 16
registered cases execute for one mechanism and architecture against the same
manifest and source commit. Every raw failure remains a harness failure until
the recorder can derive one closed outcome and stage.

## Common disposable topology

Each mechanism runs alone in a new Linux network and mount namespace with no
external route. Loopback contains these exact roles:

| Role | IPv4 | IPv6 | Port | TLS identity |
| --- | --- | --- | ---: | --- |
| Declared endpoint | `127.0.0.1` | `fd00::1` | 443 | `allowed.test` |
| Undeclared endpoint | `127.0.0.2` | `fd00::2` | 443 | `denied.test` or the allowed certificate, as the case requires |
| Other-port target | `127.0.0.1` | — | 8443 | socket-bypass sentinel |

The runner adds both IPv6 addresses to loopback explicitly. It generates one
certificate for `allowed.test` and one for `denied.test`; private keys never
leave the temporary root. Each contact-capable case starts a fresh one-exchange
fixture and uses an absent state directory. A fixture that remains uncontacted
after an exact plan, child-boundary, or routing denial is terminated and reaped
within the cell deadline; its absent contact and completion documents are part
of the raw denial observation. A second connection, fixture timeout after
contact, orphaned fixture, cleanup failure, or attempted replacement is a
harness failure. Plan-rejection and bind/listen cases start no fixture.

The dual-stack TLS fixture requires TLS 1.3, exact SNI `allowed.test`, an exact
HTTP request, and an exact response. The socket fixture requires one bounded
probe followed by write-half closure for streams, or one exact datagram, and
returns one sentinel. Neither fixture resolves a name, follows a redirect,
retries, or contacts an upstream network.

## Common child boundary

Mechanisms A and B must combine their candidate enforcement with the parent
protocol's “rest of the boundary.” A native wrapper therefore permits creation
of only IPv4 or IPv6 TCP stream sockets and permits `connect(2)`, while
returning `EPERM` for:

- UDP, raw, packet, Unix, netlink, and every other socket family or type;
- `bind`, `listen`, `accept`, `accept4`, and `socketpair`;
- datagram and message send/receive operations; and
- `io_uring_setup`, `io_uring_enter`, and `io_uring_register`.

It closes undeclared inherited descriptors, sets `no_new_privs`, drops to
uid/gid 65534, records the exact architecture-specific seccomp program, and
executes the staged case client. It deliberately leaves TCP `connect` visible
to Landlock or cgroup BPF. A seccomp-only denial may not be attributed to those
candidate mechanisms.

Mechanisms C and D retain their stronger proven child wrappers: no direct
network socket creation or connection is available, and the child receives
only the registered local channel. All four wrappers use byte-identical staged
clients from the exact Git subject and record a child-start marker.

## Candidate configuration

### A: port-only Landlock

The wrapper handles TCP connect and TCP bind. It permits outbound TCP connect
to port 443 and adds no bind rule. It records the observed Landlock ABI and
exact rules. IPv4 and IPv6 endpoints on 443 are intentionally indistinguishable.

### B: cgroup-BPF endpoint selection

The privileged loader creates closed IPv4 and IPv6 endpoint maps containing
only `127.0.0.1:443` and `fd00::1:443`. Exact `connect4` and `connect6`
programs consult their corresponding maps. The runner records map keys and
values, program instructions, verifier logs and identifiers, attachment
flags, kernel BTF identity, cgroup identity, and successful detach/removal.
The loader and maps remain outside the child cgroup.

### C: explicit operation broker

The child request schema has no target, address, URL, certificate, or transport
field. The broker configuration chooses the address family for an exact-service
case. Any literal or undeclared target field is rejected by the application
protocol. Wrong-certificate cases reach the configured endpoint but return the
closed broker error after TLS failure. An alternate routing endpoint is
rejected by the broker's connected-peer check before TLS.

### D: preconnected authenticated channel

The connector selects IPv4 or IPv6 before child release, confirms the exact
connected peer, authenticates TLS 1.3 for `allowed.test`, and then launches the
child with one transparent local stream. Every substitution case in this slice
fails before child release. The connector has no retry or second connection.

## Exact client actions

The case client has one closed command per matrix identifier:

- exact-service cases perform the exact TLS or mediated request;
- undeclared service, literal address, alternate endpoint, and mapped-address
  cases issue the exact raw or mediated attack required to distinguish routing
  from TLS or application policy;
- the wrong-certificate case performs certificate and hostname verification
  against only the registered trust root;
- direct TCP uses the socket sentinel on port 8443;
- both UDP cases use distinct exact datagrams on an undeclared endpoint;
- TCP bind/listen and UDP bind require exact `EPERM`; and
- non-scoped scope ID and alternate textual address are rejected by the
  trusted case-plan parser before any fixture or child exists.

`alternate-address-text` uses `127.000.000.001`; accepting it or silently
canonicalizing it is a plan failure. `non-scoped-ipv6-scope-id` uses
`fd00::1%1`; a scope identifier is permitted only for a registered scoped
address, which this case is not.

## Closed observation derivation

Before launch, the privileged one-case orchestrator copies the registered
expectation and decision-matrix digest into one immutable `case-plan.json`.
After execution, it writes one raw cell without comparing the observation to
that expectation. The generic recorder validates the prelaunch snapshot and
derives one immutable `CELL.json` using this precedence:

1. missing, malformed, duplicate, oversized, late, or replaceable input or
   output is `harness-failure`;
2. exact trusted-parser rejection with no fixture or child is `denied@plan`;
3. exact mediator endpoint/TLS rejection with no child is
   `denied@prelaunch`, except C's registered routing/TLS stages;
4. exact `EPERM` for a registered socket, bind, or listen syscall is
   `denied@child-boundary`;
5. exact `EPERM`/`EACCES` from `connect` or a trusted peer-tuple mismatch is
   `denied@routing`;
6. exact certificate/name rejection before HTTP bytes is `denied@tls`;
7. the broker's exact schema error is `denied@application-protocol`;
8. exact fixture and client transcripts yield `allowed@application-protocol`
   for the declared workload; and
9. exact attack bytes reaching a broader permitted route yield
   `exposes-limitation@routing`.

No generic nonzero exit, timeout, absent fixture observation, child-written
label, or TLS error text is a denial. The recorder rejects a cell unless its
raw bounded observations select exactly one rule above and match the frozen
expectation.

## Per-mechanism result

One no-replace result directory contains:

- the exact source commit and decision-manifest bytes and digest;
- all 16 `CELL.json` documents in inventory order;
- fixture ready/observation documents and bounded stdout/stderr/exit records;
- staged source and built-wrapper identities;
- mechanism configuration and enforcement identities;
- architecture, kernel, compiler, Python, OpenSSL, and relevant ABI/BTF
  identities; and
- cleanup observations for fixtures, cgroup attachments/maps, namespaces, and
  temporary channels.

`RESULT.json` is complete only when the inventory is exact, all cells match,
and cleanup succeeds. The runner exits nonzero after retaining any mismatch.
Its conclusion is only `routing-transport-slice-matched`; it cannot select a
mechanism or authorize production code.

## Implementation sequence

1. close and test the case-plan/parser and child action vocabulary;
2. implement and falsify the common A/B child boundary;
3. implement the IPv4/IPv6 cgroup-BPF maps and loader observations;
4. implement per-mechanism one-case orchestration;
5. implement the generic cell/result recorder and mutation tests;
6. compose the clean-subject namespace runner; and
7. execute and independently verify all eight architecture/mechanism results.

Every item is a separate commit. A discovered mismatch changes implementation
or amends this protocol in a later commit; it never rewrites the expected cell
after observing a run.

Items 1 through 6 are implemented on the roadmap branch. The implementation
includes closed direct and mediated client vocabularies, native A/B controls,
all four one-case orchestrators, immutable prelaunch expectation snapshots, a
generic no-replace recorder, an independent verifier, and the clean-subject
namespace runner. Portable falsifiers, strict x86_64/aarch64 cross-compilation,
shell lint, the repository-wide Rust gate, and the Lean 4.33 build pass locally.
These checks are implementation evidence, not native enforcement results.

## Recorded result

Item 7 completed at exact source commit
`eb1c3954b44d4faf04994c861241f34e38e08e4b` in GitHub Actions run
[`34484880654`](https://github.com/bordumb/proofbound-runtime/actions/runs/34484880654).
The workflow ran every mechanism natively on x86_64 and aarch64 Linux. All
eight runners exited zero, published a complete immutable result inventory,
and reported the pre-registered conclusion
`routing-transport-slice-matched`. The two native decision-fixture jobs also
passed on the same source commit.

After download, the repository's separate verifier reproduced every declared
input size and SHA-256 digest, rejected no file, confirmed the exact source and
manifest identities, and matched all 16 registered cells in every result. The
verified result identities are:

| Mechanism | Architecture | Matched cells | `RESULT.json` SHA-256 |
| --- | --- | ---: | --- |
| port-only Landlock | x86_64 | 16/16 | `06767f68c197dfc98dbe2b84ed22090d2979d6de439c3e05b930bd083cadf6ab` |
| port-only Landlock | aarch64 | 16/16 | `a003c2fbeab6b2731521a7e6c81c996440eab2368cdb7010f641a899669faa51` |
| cgroup-BPF endpoint | x86_64 | 16/16 | `ccfb40769972e5f7e3ae46b99dba70349c9e2e5c84b51ae148740e3303dd4904` |
| cgroup-BPF endpoint | aarch64 | 16/16 | `e2228bc7244caeebf4b73ac174ff3af701742ee24e590b60ada95f95931a60a7` |
| explicit operation broker | x86_64 | 16/16 | `96664e288dc7ed8eaf7b1a3fc6699a47f0fdfb604ca06af7d86935c133566de9` |
| explicit operation broker | aarch64 | 16/16 | `940a8d15c8a0172c93867c6a22adccc64879c0e6a11cf31c7aa23df672724138` |
| preconnected authenticated channel | x86_64 | 16/16 | `548ec3244e42f46b162635f57d2139458dcb4f66a1b88a842b798b9288de1bd7` |
| preconnected authenticated channel | aarch64 | 16/16 | `4e10837395327feb1ea7e2e172f4d2a60ab366d3dd7485d6dad5a76114d0dfc1` |

This records 128 matched native cells over one exact subject. The result means
only that each mechanism behaved as pre-registered for the routing and
transport slice. It does not select a mechanism, establish resolution or
application-indirection behavior, close the bypass/lifecycle or measurement
slices, authorize a production network profile, or replace the independent
review required for the network decision ADR. Experiment 0001E now advances to its frozen
resolution and application-indirection slice.

### Later synchronization regression

A later full-matrix repetition at exact source `ccfa7f3` in GitHub Actions run
[`34551042530`](https://github.com/bordumb/proofbound-runtime/actions/runs/34551042530)
retained one red x86_64 port-only Landlock envelope. Fifteen cells matched. In
`undeclared-service-ipv6-443`, the child recorded `routing-connected`, but the
fixture's atomic contact publication was interrupted between temporary-file
write and rename because cleanup observed the final path too early. The raw
cell therefore retained `fixture_contact=false` and correctly became
`harness-failure`; the expected routing limitation was not silently admitted.

Commit `4ea7e3c` freezes that delayed-publication race. Commit `6ace563` waits a
bounded 250 milliseconds for the contact rename only when the already-published
client event requires fixture contact, then applies the existing cleanup and
closed observation rules. This is a harness synchronization repair, not a
change to any expected mechanism outcome. A new complete native repetition is
required before the failed run can be superseded.
