# Experiment 0001G: Resolution and application-indirection slice

- **Status:** complete; all eight hosted results independently verified
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001](0001-network-authority-mechanisms.md)
- **Decision protocol:** [Experiment 0001E](0001e-decision-matrix-execution.md)
- **Machine domain:** [`decision-matrix.toml`](../../experiments/network_authority/decision-matrix.toml)
- **Production effect:** none

## Question

For all 18 pre-registered resolution and application-indirection cases, does a
candidate bind authority to the declared service or operation after DNS answer
changes, aliases, redirects, tunnel targets, ambient proxy variables, and
resolver substitution?

This slice begins only after the routing/transport slice is recorded. It does
not repeat those results. A complete result executes the exact 18-case
inventory for one mechanism and architecture against one manifest and source
commit. A timeout, absent transcript, parser exception, or generic nonzero exit
is a harness failure until the recorder derives one registered outcome and
stage from bounded raw observations.

## Disposable topology and identities

Every mechanism runs alone in a fresh Linux network and mount namespace with
no external route. The topology reuses the routing slice's declared TLS
service at `127.0.0.1` and `fd00::1` port 443 and its undeclared service at
`127.0.0.2` and `fd00::2` port 443. It adds:

- one authoritative scripted DNS fixture on a runner-selected loopback port,
  serving both UDP and TCP without contacting an upstream resolver;
- one declared redirect service authenticated as `allowed.test`;
- one undeclared proxy endpoint on `127.0.0.2:443` that presents the registered
  experiment certificate and implements only the exact CONNECT or SOCKS
  transcript selected by the case; and
- a second DNS configuration for the substitution case, byte-distinct from
  the registered configuration and returning only the undeclared endpoint.

The runner records generated public certificates but never retains their
private keys. It records exact DNS zone/script bytes, query and response bytes,
ordered UDP/TCP transcript, resolver configuration, environment, redirect and
proxy exchanges, fixture contacts, staged clients, native controls, and
cleanup. DNS identifiers are deterministic per case and address family. The
authoritative fixture accepts at most the registered query count and has one
bounded deadline.

No client uses the host resolver, `/etc/resolv.conf`, NSS, a browser, `curl`, or
a language HTTP proxy implementation. Those would introduce unregistered
search paths, retries, canonicalization, redirect policy, or environment
semantics. The experiment clients implement only the closed behaviors below.

## Resolution ownership

Mechanisms A and B have routing authority but no service-identity component.
For the DNS cases, a staged resolver helper performs the exact registered
queries, applies only DNS message grammar and the case's loop/depth bound, and
passes the terminal address to the transparent client. It does not reject an
otherwise well-formed terminal name or address for being undeclared. The
client then attempts the resulting route. A's port rule can therefore expose a
well-formed rebind or CNAME to another service on port 443; B's endpoint map
can deny the resulting undeclared tuple. The helper, parser, fixed query plan,
and local handoff are experiment trusted computing base and are inventoried.

Mechanism C's broker and mechanism D's connector own resolution before the
untrusted child can send application bytes. They require the terminal service
name and address to remain in the registered set, reject unrequested DNSSEC
assertions, enforce the exact CNAME and TTL policy, and fail before child
release when the case expectation says `resolver` or `prelaunch`. A stable or
declared-alias result is consumed exactly once by the broker or connector.

For `ttl-rebind-to-undeclared`, the resolver performs one successful query and
declared-service exchange, waits until the frozen one-second TTL expires, then
performs exactly one refresh. The second address is the undeclared endpoint.
There is no stale-cache fallback or retry. C and D reject the refreshed answer
at the resolver stage without releasing a second child. A attempts the second
route and observes the undeclared sentinel. B attempts it and records the
native routing denial.

## Closed DNS cases

The resolver client implements canonical A and AAAA UDP queries and exact
DNS-over-TCP framing. Each case has these required observations:

| Case | Required exchange |
| --- | --- |
| `stable-a-and-aaaa` | One A and one AAAA answer for `allowed.test`; both terminal addresses and declared TLS exchanges must match. |
| `ttl-rebind-to-undeclared` | Two A queries separated by at least the registered TTL; ordinal zero returns `127.0.0.1`, ordinal one `127.0.0.2`. |
| `cname-to-declared-service` | One A query for `alias.test`; exactly one CNAME ends at `allowed.test` and its declared address. |
| `cname-to-undeclared-service` | One A query for `alias.test`; exactly one CNAME ends at `denied.test` and `127.0.0.2`. |
| `cname-loop-or-depth` | Two sub-observations: one exact two-name loop and one acyclic chain exceeding the registered depth of four; both must close at the resolver. |
| `resolver-timeout` | One UDP query, no response bytes, and expiration of the registered response deadline; no fallback. |
| `resolver-truncated-tcp-fallback` | One truncated UDP response followed by the byte-identical question over TCP and one complete declared answer. |
| `resolver-malformed-response` | One response with the correct identifier and invalid bounded body; no retry. |
| `resolver-dnssec-flag-confusion` | One otherwise valid declared answer carrying the unrequested AD flag; no retry. |

Response identity, question identity, answer inventory, TTL, class, address
family, terminal name, and trailing bytes are exact. Any unregistered query,
extra response, fallback, or fixture deadline is a harness failure.

## Closed redirect and proxy cases

The redirect fixture returns one exact HTTP/1.1 302 response from the declared
TLS service. A and B use a transparent redirect client. C's fixed operation
schema has no redirect input and rejects the response at its application
boundary. D exposes the response on its authenticated transparent channel,
but its child boundary denies the new direct connection.

- `redirect-undeclared-host` targets `https://denied.test/v1/echo` on port 443.
  A reaches the undeclared sentinel; B denies its tuple; C rejects the
  redirect; D's child cannot open the follow-up connection.
- `redirect-cleartext` targets `http://allowed.test/v1/echo`. A and B deny the
  unregistered cleartext port at routing; C rejects the redirect; D denies the
  follow-up socket.
- `redirect-other-port` targets `https://allowed.test:8443/v1/echo` with the
  same stage distinctions as cleartext.

For `http-connect-target-confusion` and `socks-target-confusion`, the client
authenticates the allowed endpoint, sends the exact tunnel request naming
`denied.test:443`, writes one probe, and receives the undeclared-service
sentinel. A, B, and D thereby expose application authority broader than service
identity; C's operation grammar cannot encode either tunnel and rejects it.
The fixture simulates the terminal service inside the bounded transcript and
does not make an unobserved second network connection.

For `ambient-http-proxy`, `ambient-https-proxy`, and `ambient-all-proxy`, only
the named variable is present and its exact value selects the undeclared proxy
endpoint on port 443. A's transparent client parses the frozen value and
reaches the proxy sentinel. B attempts the same tuple and is denied by routing.
C and D compare the complete environment to an empty registered environment
before launch and reject the substitution at `plan`. No ordinary library
environment discovery is accepted as evidence.

`resolver-configuration-substitution` replaces the registered resolver file
after its digest is committed to the case plan and before boundary release.
A, which has no configuration-identity component, consumes the substituted
configuration and exposes the undeclared terminal answer at `resolver`. B, C,
and D compare the immutable plan identity before release and record
`denied@prelaunch`. No child or service fixture starts for those three cells.

## Child and mediator boundaries

A and B reuse the routing slice's native child wrapper and candidate controls.
Only staged resolver-result and plan descriptors registered before release may
be inherited; direct UDP, raw, packet, Unix, netlink, bind/listen, descriptor
duplication, and `io_uring` remain denied. Resolver fixture I/O occurs in the
identified helper, not through ambient child authority. TCP service attempts
remain visible to the candidate Landlock or cgroup-BPF enforcement.

C reuses the closed operation broker. Its child request contains no URL,
redirect, proxy, resolver, host, port, or tunnel field. D reuses the
preconnected authenticated-channel wrapper; transparent application bytes are
allowed only on its one inherited channel, while every follow-up socket is
denied. The broker or connector completes all registered DNS and TLS work
before child release unless the TTL-refresh case explicitly requires the
second prelaunch resolution cycle.

## Observation derivation

Each one-case orchestrator writes an immutable `case-plan.json` before any
fixture, helper, mediator, or child starts. It contains the exact expectation,
manifest digest, DNS query plan, resolver and environment identities, endpoint
plan, fixture scripts, maximum counts, and deadlines. The raw recorder does
not read the expectation while executing the case.

The generic recorder derives one outcome with this precedence:

1. missing, malformed, duplicate, oversized, late, replaceable, or
   out-of-inventory state is `harness-failure`;
2. exact environment rejection is `denied@plan`;
3. exact planned-object digest mismatch before child or service contact is
   `denied@prelaunch`;
4. exact DNS grammar, policy, loop, depth, timeout, terminal-name, terminal-
   address, or refresh rejection is `denied@resolver`;
5. an undeclared well-formed terminal answer accepted by A is
   `exposes-limitation@resolver`;
6. exact native endpoint/port rejection of a derived redirect or answer is
   `denied@routing`;
7. undeclared endpoint contact through A is `exposes-limitation@routing`;
8. exact D follow-up socket denial is `denied@child-boundary`;
9. C's exact closed-operation rejection is
   `denied@application-protocol`;
10. an exact tunnel transcript and undeclared sentinel through A, B, or D is
    `exposes-limitation@application-protocol`; and
11. exact DNS, TLS, request, response, and cleanup transcripts yield
    `allowed@application-protocol` for the declared workload.

An error string, exit status, missing fixture contact, timeout alone, or
child-selected label never establishes an outcome. Raw observations must
select exactly one rule and match the frozen expectation or result publication
fails.

## Result, verification, and execution sequence

One no-replace result directory contains all 18 `CELL.json` files, exact
source and manifest bytes, raw fixture/helper/mediator/child observations,
query and response bytes, prelaunch plans, configuration and environment,
staged and built object identities, architecture and tool identities, and
cleanup. `RESULT.json` is complete only when the inventory is exact and all
cells match. Its only successful conclusion is
`resolution-indirection-slice-matched`; it cannot select a mechanism.

Implementation proceeds as separate historical commits:

1. complete and falsify the DNS depth and fixture-contact vocabulary;
2. implement and falsify the closed resolver and redirect/proxy clients;
3. implement the immutable resolution case plan and raw classifier;
4. implement per-mechanism one-case orchestration;
5. implement the generic no-replace recorder and mutation tests;
6. compose and falsify the clean-subject namespace runner;
7. add the exact eight-job native workflow matrix; and
8. run one clean commit on both architectures, download all eight retained
   results, independently verify them, and record their identities.

The slice does not advance to bypass/lifecycle until all eight retained result
inventories verify. A mismatch changes implementation or amends this protocol
in a later commit; it never rewrites a registered expectation after observing
the run.

## Hosted result

The slice completed at exact source
`3efbd6d0c743fa16d2f72230c57171f09df5b009` in GitHub Actions run
[`34495928504`](https://github.com/bordumb/proofbound-runtime/actions/runs/34495928504).
All 18 cases matched for all four mechanisms on x86_64 and aarch64 Linux: 144
of 144 registered cells. Every downloaded immutable inventory passed the
independent verifier. The exact `RESULT.json` SHA-256 identities are:

| Mechanism | aarch64 | x86_64 |
| --- | --- | --- |
| `landlock-port` | `a697af7b5a060a4eba18148f551e10901687d587f7da3f6f292507fbed2c0b89` | `188e67089f05069fc9d35c8fdf656280757a0043814f8aa2f0259b77ce37ee16` |
| `cgroup-endpoint` | `0793503a270e9976f1acf11ce842a0c40217f188154d29887efa3f9782aa3186` | `4e0f43827308a55a2cb456c56e9db680692bd9141d964284481cb338ec881a9b` |
| `explicit-broker` | `ce67d6892b4f5d771b9fe9955f4c48b0ec0812a45f18a2d55eddb91fd2336951` | `558b1dd7f5d39d54bf751b43f12a874d7a66752c6ce665e0dbba7eda129c4072` |
| `preconnected-channel` | `6fe968fd2c11b0b1e91d80f0ba1706ffd655ea9f664f9ab6b9fd1c367747b218` | `31fe4ad9c671ead0b451b80687e088466f2516e13ab7ab2ff376b1f0a4871ff5` |

The first hosted execution exposed two harness defects at the denial boundary:
plain `socket.sendall` selected the forbidden `sendto` syscall, and cgroup
proxy-connect denials escaped instead of becoming typed routing evidence. The
falsifiers and client were corrected in `3efbd6d`; the successful rerun above
is the first decision-grade result. This closes the resolution and
application-indirection slice only. The later bypass/lifecycle, measurement,
and deterministic comparison results are recorded separately. Independent ADR
review remains required before selecting a production mechanism.
