# Experiment 0001: Network authority mechanisms

- **Status:** experiment and deterministic comparison complete; ADR review open
- **Date:** 2026-09-10
- **Roadmap:** RT-4.1 and RT-4.2
- **Decision output:** proposed [ADR 0004](../adr/0004-authenticated-service-session.md)
- **Production effect:** none

## Question

Which supported Linux mechanism, if any, can let one identified client call one
declared HTTPS service while denying every undeclared network path and keeping
the authority, trusted computing base, lifecycle, and receipt meaning honest?

This experiment does not ask whether the child can reach “port 443.” A port is
not a service identity. It does not ask whether DNS returned one address once.
An address is not a stable DNS or TLS identity. The experiment separates
routing, resolution, and transport authentication so a passing result cannot
silently substitute one for another.

## Kernel facts that constrain the experiment

Classic seccomp BPF can inspect scalar syscall arguments but cannot dereference
the `sockaddr` pointer passed to `connect(2)`. The
[kernel seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
also warns about tracee-memory time-of-check/time-of-use risk for a userspace
notification supervisor. The existing Runtime deny profile may reject socket
operations through seccomp; a classic filter alone cannot select a destination
address or hostname.

Landlock network rules identify TCP or UDP actions by port. TCP support begins
at ABI 4 and UDP support at ABI 10. The
[kernel Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
does not give a port rule a remote address, hostname, certificate, or service
identity. A port-only Landlock profile is therefore a broad-authority control,
not a candidate for the service-identity claim.

Linux exposes cgroup-BPF `connect4` and `connect6` attachment types, as listed
in the
[kernel BPF program-type documentation](https://docs.kernel.org/bpf/libbpf/program_types.html).
They can mediate routing endpoints but add privileged loading, attachment,
pinning, program/map lifecycle, and kernel-verifier identities. DNS and TLS
identity remain separate unless another trusted component binds them.

These are input facts, not experimental results. Every tested kernel interface
and ABI is still recorded by exact identity in the result.

## Frozen workload

The production-shaped workload is one identified, dynamically linked HTTPS
client making one request to:

```text
https://allowed.test:443/v1/echo
```

The request carries a fixed non-secret fixture token. The response body is a
fixed 32-byte value. The client must validate a pinned experiment trust root,
the DNS name `allowed.test`, the TLS certificate validity interval, and the
expected application response. Success means all of those checks passed; a
TCP connection alone is not success.

The deterministic corpus uses an isolated Linux network namespace or an
equivalent disposable test network containing:

- authoritative DNS servers controlled by the fixture;
- one IPv4 and one IPv6 address for `allowed.test`;
- distinct IPv4 and IPv6 addresses for `denied.test`;
- an allowed TLS server with a certificate for `allowed.test`;
- a denied TLS server with a certificate for `denied.test`;
- a server on an allowed address with the wrong certificate;
- a server that redirects to `denied.test`;
- HTTP CONNECT and SOCKS proxy fixtures;
- TCP, UDP, QUIC-shaped UDP, and Unix-socket listeners; and
- one inherited connected socket supplied before boundary installation.

No fixture contacts the public Internet. An optional later external API
observation requires a separate explicit protocol and credential handling
review. It cannot replace the deterministic corpus.

## Authority vocabulary

Every candidate profile must represent these concepts separately:

- **routing endpoint:** address family, IP address, transport, and port;
- **requested service name:** the exact lower-case DNS name;
- **resolution authority:** resolver identity, query transport, CNAME policy,
  TTL policy, address-set bounds, and the point when resolution occurs;
- **transport identity:** TLS trust roots, DNS-name verification, minimum TLS
  version, and whether redirects or proxy tunnels are permitted;
- **direction and protocol:** outbound TCP, UDP/QUIC, inbound bind, Unix socket,
  or inherited connected descriptor; and
- **credential availability:** a registered non-secret credential-source
  identity and declared service binding, never the credential value.

The experiment does not claim that making a credential available proves where
the child sent it. A mechanism can make that claim only if the credential is
released through an enforcement point that authenticates the declared service
and prevents direct disclosure paths.

## Common invariants

Every profile starts the target client through the existing stopped-launcher
sequence. Before release, the supervisor must:

1. identify the exact client, loader, libraries, plan, and compiled policy;
2. close every undeclared inherited descriptor;
3. install the complete filesystem, process, resource, and network boundary;
4. verify every selected program, map, rule, broker, namespace, and channel
   identity that the profile claims to bind; and
5. receive the launcher's bound acknowledgement.

The child receives no ambient proxy setting, resolver setting, credential, or
network descriptor unless it is explicit in the profile. Unsupported kernels,
missing privileges, partial attachment, stale pinned objects, broker startup
failure, resolver failure, certificate failure, and cleanup failure are closed
errors. No candidate may fall back to the version 1 deny profile and describe
the requested network execution as successful.

## Mechanism A: Port-only Landlock control

The child receives Landlock permission to connect to TCP port 443. Direct UDP,
other TCP ports, bind operations, Unix sockets, inherited descriptors, and
`io_uring` network paths remain denied by the rest of the boundary.

This mechanism is expected to reject attacks on other ports but permit any
reachable IPv4 or IPv6 endpoint on port 443. That expected service-substitution
failure is the control result. If it unexpectedly identifies a remote service,
the result must name the exact additional kernel mechanism responsible.

The mechanism may support only a claim such as “outbound TCP connect to any
reachable endpoint on port 443.” It must not be selected for the declared
service-identity requirement.

## Mechanism B: IP endpoint mediation with cgroup BPF

Attach exact cgroup-BPF `connect4` and `connect6` programs to the fresh
execution cgroup. The closed maps contain only the resolved experiment address,
transport, and port tuples. The profile denies child DNS and direct connection
to any other tuple.

The result records kernel BTF identity, BPF program and map bytes, verifier log
identity, loader identity, attachment type and flags, cgroup identity, map
contents, and detach/removal observation. A privileged loader remains outside
the workload cgroup and becomes trusted computing base.

This mechanism can select routing endpoints. It does not by itself establish
that the endpoint remains associated with `allowed.test`, that its TLS
certificate is acceptable, or that an application redirect stays within the
declared service. A production claim would require an explicit resolver/TLS
binding component or deliberately weaker endpoint-only language.

## Mechanism C: Per-execution egress broker

The child has no direct Internet socket authority. It receives one identified
local channel to a per-execution broker. The broker performs declared DNS
resolution, connects only to the resulting bounded endpoint set, authenticates
TLS for `allowed.test`, enforces redirect and proxy policy, and relays only the
selected application protocol.

The experiment compares at least two child interfaces:

- an explicit length-framed request/response channel; and
- a constrained CONNECT-like channel whose target field must equal the plan.

The explicit protocol is preferred unless the transparent interface can keep
target, TLS, lifecycle, and parser ambiguity equally closed. The broker,
resolver, TLS implementation, trust roots, protocol parser, configuration,
binary, local channel, and logs become trusted computing base and exact receipt
subjects.

The child must be unable to bypass the broker through direct TCP, UDP, QUIC,
Unix sockets outside the identified channel, inherited descriptors,
`io_uring`, proxy variables, or resolver configuration. Broker crash, restart,
identity drift, log loss, and cleanup races are mandatory failures.

## Mechanism D: Preconnected descriptor

Before child release, a trusted connector resolves `allowed.test`, establishes
and authenticates TLS, and passes one connected application channel through a
registered descriptor. The child has no socket-creation or connection
authority.

The descriptor number, socket endpoint observations, TLS peer identity,
connector identity, channel protocol, and close-on-exec decision are exact
subjects. The connector must prove that the descriptor delivered to the child
is the authenticated channel it observed, not another reused descriptor.

This mechanism is deliberately narrow. It may fit a purpose-built client but
is not transparent to ordinary package managers, Git, or general LLM SDKs. The
decision must not generalize a passing purpose-built fixture to those workloads.

The first control is frozen separately in
[Experiment 0001D](0001d-preconnected-channel-control.md). Because userspace
TLS state cannot be transferred as only a kernel descriptor, it keeps one
authenticated TLS session in a connector and passes one local transparent
application channel. The control must record that this denies alternate
network paths but permits arbitrary bounded application bytes to the selected
service session.

## Attack matrix

Each row runs against every mechanism. “Allowed” means the exact frozen
workload completes. “Denied” means the child cannot exchange application bytes
and the profile emits its expected typed failure. “Exposes limitation” is a
registered negative result, not a flaky failure.

| Case | Required result |
| --- | --- |
| Exact IPv4 service, name, certificate, and response | Allowed for a viable service-identity profile. |
| Exact IPv6 service, name, certificate, and response | Allowed for a viable dual-stack profile or explicitly unsupported before launch. |
| `denied.test` on TCP 443 | Denied; port-only Landlock is expected to expose its limitation. |
| Literal allowed or denied IP in the URL | Denied unless an endpoint-only profile explicitly requested that literal identity. |
| Allowed address with wrong certificate or name | Denied before application bytes are accepted. |
| DNS answer changes from allowed to denied address | Denied or re-resolved under the exact frozen TTL/address-set rule. |
| CNAME to allowed service | Allowed only if the exact CNAME policy registers and records the chain. |
| CNAME to undeclared service | Denied. |
| Redirect to undeclared host, scheme, or port | Denied. |
| HTTP CONNECT or SOCKS tunnel to undeclared endpoint | Denied. |
| Ambient `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, or resolver override | Absent unless registered; substitution is denied. |
| Direct TCP to another port | Denied. |
| Direct UDP, DNS, or QUIC-shaped traffic | Denied unless the mechanism's registered resolver channel requires the exact flow. |
| TCP/UDP bind and listen | Denied. |
| Pathname and abstract Unix sockets outside the control channel | Denied. |
| Inherited connected Internet socket | Closed before child execution. |
| `io_uring` socket creation, connect, send, or descriptor use | Denied. |
| IPv4-mapped IPv6, scope ID, and unusual address encodings | Canonicalized or denied without changing endpoint meaning. |
| Resolver timeout, truncation, TCP fallback, malformed response, or DNSSEC flag confusion | Closed typed failure; no broader retry path. |
| Broker/connector crash or restart | Closed typed failure with no reconnection to an unbound instance. |
| Policy, map, rule, trust-root, certificate, channel, or executable substitution | Identity mismatch before successful receipt. |
| Child fork/exec tree at the process limit | Same network authority, no bypass. |
| Concurrent connection race during installation | No network operation before bound launcher release. |
| Cleanup, detach, or namespace teardown failure | No positive reusable receipt. |

## Measurements

For each mechanism and architecture, record:

- cold setup time before launcher release;
- median and p95 connect/request latency over at least 100 local fixture runs;
- broker or connector resident memory and process count where applicable;
- number and byte size of trusted binaries, programs, maps, rules, trust roots,
  and configuration objects;
- required Linux capabilities, namespace operations, sysctls, kernel config,
  Landlock ABI, BPF features, and cgroup controllers;
- deterministic cleanup success over at least 1,000 create/fail/remove cycles;
- exact result for every attack row; and
- every residual path that the mechanism cannot observe or enforce.

Performance cannot compensate for a failed authority requirement. Timing is
operational metadata, not claim evidence.

## Result record

Each immutable result directory contains:

```text
RESULT.json
plan.toml
attack-results.json
fixture-manifest.json
kernel-manifest.json
tool-manifest.json
artifact-manifest.json
stdout/
stderr/
```

`RESULT.json` identifies the experiment version, mechanism, exact Git commit,
architecture, kernel release and configuration digest, all tool and artifact
digests, fixture identity, start and finish time observations, completed attack
inventory, measurements, unsupported cases, and residual limitations. Result
publication uses no-replace semantics. A failed or incomplete run remains
retained and cannot be rewritten as passing.

No result contains a secret, private key, real credential, or public-service
response. Fixture private keys exist only in a fresh temporary root and are
destroyed after the result records their public certificate identity.

## Decision criteria

A mechanism is eligible for a production ADR only if both native architectures
complete the full attack matrix and independent review confirms all of these:

1. the claimed service identity is stronger than a port or one-time address;
2. all undeclared direct and inherited network paths fail closed;
3. DNS, CNAME, TTL, TLS, redirect, proxy, and credential meanings are explicit;
4. boundary installation completes before child code and cleanup is exact;
5. every new privileged or semantic component is named as trusted computing
   base with exact identity and lifecycle;
6. the receipt can report observations without claiming the host, resolver, or
   certificate authority proved more than it did;
7. unsupported hosts fail before execution with no weaker fallback; and
8. the operational cost is acceptable for one real adopter workload.

If no mechanism satisfies the criteria, ADR 0004 rejects the network-enabled
profile for the next release and records the missing kernel or product
capability. Port-only Landlock may still be documented as a distinct broad
authority only through a separate specification and claim; it is not the
fallback meaning of a service allow-list.

## Recorded result: mechanism A control

The port-only Landlock control ran at exact source commit
`d8d468b4d853e407c1437470ba51f25e54315f09` in GitHub Actions run
[`34430301059`](https://github.com/bordumb/proofbound-runtime/actions/runs/34430301059).
Both hosted jobs reported Linux `6.17.0-1022-azure`, Landlock ABI 7, and the
expected native architecture. Each immutable bundle inventoried 14 inputs;
independent post-download verification reproduced every recorded SHA-256
digest and found no unlisted file.

| Case | x86_64 | aarch64 | Interpretation |
| --- | ---: | ---: | --- |
| Allowed service on TCP 443 | exit 0 | exit 0 | The broad port authority permits the intended fixture. |
| Different service on TCP 443 | exit 0 | exit 0 | The rule cannot select service identity. |
| Intended service on TCP 8443 | exit 7 | exit 7 | A different port is denied by Landlock. |
| Wrong certificate on TCP 443 | exit 60 | exit 60 | The HTTPS client, not Landlock, rejects the certificate. |

The aarch64 `RESULT.json` digest is
`065a2f232eec5a7d87ed654c61c494a805158e947ed2c897a307ff2610c95fe8`.
The x86_64 digest is
`d1ad6b5bdc4be9f614f3f85135819a310ece07cd34e744176b11748659577587`.
Both results record the pre-registered conclusion
`port-only-landlock-cannot-select-service`.

This control rejects port-only Landlock as a mechanism for a service-identity
claim. It does not reject a separately named broad port-authority profile, and
it does not supply evidence for one. It did not test the full frozen attack
matrix, benchmark performance, or evaluate mechanisms C and D. Production
schemas and Runtime behavior remain unchanged.

## Recorded result: mechanism B control

The first hosted attempt, run
[`34432834363`](https://github.com/bordumb/proofbound-runtime/actions/runs/34432834363),
retained four failure envelopes but produced no mechanism result. A shared
recorder extraction had left the native runners using a direct Python entry
path that could not resolve the repository package. The failure occurred after
the mechanisms ran and before result publication. Commit `8043ed0` changed the
runners to module entry and added foreign-directory direct-entry regressions;
the twelve recorder falsifiers then passed locally. The failed run is not
treated as a network observation.

The cgroup-BPF endpoint control ran at exact source commit
`8043ed0f5f8c500bc2ada475193d35a7c2a605a4` in GitHub Actions run
[`34433053261`](https://github.com/bordumb/proofbound-runtime/actions/runs/34433053261).
Both jobs used Linux `6.17.0-1022-azure` with a cgroup v2 filesystem. Each
immutable endpoint bundle inventoried 15 inputs; independent post-download
verification reproduced every recorded SHA-256 digest, found no unlisted file,
and confirmed an empty runner error stream and exit zero.

| Case | x86_64 | aarch64 | Interpretation |
| --- | ---: | ---: | --- |
| Allowed endpoint `127.0.0.1:443` | exit 0 | exit 0 | The registered routing tuple is permitted. |
| `127.0.0.2:443` substitution | exit 7 | exit 7 | The connect4 program rejects a different address on the allowed port. |
| `127.0.0.1:8443` substitution | exit 7 | exit 7 | The connect4 program rejects a different port on the allowed address. |
| Wrong name/certificate on the allowed tuple | exit 60 | exit 60 | The HTTPS client, not cgroup BPF, rejects transport identity. |

Both results record clean program detach and cgroup removal. They contain the
same connect4 instruction digest
`8b3a18759d38c8c8de26f898f52fd954c260e3c7ab743b343d9a3d33b363c67e`
and connect6 instruction digest
`59f4a931744dcdc62944a018ed3990e666ec6444616418d3b09a82dc5c753d52`.
Their architecture-specific kernel BTF identities, verifier logs, program IDs,
cgroup IDs, compiler, client, and certificate identities remain in the
downloadable result bundles.

The aarch64 `RESULT.json` digest is
`c95c8a916a13c613c76ca24ef739f64113cd50dc2a97d41fc721a4c3d9e7a310`.
The x86_64 digest is
`5df5307cd1774bd004f495e7e11d14d4c27c59326c3c7fa5d7f19d9778664e76`.
Both results record the pre-registered conclusion
`endpoint-control-selects-routing-tuple-only`.

This control confirms that cgroup BPF can select one routing tuple in the
bounded fixture. It does not establish that `127.0.0.1` remains associated with
`allowed.test`, authenticate TLS, constrain redirects or application bytes,
test the full frozen attack matrix, or justify a production endpoint profile.
The privileged loader, programs, maps for a future address set, attachment
lifecycle, BTF/kernel behavior, and resolver/TLS binding would all require
normative treatment. The next experiment step was the per-execution broker;
production schemas and Runtime behavior remain unchanged.

## Recorded result: mechanism C control

Two bounded harness failures preceded the valid broker observation. Run
[`34435998227`](https://github.com/bordumb/proofbound-runtime/actions/runs/34435998227)
did not terminate because an unused fixture listener retained an unbounded
`accept`; it was canceled, and commit `629cf25` gave every fixture accept a
deadline. Run
[`34436379091`](https://github.com/bordumb/proofbound-runtime/actions/runs/34436379091)
then retained complete failure bundles: after dropping to uid/gid 65534, the
child could not traverse the hosted checkout path to its identified Python
client. Commit `1e45d43` staged the exact four-file client package inside the
disposable root, compared every staged byte with Git source, and recorded the
expanded source inventory. Neither failed run is treated as a network
observation.

The explicit per-execution broker control ran at exact source commit
`1e45d438a3c4fd4b92bd423bc914b3a57b2c2f5a` in GitHub Actions run
[`34436646720`](https://github.com/bordumb/proofbound-runtime/actions/runs/34436646720).
Both jobs used Linux `6.17.0-1022-azure` and the expected native architecture.
Each child retained descriptor 4 as one Unix stream channel, reported
`no_new_privs`, and installed the same 45-instruction seccomp program in every
case on its architecture. Independent post-download verification reproduced
every input digest, found no mismatched case, confirmed empty runner error
streams and exit zero, and observed experiment cleanup.

| Case group | x86_64 | aarch64 | Interpretation |
| --- | ---: | ---: | --- |
| Exact canonical echo request | exit 0 | exit 0 | The broker authenticated the fixed service and returned the exact application response. |
| Added target field | exit 7 | exit 7 | The closed request schema cannot select another service. |
| Direct TCP and UDP | exit 7 | exit 7 | Child socket creation is denied instead of bypassing the broker. |
| Wrong fixture certificate | exit 7 | exit 7 | Broker-side TLS authentication closes the request. |
| Zero, oversized, truncated, duplicate-key, invalid-UTF-8, and noncanonical frames | exit 7 | exit 7 | Malformed and ambiguous protocol inputs do not broaden the operation. |
| Fork then direct TCP | exit 7 | exit 7 | A descendant retains the child seccomp boundary. |
| Broker crash | exit 7 | exit 7 | Channel loss is a closed failure with no direct fallback. |
| Unexpected inherited descriptor | exit 7 | exit 7 | The wrapper rejects an undeclared descriptor before client execution. |

The architecture-specific seccomp instruction digests are
`78e4b6f1a7653f58ea9ff2e941292e1cc7065be53bbf4ac28ac015f040419526`
for x86_64 and
`5d96d94c1351957a01d921d5f3c7fb25c075bd49b2a640b989667b048bb9159e`
for aarch64. The x86_64 `RESULT.json` digest is
`cbba2687382592ae8cd14a253ff2770c9e5a98f9d7611ec14661e848bb4750fc`;
the aarch64 digest is
`dd9d5e6d69fc7b36dfc8fc5a002a264aa8009ce72a6bae09a28f891c9d73e88d`.
Both results record the pre-registered conclusion
`explicit-broker-binds-fixed-service-control`.

This control establishes only that one immutable explicit request protocol
survived its bounded first corpus. It does not support arbitrary HTTP clients,
DNS, CNAMEs, redirects, credentials, QUIC, connection pooling, transparent
proxying, or a production Runtime profile. The broker, Python runtime and
standard library, TLS stack, fixed configuration, parser, wrapper, channel,
and fixture remain experiment trusted computing base. Mechanism D and the
remaining full attack matrix are still required before an ADR can select a
production claim.

## Recorded result: mechanism D control

The first native attempt, run
[`34439277039`](https://github.com/bordumb/proofbound-runtime/actions/runs/34439277039),
failed on both architectures before the allowed client wrote its start marker.
The child filter denied every `fcntl` command, including descriptor queries
needed while starting the staged Python client. The failure also showed that a
pre-publication recorder rejection retained only its top-level diagnostic.
Commit `9fe5d2c` narrowed `fcntl` denial to the two duplication commands and
made any future recorder failure retain sanitized case state, stdout, stderr,
and public certificates while excluding fixture private keys. The failed run
contains no mechanism result.

The preconnected authenticated-channel control then ran at exact source commit
`9fe5d2c936ce92ee1f1f161000d50284445c3b21` in GitHub Actions run
[`34439915673`](https://github.com/bordumb/proofbound-runtime/actions/runs/34439915673).
Both jobs used Linux `6.17.0-1022-azure` and the expected native architecture.
Each immutable bundle declared 82 result inputs. Independent post-download
verification found exactly those 82 files, reproduced every size and SHA-256,
confirmed an empty runner error stream and exit zero, and observed cleanup.

| Case group | x86_64 | aarch64 | Interpretation |
| --- | ---: | ---: | --- |
| Exact canonical request | exit 0 | exit 0 | One TLS 1.3 session to the registered endpoint and name returned the fixed response. |
| Undeclared path and CONNECT-shaped request | exit 0 | exit 0 | Transparent application bytes reach the authenticated service; D does not enforce an operation schema. |
| Direct TCP, direct UDP, and descendant direct TCP | exit 7 | exit 7 | Child and descendant socket creation remain denied. |
| Alternate endpoint with denied or allowed certificate | exit 7 | exit 7 | The connector rejects routing-tuple substitution before child execution, even when TLS identity could match. |
| Wrong certificate and plaintext endpoint | exit 7 | exit 7 | TLS identity or transport failure occurs before child execution. |
| Connector crash | exit 7 | exit 7 | Session loss is closed with no reconnect or direct fallback. |
| Wrong channel cookie and non-Unix descriptor | exit 2 | exit 2 | Native descriptor validation rejects both before child execution. |
| Unexpected inherited descriptor | exit 7 | exit 7 | The wrapper closes the undeclared descriptor before the client observes it. |

Per architecture, ten cases established the one authenticated session, four
failed before child execution, eight installed the child boundary, and only
the three positive/application-exposure cases completed a relay. Every
authenticated observation records TLS 1.3, `allowed.test`, peer
`127.0.0.1:443`, and the exact generated public-certificate digest. Every
installed boundary records `no_new_privs`, the registered Unix stream cookie
and peer credentials, and one stable seccomp program for that architecture.

The x86_64 program contains 60 instructions and has digest
`5a4a2d657e107785c0461328d5975076be2e8318794f7dfae946525336858b2e`.
The aarch64 program contains 58 instructions and has digest
`268c855b1364e73f24f0f706d24a2769e7cfb4fbd9b09b111db75536d89b4f5b`;
the difference reflects architecture-specific syscall availability. The
x86_64 `RESULT.json` digest is
`8c56cdf211ad029f30d57e0e4e7dcb46a1c12f14fc7e93a6e5b8f339690dad0b`;
the aarch64 digest is
`c959fbacf64b5c628fed143a567f269af3887832ca128cfc22f9f84dcb90be22`.
Both record the pre-registered conclusion
`preconnected-channel-binds-one-authenticated-session-control`.

Mechanism D is narrower in session and routing authority than a reusable
general network client, but broader in application authority than mechanism
C: the child can send arbitrary bounded bytes to the one authenticated
service session. This first control does not cover public DNS, IPv6, CNAMEs,
redirects, credentials, connection reuse, QUIC, measurements, the complete
parent attack matrix, or a production lifecycle. It authorizes no Runtime
schema or receipt change.

The decision-grade continuation is frozen in
[Experiment 0001E](0001e-decision-matrix-execution.md). It divides the complete
parent inventory into routing/transport, resolution/indirection, and
bypass/lifecycle slices plus a separate measurement slice. Every mechanism
must receive one registered outcome for every case; an unrepresentable input
is executed and recorded rather than silently skipped.

## Evidence and publication boundary

Experiment output is test or observation material. It does not create a Tier 3
claim, prove the correctness of the kernel or broker, bind a future release
artifact, or authorize a schema change. Production work begins only after the
result set receives independent review and an ADR accepts one exact mechanism
and public claim boundary. A later normative specification must repeat every
assumption, exclusion, attack, wire decision, and trusted role selected by that
ADR.
