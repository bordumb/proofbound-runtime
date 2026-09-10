# Experiment 0001: Network authority mechanisms

- **Status:** in progress; mechanism A control recorded
- **Date:** 2026-09-10
- **Roadmap:** RT-4.1 and RT-4.2
- **Decision output:** proposed ADR 0003 after reviewed results
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

If no mechanism satisfies the criteria, ADR 0003 rejects the network-enabled
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
matrix, benchmark performance, or evaluate mechanisms B through D. The next
experiment step is the endpoint-mediation control; production schemas and
Runtime behavior remain unchanged.

## Evidence and publication boundary

Experiment output is test or observation material. It does not create a Tier 3
claim, prove the correctness of the kernel or broker, bind a future release
artifact, or authorize a schema change. Production work begins only after the
result set receives independent review and an ADR accepts one exact mechanism
and public claim boundary. A later normative specification must repeat every
assumption, exclusion, attack, wire decision, and trusted role selected by that
ADR.
