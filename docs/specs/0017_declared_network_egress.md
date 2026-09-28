# Specification 0017: Declared network egress

**Status:** Proposed implementation contract

**Date:** 2026-09-28

**Owner:** Proofbound Runtime

**Depends on:** [Specification 0001](0001_initial_spec.md),
[Specification 0007](0007_memory_and_swap_profile.md),
[Specification 0014](0014_public_compatibility_and_distribution.md),
[Specification 0016](0016_authenticated_service_session.md),
[ADR 0001](../adr/0001-linux-enforcement-boundary.md),
[ADR 0003](../adr/0003-deterministic-cbor-wire-objects.md), and
[ADR 0004](../adr/0004-authenticated-service-session.md)

## 1. Decision, claim, and non-claims

### 1.1 Decision

The owner decided that Proofbound Runtime gets typed network egress. This
specification adds one network authority mode, `declared-egress`, beside the
unchanged `deny` mode and the unchanged Specification 0016
`authenticated-service-session` mode.

The driving consumer is the auths-proof gateway `exec` transport
(AP-SPEC-064). That transport runs OpenTofu `apply` under `pbr`. OpenTofu opens
many TCP connections to several cloud-provider API names, performs its own TLS,
reconnects, and starts provider plugin executables that inherit its network
needs. These are the ADR 0004 revisit conditions: multiple sessions, reconnect,
and transparent SDK sockets. The Specification 0016 session connector cannot
serve this workload, and this specification does not change it.

The mechanism is general. It contains no OpenTofu, cloud-provider, or HTTP
application semantics. Any tool that can reach the network through an HTTP
`CONNECT` proxy named by the standard proxy environment variables can use it.

Production implementation starts only after a companion ADR records the
mechanism selection in section 3 under the ADR index rules. That ADR adds a
decision record; it does not supersede ADR 0004.

### 1.2 Public claim

The admitted public claim is:

> For one supported declared-egress execution, every TCP connection that the
> child or a descendant caused to leave the execution's network namespace was
> opened by the identified egress proxy to a declared port and to either a
> declared IP address or an address that the proxy's own recorded resolution
> of a declared DNS name returned, inside that answer's recorded lifetime and
> the endpoint's declared address scope. The child had no other Internet, DNS,
> UDP, raw, packet, netlink, host Unix-socket, inherited-socket, or `io_uring`
> network path. The receipt records the declared endpoints, every resolution,
> every proxied connection with its selected address and byte counts, and
> every rejected request.

The claim has two separately registered parts: egress is limited to the
declared endpoints, and the receipt records the declared and observed
endpoints (section 9).

### 1.3 Non-claims

The claim does not state or imply:

- **No data-exfiltration guarantee over allowed endpoints.** The child can send
  arbitrary bytes, up to the declared byte bounds, to every declared endpoint.
  A declared endpoint that stores, relays, or proxies data can move that data
  anywhere its operator permits.
- **No DNS-content guarantee.** The proxy uses the answers of the declared
  resolver. It does not validate DNSSEC and does not prove that an answer is
  the address the name owner intended. Routing meaning is relative to the
  recorded answers under `PBR-EGRESS-RESOLVER-AX-033`.
- **No TLS content inspection.** The proxy never terminates, decrypts, or
  authenticates TLS. When an endpoint declares SNI binding, the proxy compares
  the plaintext `server_name` in the first ClientHello with the declared name.
  That comparison does not authenticate the remote server, does not inspect the
  HTTP `Host` header or any application byte, and does not prevent
  application-layer fronting inside an authenticated TLS session.
- **No remote-service identity.** The receipt does not say that a peer was the
  service that a name denotes. The child's own TLS stack owns that decision.
- **No attribution.** The receipt does not identify which child process or
  descendant opened each connection.
- **No observation of blocked direct attempts.** A direct socket operation that
  the kernel rejects inside the namespace is not visible to the proxy and is
  not recorded.

## 2. Claim map and production subjects

| Claim | Statement summary | Production subject | Target tier |
| --- | --- | --- | --- |
| `PBR-NETWORK-040` | The declared-egress authority is closed and bounded; normalization, the subset relation, and policy compilation preserve it exactly and never amplify it. | `rust:proofbound_runtime_core::egress` plan parser, normalizer, subset relation, and compiler | 3 |
| `PBR-NETWORK-041` | The pure tunnel decision admits a request only for a declared endpoint, an admissible unexpired resolved or declared address, and a matching SNI when bound. | `rust:proofbound_runtime_core::egress::decide_tunnel` | 3 |
| `PBR-NETWORK-042` | The identified egress proxy process applies only that decision, is confined, and reports complete bounded observations. | `pbr-egress-proxy` executable and its engine crate | 1 with native artifact observation |
| `PBR-NETWORK-043` | The child and descendants have no network path out of a loopback-only namespace except the transferred proxy listener. | Linux launcher egress profile, namespace setup, child seccomp and Landlock egress rules | Tested with native artifact observation |
| `PBR-NETWORK-044` | The execution receipt records the declared endpoints and every observed resolution, connection, and rejection; the independent verifier derives validity and reuse from them. | Version 3 receipt producer and independent `pbr-verify` version 3 path | 1, eligibility derivation 3 |
| `PBR-CLOSURE-045` | A bounded exact executable set replaces the single executable, each member keeps its exact identity and loader closure, and no member is writable by the child. | Version 3 executable-closure resolution and Landlock execute rules | 1 with native artifact observation |
| `PBR-NETWORK-046` | Composition and acceptance retain the complete egress authority and observations and never accept a receipt outside an explicit egress policy. | `pbr-compose` and `pbr-accept` version 3 paths | Tested with native artifact observation |

The claim does not cover the correctness of the kernel, the declared resolver,
DNS operators, remote services, the child's TLS stack, hardware, firmware, or
the host administrator. These premises remain visible in every reusable
receipt, composition result, and acceptance decision.

## 3. Enforcement mechanism evaluation

### 3.1 Requirements

The selected mechanism must:

1. keep `pbr` and its launcher non-root, with no setuid bit, file capability,
   or host `CAP_NET_ADMIN`;
2. keep enforcement in the kernel for every direct path, so that a child that
   ignores the proxy fails closed;
3. select destinations by declared name without converting a name into a
   child-visible address allow-list;
4. resolve names outside the child and never resolve an undeclared name;
5. support many concurrent and sequential TCP connections, reconnects, and
   descendants;
6. produce a deterministic compiled policy that does not depend on optional
   host features; and
7. fail closed on every unsupported host.

### 3.2 Options

| Option | Name selection | Privilege | Result |
| --- | --- | --- | --- |
| Landlock network rules (ABI 4 and later) | None. TCP bind and connect rules name a port only. | Unprivileged | Rejected as the mechanism. Experiment 0001 mechanism A recorded `port-only-landlock-cannot-select-service`. Retained as a secondary port rule (section 5.3). |
| cgroup BPF `connect4` and `connect6` | Address tuples only. Names need a separate resolver that rewrites maps at each TTL change. | Program load and attach need `CAP_BPF` and `CAP_NET_ADMIN` in the initial namespace. | Rejected. It breaks requirement 1, and Experiment 0001 mechanism B recorded `endpoint-control-selects-routing-tuple-only`. |
| nftables on the host | Address sets only. | `CAP_NET_ADMIN` in the host network namespace. | Rejected by requirement 1 and requirement 3. |
| nftables inside a child network namespace with slirp4netns or pasta | Address sets only; the child resolves names itself or receives a resolver. | Unprivileged with user namespaces, plus a user-mode network helper. | Rejected. It gives the child a routed interface, UDP, and DNS, and it is an address allow-list that 0001 section 3.2 forbids presenting as remote identity. |
| Transparent SNI proxy | TLS SNI or the original address only. | Needs a routed interface and destination rewriting in the namespace. | Rejected. Non-TLS protocols have no name, the child needs DNS to choose an address, and the redirect path adds a helper. |
| User and network namespace, loopback only, plus a pinned `CONNECT` proxy outside it | The client sends the declared name in `CONNECT`; the proxy resolves and pins it. | Unprivileged user namespaces only. No helper, no routed interface. | **Selected**, combined with seccomp and Landlock layers. |

### 3.3 Selected design

The selected design is a combination:

1. **Namespace boundary.** The launcher enters a new user namespace and a new
   network namespace before any boundary install. The network namespace has
   only the loopback interface and no route. This is the authoritative routing
   boundary. It needs no privilege beyond unprivileged user namespaces.
2. **Pinned egress proxy.** Inside the new namespace, the launcher creates one
   listening TCP socket on `127.0.0.1:3128` and transfers it to the supervisor.
   A socket stays in the network namespace where it was created. The
   separately identified proxy process runs in the host network namespace and
   accepts connections on that listener. Each accepted connection is the only
   way that bytes leave the child namespace. The proxy applies the pure tunnel
   decision, resolves declared names itself, and connects only to pinned
   addresses.
3. **Seccomp layer.** The child filter permits only TCP and Unix stream socket
   creation and denies raw, packet, netlink, datagram, other families,
   namespace operations, tracing operations, and `io_uring`.
4. **Landlock layer.** The child ruleset handles TCP bind and connect and
   permits connect only to port 3128, handles pathname Unix-socket resolution
   and permits it only below the write root, and scopes abstract Unix sockets
   and signals to the child domain.

The namespace boundary and the proxy decision carry the claim. The seccomp and
Landlock layers reduce the reachable kernel surface and are recorded exactly.
All four layers are mandatory. None of them is a best-effort addition.

### 3.4 Consequence for clients

A client that honors `HTTPS_PROXY` or a related variable reaches declared
endpoints. A client that ignores these variables attempts a direct connection,
and the kernel rejects it inside the namespace. This is the intended
fail-closed result, not a partial feature. The profile does not add
transparent interception.

## 4. Plan schema

### 4.1 Version transition

Specification 0014 section 3 requires a new schema identifier when a new
variant or field changes the accepted closed domain. This specification adds a
network variant and changes the executable domain from exactly one entry to a
bounded set. It therefore introduces:

- `proofbound-runtime-plan/3`;
- `proofbound-runtime-linux-policy/3`, policy model version 3;
- `proofbound-runtime-run-result/3`;
- `proofbound-runtime-execution-receipt/3`;
- `proofbound-runtime-composed-receipt/3`;
- `proofbound-runtime-acceptance-policy/2` and
  `proofbound-runtime-acceptance-decision/3`; and
- `proofbound-runtime-current-integration/2`.

Each object is deterministic CBOR with text map keys and a closed CDDL schema
with golden vectors, as ADR 0003 requires. Version 3 keeps every version 2
field and meaning that this section does not change. The version 3 network
union carries the Specification 0016 `authenticated-service-session` member
with unchanged grammar and its unchanged production gate.

Under the prelaunch policy in Specification 0014 section 8, the release that
admits version 3 execution accepts only plan version 3 for `plan check`,
`preflight`, and `run`. A version 2 plan fails with
`plan.schema.execution-obsolete`. `pbr-verify`, `pbr-compose`, and `inspect`
keep their existing frozen historical receipt paths and add a separate closed
version 3 path. No decoder converts one version into another.

### 4.2 Wire grammar

The version 3 plan changes these rules relative to
`schemas/execution-plan-v2.cddl`:

```cddl
execution-plan-v3 = {
  "id": plan-id,
  "schema": "proofbound-runtime-plan/3",
  "limits": resource-limits,
  "command": command,
  "authority": authority-v3
}

authority-v3 = {
  "read": [* path],
  "write": [path],
  "execute": [1*64 path],
  "network": network-authority-v3,
  "environment": [* environment-name],
  "runtime_read": [* absolute-path]
}

network-authority-v3 = "deny"
  / authenticated-service-session
  / declared-egress

declared-egress = {
  "mode": "declared-egress",
  "endpoints": [1*256 egress-endpoint],
  "resolver": resolution-policy,
  "limits": egress-limits,
  "proxy_executable": absolute-path,
  "proxy_runtime_read": [* absolute-path],
  "proxy_environment": [1*6 proxy-variable]
}

egress-endpoint = {
  "destination": egress-destination,
  "port": tcp-port,
  "protocol": "tcp",
  "tls_sni": sni-binding
}

egress-destination = {
  "kind": "dns-name",
  "name": egress-name,
  "address_scope": "global" / "global-or-private"
} / {
  "kind": "ipv4",
  "bytes": bytes .size 4
} / {
  "kind": "ipv6",
  "bytes": bytes .size 16
}

sni-binding = "not-inspected" / {
  "mode": "required",
  "name": egress-name
}

egress-limits = {
  "connections": 1..8192,
  "concurrent_connections": 1..512,
  "attempts_per_connection": 1..4,
  "resolutions": 1..1024,
  "dns_messages": 2..8192,
  "client_to_remote_bytes": 1..1099511627776,
  "remote_to_client_bytes": 1..1099511627776,
  "connection_idle_ms": 1..3600000
}

proxy-variable = "HTTPS_PROXY" / "https_proxy"
  / "HTTP_PROXY" / "http_proxy"
  / "ALL_PROXY" / "all_proxy"

egress-name = text .size (1..253)
```

`resolution-policy`, `tcp-port`, `path`, and `absolute-path` keep their
version 2 definitions. The normative CDDL file is
`schemas/execution-plan-v3.cddl`. JSON remains an inspection projection only.

### 4.3 Endpoint validation

A DNS name in `destination` or `tls_sni` must:

- contain 1 to 253 ASCII bytes and at least two labels;
- use labels of 1 to 63 bytes that contain lower-case letters, digits, and
  interior hyphens only;
- have no trailing dot, no wildcard label, and no upper-case byte; and
- not end in an all-digit label, so that no name can be read as an IPv4
  literal.

An IP destination must not be an unspecified address, a multicast address,
the IPv4 limited-broadcast address, or an IPv4-mapped or IPv4-compatible IPv6
address. An IPv4 address uses the `ipv4` form only. A loopback, link-local, or
private literal is valid because the plan names it explicitly; it grants that
exact address in the host network namespace where the proxy runs.

The remaining rules are:

- A `required` SNI binding on a `dns-name` destination must name exactly that
  destination name. An IP destination may bind any valid name.
- Every endpoint with the same DNS name must have the same `address_scope`,
  because the proxy resolves each name once per lifetime for all its ports.
- `attempts_per_connection` must not exceed the resolver
  `maximum_answer_count`.
- The resolver record additionally requires `maximum_cname_depth` of at most 4,
  `maximum_answer_count` of at most 16, `maximum_response_bytes` of at most
  65,535, and `resolution_deadline_ms` of at most 60,000. The version 2
  requirement that `attempt_deadline_ms` does not exceed
  `resolution_deadline_ms` applies unchanged.
- `proxy_environment` is a strictly ascending set. The plan `environment` list
  must not contain any name that matches `HTTP_PROXY`, `HTTPS_PROXY`,
  `ALL_PROXY`, or `NO_PROXY` without regard to ASCII case. The Runtime alone
  sets the declared variables to the exact value `http://127.0.0.1:3128`.
- `proxy_executable` and each `proxy_runtime_read` entry follow the connector
  path rules of Specification 0016 section 3.1: canonical absolute paths
  resolved to exact identities before proxy start.

### 4.4 Bounds and their reasons

| Bound | Value | Reason |
| --- | --- | --- |
| Endpoints | 1 to 256 | Keeps the compiled policy, Landlock port rule set, and receipt projection small. |
| Name length | 1 to 253 bytes, labels 1 to 63 bytes | DNS wire limits. |
| Connections | 1 to 8,192 | With the other record maxima, keeps the egress observation below 8 MiB and 500,000 CBOR items, inside the verifier decoder bound of 16 MiB and 1,000,000 items. |
| Concurrent connections | 1 to 512 | Bounds proxy descriptors and memory. |
| Attempts per connection | 1 to 4 | Bounds the attempt records per connection. |
| Resolutions | 1 to 1,024 | Bounds resolution records. |
| Answers per resolution | 1 to 16 | Bounds answer records. |
| CNAME depth | 1 to 4 | Bounds link records. |
| Byte counts | 1 to 2^40 per direction, aggregate | Matches the version 2 resource ceiling. |
| Idle time | 1 ms to 1 hour per connection | Bounds idle tunnels inside the wall-time limit. |
| `CONNECT` request head | 8,192 bytes, fixed | Bounds the proxy parser. |
| ClientHello | 16,384 handshake bytes in at most 4 records, fixed | Bounds the SNI parser. |
| Rejection records | 256 retained, fixed, plus a checked total count | Bounds retained records while counting every rejection. |

### 4.5 Normalization and subset

Normalization sorts endpoints by destination kind (`dns-name`, `ipv4`,
`ipv6`), then name or address bytes, then port. It removes byte-identical
duplicate endpoints. Two endpoints with the same destination and port but a
different SNI binding or address scope are ambiguous and fail validation. It
sorts and deduplicates proxy runtime-read paths and the executable set. It
never changes a name, address, port, scope, SNI binding, limit, resolver field,
or proxy identity.

A declared-egress authority is no more permissive than a reference authority
only when:

- every candidate endpoint is byte-equal to one reference endpoint;
- the resolver records are equal;
- the proxy executable is equal and the candidate proxy runtime closure is a
  subset of the reference closure;
- the candidate proxy environment is a subset of the reference set; and
- every candidate limit is less than or equal to the reference limit.

`Deny` is no more permissive than `declared-egress`. A declared-egress
authority is never no more permissive than `Deny`. A declared-egress authority
and an authenticated service session are incomparable. An endpoint whose name
resolves to the same address as another name does not grant that other name.

### 4.6 Policy compilation

Policy model version 3 binds each network role separately:

- `network` stays `deny-network-v1` for the direct base profile;
- `child_network` is `egress-namespace-v1`;
- `egress` contains the complete normalized declared-egress authority;
- `listener` is the fixed record `{address: 127.0.0.1, port: 3128,
  backlog: 128}`;
- `child_filter` is the identity of the `egress-child-v1` seccomp program for
  the selected architecture;
- `child_landlock_network` is TCP connect to port 3128 only, with TCP bind
  handled and not granted;
- `child_landlock_scope` is abstract Unix sockets and signals;
- `proxy_filter` is the identity of the `egress-proxy-v1` seccomp program;
- `proxy_landlock_network` is TCP connect to the union of declared ports and
  the resolver port, with TCP bind handled and not granted; and
- `address_classes` is `address-class-table-v1` from section 5.6.

Compilation is deterministic and total over validated plans. It never compiles
a name into an address rule, and it never emits a child rule that names a
remote address.

## 5. Enforcement

### 5.1 Topology

```text
host network namespace                 child user + network namespace
+------------------------------+       +------------------------------+
| supervisor (unconfined)      |       | lo only, no route            |
| pbr-egress-proxy (confined)  |<------| listener 127.0.0.1:3128      |
|   resolves declared names    |accept |   created here, fd moved out |
|   connects to pinned address |       | child and descendants        |
+--------------+---------------+       +------------------------------+
               |
               v declared port, pinned address only
```

### 5.2 Setup and release order

The supervisor and launcher perform these steps in order:

1. Parse, validate, and normalize the version 3 plan and compile policy
   model version 3.
2. Resolve and identify the child executable set and loader closure, the proxy
   executable and runtime closure, and the resolver configuration.
3. Create the fresh execution cgroup and a fresh sibling proxy cgroup below the
   delegation root. Install and read back the child controls from
   Specification 0007 and the proxy controls `pids.max = 1`,
   `memory.max = 16 MiB + concurrent_connections * 256 KiB`, and
   `memory.swap.max = 0`, all in the 64 KiB quantum.
4. Start the launcher stopped, place it in the execution cgroup, and send the
   policy.
5. The launcher verifies the policy and cgroup identities, then calls
   `unshare(CLONE_NEWUSER | CLONE_NEWNET)`. It writes `deny` to
   `setgroups` and writes single-line identity maps for its own non-root user
   and group identifiers. It never maps to identifier 0.
6. The launcher brings `lo` up, reads the interface inventory and the IPv4 and
   IPv6 route tables, and requires exactly `lo` and only loopback routes.
7. The launcher creates the listening socket with close-on-exec, binds
   `127.0.0.1:3128`, listens with backlog 128, and sends a `namespace-ready`
   message. The message carries the user-namespace and network-namespace
   identities (`nsfs` device and inode), the identity maps, the interface and
   route inventories, and the listener descriptor through `SCM_RIGHTS`. The
   launcher then closes its copy of the listener.
8. The supervisor validates the message. It requires both namespace identities
   to differ from its own, requires the descriptor to be a listening IPv4 TCP
   socket bound to `127.0.0.1:3128`, and requires `SIOCGSKNS` on the
   descriptor to return the reported network namespace. The supervisor has
   this authority because it is in the parent user namespace with the owner
   user identifier.
9. The supervisor starts the proxy through its retained executable descriptor
   with an empty environment, in the proxy cgroup, with the closed descriptor
   bootstrap of the Specification 0016 connector process: the listener, one
   private packet report channel, and one read-only policy input. It uses the
   PBR-NETWORK-039 setup deadline, reaper, and fail-closed abort behavior.
10. The proxy sets `PR_SET_DUMPABLE` to 0, installs `no_new_privs`, its
    Landlock ruleset, and its seccomp filter, then sends one readiness report.
    The report binds the execution, policy, proxy generation, proxy executable
    and closure, resolver configuration, listener, network namespace, and
    installed proxy-filter identities.
11. The supervisor validates the readiness report and sends `proxy-ready` to
    the launcher with the same binding.
12. The launcher closes every undeclared descriptor, drops every capability
    set including the bounding set in its user namespace, installs
    `no_new_privs`, the Landlock filesystem, network, and scope rules, and the
    `egress-child-v1` seccomp filter.
13. The launcher reads back every supported control and sends the installed
    acknowledgement. It binds the execution, policy, cgroup, namespace
    identities, identity maps, interface and route inventories, listener,
    proxy generation and readiness binding, Landlock ABI and handled access,
    and child-filter identity.
14. The supervisor validates the complete acknowledgement and sends the
    identity-bound release.
15. The launcher calls `execve` for the identified command executable.

Child code never runs before step 15. Every failure before step 15 terminates
the proxy and launcher, closes the listener, drains bounded observations, and
produces no reusable receipt. Raw calls for `unshare`, `SIOCGSKNS`,
`SCM_RIGHTS`, and `PR_SET_DUMPABLE` stay in
`crates/proofbound-runtime-linux/src/sys.rs`.

At termination, the supervisor waits for the child cgroup to drain, sends
`drain` to the proxy, and collects its final report. The proxy closes every
tunnel with close reason `proxy-draining` and exits. The supervisor reaps the
proxy, removes both cgroups, and records every cleanup result.

### 5.3 Child boundary

The `egress-child-v1` seccomp filter keeps the architecture preamble and x32
rule of the version 2 filter and applies this closed table. A denied call
returns `EPERM` except where noted.

| Operation | Rule |
| --- | --- |
| `socket` | Allowed only for `AF_INET` or `AF_INET6` with type `SOCK_STREAM` and protocol 0 or `IPPROTO_TCP`, and for `AF_UNIX` with type `SOCK_STREAM` and protocol 0. The filter masks `SOCK_NONBLOCK` and `SOCK_CLOEXEC` before comparison. Every other family, type, or protocol is denied, including `AF_PACKET`, `AF_NETLINK`, `AF_VSOCK`, `SOCK_RAW`, `SOCK_DGRAM`, SCTP, and MPTCP. |
| `socketpair` | Allowed only for `AF_UNIX`. The pair is anonymous and reaches no external endpoint. |
| `connect`, `bind`, `listen`, `accept`, `accept4`, socket options, name queries, `shutdown`, send and receive calls | Allowed. The namespace and Landlock rules constrain their effect. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | Denied. |
| `unshare`, `setns` | Denied. |
| `clone` | Denied when any `CLONE_NEW*` flag is set. |
| `clone3` | Returns `ENOSYS`, because the flags are behind a pointer. C libraries then use `clone`. |
| `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `kcmp` | Denied. |

The child Landlock ruleset requires ABI 9 through 11. In addition to the
version 2 filesystem rules, it:

- handles `LANDLOCK_ACCESS_NET_CONNECT_TCP` and grants it only for port 3128;
- handles `LANDLOCK_ACCESS_NET_BIND_TCP` and grants it for no port;
- adds pathname Unix-socket resolution to the write-root rule only, so the
  child can connect only to sockets that it or a descendant created in the
  fresh write root; and
- scopes abstract Unix sockets and signals to the child domain.

Landlock also denies tracing of processes outside the child domain. The proxy
and supervisor are outside that domain. The proxy is additionally
non-dumpable.

Descendants inherit the namespaces, cgroup, Landlock domain, and seccomp
filter. They can use the proxy within the same shared authority.

### 5.4 Proxy protocol

The proxy accepts one HTTP/1.1 or HTTP/1.0 request head per accepted
connection. The request line must match exactly:

```text
CONNECT SP authority SP ( "HTTP/1.1" / "HTTP/1.0" ) CRLF
```

`authority` is `name ":" port`, `ipv4 ":" port`, or `"[" ipv6 "]" ":" port`.
The port is 1 to 65535 in decimal without leading zeros. An IPv4 literal is
four decimal octets without leading zeros. An IPv6 literal has no zone
identifier and must not be IPv4-mapped. The proxy converts a name to ASCII
lower case and then requires the name grammar of section 4.3. Header fields
must be syntactically valid and fit in the 8,192-byte head. The proxy ignores
their values, including `Host` and `Proxy-Authorization`. Bytes after the
head terminator are tunnel payload.

The proxy responds with exactly one of these status lines and closes on every
status other than 200:

| Status | Meaning |
| --- | --- |
| `200 Connection established` | The request matched a declared endpoint. |
| `400 Bad Request` | Malformed or non-canonical request. |
| `403 Forbidden` | No declared endpoint matches. |
| `405 Method Not Allowed` | The method is not `CONNECT`, including absolute-form plaintext requests. |
| `429 Too Many Requests` | A connection, concurrency, resolution, DNS-message, or byte bound is exhausted. |
| `502 Bad Gateway` | Resolution failed, no admissible answer exists, or every attempt failed. |

For a `not-inspected` endpoint, the proxy resolves and connects before it
sends 200 and sends 502 when that fails. For an endpoint with `required` SNI,
the proxy sends 200, then reads the first TLS records before it resolves the
name or contacts any remote address. A later resolution or attempt failure
closes the client connection with the matching close reason.

For the SNI check, the proxy requires a handshake record that carries a
complete ClientHello within the fixed bound, exactly one
`server_name` extension with exactly one `host_name` entry, and no duplicate
extension. It converts the name to ASCII lower case and requires byte equality
with the declared SNI name. It rejects a ClientHello that contains the
`encrypted_client_hello` extension, because the outer name then does not
identify the inner name. On success it connects and forwards the buffered
bytes unchanged. On failure it closes the client connection without any
remote attempt. For `not-inspected`, the proxy parses no payload.

### 5.5 Proxy confinement and lifecycle

The proxy is a single-threaded event loop. Its boundary is:

- the fresh proxy cgroup from section 5.2;
- Landlock with read access only to its runtime closure and resolver
  configuration, no write access, no pathname Unix-socket resolution, TCP
  connect only to declared ports and the resolver port, no TCP bind, and the
  abstract Unix-socket and signal scopes; and
- the `egress-proxy-v1` seccomp filter, which permits `AF_INET` and `AF_INET6`
  TCP socket creation and denies every other socket family and type,
  `execve`, `execveat`, namespace calls, tracing calls, and `io_uring`.

The proxy lifecycle uses closed phases: `created`, `ready`, `serving`,
`draining`, `closed`, and `failed(reason)`. Only `created -> ready ->
serving -> draining -> closed` and one `failed` transition from each
nonterminal phase are valid. When any aggregate byte bound is reached, the
proxy closes every open tunnel with the matching byte-limit reason and refuses
every later request with 429 until drain. The proxy never relays a byte beyond
a bound.

The proxy reports each completed record over its report channel as it
happens and a final counter record at drain. Proxy crash, report loss, report
malformation, exit before drain, or a phase violation makes the receipt
non-reusable.

### 5.6 DNS resolution and pinning

The proxy owns every DNS operation. It sends DNS over TCP only to the declared
resolver endpoint and reuses the Specification 0016 resolver record, bounded
DNS message parser, CNAME rules, effective-expiry rule, and duplicate-answer
rule. The event loop drives the resolver transport without blocking other
tunnels. The child has no resolver path.

The proxy resolves a name only after a request matches a declared endpoint for
that name. It never resolves an undeclared name. Resolution follows these
rules:

1. The proxy keeps at most one current resolution record per declared name.
2. A request uses the current record while at least one admissible answer has
   an effective expiry later than the attempt start. Otherwise the proxy
   performs a new resolution, which becomes the current record.
3. Concurrent requests for the same name wait for one in-flight resolution.
4. The connection that triggered a resolution may use that record's
   admissible answers for its own attempt sequence even when their TTL is 0 or
   they expire during that sequence. Every other connection must start each
   attempt no later than the answer's effective expiry.
5. The proxy attempts admissible answers in the fixed
   `ipv4-then-ipv6-lexicographic` order, skips expired answers under rule 4,
   performs at most `attempts_per_connection` attempts with one active attempt,
   and stops at the first established TCP connection.
6. A resolution change affects only later attempts. An open tunnel is never
   moved or closed because its answer expired.

An answer is admissible when its address class, under `address-class-table-v1`,
is permitted by the endpoint scope:

| Class | Ranges | `global` | `global-or-private` |
| --- | --- | --- | --- |
| special | `0.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`, `::/128`, `::1/128`, `::ffff:0:0/96`, `64:ff9b::/96`, `100::/64`, `2001::/23`, `2001:db8::/32`, `fe80::/10`, `ff00::/8` | no | no |
| private | `10.0.0.0/8`, `100.64.0.0/10`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | no | yes |
| global | every other unicast address | yes | yes |

The special class prevents a declared name from rebinding the proxy to host
loopback, link-local metadata services, or translated IPv4 space. An operator
who needs such an address declares it as an IP destination.

A resolution with no admissible answer has outcome `no-admissible-answer`, and
the connection fails under section 5.4. A failed resolution, a failed attempt
sequence, and a 502 response are observations. They do not by themselves make
a receipt non-reusable.

### 5.7 IPv4, IPv6, and UDP

The proxy listener is IPv4 loopback only. Remote connections use IPv4 or IPv6
according to the declared literal or the admissible answers. A host without a
route for one family records the failed attempt and continues with the next
answer.

The child cannot create a UDP socket. No UDP, QUIC, or DNS datagram leaves the
child namespace. The proxy uses TCP for DNS and for every remote connection.
Clients that prefer QUIC fall back to TCP or fail closed.

### 5.8 Bypass analysis

| Path | Closing control |
| --- | --- |
| Direct TCP to a remote address | No route in the namespace; Landlock connect permits only port 3128. |
| TCP Fast Open or implicit connect | No route in the namespace. |
| UDP, QUIC, ICMP datagram sockets | Seccomp type rule; no route. |
| Raw sockets | Seccomp type rule; no capability after `execve`. |
| `AF_PACKET` | Seccomp family rule; the namespace has only `lo`. |
| `AF_NETLINK` | Seccomp family rule; no network-administration capability after `execve`. |
| `AF_VSOCK` and other families | Seccomp family allow-list. |
| Abstract Unix socket to a host service | Abstract names are per network namespace; Landlock abstract scope. |
| Pathname Unix socket to a host service | Landlock pathname resolution is granted only below the fresh write root. |
| Inherited socket | Launcher descriptor closure; listener copy closed before release. |
| `io_uring` socket operations | Seccomp denial. |
| New namespace or `setns` into the host namespace | Seccomp denial; no capability in the host namespaces. |
| Tracing or descriptor theft from the proxy | Landlock domain rule, seccomp denial, non-dumpable proxy. |
| Signal to the proxy | Landlock signal scope. A proxy that stops by any cause fails the execution closed. |
| Undeclared name or port through the proxy | Pure tunnel decision; 403 and a rejection record. |
| Address literal of a declared name's answer | Denied unless declared as an IP destination. |
| DNS rebinding to host or internal space | Address-class table and endpoint scope. |
| Exfiltration in DNS query names | The proxy never resolves an undeclared name. |
| SNI mismatch or hidden SNI | SNI binding and the ECH rule, when declared. |
| Proxy resource exhaustion | Separate proxy cgroup and declared bounds. |

## 6. Host readiness and privilege

The profile keeps `pbr` non-root. It needs unprivileged creation of a user
namespace and a network namespace. It needs no setuid bit, no file capability,
no host `CAP_NET_ADMIN` or `CAP_BPF`, and no slirp4netns or pasta helper,
because the child namespace has no routed interface.

A host that forbids unprivileged user namespaces cannot run this profile. This
is a host policy, not a missing Runtime privilege. `pbr` does not work around
it. The host administrator can permit it with the distribution's documented
control, for example a sysctl or an AppArmor profile that grants user
namespaces to the exact installed launcher path. Unprivileged user namespaces
expose more kernel code to the child. Section 10 records this risk.

`pbr doctor` reports schema `proofbound-runtime-doctor/2` with these added
entries, and the explanation projection of Specification 0004 moves to
`proofbound-runtime-doctor-explanation/2`:

| Entry | Requirement | Unavailable codes |
| --- | --- | --- |
| `user_namespace` | `user.max_user_namespaces` is nonzero, a present `kernel.unprivileged_userns_clone` is 1, and the transient probe can create a user namespace and write identity maps. | `host.userns.sysctl-disabled`, `host.userns.apparmor-restricted`, `host.userns.probe-failed` |
| `network_namespace` | `user.max_net_namespaces` is nonzero and the transient probe can create a network namespace, bring up `lo`, and bind `127.0.0.1:3128`. | `host.netns.sysctl-disabled`, `host.netns.probe-failed`, `host.netns.loopback-failed` |
| `landlock_egress` | Landlock ABI 9 through 11. | `host.landlock.abi-below-egress` |

`host.userns.apparmor-restricted` applies when
`kernel.apparmor_restrict_unprivileged_userns` is 1 and the probe fails. The
transient probe runs in a forked helper, creates only kernel objects that end
when the helper exits, writes no file or cgroup, sends no packet, and runs no
plan command. `doctor` therefore still runs no workload. The existing cgroup
entry must also report that the delegation root can hold the additional proxy
cgroup. `pbr run` repeats every step at execution time and fails with exit
class 3 if any step fails.

## 7. Executable closure and process limits

Version 3 changes these rules from Specification 0001 sections 4.1 and 5.2:

1. `execute` is a strictly ascending set of 1 to 64 exact paths instead of
   exactly one path. `command.executable` must be a member.
2. Each member resolves to one regular file with an exact digest, size, mode,
   and role `plan-executable`. A directory, symlink target outside its
   resolution root, device, or other file kind is invalid.
3. For each ELF member, the `PT_INTERP` rule applies per member. Its exact
   interpreter becomes a `runtime-loader-executable` closure entry with its own
   identity.
4. A member that starts with `#!` requires its interpreter path to be another
   member. Otherwise the plan is invalid.
5. No member may be equal to or below a write root, and no write root may be
   below a member's directory chain in a way that lets the child rename or
   replace the member. The child can therefore not change the bytes that a
   later `execve` loads through the member path.
6. Landlock grants `READ_FILE | EXECUTE` on each exact member and loader file.
   Directory-wide execute authority remains forbidden.
7. The supervisor revalidates every member and loader identity immediately
   before the launch request. Drift fails with exit class 4.

These rules let a plan list OpenTofu and each exact provider plugin binary.
The plugin binaries then run inside the same boundary as the parent.

The `processes` limit keeps its version 2 grammar and maps to `pids.max`.
Values above 1 were already valid. `pids.max` counts kernel tasks, including
threads, so a multi-threaded runtime needs a limit that covers every thread of
every descendant. The proxy runs in its own cgroup, so child task exhaustion
cannot stop the proxy.

## 8. Receipt and verifier

### 8.1 Receipt facts

The version 3 execution receipt has one required `network` map. For `deny`,
it contains only the mode. For `declared-egress`, it contains the closed
fragment `proofbound-runtime-egress-observation/1` with these typed facts:

- **Declared authority:** the complete normalized endpoint list, resolver
  record, limits, proxy environment, and the policy identity.
- **Boundary:** user-namespace and network-namespace identities and the
  supervisor network-namespace identity; identity maps; interface and route
  inventories; listener record; Landlock ABI and handled network access;
  child-filter and proxy-filter identities.
- **Proxy:** executable, runtime-closure, and resolver-configuration
  identities; process generation; readiness binding; lifecycle phases;
  terminal reason.
- **Resolutions:** for each record, its index, name, triggering connection,
  start and finish times, response-message SHA-256 identities, CNAME links
  with owner, target, TTL, expiry, and message identity, answers with address,
  TTL, record expiry, and effective expiry, and one outcome.
- **Connections:** for each proxied connection, its index, endpoint index,
  open and close sequence numbers from one proxy event counter, accept time,
  resolution index or null for an IP destination, SNI result, attempts with
  answer index or null, start time, and result, the selected attempt or null,
  bytes in each direction, and one close reason.
- **Rejections:** up to 256 retained records with sequence number, time,
  reason, target kind, port when parsed, target byte length, and the SHA-256
  of the exact target bytes, plus the checked total rejection count.
- **Counters and events:** totals for connections, resolutions, DNS messages,
  bytes in each direction, and rejections, and the sorted limit-event set.
- **Cleanup:** proxy reap result, proxy cgroup removal, and listener closure.

All times use proxy monotonic milliseconds from the readiness report. The
receipt never contains DNS packet contents, TLS bytes, application bytes, a
credential value, or an undeclared target as text. A retained target is a
digest and length so that child-chosen text cannot enter shared evidence.

The closed reason vocabularies are:

- rejection reasons, class `authority`: `method-not-connect`,
  `request-malformed`, `request-head-too-large`, `target-noncanonical`,
  `endpoint-undeclared`;
- rejection reasons, class `limit`: `limit-connections`,
  `limit-concurrent-connections`, `limit-resolutions`, `limit-dns-messages`,
  `limit-bytes-exhausted`;
- SNI results: `not-inspected`, `matched`, `denied-absent`,
  `denied-mismatch`, `denied-ech`, `denied-malformed`, `denied-too-large`;
- attempt results: `connected`, `refused`, `timed-out`, `unreachable`,
  `failed`; and
- close reasons: `client-closed`, `remote-closed`, `reset`, `idle-timeout`,
  `client-byte-limit`, `remote-byte-limit`, `proxy-draining`, `sni-denied`,
  `resolution-failed`, `no-admissible-answer`, `connect-failed`.

### 8.2 Independent derivation

The independent verifier owns a separate version 3 decoder and separate egress
checks. It shares no semantic code with the producer or proxy. It rejects the
receipt as invalid when any of these relations fails:

1. Every connection endpoint index names a declared endpoint.
2. For a DNS-name endpoint, the resolution index names an `answered` record
   for the same name, every attempt names an answer in that record, every
   named answer is admissible under the endpoint scope and the fixed class
   table, and every attempt starts no later than the answer's effective expiry
   unless the connection triggered that resolution.
3. For an IP endpoint, the resolution index and every answer index are null.
4. A connection has at most `attempts_per_connection` attempts and at most one
   `connected` attempt, which is the selected attempt and the last one. A
   connection without a selected attempt has zero bytes in both directions.
5. Every connection to a `required` SNI endpoint has a `matched` or `denied-*`
   result. A `denied-*` result has no resolution, zero attempts, and close
   reason `sni-denied`. Every connection to a `not-inspected` endpoint has the
   `not-inspected` result.
6. Sequence numbers are unique and ordered. The verifier recomputes peak
   concurrency from open and close sequences and requires it to be at most
   `concurrent_connections`.
7. Every counter equals the sum of its records. Every total is at most its
   bound. The number of retained rejections is the minimum of 256 and the
   total.
8. The verifier derives the limit-event set: `egress-limit-connections`,
   `egress-limit-concurrent`, `egress-limit-resolutions`,
   `egress-limit-dns-messages`, `egress-limit-client-bytes`, and
   `egress-limit-remote-bytes`, each from its rejection reason or close
   reason and bound equality. It requires equality with the recorded set.
9. Namespace identities differ from the supervisor identity, the interface
   inventory is exactly `lo`, the routes are loopback only, the identity maps
   map one non-root identifier to itself, and the listener equals the policy
   listener.
10. Every identity and binding agrees across the policy, launcher
    acknowledgement, proxy readiness report, and observation fragment.
11. Proxy phases form a valid sequence of section 5.5.

### 8.3 Reuse eligibility

A version 3 receipt with `declared-egress` is reusable only when every version
2 condition holds and all of these hold:

- no retained or counted rejection has class `authority`;
- no connection has a `denied-*` SNI result;
- the derived limit-event set is empty;
- the proxy reached `closed` without `failed`; and
- every cleanup result is complete.

The non-reuse reasons follow the version 2 reasons in this fixed order:
`egress-request-denied`, `egress-sni-denied`, `egress-limit-reached`,
`egress-proxy-failed`, `egress-cleanup-incomplete`. The verifier derives the
complete canonical set. An invalid relation in section 8.2 is a verification
failure, not a non-reuse reason.

### 8.4 Composition and acceptance

The version 3 composed receipt retains the egress observation identity, the
complete declared authority, the non-reuse reasons, the new assumptions, and
the new trusted-computing-base roles. Composition never removes or summarizes
them.

Acceptance policy version 2 adds a required `network` predicate: `"deny"`, or
a declared-egress predicate with an allowed endpoint list, the relation
`equal` or `subset`, and the exact proxy executable SHA-256. Decision version 3
adds `network-mode-mismatch`, `egress-endpoint-not-allowed`, and
`egress-proxy-identity-mismatch`. A deny policy never accepts an egress
receipt. An egress policy never accepts a receipt whose declared endpoint set
fails the chosen relation, even when the observed connections used only
allowed endpoints.

### 8.5 Stable codes

Implementations refine existing exit classes with closed codes in the families
of Specification 0016 section 10. Code never branches on diagnostic text.

| Family | Codes |
| --- | --- |
| `plan.authority.network.egress.*` | `endpoint-count`, `endpoint-duplicate`, `endpoint-conflict`, `name-invalid`, `address-invalid`, `sni-invalid`, `sni-mismatch`, `scope-conflict`, `limit-range`, `resolver-bound`, `proxy-environment-invalid`, `proxy-environment-conflict`, `unsupported` |
| `plan.authority.execute.*` | `count`, `command-not-member`, `interpreter-not-member`, `writable-member` |
| `host.*` | the section 6 codes |
| `launcher.network.egress.*` | `namespace-create`, `identity-map`, `loopback`, `route-inventory`, `listener`, `handoff`, `proxy-ready-invalid` |
| `launcher.ack.network.egress.*` | `binding-missing`, `binding-mismatch` |
| `network.egress.proxy.*` | `identity`, `start`, `ready-timeout`, `ready-invalid`, `report-invalid`, `crash`, `phase-invalid`, `cleanup` |
| `receipt.network.egress.*` | `observation-incomplete`, `size-exceeded`, `counter-overflow` |
| `verify.network.egress.*` | `endpoint-unknown`, `resolution-mismatch`, `answer-unknown`, `answer-expired`, `address-scope`, `attempt-bound`, `sni-unbound`, `sequence-invalid`, `concurrency-exceeded`, `counter-mismatch`, `limit-exceeded`, `limit-event-mismatch`, `boundary-invalid`, `binding-mismatch`, `phase-invalid`, `reason-mismatch` |

Each code name above is the suffix after its family prefix. The Specification
0009 run diagnostic vocabulary gains phases `network-namespace`,
`egress-listener`, and `egress-proxy`, with rules
`network-namespace-installed`, `egress-listener-transferred`, and
`egress-proxy-ready`.

## 9. Claims, evidence, and assumptions

### 9.1 Tier 0 registration

This specification registers the seven claims of section 2 at Tier 0 in the
`ledger` profile with no evidence units. Each claim names its intended
production subject, assumptions, exclusions, and open obligations. No claim
receives status from existing network, connector, or resource evidence. The
production execution parser keeps rejecting `declared-egress` with
`plan.authority.network.egress.unsupported` until every wave in section 11.3
is admitted.

The registration adds two assumptions:

- `PBR-NAMESPACE-AX-032`: the identified kernel implements user-namespace
  identity maps and capabilities, network-namespace isolation, loopback-only
  routing, per-namespace abstract Unix-socket names, socket namespace
  retention across `SCM_RIGHTS`, and `SIOCGSKNS` as the profile uses them.
- `PBR-EGRESS-RESOLVER-AX-033`: the declared resolver and the DNS operators of
  declared names return answers that the plan author accepts as the meaning
  of those names; DNS is not authenticated.

The native claims also join the existing `PBR-LINUX-AX-001` and
`PBR-HOST-AX-002`. The Specification 0016 DNS and TLS assumptions do not
apply, because this profile does not authenticate TLS and uses DNS answers
for routing.

### 9.2 Evidence plan

| Claim | Evidence |
| --- | --- |
| `PBR-NETWORK-040` | Rust unit and property tests for every validation rule and bound; golden version 3 plan and policy vectors reproduced by the independent Python encoder; a Kani harness over a bounded endpoint catalog for normalization and compilation non-amplification; a Lean theorem in `formal/ProofboundRuntime/Egress.lean`; Charon and Aeneas refinement of the selected Rust functions. |
| `PBR-NETWORK-041` | Exhaustive source tests over the request, endpoint, answer, expiry, scope, and SNI domain; a Kani harness that proves on a bounded catalog that an allowed decision implies a declared endpoint, an admissible unexpired or triggered answer, and a matching SNI; a Lean soundness theorem and refinement for `decide_tunnel`. |
| `PBR-NETWORK-042` | `CONNECT` and ClientHello parser property tests and fuzz targets with retained seeds; source-mutation witnesses for each guard; bounded proxy integration tests with fixture resolvers; native proxy confinement tests on both architectures. |
| `PBR-NETWORK-043` | The complete section 9.3 native corpus on `x86_64` and `aarch64` release artifacts. Containers, mocks, and skipped hosts are not evidence. |
| `PBR-NETWORK-044` | Producer and independent-verifier agreement on golden success and failure receipts; a closed receipt-mutation corpus for every relation in section 8.2; a Kani harness and Lean theorem for the eligibility derivation of section 8.3 with refinement. |
| `PBR-CLOSURE-045` | Resolution tests for sets, loaders, scripts, and writable members; native tests that execute each member and fail to execute or replace any other file. |
| `PBR-NETWORK-046` | Composition and acceptance attack corpora for egress premise loss, endpoint-set substitution, relation downgrade, proxy identity substitution, and mode confusion; exact native artifact observation. |

### 9.3 Required falsifiers and native corpus

Each security-relevant guard has a causal mutation or another registered
falsifier that is rejected for the expected reason. The native corpus runs the
exact release artifacts on both architectures and covers at least:

- positive IPv4 and IPv6 connections to named and literal endpoints, many
  concurrent and sequential connections, reconnects, descendants, and a plugin
  process started from a second executable-set member;
- undeclared names, undeclared ports, literals of declared names' answers,
  non-canonical targets, absolute-form requests, oversized heads, and every
  other rejection reason;
- DNS answer change, TTL 0, expiry during an attempt sequence, CNAME chains,
  rebinding to every special and private range under both scopes, and
  malformed, truncated, oversized, and excess resolver responses;
- SNI absent, mismatched, ECH-bearing, malformed, split across records, and
  oversized ClientHello messages;
- direct TCP to IPv4 and IPv6 addresses including host loopback, TCP Fast
  Open, UDP, QUIC-shaped UDP, ICMP datagram sockets, raw, packet, netlink,
  VSOCK, SCTP, and MPTCP sockets;
- abstract and pathname Unix sockets to a host listener, inherited sockets,
  `SCM_RIGHTS` among descendants, and `io_uring` operations;
- `unshare`, `setns`, `clone` with namespace flags, `clone3`, tracing,
  `pidfd_getfd`, and signals directed at the proxy;
- every egress limit, proxy crash, proxy stop, report loss, drain timeout, and
  cleanup failure;
- namespace, listener, proxy executable, proxy closure, resolver
  configuration, and filter substitution during setup;
- executable-set member substitution, a writable member, and an undeclared
  interpreter; and
- receipt, composition, and acceptance mutations for every section 8 relation.

A test fixture never contacts the public Internet. The final wave adds one
maintained real workload: OpenTofu `apply` with two provider plugins against a
local fixture API reached by declared names, with non-retained test
credentials.

## 10. Threat model additions

The threat model gains a declared-egress section at the release that admits
this profile.

Covered threats:

- child connection to an undeclared name, address, or port;
- child bypass of the proxy through any direct socket, datagram, raw, packet,
  netlink, VSOCK, Unix-socket, inherited-descriptor, or `io_uring` path;
- child use of the proxy to reach host loopback, link-local, or translated
  address space through a declared name;
- DNS exfiltration through query names for undeclared names;
- SNI substitution or hiding on an endpoint with SNI binding;
- child interference with the proxy through tracing, descriptor theft,
  signals, or task exhaustion; and
- producer omission, substitution, or inflation of egress observations.

Remaining threats, outside the claim:

- data exfiltration and command-and-control over any declared endpoint,
  including relays and open proxies that a declared endpoint provides;
- application-layer fronting inside TLS to a declared name that shares
  infrastructure with other services;
- a malicious or compromised resolver or DNS operator for a declared name;
- covert channels through connection timing, byte volume, and resolution
  timing;
- the remote service's identity and behavior;
- host services reachable through a declared loopback, link-local, or private
  literal;
- kernel defects in user and network namespaces, which unprivileged user
  namespaces make reachable from the child; and
- a defective proxy, which is trusted computing base.

Trusted computing base additions: the proxy executable and runtime closure,
the shared DNS engine, the resolver configuration, the kernel user-namespace,
network-namespace, and loopback implementation, and Landlock network and scope
mediation.

## 11. Compatibility, distribution, and release gate

### 11.1 Compatibility

Section 4.1 defines the schema transition. The current-integration record
moves to `proofbound-runtime-current-integration/2` because its closed
executable inventory gains `pbr-egress-proxy` for both architectures and
because it adds a `network_modes` inventory. That inventory lists `deny` and
lists `declared-egress` only in a release that admits every section 11.3 wave.
Consumers treat an absent mode as unsupported.

### 11.2 Distribution

`pbr-egress-proxy` is a separate release executable, not an embeddable
library, under Specification 0014 section 4.3. The release bundle, closed
release manifest, current-integration record, and Proofbound artifact
observations bind its exact bytes on each architecture. SDKs construct version
3 plans with the same validation rules and never start the proxy themselves.

### 11.3 Release gate

The declared-egress product claim stays unavailable until these waves are
committed in order, with one wave per commit. A single pull request may carry
the ordered commits. Each wave requires exact-source independent review and
hosted evidence before the next wave is admitted. After the pull request is
merged, exact-main verification must replay every affected wave before a
release lists `declared-egress` as available:

1. companion ADR, closed version 3 CDDL schemas, golden vectors, and the pure
   authority, subset, and compilation contract (`PBR-NETWORK-040`);
2. the pure tunnel decision (`PBR-NETWORK-041`);
3. the executable-set closure (`PBR-CLOSURE-045`);
4. the proxy engine and process (`PBR-NETWORK-042`);
5. the launcher namespace profile, listener transfer, and child filters
   (`PBR-NETWORK-043`);
6. receipt production and independent verification (`PBR-NETWORK-044`);
7. composition, acceptance, doctor version 2, and current-integration
   version 2 (`PBR-NETWORK-046`);
8. the complete native corpus on both architectures; and
9. the maintained OpenTofu workload and the threat-model revision.

A release is blocked when any gate in Specification 0001 section 13 fails,
when a section 9.3 case has an unexpected result, or when the release artifact
set lacks the exact proxy identity.

## 12. Consumer contract

An external gateway, such as the auths-proof `exec` transport, uses egress as
follows:

1. **Pin.** Pin one current-integration version 2 record: the Runtime source
   revision, both architecture bundle digests, the exact `pbr`,
   `pbr-native-launcher`, `pbr-egress-proxy`, and `pbr-verify` digests, plan
   schema `proofbound-runtime-plan/3`, receipt schema
   `proofbound-runtime-execution-receipt/3`, and a `network_modes` inventory
   that contains `declared-egress`. Reject any other tuple under
   Specification 0013 section 8.
2. **Check the host.** Require `pbr doctor` version 2 to report
   `user_namespace`, `network_namespace`, and `landlock_egress` as available.
   An unavailable entry is a gateway failure. It is not a reason to run the
   same action under `deny` and report success.
3. **Build the plan.** Build a version 3 plan through a pinned SDK. Derive the
   endpoint set from the authorized action through an explicit gateway
   mapping; an Auths provider name never becomes a Runtime name implicitly.
   List the tool and every plugin executable in `execute`. Put plugin sockets
   and temporary files below the write root, for example through a registered
   `TMPDIR` that points there. Size `processes` for every thread. Declare
   `HTTPS_PROXY` and `https_proxy`, and add the other variables only when the
   tool needs them. Pass provider credentials only through registered
   environment names; the receipt records the names, not the values.
4. **Run and commit.** Run `pbr run` and compute the SHA-256 commitment over
   the exact receipt bytes that the gateway itself read from the output path.
   A commitment carried beside the receipt is not a trust anchor.
5. **Verify and accept.** Run the pinned `pbr-verify` with that commitment and
   the expected execution identifier. Evaluate an acceptance policy version 2
   whose egress predicate uses the relation `equal` or `subset` against the
   gateway's allowed endpoints and pins the proxy digest.
6. **Consume facts.** Read declared endpoints, resolutions, connections, and
   byte counts only from the verified receipt, never from a JSON projection.
   Treat them as observations under `PBR-EGRESS-RESOLVER-AX-033`. They do not
   prove that a provider API performed an action, under Specification 0013
   section 4.2.
7. **Retain premises.** Retain every assumption, non-reuse reason, and
   trusted-computing-base role in the gateway's own record and linkage.

For OpenTofu, `init` and `apply` are separate executions with separate
endpoint sets. The `apply` execution lists the exact provider binaries that
`init` placed, and the state and lock files lie inside the write root.

## 13. Explicit boundaries

These are decisions of this profile. They are not deferred features.

- **No wildcard names.** A wildcard under a multi-tenant provider domain grants
  tenants that the plan author does not control.
- **No plaintext proxy forwarding.** Absolute-form HTTP requests receive 405.
  Plaintext protocols can use `CONNECT` to a declared endpoint.
- **No transparent interception.** A client that ignores the proxy variables
  fails closed.
- **No inbound listening.** The child cannot bind TCP ports, and the proxy
  accepts only on the child listener.
- **No UDP or QUIC.** Datagram sockets are denied.
- **No DNSSEC validation and no TLS termination.** These remain non-claims
  under section 1.3.
- **No per-process attribution.** Descendants share one authority.
