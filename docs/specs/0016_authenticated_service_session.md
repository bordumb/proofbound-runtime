# Specification 0016: Authenticated service session

**Status:** Proposed implementation contract

**Date:** 2026-09-17

**Owner:** Proofbound Runtime

**Depends on:** [Specification 0001](0001_initial_spec.md),
[ADR 0003](../adr/0003-deterministic-cbor-wire-objects.md), and
[ADR 0004](../adr/0004-authenticated-service-session.md)

## 1. Purpose

This specification defines the first production network authority that is more
permissive than network denial. It permits one untrusted child execution to
exchange bounded application bytes with one authenticated TLS service session.
It does not give the child a resolver, an Internet socket, or authority to open
a second session.

The admitted public claim is:

> Before child release, the identified connector established one bounded TLS
> session to the declared service name under the recorded resolver and trust
> policy. The child and its descendants could exchange arbitrary bounded
> application bytes on that session. They had no other declared Internet, DNS,
> proxy, inherited-socket, Unix-socket, or `io_uring` network path.

The Runtime MUST keep the existing deny-network authority unchanged. A request
for this service-session authority MUST fail closed when any required field,
identity, mechanism, observation, or cleanup result is missing.

## 2. Claim and production subjects

The claim covers these exact production subjects:

- service-session plan parsing and domain validation;
- authority normalization and subset decisions;
- deterministic policy compilation;
- the connector executable and its runtime closure;
- bounded DNS message parsing and address selection;
- TLS configuration, authentication, and stream ownership;
- the supervisor and launcher setup protocol;
- child descriptor closure and seccomp installation;
- connector, channel, child, and cgroup lifecycle handling;
- service-session receipt construction;
- the independent receipt verifier;
- composed-receipt premise preservation; and
- consumer acceptance-policy evaluation.

The claim does not cover the correctness of the kernel, resolver, certificate
authorities, TLS implementation, remote service, hardware, firmware, or host
administrator. These premises MUST stay visible in every reusable receipt and
composition result.

## 3. Closed authority modes

The proposed authority contract contains exactly these modes:

```text
Deny
AuthenticatedServiceSession(ServiceSessionAuthority)
```

`Deny` retains its existing meaning and wire value. The service-session form
contains exactly one service. Empty service records and service arrays are not
valid substitutes.

During the contract wave, the dedicated service-session parser can validate
the new form but the production execution parser MUST reject it with
`plan.authority.network.unsupported`. The parsed child base plan retains direct
network denial. Removing that execution rejection is part of the complete
native policy, connector, launcher, receipt, verifier, composition, and
acceptance wave. SDK construction does not remove this gate.

### 3.1 Service identity

`ServiceSessionAuthority` contains:

- one lower-case ASCII DNS service name;
- one nonzero TCP port;
- one resolution policy;
- one TLS policy;
- one session-limit record;
- one connector executable path;
- a bounded connector runtime-read closure;
- the closed local-channel protocol;
- the child descriptor number reserved for that channel; and
- zero or one credential-source descriptor.

The DNS name MUST contain 1 to 253 ASCII bytes. Each label MUST contain 1 to 63
bytes. A label can contain lower-case letters, digits, and interior hyphens. It
MUST NOT start or end with a hyphen. The name MUST NOT have a trailing dot and
MUST NOT be an IPv4 or IPv6 literal.

The connector executable and each runtime-read path MUST be canonical absolute
paths. Plan resolution MUST identify the exact bytes, sizes, modes, and roles
before connector start. The execution receipt records those resolved artifact
identities. A path string is not an executable identity.

### 3.2 Resolution policy

The first profile uses connector-owned DNS over TCP to one declared numeric
resolver endpoint. The child receives no resolver configuration and cannot send
DNS messages.

The resolution policy contains:

- the resolver IPv4 or IPv6 address and nonzero TCP port;
- the exact resolver-configuration artifact identity;
- a maximum CNAME depth;
- a maximum answer count;
- a maximum DNS response byte count;
- a total resolution deadline in milliseconds;
- a per-connection-attempt deadline in milliseconds; and
- the fixed address-order rule `ipv4-then-ipv6-lexicographic`.

Every bound MUST be nonzero. The per-attempt deadline MUST NOT exceed the total
resolution deadline. The resolution deadline MUST NOT exceed the total
service-setup deadline. The first profile does not use UDP, DNS-over-HTTPS,
search domains, local host files, multicast DNS, a system resolver fallback, or
automatic resolver discovery.

The connector records the complete bounded CNAME chain, all admitted A and
AAAA answers, their TTL values, the response-message identity, and the resolver
endpoint. It rejects truncation, malformed messages, loops, excessive depth,
excess answers, excess bytes, an undeclared terminal name, and expiration.

After canonical deduplication, connection attempts use this total order:

1. IPv4 addresses in ascending network-byte order.
2. IPv6 addresses in ascending network-byte order.

Only one attempt can be active. The connector can advance to the next recorded
answer after a refused, timed-out, or otherwise failed attempt. It MUST record
every attempted endpoint and result. It stops after the first authenticated TLS
session. It MUST NOT resolve again, reconnect after child release, or attempt an
address outside the recorded answer set.

### 3.3 TLS policy

The TLS policy contains:

- the exact trust-root-set artifact identity;
- a closed minimum TLS version, `tls-1.2` or `tls-1.3`;
- the required service-name verification rule `dns-san-exact`;
- the required revocation behavior `not-checked-recorded-assumption`;
- `session-resumption = deny`; and
- `early-data = deny`.

The connector authenticates the declared DNS name. It does not authenticate an
IP address as the service identity. It rejects a name mismatch, an untrusted or
malformed chain, an unsupported negotiated version, resumption, early data,
and any TLS completion after the selected DNS answer expires.

### 3.4 Session limits

The session-limit record contains nonzero bounds for:

- service setup time;
- authenticated session duration;
- child-to-service application bytes;
- service-to-child application bytes;
- DNS messages;
- endpoint attempts; and
- TLS handshake bytes.

The endpoint-attempt bound MUST NOT exceed the answer-count bound. The first
profile permits exactly one authenticated session and no reconnect. Exceeding a
bound terminates the connector and makes the execution receipt non-reusable.

### 3.5 Local channel and credential source

The only local-channel protocol is `unix-stream-v1`. The supervisor creates one
private `AF_UNIX` stream socket pair before child release. The connector owns
one endpoint. The child receives exactly the declared other endpoint. Neither
endpoint is a filesystem pathname.

An optional credential-source descriptor contains a stable source identifier,
the declared service name, and one registered environment-variable name. It
never contains a credential value or a digest derived from that value. The
environment value can be released only after the authenticated session, child
boundary, and complete launcher acknowledgement are ready. Plans, policies,
receipts, diagnostics, fixtures, logs, and retained evidence MUST NOT contain
the value.

The network claim does not state that the child protected, formatted, or used a
credential correctly. The connector can observe the plaintext application
stream and is part of the trusted computing base.

## 4. Deterministic wire contract

The current execution-plan, compiled-policy, launcher-message, run-result,
execution-receipt, composed-receipt, and acceptance-decision schemas use closed
deterministic CBOR with text map keys. The service-session form is one closed
map. Unknown keys, unknown enum values, duplicate map keys, non-deterministic
encodings, partial records, and non-canonical identities are errors.

The plan network field is this union:

```cddl
network-authority = "deny" / authenticated-service-session

authenticated-service-session = {
  "mode": "authenticated-service-session",
  "service": service-identity,
  "resolver": resolution-policy,
  "tls": tls-policy,
  "limits": service-session-limits,
  "connector_executable": absolute-path,
  "connector_runtime_read": [* absolute-path],
  "local_channel": local-channel-policy,
  ? "credential_source": credential-source
}
```

The normative CDDL files define the complete field encodings. JSON remains an
inspection projection and MUST NOT be accepted as execution wire data.

The compiled service policy MUST bind each network role separately. Its
`network` field is `deny-network-v1` for the direct child base. Its
`child_network` field is `channel-only-v1` for the filter that retains only the
declared local byte channel. Its `service_session` field contains the complete
connector-owned authenticated-service authority. Omitting, merging, or
substituting any of these fields changes the policy identity and is invalid.

## 5. Pure decisions

Normalization sorts and deduplicates connector runtime-read paths. It MUST NOT
change a service name, resolver endpoint, TLS policy, credential source,
descriptor number, limit, or authority mode.

A service-session authority is no more permissive than another only when:

- both have the same service name and TCP port;
- both have the same resolver endpoint and configuration identity;
- both have the same TLS trust-root identity and verification rules;
- both have the same connector executable and local-channel contract;
- both have the same credential-source descriptor;
- every limit in the candidate is less than or equal to the corresponding
  limit in the reference; and
- the candidate connector runtime closure is a subset of the reference
  closure.

`Deny` is no more permissive than either mode. A service session is never no
more permissive than `Deny`. Two different service names are incomparable even
when DNS returned the same endpoint.

Policy compilation MUST be deterministic and MUST retain every field that
affects setup, child release, enforcement, observation, and receipt meaning.
It MUST NOT compile a service session into a port-only or address-only rule.

## 6. Setup and release protocol

The supervisor performs these steps in order:

1. Parse and normalize the complete plan.
2. Resolve and identify the child and connector executable closures.
3. Create the execution cgroup and resource controls.
4. Create the private local channel with close-on-exec on all temporary copies.
5. Start the connector outside the child boundary.
6. Complete bounded DNS resolution and record every result.
7. Complete the bounded TCP and TLS handshake to the declared service.
8. Start the child launcher in the stopped pre-execution state.
9. Close every undeclared child descriptor.
10. Retain only standard streams, launcher control descriptors, and the exact
    declared local-channel descriptor.
11. Install `no_new_privs`, Landlock, cgroup membership, and the
    service-session seccomp profile.
12. Read back or otherwise validate every supported installed control.
13. Bind the execution, policy, cgroup, connector process generation, DNS
    result, selected endpoint, TLS session, channel endpoints, descriptor role,
    and limits into one launcher acknowledgement.
14. Validate the complete acknowledgement in the supervisor.
15. Release the credential value, when declared.
16. Release the child to `execve`.

Child code MUST NOT execute before step 16. A failure in any earlier step closes
the channel, terminates the connector and launcher, drains bounded observations,
and produces no reusable success receipt.

The proposed service-specific handshake is
`proofbound-runtime-service-launcher/1`. Its install request and installed
acknowledgement carry the complete service binding. Every later message carries
the SHA-256 identity of the complete deterministic-CBOR install request. The
credential and release messages also carry the SHA-256 identity of the service-
binding map. Together, the outer message identities and service map bind the
execution, policy, cgroup, connector generation and closure, DNS and TLS
observation identities, selected endpoint, private-channel endpoints and child
descriptor, session limits, and exact child-filter identity. Each private
launcher frame is at most 1,048,576 bytes. The
optional credential-release message is sensitive transient input after the
installed acknowledgement. No credential value or value-derived digest can
enter a retained vector, receipt, diagnostic, or log. The production launcher
protocol does not accept these messages until the native implementation and
failure handshake are admitted.

For the proposed source contract, the connector runtime-closure identity is
the SHA-256 digest of its deterministic-CBOR ordered artifact array. The DNS
and TLS observation identities are the SHA-256 digests of their respective
deterministic-CBOR observation maps. The launcher child-endpoint identity is
the observation channel identity. Receipt validation recomputes these three
digests and requires the execution, policy, service, connector executable and
generation, endpoint, channel descriptor, limits, and credential-source fields
to agree across the launcher transcript and successful observation.

## 7. Child boundary

The service-session seccomp profile denies at least:

- Internet, packet, raw, netlink, and Unix socket creation;
- `connect`, `bind`, `listen`, `accept`, and datagram operations;
- `sendmsg` and `recvmsg`, including `SCM_RIGHTS` transfer;
- descriptor-duplication operations that can create an unregistered channel
  descriptor;
- all `io_uring` setup, entry, and registration operations; and
- namespace, privilege, and tracing operations already denied by the base
  profile.

The child can use ordinary bounded byte-stream I/O on the inherited channel.
The launcher closes every other inherited socket before acknowledgement. A
descriptor that cannot be classified and closed makes setup fail.

Descendants remain in the same cgroup and inherit the same seccomp and
filesystem boundary. They can inherit the registered channel within the shared
execution authority. The receipt does not claim which process sent each byte.

## 8. Terminal state machine

The connector uses these closed states:

```text
created
  -> resolving
  -> connecting
  -> authenticating
  -> ready
  -> active
  -> closing
  -> closed
```

Every nonterminal state also has a terminal `failed(reason)` transition. A
terminal `closed` or `failed` state has no outgoing transition. There is no
transition from `active` or `closing` to `resolving`, `connecting`,
`authenticating`, or `ready`. There is no reconnect transition.

The supervisor owns connector termination and reaping. It completes bounded
stream collection before it publishes the final result. Connector crash,
channel loss, excess bytes, deadline expiry, TLS close inconsistency, remaining
connector process, remaining child process, cgroup cleanup failure, or missing
counter evidence makes the receipt non-reusable.

## 9. Receipt and independent verification

The execution receipt records:

- the complete requested service-session authority;
- the normalized authority and compiled policy identities;
- connector executable and runtime-closure identities;
- resolver endpoint and configuration identity;
- bounded CNAME, answer, TTL, message-identity, attempt, and timing records;
- selected endpoint;
- negotiated TLS version, exact-name verification result, certificate-chain
  identity, trust-root identity, and recorded revocation assumption;
- connector process generation and lifecycle observations;
- local-channel endpoint identity and child descriptor role;
- application byte counts and every configured bound;
- credential-source identity and service binding, when present;
- launcher acknowledgement and installed child-filter identity;
- connector, channel, child, cgroup, and namespace cleanup observations; and
- every new trusted-computing-base role and assumption.

It MUST NOT record DNS packet contents that can contain unrelated names, a
credential value, application request bytes, application response bytes, or a
digest of a secret value.

The independent verifier owns a separate decoder and separate semantic checks.
It rejects a service-session receipt when any identity, bound, transition,
observation, acknowledgement binding, cleanup result, or premise is absent or
inconsistent. It MUST NOT depend on a Runtime producer crate.

The proposed closed observation fragment is
`proofbound-runtime-service-session-observation/1`. It freezes the successful
session projection before production receipt integration. The fragment is not
a reusable receipt and cannot be accepted by the production verifier,
composer, or acceptance engine. A later integration MUST embed the same facts,
add non-reusable failure forms, and retain the outer receipt's exact plan,
policy, boundary, outcome, resource, assumption, and trusted-computing-base
bindings.

The proposed outer fragment is
`proofbound-runtime-service-session-receipt/1`. It binds one expected
execution, plan, compiled policy, service, and exact launcher install request.
A reusable success also binds the installed acknowledgement, child release,
canonical successful observation, and zero child exit. A failed form is always
non-reusable. It retains a closed phase and reason, a reported Linux monotonic
failure timestamp without claiming producer-side ordering at this contract wave,
boundary-install state, child-release identity when release occurred, and
terminal cleanup result. Post-release failures MUST bind the exact installed
acknowledgement and release; pre-release failures MUST NOT claim a release.
The contract checker validates the exact retained launcher prefix: the install
request is always present, the installed acknowledgement is present only when
the boundary reached `installed`, and the release is present only after child
release. It rejects absent required frames and premature later frames. It does
not fabricate a successful suffix for an early failure. A retained
credentialed release contains only the source identifier and environment in
the release state. The transient credential-release frame and its secret value
are not receipt inputs.
Assumption identifiers and the service-specific trusted-computing-base
projection are closed and complete for this fragment. They contain only the
new DNS and TLS assumptions and the connector executable, connector runtime
closure, TLS implementation, and TLS trust-root roles. The outer execution
receipt still owns its existing host, kernel, toolchain, Runtime, launcher,
filesystem, cgroup, and other base assumptions and roles. Service-specific identities are SHA-256 values so the
fragment does not admit arbitrary retained identity text. The registered DNS
and TLS assumptions are `PBR-DNS-AX-004` and `PBR-TLS-AX-005`.

This fragment remains a proposed source contract. The production producer and
independent Rust verifier reject it. The independent Python checker is a
contract falsifier, not the shipping verifier, and its implementation MUST NOT
be shared with the later production verifier.

Composition retains the complete service authority, service observations,
limits, assumptions, and trusted-computing-base roles. Consumer acceptance uses
an explicit service-session policy. A policy for network denial does not accept
a service-session receipt. A policy for one service name does not accept a
different name, even when the endpoint or certificate chain overlaps.

## 10. Stable failure classes

Implementations refine existing CLI exit classes with closed machine codes.
The first required code families are:

- `plan.authority.network.*` for invalid or unsupported authority input;
- `network.resolver.*` for resolver setup and DNS failures;
- `network.endpoint.*` for answer selection and TCP attempt failures;
- `network.tls.*` for trust and handshake failures;
- `network.connector.*` for connector identity, protocol, and lifecycle
  failures;
- `network.channel.*` for descriptor and local-channel failures;
- `network.limit.*` for bound exhaustion;
- `launcher.ack.network.*` for incomplete or inconsistent acknowledgement;
- `receipt.network.*` for producer-side receipt construction failures; and
- `verify.network.*` for independent semantic rejection.

Code MUST NOT branch on diagnostic text. Unknown network modes and missing
enforcement remain unsupported. They never fall back to network denial after a
service session was requested and never fall back to ambient networking.

## 11. Required falsifiers and native corpus

The claim cannot ship until both supported architectures run positive and
negative cases for at least:

- valid resolution, TLS authentication, one request, one response, and clean
  shutdown;
- malformed, truncated, oversized, looping, expired, and substituted DNS
  results;
- undeclared terminal names and addresses outside the recorded answer set;
- deterministic address order and bounded failed attempts;
- certificate name, chain, trust-root, minimum-version, resumption, and early
  data failures;
- connector executable, runtime closure, configuration, and process-generation
  substitution;
- direct IPv4 and IPv6 sockets, raw and packet sockets, child DNS, proxies,
  Unix sockets, inherited sockets, `SCM_RIGHTS`, descriptor duplication, and
  `io_uring` bypass attempts;
- descendant inheritance of the registered channel and denial of a second
  channel;
- setup, session, byte, handshake, message, answer, and attempt limits;
- connector crash, channel loss, premature TLS close, timeout, lingering
  process, and cleanup failure;
- receipt field deletion, substitution, reordering, and cross-service
  confusion;
- composition premise loss and acceptance-policy downgrade; and
- secret canaries proving that no credential value or derivative entered
  retained evidence.

Each security-relevant production guard MUST have a causal mutation or another
registered falsifier that removes or corrupts that guard and is rejected for
the expected reason.

## 12. Evidence and release gate

The implementation follows claim-sized proof-driven waves:

1. closed domain, wire, normalization, policy, verifier, composition, and
   acceptance contracts;
2. connector resolution, TLS, limit, and lifecycle behavior;
3. launcher descriptor transfer and child syscall boundary;
4. receipt production and independent verification;
5. native positive and attack corpus on `x86_64` and `aarch64`; and
6. one maintained real API client with a non-retained test credential.

Pure non-amplification, deterministic compilation, and state-transition
properties target formal model and selected Rust refinement evidence. Effectful
DNS, TLS, connector, kernel, and remote-service behavior remains bounded native
evidence with explicit assumptions unless a valid stronger subject is added.

Each wave requires an exact-source independent review, hosted evidence,
approval-only commit, unsigned merge, and exact-main verification. The
service-session product claim remains unavailable until every required wave is
merged and admitted.

## 13. Non-goals

This profile does not provide:

- a hostname allow-list implemented as a port or IP rule;
- HTTP method, path, header, model, prompt, or response semantics;
- multiple services or multiple authenticated sessions;
- reconnect, redirect following, proxy tunnelling, connection pooling, QUIC,
  or cleartext fallback;
- transparent compatibility with an unmodified client that cannot use the
  registered local channel;
- protection of a credential from the declared service or connector;
- certificate revocation checking; or
- proof that the remote service performed an intended action.

RT-9 can extend the accepted mechanism to a typed non-empty service set only
after this single-service profile ships and the reference workload validates
its operational use.
