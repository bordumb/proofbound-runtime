# ADR 0004: Use one connector-owned authenticated service session

- **Status:** accepted by the maintainer on Claude's independent model review;
  production implementation remains gated
- **Date:** 2026-09-10
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** first version 2 network-enabled execution profile
- **Evidence input:** [Experiment 0001J](../experiments/0001j-deterministic-network-comparison.md)

## Context

Version 1 denies network authority. The first network-enabled profile must let
one identified client make one request to one declared HTTPS service while
denying undeclared direct and inherited network paths. A port, one-time IP
address, or child-side TLS check is not a service identity.

Experiment 0001 executed four candidates through three functional slices and
one measurement slice on x86_64 and aarch64 Linux. The deterministic comparison
consumed all 32 independently verified results and was independently reproduced
with exact result identity
`2b42d8a5dfdc617bf6324db2ad26d0d5ff27c35730e3145c9aacad409deb7c1f`.
It classified:

- port-only Landlock and cgroup endpoint filtering as
  `ineligible-service-identity`;
- the explicit broker as eligible for review only under explicit-operation
  authority; and
- the preconnected connector as eligible for review under authenticated
  service-session authority.

The two eligible mechanisms have different meanings. The explicit broker
admits only a closed operation but makes its application parser and operation
schema trusted. The preconnected connector authenticates one service session
and permits arbitrary bounded application bytes on that session. It does not
claim to understand an HTTP path, method, redirect, proxy target, prompt, or
response.

## Proposed decision

If this ADR receives independent approval, the first version 2 network-enabled
profile uses one connector-owned authenticated TLS service session. The public
claim is deliberately limited to:

> Before child release, the identified connector established one bounded TLS
> session to the declared service identity under the recorded resolver and
> trust policy. The child and its descendants could exchange arbitrary bounded
> application bytes on that session but had no other declared Internet, DNS,
> proxy, inherited-socket, Unix-socket, or `io_uring` network path.

The profile does not claim that the child used HTTP correctly, contacted only
one application path, honored a redirect, protected a credential from the
declared service, or caused the remote service to perform an intended action.

### Closed authority mode

The version 2 authority domain adds one mode beside the unchanged deny mode:

```text
Deny
AuthenticatedServiceSession
```

`AuthenticatedServiceSession` requires exactly one service declaration for the
first profile. It contains separate, nonempty identities for:

- the lower-case ASCII DNS service name and TCP port;
- the resolution policy and resolver configuration;
- the TLS trust policy, exact trust-root set identity, minimum TLS version, and
  service-name verification rule;
- maximum CNAME depth, answer count, response bytes, and resolution deadline;
- maximum session count, application bytes in each direction, and session
  duration;
- connector executable and runtime closure;
- the local channel protocol and child descriptor role; and
- an optional credential-source identity and declared service binding, never
  the credential value.

Unknown modes, empty or multiple service declarations, unbounded fields, and
partial records fail during plan validation. They never fall back to `Deny`, a
port rule, an endpoint rule, or ambient networking.

### Resolution and connection timing

The connector owns resolution. The child receives no resolver configuration and
cannot issue DNS requests. Before child release, the connector:

1. reads one exact resolver configuration and records its identity;
2. resolves the declared name over its bounded registered DNS transport;
3. records the complete bounded CNAME chain, A/AAAA answer set, TTLs, response
   identities, resolver endpoint, and monotonic timing;
4. rejects a loop, excessive chain, undeclared terminal name, malformed or
   contradictory response, timeout, excess answer, or substituted resolver;
5. establishes one TCP connection before the selected answer expires; and
6. authenticates TLS for the declared service name under the exact trust
   policy before making the child channel usable.

The first profile performs no DNS refresh, reconnect, redirect following,
connection pooling, proxy tunneling, QUIC, or cleartext fallback. If the
connection is not authenticated before the registered answer expires, the
operation fails before child release. Loss of the established session is
terminal; the connector does not resolve or connect again under the same
execution. The first profile performs no certificate revocation check, accepts
no TLS session resumption, and sends no 0-RTT early data.

The connector may choose one address from the bounded A/AAAA answer set only by
a deterministic, versioned rule. An address that was not present in the
recorded answer set is never attempted.

### Open obligations before implementation

- Specify the deterministic address-selection rule for the bounded A/AAAA
  answer set.
- Specify the exact IPv4/IPv6 connection-attempt order and terminal behavior.
- Add registered native cases for descendant inheritance of the child channel
  and `SCM_RIGHTS` transfer or escape of that descriptor.

### Child boundary and launch acknowledgement

The connector starts outside the untrusted child boundary and creates one
private Unix stream channel. The launcher closes every undeclared descriptor
and retains exactly the child endpoint of that channel. Before acknowledging
the boundary it installs the existing filesystem, process, resource, identity,
and privilege restrictions plus a network filter that denies:

- Internet and Unix socket creation, connection, bind, listen, accept, and
  datagram operations;
- descriptor duplication that could escape the registered channel contract;
- all `io_uring` setup, entry, and registration paths; and
- inherited Internet or unregistered local-channel descriptors.

Ordinary bounded reads and writes on the one registered channel remain
available. The connector does not parse or rewrite those application bytes.

The launcher acknowledgement binds the execution identity, compiled policy,
cgroup, connector executable, connector process generation, authenticated TLS
session, selected endpoint, local-channel endpoints, descriptor role, byte and
time limits, and every installed child-side control. Child code is released
only after the supervisor validates that complete acknowledgement against its
prelaunch observations.

### Credentials

A real API observation may supply a credential through a separately declared
secret source after the authenticated session and child boundary are ready.
Plans, policies, launcher messages, receipts, diagnostics, fixtures, CI logs,
and retained artifacts contain only the credential-source identity and declared
service binding. They never contain the value.

Making a credential available does not prove that the child used it, kept it
out of output files, or formatted an intended request. The network claim says
only that the child had no other registered network path while the credential
was available. A future credential broker that releases a secret only for a
parsed operation would be a different authority mode and a new trusted
component.

### Terminal behavior and receipt meaning

A successful execution receipt records bounded observations including:

- requested service and resolution-policy identities;
- complete bounded CNAME and address-set observations;
- selected routing endpoint and connection timing;
- TLS version, service-name verification result, peer-certificate chain and
  trust-root set identities;
- connector executable/runtime identity, process generation, and local-channel
  identity;
- installed child-filter identity and bound launcher acknowledgement;
- application byte counts, configured bounds, session-close reason, and
  whether any excess exchange was rejected; and
- connector, channel, child, cgroup, and namespace cleanup observations.

These observations do not prove the resolver, certificate authority, TLS
library, kernel, host, or remote service correct. Those premises remain visible
as assumptions or trusted computing base.

Missing, malformed, substituted, expired, oversized, or inconsistent
resolution, TLS, connector, acknowledgement, counter, close, or cleanup
evidence makes the run unsupported or non-reusable according to the normative
outcome table. Connector crash, channel loss, limit exceedance, attempted
second session, or reconnect never produces a reusable success receipt.

Historical version 1 deny-network plans and receipts retain their existing
meaning and canonical JSON encoding. Version 2 plans, compiled policies, run
results, execution receipts, and composed receipts follow
[ADR 0003](0003-deterministic-cbor-wire-objects.md): deterministic CBOR with
closed CDDL and golden vectors, separate producer and independent-verifier
codecs, text map keys, and JSON only as a decoded inspection projection. The
map-key decision was recorded on 2026-09-11 and is no longer an open gate.

## Trusted computing base and assumptions

The profile adds these identified subjects to the trusted computing base:

- the Runtime supervisor and native launcher;
- the connector executable and its complete runtime closure;
- the resolver implementation and exact resolver configuration;
- the TLS implementation and exact trust-root set;
- the connector configuration, deterministic address-selection rule, local
  channel, counters, and lifecycle code;
- the Linux kernel mechanisms enforcing the child boundary; and
- the host process that provisions the connector's network namespace and
  routing environment.

The claim assumes the host administrator, kernel, resolver behavior, DNS
operator for the declared name, certificate authorities admitted by the trust
policy, hardware, firmware, toolchain, and remote service are not malicious in
ways outside the recorded model. A digest identifies bytes; it does not prove
their behavior. Certificate revocation is a recorded assumption because the
first profile performs no revocation check. Descendant inheritance of the
registered child channel and `SCM_RIGHTS` transfer of that descriptor remain
untested until the native cases in the open-obligation list pass on both
release architectures.

## Operational basis

All candidates completed 1,000 of 1,000 lifecycle trials per architecture. The
preconnected connector's cold setup median/p95 was 14,256,653/15,673,552 ns on
x86_64 and 22,391,804/22,994,776 ns on aarch64. Its exact-request median/p95
was 285,143,749/291,164,258 ns and 270,483,508/278,302,904 ns respectively.
Maximum observed connector RSS was 25,886,720 bytes on x86_64 and 24,510,464
bytes on aarch64, with one maximum simultaneous connector process.

The explicit broker had materially higher setup medians of 96,946,069 ns and
86,731,092 ns, while request medians were similar. Performance does not decide
security adequacy. The proposal selects the connector because its honest
authenticated-session authority fits the first one-service API workload without
making an application parser trusted; the measured cost only shows that this
candidate is operationally plausible for independent review.

## Consequences

### Positive

- The public claim names authenticated service-session authority rather than a
  port, address, hostname string, or application operation the boundary did not
  enforce.
- The child owns no resolver or Internet socket and cannot silently reconnect,
  follow a redirect, use an ambient proxy, or open a second session.
- Ordinary clients can exchange their application protocol over a byte stream
  without moving an HTTP or LLM protocol parser into the Runtime TCB.
- Every new resolver, TLS, connector, channel, lifecycle, and observation role
  remains explicit and identity-bound.

### Negative

- The child can send arbitrary bounded bytes to the authenticated service. The
  profile cannot enforce an HTTP method, path, header, model name, prompt
  purpose, or response meaning.
- General SDK behavior that needs multiple connections, HTTP/2 multiplexing,
  reconnect, streaming beyond the fixed bounds, or QUIC is unsupported.
- The connector, resolver, TLS stack, trust roots, and network provisioning
  materially expand the trusted computing base.
- A general dynamically linked client may need adaptation to use the registered
  local byte channel; transparent socket interception is not implied.
- The version 2 claim wave is larger because all committed wire objects and the
  independent verifier must change together under ADR 0003.

## Alternatives considered

### Explicit-operation broker

Not selected for the first profile. It offers the narrowest authority and
remains a valid future candidate, but each supported API operation would make a
new parser, schema, canonicalization rule, streaming behavior, and error mapping
security-critical. The experiment's fixed echo operation does not establish a
general LLM API grammar. A later credential broker or closed high-value
operation may justify this separate mode through its own specification and
claim.

### Cgroup endpoint filtering

Rejected for the service-identity profile. It selected one routing tuple in the
bounded corpus but left TLS and arbitrary application bytes under child
control. DNS rebinding, certificate meaning, and application indirection cannot
be upgraded into service identity by naming the endpoint differently.

### Port-only Landlock

Rejected for the service-identity profile. It permitted any reachable address
on the allowed port. Its lower setup cost cannot compensate for that authority
mismatch. A separately named broad port-authority feature would require a new
specification and claim and is not a fallback for this mode.

### Continue denying all network authority

Safe but insufficient for the first declared API workload. This remains the
only production behavior unless and until this ADR is approved and the complete
version 2 claim wave is independently reviewed and released.

## Independent review

Claude independently reviewed the authenticated service-session decision on
2026-09-11 against Experiment 0001J, the retained result identities, and the
registered network attack domain. The verdict was **approve with required
changes**. This revision resolves all four required changes: it cites the
decided text-key CBOR contract, closes the first TLS profile against revocation,
resumption, and early data, makes the two untested descriptor-transfer paths
explicit required native work, and promotes address selection and connection
order from prose to open obligations.

The independent review confirmed:

1. the public claim is no broader than authenticated-session authority;
2. the prelaunch resolver, TLS, connector, child boundary, and acknowledgement
   close the tested direct, inherited, substitution, reuse, and race paths;
3. arbitrary application bytes, credential limitations, TCB additions, and
   host/resolver/CA assumptions remain visible;
4. unsupported behavior and terminal failures cannot silently reconnect or
   fall back;
5. the operational observations are sufficient for the first adopter workload
   without being treated as proof; and
6. every review comment is resolved without weakening the frozen result or
   silently broadening the authority mode.

Acceptance authorizes a normative version 2 specification and threat-model
change, not production code by itself. Production implementation still waits
for closed CDDL schemas and golden vectors, falsifiers, pure non-amplification
and deterministic-compilation evidence, the full native attack corpus on both
architectures, independent verifier agreement, release composition, and
reviewed publication.

## Revisit conditions

Revisit this decision when:

- the first real adopter requires multiple sessions, HTTP/2 multiplexing,
  reconnect, QUIC, or transparent unmodified SDK sockets;
- a closed operation or credential broker materially reduces authority for a
  demonstrated workload;
- the connector cannot bind its authenticated session to the stopped-launcher
  acknowledgement without an unacceptable trusted shim;
- resolver, TLS, trust-root, or cleanup observations cannot remain bounded; or
- a kernel or isolated execution mechanism provides a smaller, independently
  evidenced trusted computing base for the same honest claim.
