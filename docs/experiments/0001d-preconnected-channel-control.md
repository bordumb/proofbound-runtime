# Experiment 0001D: Preconnected authenticated channel control

- **Status:** first native control recorded; full parent matrix remains open
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001](0001-network-authority-mechanisms.md)
- **Roadmap:** RT-4.2 mechanism D
- **Production effect:** none

## Control question

Can a trusted per-execution connector establish exactly one authenticated TLS
session before child release, give the identified child one local stream for
that session, and deny every direct network path? How much application
authority does that transparent stream expose compared with the explicit
operation protocol in mechanism C?

A userspace TLS session is not only a kernel file descriptor. Its handshake,
record, alert, and shutdown state lives in the TLS implementation's process
memory. Passing the underlying connected TCP descriptor after a userspace
handshake would not pass that authenticated TLS state. This control therefore
keeps the TLS session in the connector and gives the child one end of an
identified Unix stream socket pair. The connector relays plaintext application
bytes over the already-authenticated TLS session without parsing or rewriting
them.

That relay is a trusted component, but it is not mechanism C's broker. It has
no request schema, target field, resolver API, retry set, connection pool, or
operation allow-list. It owns exactly one pre-established remote session and
cannot reconnect. The distinction under test is closed operation authority
versus arbitrary application bytes to one authenticated session.

## Frozen fixture and connection

The disposable Linux network namespace contains:

- `allowed.test` at `127.0.0.1:443`, presenting the generated certificate for
  `allowed.test` and serving a deterministic bounded HTTP/1.1 fixture;
- an alternate endpoint at `127.0.0.2:443` that can present either the denied
  certificate or the allowed certificate for endpoint-substitution cases;
- a plaintext listener for TLS-downgrade rejection; and
- no route outside loopback.

The connector configuration is fixed before it starts:

```text
service name: allowed.test
routing endpoint: 127.0.0.1:443
transport: TLS 1.3
trust root: exact allowed fixture certificate
ALPN: none
SNI and verification name: allowed.test
maximum child-to-service bytes: 4096
maximum service-to-child bytes: 4096
session count: 1
reconnect count: 0
```

The connector first creates the local socket pair, then opens the registered
routing endpoint and confirms the connected peer tuple. It performs TLS with
certificate and name verification and records the negotiated version, cipher,
peer public-certificate digest, and local and remote socket observations. Only
after all checks pass does it launch the stopped child boundary and release
the relay. A connection, endpoint, TLS, or identity failure must occur before
child code and produces no successful case receipt.

Private keys exist only inside the temporary root. Published results retain
public certificate identities and bounded fixture observations, never a key.

## Child boundary and descriptor identity

The native child wrapper receives one registered Unix `SOCK_STREAM`
descriptor plus its expected `SO_COOKIE` and peer credentials. Before `exec`
it:

1. rejects a descriptor below 3, an unexpected family or type, a disconnected
   channel, a cookie mismatch, or peer-credential mismatch;
2. closes every non-stdio descriptor except the registered channel and rejects
   any requested foreign descriptor case;
3. sets `no_new_privs`;
4. installs an architecture-specific classic seccomp program that denies
   socket creation, connect, bind, listen, accept, socket pairs, datagram and
   message I/O, socket options, descriptor duplication, and `io_uring` setup,
   entry, and registration;
5. drops supplementary groups and changes to uid/gid 65534; and
6. executes the exact staged case client.

Ordinary `read`, `write`, `close`, and one final `shutdown` remain available on
the retained stream. The child receives no certificate, trust root, endpoint,
resolver setting, proxy setting, credential, or connector control channel.
The connector never passes its Internet descriptor to the child.

The wrapper records its source, binary, exact seccomp instruction bytes,
installed architecture, retained descriptor, channel cookie, socket family and
type, and peer credentials. The connector records the corresponding local
channel identity before child release. A mismatch is a closed experiment
failure.

## Transparent application channel

The allowed child sends one canonical bounded HTTP/1.1 request and half-closes
its local write direction. The connector forwards bytes without inspecting
method, path, headers, or body, half-closes TLS output, relays the bounded
response, observes authenticated TLS shutdown, and exits. It never opens a
second network connection.

Because the connector is transparent, a malicious child with the channel can
send any bytes accepted by the already-authenticated service within the byte
and lifetime bounds. Two cases deliberately demonstrate that an undeclared
HTTP path and a CONNECT-shaped request reach the fixed fixture. Those are
expected authority exposures, not successful operation enforcement. A result
that hides either observation is invalid.

## First native falsifiers

| Case | Expected result |
| --- | --- |
| Exact canonical request | One authenticated session returns the fixed response. |
| Undeclared HTTP path | Bytes reach the same authenticated fixture, exposing application-wide authority. |
| CONNECT-shaped request | Bytes reach the same authenticated fixture, exposing protocol transparency. |
| Child opens direct TCP | `EPERM` before connect. |
| Child opens or sends through UDP | `EPERM`. |
| Child forks before direct TCP | The descendant retains the same seccomp restriction. |
| Alternate endpoint with denied certificate | Connector rejects endpoint and TLS identity before child start. |
| Alternate endpoint with allowed certificate | Connector rejects the routing tuple before child start. |
| Allowed endpoint presents wrong certificate | Connector rejects TLS identity before child start. |
| Plaintext endpoint | TLS failure before child start. |
| Connector exits after child release | Closed child failure with no direct or reconnect fallback. |
| Wrong channel cookie | Wrapper rejection before child `exec`. |
| Unconnected or non-Unix descriptor | Wrapper rejection before child `exec`. |
| Unexpected inherited descriptor | Wrapper rejection before child `exec`. |
| Existing output or result path | No replacement and no positive result. |

Every case has a finite connector, fixture, and child deadline. The runner
kills and reaps every remaining process and requires namespace cleanup. An
unbounded listener, relay, TLS shutdown, or wait is a harness failure retained
outside the positive result.

## Result boundary

The immutable result uses the parent inventory and additionally records:

- canonical connector configuration bytes;
- connector, child, fixture, wrapper, and recorder source identities;
- wrapper binary and seccomp instruction identities;
- the Internet socket's exact pre-TLS local and peer tuples;
- the TLS version, cipher, verification name, and peer public-certificate
  identity observed before child release;
- both ends' local-channel cookie and peer-credential observations;
- whether child execution began in each prelaunch-failure case;
- exact child, connector, and fixture stdout, stderr, exit status, byte counts,
  and bounded application observation;
- compiler, Python, TLS library, kernel, and architecture identities;
- connector, child, fixture, descriptor, and namespace cleanup; and
- the two expected application-authority exposures.

The result does not retain TLS secrets, fixture private keys, traffic payloads
beyond fixed public sentinels, or public-network responses. Publication is
no-replace. Independent post-download verification is required before the
roadmap records an observation.

## Control conclusion

If every denial, prelaunch failure, identity check, cleanup check, allowed
request, and expected authority exposure matches, the result may say
`preconnected-channel-binds-one-authenticated-session-control`. This means one
transparent bounded channel remained tied to one connector-owned,
authenticated TLS session while direct child networking was denied.

It does not mean the mechanism constrains HTTP methods, paths, headers,
credentials, or application messages; supports DNS refresh, redirects,
connection reuse, QUIC, or ordinary unmodified clients; or is ready for a
Runtime schema. Those limitations must remain visible when mechanism D is
compared with mechanism C and when ADR 0003 decides whether any production
claim is worth the added trusted computing base.

## Recorded control

The valid control ran from exact commit
`9fe5d2c936ce92ee1f1f161000d50284445c3b21` in GitHub Actions run
[`34439915673`](https://github.com/bordumb/proofbound-runtime/actions/runs/34439915673).
All 14 cases matched on x86_64 and aarch64. The canonical request and both
expected authority exposures exited zero. Direct TCP, UDP, descendant TCP,
endpoint substitution, wrong certificate, plaintext transport, connector
failure, and foreign-descriptor cases exited 7. Wrong-cookie and non-Unix
descriptor validation exited 2 before child execution.

Each architecture recorded ten authenticated TLS 1.3 sessions, four expected
prelaunch failures, eight installed child boundaries, three completed relays,
and successful cleanup. Independent download verification reproduced every
one of 82 declared input digests and found no unlisted input. The immutable
result digests are:

- x86_64:
  `8c56cdf211ad029f30d57e0e4e7dcb46a1c12f14fc7e93a6e5b8f339690dad0b`;
- aarch64:
  `c959fbacf64b5c628fed143a567f269af3887832ca128cfc22f9f84dcb90be22`.

Run `34439277039` remains the failed first attempt. Its missing client-start
markers exposed an overbroad `fcntl` denial and insufficient retained failure
diagnostics; `9fe5d2c` narrowed the filter and preserved sanitized future
failure state. It is not positive mechanism evidence.

The passing result retains the deliberately narrow conclusion
`preconnected-channel-binds-one-authenticated-session-control`. In particular,
the undeclared-path and CONNECT-shaped sentinels reached the authenticated
fixture. That is positive evidence of the expected application-authority
exposure, not operation-level confinement and not satisfaction of the parent
experiment's production decision gate.
