# Experiment 0001C: Explicit per-execution broker control

- **Status:** design frozen; implementation not yet recorded
- **Date:** 2026-09-10
- **Parent protocol:** [Experiment 0001](0001-network-authority-mechanisms.md)
- **Roadmap:** RT-4.2 mechanism C
- **Production effect:** none

## Control question

Can an identified child with no direct network syscalls use one preconnected,
length-framed local channel to ask an identified per-execution broker for one
fixed HTTPS operation, while target substitution, direct TCP, direct UDP, TLS
identity failure, and malformed protocol inputs fail closed?

A passing control does not make the broker production-ready. It tests the
narrow explicit-channel mechanism against a first closed corpus. It does not
authorize a transparent proxy, CONNECT tunnel, hostname allow-list, public
schema, or Runtime receipt change.

## Frozen fixture

The disposable Linux network namespace contains:

- `allowed.test` at `127.0.0.1:443`, presenting the generated certificate for
  `allowed.test` and returning the fixed 32-byte experiment response;
- a distinct service at `127.0.0.2:443`, presenting the generated certificate
  for `denied.test`; and
- no route outside loopback.

Private keys exist only inside the temporary root. Result publication retains
the public certificate identities, not the certificate or key bytes.

The broker is configured before the child starts with exactly:

```text
service name: allowed.test
routing endpoint: 127.0.0.1:443
transport: TLS
trust root: exact allowed fixture certificate
operation: echo
maximum request payload: 1024 bytes
maximum frame: 4096 bytes
```

The configuration has no proxy fallback, environment-derived target, redirect,
DNS query, alternate address, or retry destination.

## Child boundary

The root experiment supervisor creates one Unix `SOCK_STREAM` socket pair
before child execution. The child receives exactly one end at a registered
descriptor. Before `exec`, a native wrapper:

1. closes every non-stdio descriptor except the registered channel;
2. sets `no_new_privs`;
3. installs a classic seccomp filter that returns `EPERM` for socket creation,
   connection, bind/listen/accept, socket-pair creation, datagram send/receive,
   message send/receive, and socket options; `shutdown` remains available to
   delimit the retained local channel after every other socket descriptor is
   closed and socket creation is denied;
4. drops supplementary groups and changes to uid/gid 65534; and
5. executes the identified case client.

The wrapper records its exact source and binary identity plus the seccomp
instruction bytes. It is experiment trusted computing base. This control does
not reuse the Runtime launcher and creates no Runtime assurance evidence.

The broker owns the other socket-pair end and remains outside the child
boundary. The broker process, Python runtime and standard library, TLS stack,
configuration, trust root, framing parser, fixture server, and local channel
are experiment trusted computing base.

## Closed channel protocol

Each direction is one four-byte unsigned big-endian length followed by exactly
that many UTF-8 bytes. Length zero, length above 4096, truncation, trailing
bytes, invalid UTF-8, duplicate JSON keys, unknown fields, and noncanonical
JSON fail closed.

The only request schema is:

```json
{"operation":"echo","payload":"<1 to 1024 UTF-8 bytes>"}
```

The request contains no target, hostname, port, URL, method, headers, proxy,
redirect choice, trust root, or credential selector. The broker's frozen
configuration supplies the service identity. The success response is:

```json
{"payload":"<exact echoed bytes>","status":"ok"}
```

The broker may return one closed error response, but no error is success. It
never relays arbitrary stream bytes and never accepts a CONNECT-like target.

## Falsifiers

| Case | Expected result |
| --- | --- |
| Exact canonical echo request | The broker authenticates `allowed.test`, verifies the fixed application response, and returns the exact payload. |
| Request adds `target` for `denied.test` | Protocol rejection before a network connection. |
| Child opens direct TCP to either fixture | `EPERM` from the child boundary before connect. |
| Child opens or sends through UDP | `EPERM` from the child boundary. |
| Broker endpoint presents the wrong certificate | TLS failure and no success response. |
| Zero, oversized, truncated, duplicate-key, unknown-field, invalid-UTF-8, or noncanonical frame | Protocol rejection with no broader parse or retry. |
| Child forks before attempting direct network | Descendant retains the same seccomp restriction. |
| Broker exits before or during a request | Closed child failure; no direct fallback. |
| No client reaches a fixture listener | Fixture timeout and incomplete result rather than an unbounded run. |
| Unexpected inherited descriptor | Wrapper rejection before child `exec`. |
| Existing output or result path | No replacement and no positive result. |

The first native run must execute at least the first five rows plus every frame
parser row. The fork, broker-crash, descriptor, and publication rows are local
falsifiers before the native run. The full parent attack matrix remains
required before any ADR can accept the mechanism.

## Result boundary

The immutable result uses the parent experiment inventory and additionally
records:

- canonical broker configuration bytes;
- broker, case client, fixture, wrapper source, and wrapper binary identities;
- the seccomp instruction bytes and installed architecture;
- the retained descriptor number and local channel type;
- exact case stdout, stderr, and exit status;
- broker and fixture logs;
- TLS library, Python, compiler, kernel, and architecture identities;
- cleanup observations for broker, child, fixture, socket, and namespace; and
- residual paths not tested by this control.

A failed or incomplete run remains downloadable. Result hashes are verified
independently after download before the roadmap records an observation.

## Control conclusion

If every required first-run case matches and cleanup is observed, the result
may say `explicit-broker-binds-fixed-service-control`. That conclusion means
only that this explicit fixture survived this bounded corpus. It does not mean
the mechanism supports arbitrary HTTP clients, package managers, redirects,
DNS, QUIC, credentials, transparent proxying, or a production Runtime profile.

If any case fails, the result is `unexpected-control-result`. The design is
revised or rejected before another exact-subject run; a weaker fallback is not
substituted silently.
