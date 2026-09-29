# ADR 0010: Select a declared network egress boundary

**Status:** accepted

## Context

Specification 0016 gives one connector process one authenticated service
session. Tools that open their own TCP connections, reconnect, and launch
plugins need a different authority. A host firewall or cgroup BPF program
would require host privileges and would select addresses rather than names.
Landlock network rules select ports but not names.

## Decision

Use the mechanism in Specification 0017: a child user and network namespace
with loopback only, one transferred loopback listener, and a separately
identified host-network `CONNECT` proxy. The proxy resolves only declared
names, pins answer addresses for attempts, and records its observations.
Seccomp and Landlock remain mandatory child and proxy boundaries. Unsupported
hosts fail closed. The proxy does not authenticate DNS or TLS.

This decision does not supersede ADR 0004. The authenticated service session
and declared egress are separate, incomparable network modes.

## Consequences

The Runtime needs unprivileged user namespaces and Landlock ABI 9 through 11.
Clients must use the declared proxy environment variables; direct connections
fail. The proxy and resolver become trusted computing base. The receipt
retains the resolver and namespace assumptions. Declared egress remains
unavailable for production execution until the Specification 0017 release
gate is admitted.
