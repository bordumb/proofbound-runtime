# Network authority experiment harness

This directory implements the pre-registered protocol in
[`docs/experiments/0001-network-authority-mechanisms.md`](../../docs/experiments/0001-network-authority-mechanisms.md).
It is not Runtime production code and is not included in release bundles.

The first control is `landlock_port_control.c`. On Linux with Landlock ABI 4 or
newer, it installs one network-only ruleset that handles outbound TCP connect
and permits port 443. It then executes the supplied command. The wrapper does
not claim to identify an address, DNS name, certificate, or remote service.

Compile the control with strict warnings:

```console
cc -std=c11 -Wall -Wextra -Werror -O2 \
  experiments/network_authority/landlock_port_control.c \
  -o /tmp/landlock-port-control
```

`landlock-port-control --print-abi` prints the exact observed ABI without
installing a rule. The wrapper exits `3` when the host is not Linux or does not
expose Landlock ABI 4 for command execution. Setup or enforcement failure exits
`4`. Invalid command grammar exits `2`. After successful installation, the
wrapper replaces itself with the requested command and preserves that command's
exit behavior.

The wrapper deliberately installs no filesystem policy and no general Runtime
boundary. It exists only to falsify the proposition that a Landlock port rule
can represent one remote service.

The second control is `cgroup_endpoint_control.c`. On native Linux, a root
supervisor loads exact `BPF_CGROUP_INET4_CONNECT` and
`BPF_CGROUP_INET6_CONNECT` programs, attaches them to one already-created
cgroup, moves one child into that cgroup, drops the child to uid/gid 65534,
waits for it, and detaches both programs. The IPv4 program permits only one
registered address and TCP port tuple. The IPv6 program denies every connect.
The supervisor writes the exact instruction bytes, verifier logs, observed
program identifiers, and cgroup inode to one new state directory.

This endpoint control can distinguish routing tuples. It cannot establish DNS
continuity, certificate validity, requested host identity, or application
redirect policy, and it is not a Runtime boundary or production loader.

The third control begins with `broker_child_control.c`. It accepts exactly one
inherited Unix stream descriptor, closes every other non-stdio descriptor,
records and installs a network-denying seccomp program, sets `no_new_privs`,
drops to uid/gid 65534, and executes the explicit-channel case client. Socket
creation, direct connection, datagram and message I/O, socket options, and
`io_uring` setup/entry/registration are denied. Ordinary `read` and `write`
remain available on the inherited channel, and `shutdown` delimits its single
frame after all other sockets have been closed.

`explicit_broker.py` supplies the closed frame parser, fixed broker-side
service/TLS policy, and deterministic TLS fixture. The broker and wrapper are
experiment trusted computing base. Neither is linked into Runtime or included
in a release bundle.

The fourth control is specified in
[`0001d-preconnected-channel-control.md`](../../docs/experiments/0001d-preconnected-channel-control.md).
It keeps one authenticated TLS session in a connector and gives the child one
transparent local stream for that session. Its implementation must preserve
the contrast with the explicit broker: routing and TLS identity are fixed, but
the connector does not parse or constrain application operations.

`run_preconnected_control.sh` implements that control in a disposable native
Linux network namespace. It runs 14 cases, including two expected observations
that undeclared application bytes reach the fixed authenticated service. Its
recorder requires exact connector, certificate, local-channel, child-start,
seccomp, case, and cleanup observations before it can publish the narrow
pre-registered conclusion. This remains experiment code with no Runtime schema
or release effect.

The decision-grade execution protocol is specified in
[`0001e-decision-matrix-execution.md`](../../docs/experiments/0001e-decision-matrix-execution.md).
Its first functional slice is frozen separately in
[`0001f-routing-transport-slice.md`](../../docs/experiments/0001f-routing-transport-slice.md).
The second functional slice is frozen in
[`0001g-resolution-indirection-slice.md`](../../docs/experiments/0001g-resolution-indirection-slice.md).
The committed decision matrix, generated inventory, and deterministic
DNS/TLS/redirect/proxy/socket fixtures are inputs to those slices; they do not
change a Runtime network policy or release artifact.

The routing/transport slice implementation uses
`run_routing_transport.sh`. For one selected mechanism, it requires a clean
exact Git commit, enters a loopback-only network namespace, stages the closed
child package, compiles the selected native controls, executes all 16 cases,
and publishes an immutable result. `record_routing_transport.py` is the only
component that compares raw observations to the frozen expectations.
`verify_routing_transport.py` independently checks the result inventory,
digests, manifests, case plans, raw-cell derivation, and conclusion without
importing the producer or classifier.

Run one routing/transport mechanism as root on native Linux:

```console
sudo experiments/network_authority/run_routing_transport.sh \
  cgroup-endpoint \
  /absolute/path/to/new-routing-result
```

The four valid mechanism names are `landlock-port`, `cgroup-endpoint`,
`explicit-broker`, and `preconnected-channel`. A successful local invocation
does not complete the slice: the exact same clean source commit must produce
and independently verify all eight mechanism/architecture results.

Run the control as root on a clean exact Git commit:

```console
sudo experiments/network_authority/run_port_control.sh \
  /absolute/path/to/new-result-directory
```

The runner creates a disposable network namespace with loopback only. It
generates temporary certificates and private keys, starts three local TLS
servers, and executes four port-rule cases. It uses `curl --resolve` so this
first control isolates port selection from the later DNS experiments. Private
keys remain in the temporary root and are removed after the recorder stores
only public certificate identities.

The result directory is created with no-replace semantics and retains every
case log plus canonical attack, fixture, kernel, tool, and artifact manifests.
The expected control result is that both distinct services on port 443 are
reachable, port 8443 is denied, and the TLS client rejects a wrong certificate.
The runner retains an unexpected result and then exits nonzero.

The `Network authority experiment` workflow is path-limited to changes in this
directory or the workflow itself while it is introduced by a pull request.
After the workflow exists on the default branch it may also be run through an
explicit manual dispatch. It executes the selected controls on hosted x86_64
and aarch64 Linux and retains each exact result for 14 days. Unrelated pushes
and pull-request changes do not run experiments.
