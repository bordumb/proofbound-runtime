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
