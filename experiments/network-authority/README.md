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
  experiments/network-authority/landlock_port_control.c \
  -o /tmp/landlock-port-control
```

The wrapper exits `3` when the host is not Linux or does not expose Landlock
ABI 4. Setup or enforcement failure exits `4`. Invalid command grammar exits
`2`. After successful installation, the wrapper replaces itself with the
requested command and preserves that command's exit behavior.

The wrapper deliberately installs no filesystem policy and no general Runtime
boundary. It exists only to falsify the proposition that a Landlock port rule
can represent one remote service. Later harness steps add the complete
disposable TLS fixture, exact result record, and manual native workflow before
any result is recorded.
