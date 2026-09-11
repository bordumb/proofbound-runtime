# Static hello example

This source bundle takes the shortest maintained path from installed Runtime
binaries to an independently verified execution receipt. It compiles a tiny
static Linux program, creates a deny-network plan with one fresh output root,
runs the program through `pbr`, and verifies the exact receipt with
`pbr-verify`.

The example requires a supported `x86_64` or `aarch64` Linux host, the delegated
cgroup v2 root described in the installation guide, `cc` with static libc
support, `file`, and Python 3. It writes only beneath a new absolute work
directory supplied by the user.

```console
./run-example.sh \
  /absolute/path/to/proofbound-runtime-v0.2.0 \
  /path/to/delegated/cgroup \
  /absolute/new/proofbound-hello-run
```

Success prints a compact JSON object containing the independently supplied
receipt commitment and the retained receipt, verification report, and output
paths. The example does not prove that the child program is semantically
correct, and its source archive checksum establishes byte identity only after
the expected checksum and release channel have been trusted.
