# Build and run the maintained static example

**Status:** implemented on the post-0.1 development branch; not yet attached to
the `v0.1.0` GitHub release.

The maintained example is a deterministic source bundle that turns an
installed Runtime into one independently verified execution receipt. It
contains a small C program, an orchestration script, instructions, and a closed
manifest of the exact source-file identities. It does not contain a prebuilt
child executable: the supported host compiles that deliberately untrusted
program locally and Runtime records the resulting executable identity.

## Build the exact source bundle

From a reviewed source checkout, choose an existing empty output directory:

```console
mkdir -p dist/example
python3 tools/release/build_example.py --output-directory dist/example
(cd dist/example && sha256sum --check ./*.sha256)
```

For the source files introduced on 2026-09-09 with project version `0.1.0`, the
deterministic archive identity is:

```text
sha256:d3f367a96063d14ec8a58647cb22c53e6c8cd8b0fc5e62e6c3d06bf777540ab8
```

The build refuses to replace either the archive or checksum. It fixes member
order, ownership, modes, timestamps, gzip metadata, and the exact three-file
source inventory. Its adjacent checksum is a convenient integrity check, not
publisher authentication; the reviewed source revision and distribution
channel remain trust inputs.

The release workflow builds and checks the same bundle independently in both
architecture jobs and retains it with the release candidates. Do not describe
the bundle as a published GitHub release asset until that reviewed workflow has
completed and the exact archive has been attached.

## Run the example

Extract the archive, then supply the installed Runtime directory, the prepared
delegated cgroup root, and a new absolute work directory:

```console
tar -xzf proofbound-runtime-example-v0.1.0.tar.gz
cd proofbound-runtime-example-v0.1.0
./run-example.sh \
  /absolute/path/to/proofbound-runtime-v0.1.0 \
  /path/to/delegated/cgroup \
  /absolute/new/proofbound-hello-run
```

The host must provide `cc` with static libc support, `file`, and Python 3. The
script refuses an existing work directory, checks all required Runtime
binaries, builds a static executable, creates a deny-network plan, probes the
host, checks the plan, runs it, and invokes `pbr-verify` with the commitment
transported outside the receipt. Success prints the retained output, receipt,
verification report, and commitment paths as JSON.

The script and native CI require the output text and independently derived
`reusable` result. This remains a bounded example. It does not prove the child
program correct, authenticate the archive publisher, remove the Linux and host
assumptions, or make a preflight report into execution evidence.
