# Proofbound Runtime

Run untrusted tools with declared authority and produce an independently
verifiable account of the execution boundary.

> **Status:** version 0.1.0 released. The executable product surface and
> native Linux boundary are implemented and exercised on `x86_64` and
> `aarch64`. The Proofbound release envelope is independently verified, and a
> typed Runtime plugin composes it with one verified execution receipt. The
> final contextual release build at revision
> `c78e189e2e098489ebf9f45840bdf9ff6cb0fd6d` bound all four
> source-refined claims to the exact native `pbr` member and independently
> observed the Runtime, launcher, verifier, and composer roles on both native
> architectures. No claim facet was promoted by observation. The exact-SHA
> build passed on both architectures in
> [run 34361101393](https://github.com/bordumb/proofbound-runtime/actions/runs/34361101393),
> and its runtime and assurance bundles are published in the
> [v0.1.0 release](https://github.com/bordumb/proofbound-runtime/releases/tag/v0.1.0).

## What it is

Proofbound Runtime is a Linux-first execution-assurance gateway for autonomous
agents and other untrusted tools. A caller declares the command, inputs,
environment, executable closure, filesystem access, network mode, and resource
limits for one execution. The runtime installs the requested operating-system
boundary before child code starts and emits a canonical execution receipt.

The intended initial boundary uses:

- Landlock for filesystem authority;
- seccomp with `no_new_privs` for syscall restrictions;
- cgroup v2 for process and resource limits;
- an explicit environment allow-list;
- an exact executable and loader closure; and
- fresh output roots with bounded process streams.

Proofbound Runtime is not an operating-system kernel, container runtime, or
virtual machine. It is a gateway that uses kernel-enforced mechanisms.

## What a receipt means

A valid receipt identifies the execution plan, compiled policy, platform,
runtime, inputs, outputs, enforcement mechanism, and outcome for one run. It
does not prove that Linux is correct or that every possible information leak is
absent.

The receipt producer records typed facts. A separately implemented verifier
derives validity and reuse eligibility. The producer cannot declare its own
receipt successful.

```mermaid
flowchart LR
    A[Declared command and authority] --> B[Validated execution plan]
    B --> C[Linux enforcement boundary]
    C --> D[Untrusted agent or tool]
    D --> E[Canonical execution receipt]
    E --> F[Independent verifier]
```

## Relationship to Proofbound

[Proofbound](https://github.com/bordumb/proof-bound) is the assurance compiler
used to develop and release this product. It owns claim status, evidence
meaning, assumptions, artifact linkage, and the generic rules that make typed
evidence composition possible.

Proofbound Runtime owns agent execution plans, authority semantics, Linux
policy compilation, boundary installation, run observations, and execution
receipts. It also owns `pbr-compose`, the Runtime-specific typed join between a
verified Proofbound release and a verified execution. Proofbound does not run
in the child security path.

Runtime discoveries that require generic Proofbound support are recorded in
[`docs/proofbound-feedback`](docs/proofbound-feedback/README.md) before they are
deliberately upstreamed.

## Development approach

The project uses Proof-Driven Development:

1. Register the complete product claim map at Proofbound Tier 0.
2. Take one small foundational claim through Tier 3 before expanding the
   architecture.
3. Develop later behavior in claim-sized assurance waves.
4. Refactor when stronger evidence exposes a weak abstraction or missing
   linkage.
5. Rebuild every affected evidence path after source or artifact changes.

Four claims have completed source-refinement linkage and contextual exact-
artifact binding: `PBR-AUTH-001`, `PBR-POLICY-002`, `PBR-RECEIPT-004`, and
`PBR-BINDING-005`. They cover authority normalization, policy compilation,
receipt eligibility, and the production receipt binding projection. Each keeps
the compiler/toolchain assumption visible. The remaining four claims retain
their tested/model-only status even when their exact release roles are
independently observed.

## Quick start

Install the four colocated `v0.1.0` binaries on a supported native Linux host.
The expected archive digest is part of this reviewed source document; the
GitHub repository and release channel remain distribution trust inputs.

```console
version=0.1.0
case "$(uname -m)" in
  x86_64)
    architecture=x86_64
    target=x86_64-unknown-linux-gnu
    expected_sha256=e0bf91c787d67be9c96f76992b661c3fa905707491e51310673302bf88776040
    ;;
  aarch64)
    architecture=aarch64
    target=aarch64-unknown-linux-gnu
    expected_sha256=a30e3b83eaa56a2a97b111a551d75c63261e0247ac65c30c51e787f49db6138f
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 3
    ;;
esac
archive="proofbound-runtime-v${version}-${target}.tar.gz"
install_root="$PWD/proofbound-runtime-v${version}-${architecture}"
test ! -e "$archive"
test ! -e "$install_root"
curl --proto '=https' --tlsv1.2 --fail --location \
  --output "$archive" \
  "https://github.com/bordumb/proofbound-runtime/releases/download/v${version}/${archive}"
printf '%s  %s\n' "$expected_sha256" "$archive" | sha256sum --check -
mkdir "$install_root"
tar --extract --gzip --file "$archive" --directory "$install_root"
"$install_root/pbr" --version
"$install_root/pbr-verify" --version
"$install_root/pbr-compose" --version
```

The maintained installer performs the same archive check, rejects any changed
member or embedded binary identity, and requires a new absolute destination:

```console
python3 tools/install_release.py \
  --version 0.1.0 \
  --destination /absolute/new/proofbound-runtime-v0.1.0
```

To build from source instead:

```console
cargo build --locked --release --bins
target/release/pbr --version
target/release/pbr-verify --version
target/release/pbr-compose --version
```

The host must provide a delegated cgroup v2 directory with the `pids`
controller enabled and no direct processes. See the
[version 0.1 installation and host-readiness guide](docs/guides/install-v0.1.md)
for the maintained systemd delegation recipe. Confirm all required mechanisms
before running a workload:

```console
target/release/pbr doctor --cgroup-root /path/to/delegated/cgroup
```

Create a plan beside an existing statically linked executable. Replace the
absolute executable path below, and make sure `output/` and `receipt.json` do
not already exist:

```toml
schema = "proofbound-runtime-plan/1"
id = "example.hello"

[command]
executable = "/absolute/path/to/static-tool"
arguments = []
working_directory = "."

[authority]
network = "deny"
environment = []
read = []
runtime_read = []
write = ["output"]
execute = ["/absolute/path/to/static-tool"]

[limits]
wall_time_ms = 5000
stdout_bytes = 65536
stderr_bytes = 65536
processes = 1
```

Validate, execute, independently verify, and inspect it:

```console
target/release/pbr plan check --plan plan.toml
target/release/pbr run --plan plan.toml --receipt receipt.json \
  --cgroup-root /path/to/delegated/cgroup >run-result.json
COMMITMENT=$(python3 -c \
  'import json; print(json.load(open("run-result.json"))["commitment"])')
EXECUTION_ID=$(python3 -c \
  'import json; print(json.load(open("run-result.json"))["execution_id"])')
target/release/pbr-verify --expected-commitment "$COMMITMENT" receipt.json
target/release/pbr inspect receipt.json
```

`runtime_read` must explicitly list canonical absolute library roots for a
dynamically linked workload. Those roots are measured authority, not an
implicit convenience. `tools/ci/native-linux.sh` is the maintained reference
for creating a delegated test boundary with systemd.

The release workflow goes one step further. For each supported architecture it
builds the bundle twice, independently verifies the Proofbound release, runs
the exact extracted Runtime binaries, and invokes the extracted `pbr-compose`:

```console
pbr-compose \
  --release /path/to/proofbound-release \
  --proofbound-verifier /path/to/proofbound-release/bin/proofbound-verify \
  --runtime-bundle /path/to/extracted-runtime-bundle \
  --execution-receipt execution-receipt.json \
  --execution-commitment "$COMMITMENT" \
  --expected-execution-id "$EXECUTION_ID" \
  --output composed-receipt.json
```

The composition preserves claim facets, assumptions, exclusions, open
obligations, verifier identities, and trusted-computing-base identities. It
does not promote `MODEL_ONLY` or `TESTED` evidence to `ARTIFACT_BOUND`.

## Repository checks

Install the pinned Rust and Lean toolchains, `just`, `cargo-deny`, Kani 0.67.0,
and the pinned `proofbound` revision. Then run:

```console
just ci
```

The current CI checks documentation, project metadata, the Rust workspace,
independent conformance, dependency policy, Lean 4.33 models,
source-refinement bridges, bounded Kani domains, Proofbound status derivation,
and native Linux enforcement. The release workflow builds each architecture
twice and rejects byte drift before it executes, verifies, and composes the
exact release binaries.

`just release-receipt <context> <observation-inputs> /absent/output/path`
rebuilds the current assurance graph for one reviewed native release context,
creates a fresh Proofbound release envelope, and retains the independent
verifier report beside it.

## Documentation

- [Documentation map](docs/README.md)
- [Initial specification](docs/specs/0001_initial_spec.md)
- [Version 1 CLI specification](docs/specs/0002_cli_surface.md)
- [Release receipt composition specification](docs/specs/0003_release_receipt_composition.md)
- [Host-readiness explanation specification](docs/specs/0004_doctor_explanations.md)
- [Read-only preflight specification](docs/specs/0005_read_only_preflight.md)
- [Maintained static example](docs/guides/maintained-example.md)
- [Threat model](docs/threat-model.md)
- [Architecture decisions](docs/adr/README.md)
- [Proofbound feedback loop](docs/proofbound-feedback/README.md)
- [Contributor and agent rules](AGENTS.md)

## Supported platforms

Version 0.1 targets native Linux on `x86_64` and `aarch64`. A supported host is
non-root, exposes the reviewed Landlock ABI range 3 through 11, supports
`no_new_privs` and the registered seccomp actions, and supplies a delegated
cgroup v2 root with the `pids` controller enabled. `pbr doctor` reports the
observed capability identity. Any missing, older, newer, mismatched, or
unreviewed mechanism fails closed; macOS and Windows can validate plans and
inspect receipts but cannot execute them. A container or mock does not count as
native enforcement evidence.

## License

Proofbound Runtime is available under the [MIT License](LICENSE).
