# Local CI tools

This directory contains small, networkless checks shared by local development
and hosted CI.

| Tool | Purpose |
| --- | --- |
| `version.py` | Verify that `VERSION` and Cargo workspace metadata agree. |
| `changelog.py` | Validate changelog structure and release-version coverage. |
| `documentation.py` | Check text hygiene, Markdown fences, local links, and feedback IDs. |
| `summarize_timings.py` | Validate retained CI timing JSONL and print deterministic human latency statistics. |
| `authority-refinement.sh` | Compile the generated authority translation and handwritten refinement modules. |
| `policy-refinement.sh` | Compile the generated policy translation and handwritten refinement modules. |
| `receipt-refinement.sh` | Compile the generated receipt translation and handwritten refinement modules. |
| `manifests.sh` | Compile Proofbound manifests and derive current claim status. |
| `pre-commit.sh` | Run the fast metadata, documentation, fixture, formatting, lint, and workspace-test checks. |
| `ci.sh` | Run the complete current repository gate in a fixed order. |
| `../release/build-linux.sh` | Build a native Linux release bundle twice and require byte equality. |
| `../release/observation_inputs.py` | Build the closed external byte-input manifest for one native release context. |
| `../release/proofbound-release.sh` | Build a fresh Proofbound release envelope and retain the independent verification report beside it. |

Run the full gate with:

```console
just ci
```

Create and independently verify a Proofbound release envelope at a path that
does not yet exist:

```console
just release-receipt \
  release-linux-x86-64 \
  dist/native-evidence/x86_64/proofbound-observation-inputs.json \
  /absolute/path/to/proofbound-runtime-release
```

The command writes the independent verifier's canonical JSON report beside the
release directory with the suffix `.verification.json`. It refuses to replace
either output.

Install the optional local pre-commit hook with:

```console
just hooks
```

The fast hook deliberately excludes Lean refinement and fresh Proofbound/Kani
evidence. Run `just ci` once at each completed claim-wave head; that complete
gate retains every formal and fresh-evidence requirement.

The scripts must not fetch dependencies or update committed files. Bootstrap
and dependency installation are separate operations. CI installs exact tool
versions before it invokes the same scripts.

Each refinement script compiles one generated Aeneas environment as a separate
Lean root. The policy translation repeats declarations from the authority
translation, so the root library cannot import both generated environments.
The complete gate must invoke every refinement script before Proofbound audits
the registered theorem modules.

The workspace Rust test stage also runs the bounded-domain consistency guard
defined by Specification 0006. It checks the committed claim, cited bounded
evidence, and model-check declarations before the later Proofbound stage. It
is a local fail-closed invariant, not an evidence producer.

The fast and full gates test the network experiment recorders and performance
verifiers without running either hosted experiment. Only an explicit manual
workflow dispatch against one exact 40-character commit creates a network
namespace, applies an experiment rule, publishes a network result, or runs the
hosted performance matrix.

Every required lane also renders its validated timing table in the GitHub job
summary so an actionable regression does not require downloading artifacts.

After downloading one or more `proofbound-runtime-ci-timing-*` artifacts from
successful and failed required runs, summarize their stage and unit records
with:

```console
python3 tools/ci/summarize_timings.py /absolute/path/to/downloaded-artifacts
```

The report groups successful durations by runner architecture and the closed
stage and unit names, prints integer median and nearest-rank p95 values, and
retains the failure count. It rejects malformed, duplicate,
substituted-revision, and outcome-inconsistent records. This remains
operational metadata for evaluating RT-0.4; it is not Proofbound evidence or a
verification input.

As the implementation grows, add a named script for each distinct evidence
family. Keep `ci.sh` as an ordered coordinator. Do not hide theorem, bounded,
native Linux, or independent-verifier failures behind one generic check.
