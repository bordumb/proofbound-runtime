# Local CI tools

This directory contains small, networkless checks shared by local development
and hosted CI.

| Tool | Purpose |
| --- | --- |
| `version.py` | Verify that `VERSION` and Cargo workspace metadata agree. |
| `changelog.py` | Validate changelog structure and release-version coverage. |
| `documentation.py` | Check text hygiene, Markdown fences, local links, and feedback IDs. |
| `authority-refinement.sh` | Compile the generated authority translation and handwritten refinement modules. |
| `policy-refinement.sh` | Compile the generated policy translation and handwritten refinement modules. |
| `receipt-refinement.sh` | Compile the generated receipt translation and handwritten refinement modules. |
| `manifests.sh` | Compile Proofbound manifests and derive current claim status. |
| `pre-commit.sh` | Run the fast metadata, documentation, formatting, and manifest checks. |
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

The scripts must not fetch dependencies or update committed files. Bootstrap
and dependency installation are separate operations. CI installs exact tool
versions before it invokes the same scripts.

Each refinement script compiles one generated Aeneas environment as a separate
Lean root. The policy translation repeats declarations from the authority
translation, so the root library cannot import both generated environments.
The complete gate must invoke every refinement script before Proofbound audits
the registered theorem modules.

As the implementation grows, add a named script for each distinct evidence
family. Keep `ci.sh` as an ordered coordinator. Do not hide theorem, bounded,
native Linux, or independent-verifier failures behind one generic check.
