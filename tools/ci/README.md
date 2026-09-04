# Local CI tools

This directory contains small, networkless checks shared by local development
and hosted CI.

| Tool | Purpose |
| --- | --- |
| `version.py` | Verify that `VERSION` and Cargo workspace metadata agree. |
| `changelog.py` | Validate changelog structure and release-version coverage. |
| `documentation.py` | Check text hygiene, Markdown fences, local links, and feedback IDs. |
| `manifests.sh` | Run Proofbound Tier 0 manifest compilation and status derivation. |
| `pre-commit.sh` | Run the fast metadata, documentation, formatting, and manifest checks. |
| `ci.sh` | Run the complete current repository gate in a fixed order. |

Run the full gate with:

```console
just ci
```

Install the optional local pre-commit hook with:

```console
just hooks
```

The scripts must not fetch dependencies or update committed files. Bootstrap
and dependency installation are separate operations. CI installs exact tool
versions before it invokes the same scripts.

As the implementation grows, add a named script for each distinct evidence
family. Keep `ci.sh` as an ordered coordinator. Do not hide theorem, bounded,
native Linux, or independent-verifier failures behind one generic check.
