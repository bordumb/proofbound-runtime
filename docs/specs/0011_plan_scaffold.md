# Specification 0011: Reviewable execution-plan scaffold

- **Status:** accepted for implementation
- **Applies to:** `pbr plan scaffold` in Runtime 0.2
- **Roadmap:** RT-3.3

## Purpose and non-claim

`pbr plan scaffold` helps an operator inventory the static ELF closure of one
exact executable. It never executes the target and never describes its output
as a safe, complete, validated, or executable Runtime policy.

The output schema is `proofbound-runtime-plan-scaffold/1`. It is a JSON
diagnostic artifact, not a version 1 canonical-JSON plan and not a version 2
deterministic-CBOR plan. `pbr plan check`, `pbr run`, the receipt producer, and
the independent verifier do not accept it as verification input.

## Closed command

The first command shape is:

```text
pbr plan scaffold --executable ABSOLUTE_PATH --host-profile PROFILE
```

`PROFILE` is one of these closed Linux ELF64 profiles:

- `linux-glibc-x86-64-v1`
- `linux-glibc-aarch64-v1`
- `linux-musl-x86-64-v1`
- `linux-musl-aarch64-v1`

The selected profile fixes the ELF architecture, dynamic-loader family,
default library search directories, loader-cache behavior, and musl path-file
behavior. An executable whose architecture or interpreter family differs from
the selected profile is rejected before dependency traversal.

## Bounded read-only discovery

The scaffold implementation performs only metadata inspection and bounded file
reads. It does not invoke the executable, its interpreter, `ldd`, or any other
mechanism that can transfer control to target-controlled code.

The implementation:

1. requires an absolute executable path;
2. records every symlink hop and rejects cycles, relative-root escapes,
   non-regular final targets, and path or identity drift;
3. parses ELF64 little-endian headers, `PT_INTERP`, `PT_DYNAMIC`, load-segment
   virtual-address mappings, `DT_NEEDED`, `DT_RPATH`, and `DT_RUNPATH` without
   executing the image;
4. resolves the interpreter and the transitive `DT_NEEDED` closure using the
   selected profile's ordered search semantics;
5. treats `DT_RUNPATH` as applying only to the declaring object's direct
   dependencies and inherited `DT_RPATH` according to the selected glibc or
   musl profile;
6. expands only `$ORIGIN` and `${ORIGIN}` relative to the declaring object's
   resolved parent; other dynamic tokens remain open items;
7. consults the glibc loader cache or musl path file as data, records its exact
   identity, and never trusts environment-provided library paths; and
8. bounds file size, dependency count, search-directory count, symlink depth,
   string-table size, and total bytes read.

Resolution records the requested soname, declaring object, ordered candidates,
selected regular file, symlink chain, content identity, and the search rule
that selected it. A missing dependency is a typed failure. Multiple viable
candidates remain visible as a `search-path-conflict` open item even though the
profile deterministically selects the first candidate.

## Output

The JSON object is closed and contains:

- `schema`, `safe_policy: false`, and the selected `host_profile`;
- the requested executable and its resolved artifact identity;
- the optional ELF interpreter and its artifact identity;
- the exact loader cache or path file and identified host helper used during
  resolution;
- one ordered record per directly or transitively resolved dependency;
- suggested runtime roots, each with the exact dependency paths and resolution
  facts that caused the suggestion; and
- a sorted, deduplicated `open_items` array.

Every output includes open items requiring a human to choose:

- write roots;
- environment variable names;
- wall-time, process, stdout, stderr, memory, and swap limits; and
- network mode.

Dynamic language packages, plugin loading, configuration searches, unsupported
dynamic tokens, environment-dependent searches, and other unresolved dynamic
loads are reported as open items. Absence of a reported dynamic load is not a
claim that no such load can occur.

## Stable failures

Failures use the existing `pbr: CODE` channel and exit class 2. The closed
initial codes are:

- `scaffold.executable.path-invalid`
- `scaffold.executable.read-failed`
- `scaffold.executable.identity-drift`
- `scaffold.elf.invalid`
- `scaffold.elf.architecture-mismatch`
- `scaffold.elf.interpreter-mismatch`
- `scaffold.elf.dynamic-invalid`
- `scaffold.profile.unsupported`
- `scaffold.loader-data.invalid`
- `scaffold.dependency.missing`
- `scaffold.dependency.identity-drift`
- `scaffold.bound.exceeded`
- `cli.output.write-failed`

## Evidence and fixtures

The registered attack corpus covers a static ELF, glibc closure, musl closure,
missing library, conflicting search path, plugin/open-load warning, symlink
cycle, unsupported dynamic token, and identity drift. Tests use synthetic ELF
fixtures in isolated temporary trees; fixture `RPATH`/`RUNPATH` entries take
precedence over unrelated developer-machine libraries.

The claim is limited to bounded, deterministic static discovery under the
selected host profile. Runtime completeness, target behavior, package-manager
semantics, and the safety of a human-authored plan remain outside that claim.
